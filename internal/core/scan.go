// Secret-value scanning: betterleaks embedded in-process, the sole authority
// on secret values. Any engine error or scan-deadline truncation blocks: a
// guard that fails closed does not get a backup engine or a hand-rolled
// pre-filter.
package core

import (
	"bufio"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/regexp"
	regexpre2 "github.com/betterleaks/betterleaks/regexp/re2"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/rs/zerolog"
)

// scanDeadline is the cooperative cancellation budget for one scan. It is
// half the smallest configured post-hook timeout (Codex: 6s), leaving margin
// when Betterleaks observes cancellation promptly.
// Measured 2026-07-25 with the agent-guard-authenticated-url rule added:
// ordinary output (logs, JSON, source) stays at tens of ms even at 4 MB, and
// verbose pip/uv output carrying an auth URL every other line is 275ms at
// 512 KB. But cost is quadratic in MATCH COUNT, not bytes, because
// betterleaks builds a +/-20-line context window per match before the filter
// runs. A maximally dense corpus (one auth-URL-shaped token per 18 bytes)
// crosses this deadline at roughly 290 KB and takes 9s at 512 KB. Betterleaks
// checks cancellation between phases rather than enforcing a hard wall, so a
// dense payload can continue consuming CPU after the context expires. When
// control returns Agent Guard denies the event, but a host that abandons a
// timed-out post hook may expose the original output. This is an accepted
// denial-of-service and host-contract limitation; see
// rule_authenticated_url.go and docs/LIMITATIONS.md.
const scanDeadline = 3 * time.Second

// buildDetector constructs one betterleaks detector for the process lifetime.
// Betterleaks reports construction failures through zerolog.Fatal, whose
// default handler calls os.Exit and therefore cannot be recovered. Override
// that handler before construction so the CLI's panic boundary can normalize
// the failure into a fail-closed result.
func buildDetector() *detect.Detector {
	// Discard Betterleaks logs without disabling Fatal events. A Nop logger
	// would suppress the Fatal callback as well and let construction continue
	// after an unrecoverable error.
	logging.Logger = zerolog.New(io.Discard)

	// re2 is the CLI default; recall parity was validated only against it,
	// and stdlib regexp can Fatal on a rule it cannot compile. The engine is
	// captured at regex-compile time (during TOML parse), so this must
	// precede config.Default().
	regexp.SetEngine(regexpre2.RE2{})
	cfg, err := config.Default()
	if err != nil {
		panic("agent-guard: config.Default failed: " + err.Error())
	}
	// One local rule on top of the embedded defaults; see
	// rule_authenticated_url.go for why it is not a config file.
	if err := addAuthenticatedURLRule(cfg); err != nil {
		panic("agent-guard: authenticated-url rule failed: " + err.Error())
	}

	det := newDetectorContext(context.Background(), cfg)
	// The library defaults to 0 (no base64/hex/percent decoding); the CLI
	// sets 5. Set explicitly or lose the encoded-secret recall the benchmark
	// credits.
	det.MaxDecodeDepth = 5
	// Otherwise any line containing gitleaks:allow/betterleaks:allow
	// suppresses findings — a one-token agent-forgeable bypass. The human
	// escape hatch (allowFile) replaces it with a non-forgeable one.
	det.IgnoreGitleaksAllow = true
	return det
}

func newDetectorContext(ctx context.Context, cfg *config.Config) *detect.Detector {
	previousFatalExit := zerolog.FatalExitFunc
	zerolog.FatalExitFunc = func() {
		panic("betterleaks reported a fatal initialization error")
	}
	defer func() {
		zerolog.FatalExitFunc = previousFatalExit
	}()
	return detect.NewDetectorContext(ctx, cfg, detect.ValidationOptions{})
}

// scan runs one detection pass bounded by scanDeadline. See scanWithContext
// for the deadline-fail-closed mechanics.
func scan(det *detect.Detector, text string, allowed map[string]struct{}) ([]Finding, error) {
	ctx, cancel := context.WithTimeout(context.Background(), scanDeadline)
	defer cancel()
	return scanWithContext(ctx, det, text, allowed)
}

// scanWithContext runs one detection pass and drops any finding whose
// allow-key is present in the allowlist. A deadline hit returns partial
// findings with no error from DetectContext, so ctx.Err() must be checked: a
// non-nil error means the scan was truncated and the caller must fail closed
// (never treated as "clean, N findings"). Split from scan so tests can inject
// a short deadline without a real multi-second sleep.
func scanWithContext(ctx context.Context, det *detect.Detector, text string, allowed map[string]struct{}) ([]Finding, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}

	raw := det.DetectContext(ctx, sources.Fragment{Raw: text})
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var newlines []int
	if len(raw) > 0 {
		newlines = newlineOffsets(text)
	}

	findings := make([]Finding, 0, len(raw))
	for _, f := range raw {
		key := allowKey(f.Secret)
		if key != "" {
			if _, ok := allowed[key]; ok {
				continue
			}
		}
		start, end := matchSpan(len(text), newlines, f.StartLine, f.StartColumn, f.EndColumn)
		findings = append(findings, Finding{Rule: f.RuleID, Secret: f.Secret, AllowKey: key, Start: start, End: end})
	}
	return findings, nil
}

// newlineOffsets lists the byte index of every '\n' in text, mirroring
// betterleaks' own findNewlineIndices. matchSpan depends on this being the
// same enumeration the engine used to derive its columns.
func newlineOffsets(text string) []int {
	offsets := make([]int, 0, strings.Count(text, "\n"))
	for i, b := range []byte(text) {
		if b == '\n' {
			offsets = append(offsets, i)
		}
	}
	return offsets
}

// matchSpan converts one betterleaks match location into a half-open byte
// range in the scanned text, returning an empty range (0, 0) when the inputs
// are not self-consistent so the caller falls back to whole-output
// replacement.
//
// The conversion is not the obvious one, and the report struct does not say
// so. betterleaks derives columns in detect.location() as
//
//	startColumn = (start - prevNewLine) + 1
//	endColumn   = end - prevNewLine
//
// where prevNewLine is the byte index OF the newline that ends the previous
// line, not the first byte of the current line. Columns are therefore
// line-relative, and every line after the first is additionally shifted by
// one against a normal 1-based column. StartLine is 0-based here because the
// fragment is constructed with StartLine 0. Reconstructing the same base
// makes the arithmetic exact:
//
//	base  = 0 for line 0, else the offset of the newline ending the line before
//	start = base + startColumn - 1
//	end   = base + endColumn
//
// This holds uniformly, including for decoded findings (the engine maps those
// back to raw coordinates before computing the location) and for the
// "last line with no trailing newline" branch, which leaves the report's Line
// field covering the whole text and so cannot be used as the base instead.
// Verified against single-line, first/middle/last-line, CRLF, multi-byte
// UTF-8, and base64 inputs; the guarded arithmetic below plus the caller's
// re-scan check keep a future engine change from failing open.
func matchSpan(textLen int, newlines []int, startLine, startColumn, endColumn int) (int, int) {
	if startLine < 0 || startLine > len(newlines) {
		return 0, 0
	}
	base := 0
	if startLine > 0 {
		base = newlines[startLine-1]
	}
	start, end := base+startColumn-1, base+endColumn
	if start < 0 || end > textLen || start >= end {
		return 0, 0
	}
	return start, end
}

// allowKey is a stable, position-independent SHA-256 key for a
// matched secret value: a human vets the value once and lists the key in
// ~/.config/agent-guard/allow. betterleaks' own Finding.Fingerprint is
// rejected as the key because it is position-sensitive (same secret, new
// location, new fingerprint).
func allowKey(secret string) string {
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// redact replaces each finding's matched byte span with a marker, preserving
// the rest of the text. Returns "", false when any finding has no usable span,
// so the caller falls back to replacing the whole output.
//
// Spans, not substring replacement. Replacing Finding.Secret misses every
// decoded finding outright (the decoded value is absent from the raw text, so
// ReplaceAll no-ops while still reporting success) and, for a low-entropy
// false positive, rewrites every unrelated occurrence of that string elsewhere
// in the output.
//
// Overlapping spans are merged rather than rejected: two rules matching the
// same token is routine, and rejecting would push the common case onto
// whole-output replacement. Sorting by start and copying through a single
// cursor makes that merge fall out for free.
func redact(text string, findings []Finding) (string, bool) {
	ordered := make([]Finding, len(findings))
	copy(ordered, findings)
	for _, f := range ordered {
		if f.Start < 0 || f.End > len(text) || f.Start >= f.End {
			return "", false
		}
	}
	// Widest span first on a tie so the emitted marker is deterministic:
	// SortFunc is not stable, and this output goes to the model.
	slices.SortFunc(ordered, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(b.End, a.End))
	})

	var b strings.Builder
	prev := 0
	for _, f := range ordered {
		if f.Start >= prev {
			b.WriteString(text[prev:f.Start])
			b.WriteString("[REDACTED:" + f.Rule + "]")
			prev = f.End
			continue
		}
		// Overlaps a span already written. Advancing the cursor without
		// emitting text or a second marker merges the two, so the shared
		// region stays covered by one marker.
		prev = max(prev, f.End)
	}
	b.WriteString(text[prev:])
	return b.String(), true
}

// redactVerified is the redaction the post-call path uses: a span redaction
// that is only accepted once a re-scan proves the secret is actually gone.
//
// The span arithmetic in matchSpan reconstructs an unexported betterleaks
// convention, so it is the fast path, not the guarantee. Re-scanning the
// result checks the property that actually matters and stays correct if a
// future engine bump changes how locations are reported. Anything short of a
// clean re-scan (residual findings, or the shared deadline expiring
// mid-verify) returns false and falls back to whole-output replacement.
//
// The guarantee is exactly "the returned text re-scans clean", not "every
// span was byte-exact": a span that is wrong but still swallows the secret
// passes, and so does one that leaves only a fragment the engine no longer
// recognizes. That is the same bar the guard applies everywhere else, since a
// clean scan is what it accepts as safe on every other path.
//
// ctx is deliberately the SAME context used by the first scan, so verification
// does not receive a fresh three-second budget. This still is not a hard
// runtime bound because Betterleaks observes cancellation between phases.
func redactVerified(ctx context.Context, det *detect.Detector, text string, findings []Finding, allowed map[string]struct{}) (string, bool) {
	out, ok := redact(text, findings)
	if !ok {
		return "", false
	}
	residual, err := scanWithContext(ctx, det, out, allowed)
	if err != nil || len(residual) > 0 {
		return "", false
	}
	return out, true
}

// redactStructuredVerified applies findings from the newline-joined string
// leaves back to their originating leaves. Maps, slices, non-string scalars,
// and unaffected strings remain unchanged, so schema-valid host output stays
// schema-valid after redaction.
func redactStructuredVerified(
	ctx context.Context,
	det *detect.Detector,
	value any,
	findings []Finding,
	allowed map[string]struct{},
) (any, string, bool) {
	original := walkStrings(value, nil, nil)
	local := make([][]Finding, len(original))
	for _, finding := range findings {
		offset := 0
		mapped := false
		for index, text := range original {
			end := offset + len(text)
			if finding.Start >= offset && finding.End <= end {
				adjusted := finding
				adjusted.Start -= offset
				adjusted.End -= offset
				local[index] = append(local[index], adjusted)
				mapped = true
				break
			}
			offset = end + 1
		}
		if !mapped {
			return nil, "", false
		}
	}

	redacted := make([]string, len(original))
	for index, text := range original {
		if len(local[index]) == 0 {
			redacted[index] = text
			continue
		}
		var ok bool
		if redacted[index], ok = redact(text, local[index]); !ok {
			return nil, "", false
		}
	}
	flat := strings.Join(redacted, "\n")
	residual, err := scanWithContext(ctx, det, flat, allowed)
	if err != nil || len(residual) > 0 {
		return nil, "", false
	}

	index := 0
	updated := replaceStringLeaves(value, redacted, &index)
	if index != len(redacted) {
		return nil, "", false
	}
	return updated, flat, true
}

func replaceStringLeaves(value any, replacements []string, index *int) any {
	switch value := value.(type) {
	case string:
		if *index >= len(replacements) {
			return value
		}
		replacement := replacements[*index]
		*index = *index + 1
		return replacement
	case map[string]any:
		updated := make(map[string]any, len(value))
		for _, key := range sortedKeys(value) {
			updated[key] = replaceStringLeaves(value[key], replacements, index)
		}
		return updated
	case []any:
		updated := make([]any, len(value))
		for i, child := range value {
			updated[i] = replaceStringLeaves(child, replacements, index)
		}
		return updated
	default:
		return value
	}
}

// loadAllowlist reads the human-maintained allow-key file, one key per line,
// blank lines and #-comments ignored. A missing file is not an error (the
// common case: no false positives vetted yet).
func loadAllowlist(path string) (map[string]struct{}, error) {
	allowed := map[string]struct{}{}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return allowed, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allowed[line] = struct{}{}
	}
	return allowed, scanner.Err()
}

func defaultAllowlistPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "agent-guard", "allow")
}

// LoadAllowlist reads the human-maintained allow-key file.
func LoadAllowlist(path string) (map[string]struct{}, error) {
	return loadAllowlist(path)
}

// DefaultAllowlistPath returns the fixed per-user allowlist path.
func DefaultAllowlistPath() string {
	return defaultAllowlistPath()
}
