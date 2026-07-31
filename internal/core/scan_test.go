package core

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/config"

	"github.com/betterleaks/betterleaks/detect"
)

var (
	testDetectorOnce sync.Once
	testDetectorInst *detect.Detector
)

func testDetector(t *testing.T) *detect.Detector {
	t.Helper()
	testDetectorOnce.Do(func() { testDetectorInst = buildDetector() })
	return testDetectorInst
}

// stripeKey and ghToken are assembled from parts at runtime so no scanner
// (including the deployed guard watching this repo's own tool calls) flags
// this test file's source text.
func stripeKey() string { return "sk_live_" + "4eC39HqLyj" + "WDarjtT1zdp7dc" }
func ghToken() string   { return "ghp_" + strings.Repeat("A1b2C3d4", 5) }

// throwawayPrivateKeyPEM generates a fresh ed25519 key at test time; never a
// real or pasted credential.
func throwawayPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: priv}
	return string(pem.EncodeToMemory(block))
}

func TestScanFindsStripeKey(t *testing.T) {
	findings, err := scan(testDetector(t), "export STRIPE_KEY="+stripeKey(), nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 1 || findings[0].Rule != "stripe-access-token" {
		t.Fatalf("findings = %#v, want one stripe-access-token finding", findings)
	}
}

func TestScanFindsGithubToken(t *testing.T) {
	findings, err := scan(testDetector(t), "token: "+ghToken(), nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 1 || findings[0].Rule != "github-pat" {
		t.Fatalf("findings = %#v, want one github-pat finding", findings)
	}
}

func TestScanFindsPrivateKey(t *testing.T) {
	findings, err := scan(testDetector(t), throwawayPrivateKeyPEM(t), nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 1 || findings[0].Rule != "private-key" {
		t.Fatalf("findings = %#v, want one private-key finding", findings)
	}
}

func TestScanCleanTextFindsNothing(t *testing.T) {
	findings, err := scan(testDetector(t), "just some ordinary log output, nothing here", nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
}

func TestScanIgnoresGitleaksAllowComment(t *testing.T) {
	// IgnoreGitleaksAllow=true closes the forgeable inline-comment bypass: an
	// agent cannot suppress a finding by appending "gitleaks:allow".
	findings, err := scan(testDetector(t), "STRIPE_KEY="+stripeKey()+" # gitleaks:allow", nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want the gitleaks:allow comment to be ignored", findings)
	}
}

func TestScanEmptyTextShortCircuits(t *testing.T) {
	findings, err := scan(testDetector(t), "   \n\t  ", nil)
	if err != nil || findings != nil {
		t.Fatalf("scan(blank) = %#v, %v; want nil, nil", findings, err)
	}
}

func TestScanDeadlineFailsClosed(t *testing.T) {
	// A scan whose context is already expired must return an error (fail
	// closed), never partial/empty findings treated as "clean".
	det := testDetector(t)
	big := strings.Repeat("filler text with a token-like blob abcdefghij0123456789\n", 400000)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure the deadline has actually elapsed

	_, err := scanWithContext(ctx, det, big, nil)
	if err == nil {
		t.Fatal("scanWithContext with an expired deadline returned no error; must fail closed")
	}
}

func TestAllowlistDropsVettedSecretButNotOthers(t *testing.T) {
	secret := stripeKey()
	allowed := map[string]struct{}{allowKey(secret): {}}

	findings, err := scan(testDetector(t), "STRIPE_KEY="+secret, allowed)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want the allowlisted key dropped", findings)
	}

	// A different secret value is unaffected by another value's allow-key.
	findings, err = scan(testDetector(t), "token: "+ghToken(), allowed)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want the non-allowlisted secret still flagged", findings)
	}
}

func TestAllowKeyIsPositionIndependentAndNonReversible(t *testing.T) {
	// The same secret value found in two different surrounding texts (i.e.
	// two different positions/spans) must produce the same allow-key, since
	// a human vets the VALUE, not where it happened to appear.
	secret := stripeKey()
	findingsA, err := scan(testDetector(t), "STRIPE_KEY="+secret, nil)
	if err != nil || len(findingsA) != 1 {
		t.Fatalf("scan A: findings=%#v err=%v", findingsA, err)
	}
	findingsB, err := scan(testDetector(t), "some preamble text\nexport OTHER="+secret+"\nmore text", nil)
	if err != nil || len(findingsB) != 1 {
		t.Fatalf("scan B: findings=%#v err=%v", findingsB, err)
	}
	if findingsA[0].AllowKey != findingsB[0].AllowKey {
		t.Fatalf("allow keys differ across positions: %q vs %q", findingsA[0].AllowKey, findingsB[0].AllowKey)
	}
	if strings.Contains(findingsA[0].AllowKey, secret) {
		t.Fatal("allow key must not embed the plaintext secret")
	}
}

func TestLoadAllowlistParsesKeysIgnoringBlanksAndComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow")
	content := "# comment\n\nabc123\n  \ndef456\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	allowed, err := loadAllowlist(path)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	for _, key := range []string{"abc123", "def456"} {
		if _, ok := allowed[key]; !ok {
			t.Errorf("allowed = %#v, missing %q", allowed, key)
		}
	}
	if len(allowed) != 2 {
		t.Fatalf("allowed = %#v, want exactly 2 keys", allowed)
	}
}

func TestLoadAllowlistMissingFileIsNotAnError(t *testing.T) {
	allowed, err := loadAllowlist(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	if len(allowed) != 0 {
		t.Fatalf("allowed = %#v, want empty", allowed)
	}
}

func TestPayloadCannotOverrideAllowlist(t *testing.T) {
	// The allowlist is human-maintained at a fixed filesystem path; nothing
	// in the hook payload itself can add an entry. An agent-forgeable field
	// (e.g. an "allow" key in tool input) must have zero effect on scanning.
	payload := map[string]any{
		"tool_input": map[string]any{
			"command": "echo " + stripeKey(),
			"allow":   allowKey(stripeKey()),
		},
	}
	findings, err := scan(testDetector(t), preText(payload), nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want the secret still flagged despite an in-payload allow field", findings)
	}
}

func TestRedactReplacesEverySpanPreservingSurroundingText(t *testing.T) {
	text := "before AAAA middle BBBB after"
	findings := []Finding{
		{Rule: "rule-a", Start: 7, End: 11},
		{Rule: "rule-b", Start: 19, End: 23},
	}

	got, ok := redact(text, findings)
	if !ok {
		t.Fatal("redact returned ok=false, want a span-level redaction")
	}
	want := "before [REDACTED:rule-a] middle [REDACTED:rule-b] after"
	if got != want {
		t.Fatalf("redact = %q, want %q", got, want)
	}
}

// Redaction must rewrite only the matched span. The old substring
// implementation replaced every occurrence of the secret text anywhere in the
// output, so one low-entropy false positive mangled unrelated text.
func TestRedactLeavesIdenticalTextOutsideTheMatchedSpan(t *testing.T) {
	text := "log level=debug\nkey=debug\ntrailer debug"
	findings := []Finding{{Rule: "generic-api-key", Secret: "debug", Start: 20, End: 25}}

	got, ok := redact(text, findings)
	if !ok {
		t.Fatal("redact returned ok=false, want a span-level redaction")
	}
	want := "log level=debug\nkey=[REDACTED:generic-api-key]\ntrailer debug"
	if got != want {
		t.Fatalf("redact = %q, want %q", got, want)
	}
}

// Two rules matching the same token is routine; merging keeps the common case
// on the span path instead of pushing it onto whole-output replacement.
func TestRedactMergesOverlappingSpans(t *testing.T) {
	text := "prefix OVERLAPPINGVALUE suffix"
	findings := []Finding{
		{Rule: "wide", Start: 7, End: 23},
		{Rule: "partial", Start: 14, End: 23},
		{Rule: "shares-start", Start: 7, End: 18},
		// Strictly nested. The cursor must not move backward here: the
		// widely-used gotextdiff applier assigns its cursor unconditionally
		// and so re-emits source already covered by the outer marker.
		{Rule: "nested", Start: 9, End: 12},
	}
	got, ok := redact(text, findings)
	if !ok {
		t.Fatal("redact returned ok=false, want overlapping spans merged")
	}
	want := "prefix [REDACTED:wide] suffix"
	if got != want {
		t.Fatalf("redact = %q, want %q", got, want)
	}
}

func TestRedactFallsBackToWholeReplacementWhenSpanUnusable(t *testing.T) {
	for name, f := range map[string]Finding{
		// The zero value: a Finding built without a span must fail closed.
		"no span":     {Rule: "generic-secret"},
		"negative":    {Rule: "generic-secret", Start: -1, End: 4},
		"past end":    {Rule: "generic-secret", Start: 4, End: 999},
		"inverted":    {Rule: "generic-secret", Start: 8, End: 3},
		"empty range": {Rule: "generic-secret", Start: 4, End: 4},
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := redact("some output", []Finding{f}); ok {
				t.Fatal("redact with an unusable span must signal fallback (ok=false)")
			}
		})
	}
}

// The regression this whole span mechanism exists for. With MaxDecodeDepth 5 a
// finding from a base64/hex/percent pass carries the DECODED secret, which
// never appears in the raw text. The previous ReplaceAll redaction silently
// no-opped and still reported success, so the untouched blob was handed to the
// model. The span covers the encoded chunk in raw coordinates instead.
func TestRedactDecodedFindingRewritesTheEncodedSpan(t *testing.T) {
	det := testDetector(t)
	plain := "export TOKEN=" + ghToken()
	for name, encoded := range map[string]string{
		"base64":  base64.StdEncoding.EncodeToString([]byte(plain)),
		"hex":     hex.EncodeToString([]byte(plain)),
		"percent": url.QueryEscape(plain),
	} {
		t.Run(name, func(t *testing.T) {
			text := "value: " + encoded
			findings, err := scan(det, text, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(findings) == 0 {
				t.Fatalf("no finding for %s-encoded secret; fixture no longer exercises the decode path", name)
			}
			got, ok := redactVerified(context.Background(), det, text, findings, nil)
			if !ok {
				t.Fatalf("redactVerified fell back to whole-output replacement for a %s finding", name)
			}
			if got == text {
				t.Fatalf("redactVerified returned the text unchanged; the %s blob was shipped verbatim", name)
			}
			if strings.Contains(got, encoded) {
				t.Fatalf("redactVerified left the encoded blob intact: %q", got)
			}
			if !strings.HasPrefix(got, "value: ") {
				t.Fatalf("redactVerified dropped surrounding text: %q", got)
			}
		})
	}
}

// A base64 value inside a kubectl-style secret dump is the motivating case:
// redact the one encoded value, keep the rest of the document readable.
func TestRedactDecodedFindingPreservesSurroundingDocument(t *testing.T) {
	det := testDetector(t)
	blob := base64.StdEncoding.EncodeToString([]byte("export TOKEN=" + ghToken()))
	benign := base64.StdEncoding.EncodeToString([]byte("hello"))
	text := "apiVersion: v1\nkind: Secret\ndata:\n  token: " + blob + "\n  greeting: " + benign + "\n"

	findings, err := scan(det, text, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got, ok := redactVerified(context.Background(), det, text, findings, nil)
	if !ok {
		t.Fatal("redactVerified fell back to whole-output replacement")
	}
	if strings.Contains(got, blob) {
		t.Fatalf("secret blob survived: %q", got)
	}
	for _, keep := range []string{"apiVersion: v1", "kind: Secret", "greeting: " + benign} {
		if !strings.Contains(got, keep) {
			t.Fatalf("redactVerified dropped %q from the document: %q", keep, got)
		}
	}
}

// Span arithmetic reconstructs an unexported betterleaks convention, so the
// re-scan is the actual guarantee. A wrong span must fail closed onto
// whole-output replacement rather than emit text that still holds the secret.
func TestRedactVerifiedRejectsAWrongSpan(t *testing.T) {
	det := testDetector(t)
	text := "padding padding\ntoken: " + ghToken()
	findings, err := scan(det, text, nil)
	if err != nil || len(findings) != 1 {
		t.Fatalf("scan: findings=%#v err=%v", findings, err)
	}

	// Point the span at unrelated leading text, leaving the secret intact.
	wrong := findings[0]
	wrong.Start, wrong.End = 0, len("padding")
	if _, ok := redactVerified(context.Background(), det, text, []Finding{wrong}, nil); ok {
		t.Fatal("redactVerified accepted a span that leaves the secret in the output")
	}

	// The correct span still passes, so the check above is not vacuous.
	if _, ok := redactVerified(context.Background(), det, text, findings, nil); !ok {
		t.Fatal("redactVerified rejected the correct span")
	}
}

func TestRedactVerifiedFailsClosedOnExpiredDeadline(t *testing.T) {
	det := testDetector(t)
	text := "token: " + ghToken()
	findings, err := scan(det, text, nil)
	if err != nil || len(findings) != 1 {
		t.Fatalf("scan: findings=%#v err=%v", findings, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)

	if _, ok := redactVerified(ctx, det, text, findings, nil); ok {
		t.Fatal("redactVerified must fail closed when the verifying re-scan cannot complete")
	}
}

// betterleaks reports columns relative to the byte index OF the newline
// ending the previous line, so every line after the first is shifted by one
// against a normal 1-based column, and the report's Line field is unusable as
// a base on the last line of an unterminated text. Pin the mapping across the
// shapes that exercise each branch.
func TestScanSpanCoversTheMatchAtEveryLinePosition(t *testing.T) {
	det := testDetector(t)
	secret := ghToken()
	for name, text := range map[string]string{
		"only line":         "token: " + secret,
		"first of three":    "token: " + secret + "\nsecond\nthird",
		"middle of three":   "first\ntoken: " + secret + "\nthird",
		"last unterminated": "first\nsecond\ntoken: " + secret,
		"last terminated":   "first\nsecond\ntoken: " + secret + "\n",
		"leading blanks":    "\n\ntoken: " + secret + "\n",
		"crlf":              "first\r\ntoken: " + secret + "\r\nthird",
		"multibyte before":  "héllo wörld ünïcode\ntoken: " + secret,
	} {
		t.Run(name, func(t *testing.T) {
			findings, err := scan(det, text, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("findings = %#v, want exactly one", findings)
			}
			f := findings[0]
			if f.Start < 0 || f.End > len(text) || f.Start >= f.End {
				t.Fatalf("span [%d:%d] is unusable for text of length %d", f.Start, f.End, len(text))
			}
			// Contains, not equals: the span covers the rule's whole match,
			// which is a superset of the reported secret whenever the rule
			// narrows it to a capture group.
			if got := text[f.Start:f.End]; !strings.Contains(got, f.Secret) {
				t.Fatalf("text[%d:%d] = %q, does not cover the reported secret", f.Start, f.End, got)
			}
			if out, ok := redact(text, findings); !ok || strings.Contains(out, f.Secret) {
				t.Fatalf("redact(ok=%v) = %q, secret survived", ok, out)
			}
		})
	}
}

func TestMatchSpanRejectsOutOfRangeLocations(t *testing.T) {
	// text is "ab\ncd", a single newline at offset 2.
	newlines := []int{2}
	for name, tc := range map[string]struct{ line, startCol, endCol int }{
		"line past newline count": {5, 1, 2},
		"negative line":           {-1, 1, 2},
		"column past end":         {1, 1, 99},
		"inverted columns":        {0, 3, 1},
		"zero width":              {0, 2, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if start, end := matchSpan(5, newlines, tc.line, tc.startCol, tc.endCol); start != 0 || end != 0 {
				t.Fatalf("matchSpan = (%d, %d), want the empty range that forces fallback", start, end)
			}
		})
	}
}

// Fixtures for the auth-URL rule are generated, never written down. Inline
// literals would make this file self-tripping twice over: the guard would
// block any agent reading or diffing its own test source, and it would block
// the edit that introduced them (which is exactly what happened on the first
// attempt at this test).
func fakeSecret(n int) string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[(i*17+7)%len(alphabet)]
	}
	return string(b)
}

func authURL(scheme, user, secret, host string) string {
	return scheme + "://" + user + ":" + secret + "@" + host
}

// TestScanAuthenticatedURL pins both halves of the one rule agent-guard adds
// on top of betterleaks' defaults: the shapes it must catch, and the
// placeholders and host:port lists it must not fire on, since a false positive
// here blocks or rewrites real tool output.
func TestScanAuthenticatedURL(t *testing.T) {
	ph := func(s string) string { return authURL("https", "user", s, "host.example.com/path") }
	for _, tc := range []struct {
		name string
		text string
		want bool
	}{
		// The shape of the 2026-07-25 leak: a uv/pip index-url with a token.
		{"uv index-url", `index-url = "` + authURL("https", "svc", fakeSecret(36), "registry.example.io/pypi/simple/") + `"`, true},
		{"postgres dsn", authURL("postgres", "svc", fakeSecret(20), "db.internal:5432/app"), true},
		{"redis empty user", authURL("redis", "", fakeSecret(20), "cache.internal:6379/0"), true},
		{"long opaque token", authURL("https", "x-access-token", fakeSecret(40), "git.example.com/org/repo.git"), true},
		{"amqp", authURL("amqp", "worker", fakeSecret(20), "broker.internal:5672"), true},

		// Placeholders and variable references.
		{"literal password", ph("password"), false},
		{"changeme", ph("changeme"), false},
		{"shell var", ph("${GITHUB_TOKEN}"), false},
		{"env percent", ph("%TOKEN%"), false},
		{"angle placeholder", ph("<your-password>"), false},

		// host:port,host:port lists must not read as a credential.
		{"etcd multi host", "etcd://node1:2379,node2:2379@cluster", false},
		{"kafka multi host", "kafka://broker1:9092,broker2:9092@cluster", false},
		{"stack trace shape", "http://src:line123:col45@trace", false},

		// Entropy floor is 3.0 and Shannon entropy is bounded by log2(n), so
		// nothing <=8 chars can match however random it looks.
		{"8 chars", ph(fakeSecret(8)), false},
		{"9 chars", ph(fakeSecret(9)), true},

		{"scp style no password", "git@github.com:org/repo.git", false},
		{"no credential", "https://github.com/org/repo.git", false},
		{"plain prose", "see https://example.com/docs for the ratio 3:1@scale", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := scan(testDetector(t), tc.text, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			var got bool
			for _, f := range findings {
				if f.Rule == authenticatedURLRuleID {
					got = true
				}
			}
			if got != tc.want {
				t.Fatalf("%s matched = %v, want %v (findings %#v)", authenticatedURLRuleID, got, tc.want, findings)
			}
		})
	}
}

// The guard must not block an agent from reading its own source.
func TestScanTestFileIsNotSelfTripping(t *testing.T) {
	src, err := os.ReadFile("scan_test.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	findings, err := scan(testDetector(t), string(src), nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("scan_test.go trips the guard: %#v", findings)
	}
}

// The rule must defer to an upstream rule of the same id, not shadow it.
func TestAddAuthenticatedURLRuleIsNoOpWhenPresent(t *testing.T) {
	cfg := &config.Config{Rules: map[string]config.Rule{authenticatedURLRuleID: {RuleID: authenticatedURLRuleID}}}
	if err := addAuthenticatedURLRule(cfg); err != nil {
		t.Fatalf("addAuthenticatedURLRule: %v", err)
	}
	if len(cfg.NoKeywordRules) != 0 || len(cfg.OrderedRules) != 0 {
		t.Fatalf("registered over an existing rule: %#v / %#v", cfg.NoKeywordRules, cfg.OrderedRules)
	}
}
