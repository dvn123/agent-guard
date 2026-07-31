// One locally-added betterleaks rule, kept in its own file so it can be
// deleted in one move once upstream ships an equivalent.
//
// Why it exists: betterleaks' 325 vendored default rules have no generic rule for a
// credential in a URL userinfo component (scheme://user:secret@host). Upstream
// ships only vendor-pinned variants — mongodb-connection-string,
// sidekiq-sensitive-url (hardcoded to contribsys.com), the azure connection
// strings — and curl-auth-user is gated on a literal "curl". Verified against
// the vendored betterleaks v1.6.1 on 2026-07-25: a uv/pip index-url carrying a real
// registry token scanned clean, as did a generic https URL with a 32-char
// random password, while provider-prefixed tokens in the same file were all
// caught.
//
// That shape is everywhere: pip/uv index-url, npm registry auth, git remotes
// with an embedded PAT, and every postgres:// redis:// amqp:// mongodb:// DSN.
//
// ACCEPTED RISK (decided 2026-07-25, deliberately not mitigated): this rule
// has no keywords, so it is evaluated on every scan, and betterleaks builds a
// +/-20-line context window per match before the filter runs. Cost is
// therefore quadratic in match count. Ordinary output is unaffected (4 MB of
// logs: 28ms; 512 KB of verbose pip output with an auth URL every other line:
// 275ms), but a maximally dense corpus (one auth-URL-shaped token per 18
// bytes) crosses the 3s scanDeadline at roughly 290 KB and takes 9s at 512 KB.
// Betterleaks does not enforce cancellation as a hard wall within every
// phase. Agent Guard denies the event once the detector returns, but the scan
// can still wedge the tool call and a host may abandon a timed-out post hook.
// The alternative (bounding scan input) was judged not worth the global
// recall change. Revisit that decision before claiming a hard runtime bound;
// the full host-level consequence is documented in docs/LIMITATIONS.md.
//
// Deliberately not solved by config file. agent-guard uses only the embedded
// default config so a tool payload cannot extend or weaken it; reading an
// external TOML would trade that guarantee away to fix a recall gap.
package core

import (
	"strings"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

// Namespaced so that if upstream ever ships its own "authenticated-url",
// both run rather than ours silently disappearing and regressing recall.
// Duplicate findings on one span are harmless: redaction is idempotent and
// specificity suppression handles the overlap.
const authenticatedURLRuleID = "agent-guard-authenticated-url"

// Any scheme, optional username (redis://:secret@host is common), a password
// of 9+ characters, then the host. 9 because the entropy floor below is 3.0
// and Shannon entropy is bounded by log2(n), so nothing shorter can ever
// pass; a lower bound here would imply coverage the filter cannot deliver.
// The password class excludes ':' and ',' so a host:port,host:port list in
// etcd:// and kafka:// URLs is not mistaken for a credential. Deliberately broad; precision comes from
// the filter below rather than from narrowing the shape. RE2: no lookarounds,
// and repeat counts cap at 1000.
const authenticatedURLPattern = `(?i)\b[a-z][a-z0-9+.\-]{1,31}://[^\s/?#\[\]@:]{0,256}:([^\s/?#\[\]@:,]{9,1000})@[^\s/?#@]{1,256}`

// Anchored, and matched against the captured password only, so these reject a
// placeholder wholesale rather than as a substring.
var authenticatedURLPlaceholders = []string{
	`^\$\{[^}]*\}$`,              // ${GITHUB_TOKEN}
	`^\$\([^)]*\)$`,              // $(pass show ...)
	`^\$[a-zA-Z_][a-zA-Z0-9_]*$`, // $TOKEN
	`^%[a-zA-Z_][a-zA-Z0-9_]*%$`, // %TOKEN%
	`^<[^>]{1,64}>$`,             // <your-password>
	`^\{\{[^}]*\}\}$`,            // {{ vault_password }}
	`^\[[^\]]{1,64}\]$`,          // [redacted]
	`^(?i)pass(word)?[0-9]*$`,    //
	`^(?i)(passwd|pwd|secret|token)$`,
	`^(?i)api[_-]?key$`,
	`^(?i)change(me|it)$`,
	`^(?i)(example|sample|dummy|placeholder|redacted|hidden)$`,
	`^(?i)test(ing|123)?$`,
	`^(?i)(user(name)?|admin|root|guest)$`,
	`^(?i)(none|null|nil)$`,
	`^x{3,}$`,
	`^\*{3,}$`,
	`^\.{3,}$`,
	`^(abc123|123456[0-9]*)$`,
}

// authenticatedURLFilter builds the rule's filter expression. A filter returns
// true to SKIP the finding, false to keep it.
//
// 3.0 clears every realistic credential (a UUID is ~3.6, 16 random alnum ~3.9)
// while dropping the low-entropy words the placeholder list would otherwise
// have to enumerate exhaustively. "password" is 2.75.
func authenticatedURLFilter() string {
	quoted := make([]string, len(authenticatedURLPlaceholders))
	for i, p := range authenticatedURLPlaceholders {
		quoted[i] = "`" + p + "`"
	}
	return `entropy(finding["secret"]) <= 3.0 || matchesAny(finding["secret"], [` +
		strings.Join(quoted, ", ") + `])`
}

// addAuthenticatedURLRule registers the rule on an already-parsed config.
//
// A no-op if upstream has shipped a rule under the same ID, so bumping the
// betterleaks dependency silently retires this file's effect rather than
// producing duplicate findings on the same span.
func addAuthenticatedURLRule(cfg *config.Config) error {
	if _, exists := cfg.Rules[authenticatedURLRuleID]; exists {
		return nil
	}

	re, err := regexp.Compile(authenticatedURLPattern)
	if err != nil {
		return err
	}

	rule := config.Rule{
		RuleID:      authenticatedURLRuleID,
		Description: "Credential embedded in a URL userinfo component.",
		Regex:       re,
		// The password capture, so redaction replaces only the credential and
		// leaves the rest of the URL readable.
		SecretGroup: 1,
		// Filter, not the deprecated Entropy/Allowlists fields. Those are
		// translated into filter expressions during TOML parsing, which a rule
		// added afterwards never goes through, leaving them silently inert.
		// Compiled lazily on first use (detect.go: rule.FilterProgram()).
		Filter: authenticatedURLFilter(),
		Tags:   []string{"agent-guard-local"},
		// Explicit rather than the zero value: a deliberately generic rule
		// should yield to a specific one on an overlapping span.
		Specificity: 0,
	}

	if cfg.Rules == nil {
		cfg.Rules = map[string]config.Rule{}
	}
	cfg.Rules[authenticatedURLRuleID] = rule
	// No keywords: a URL credential has no reliable literal to prefilter on,
	// so the rule must be evaluated on every scan.
	cfg.NoKeywordRules = append(cfg.NoKeywordRules, authenticatedURLRuleID)
	cfg.OrderedRules = append(cfg.OrderedRules, authenticatedURLRuleID)
	return nil
}
