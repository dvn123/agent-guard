// A second locally-added betterleaks rule, kept in its own file so it can be
// deleted in one move once upstream ships an equivalent. Same reasoning as
// rule_authenticated_url.go; see that file for why this is not a config file.
//
// Why it exists: betterleaks' vendored default rules cannot match a Google
// OAuth2 access token — the opaque bearer token returned by the GCP token
// endpoint and by Terraform's data.google_service_account_access_token.
// Verified against the vendored betterleaks v1.6.1 on 2026-08-25: the string
// "ya29" does not appear anywhere in config/betterleaks.toml, and the two GCP
// rules that do exist (gcp-application-default-credentials, gcp-service-account)
// are both anchored on a JSON credential blob, so neither covers a bare token.
//
// generic-api-key does not cover it either, despite the token almost always
// appearing after an "access_token"/"token" label. Its secret alternation is
//
//	([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})
//
// followed by a mandatory trailing boundary (?:\\?['"\x60]|[\s;]|\\[nr]|$).
// Branch one caps at 150 characters while a real token runs to several
// hundred, so at every length in [10,150] the next character is more token and
// the boundary can never be satisfied. Branch two is standard base64, not
// base64url: it excludes '.', '_' and '-', and the token hits its first '.' at
// character five, well short of the 12-character minimum.
//
// The blast radius is high — the token is a live bearer credential for
// whatever scopes it was minted with — and the shape is common in agent
// output: terraform plan/apply, gcloud auth print-access-token, and any curl
// carrying an Authorization header.
package core

import (
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

// Namespaced like the authenticated-url rule, so that if upstream ever ships
// its own "gcp-oauth-access-token" both run rather than ours silently
// disappearing and regressing recall. Duplicate findings on one span are
// harmless: redaction is idempotent and specificity suppression handles the
// overlap.
const gcpOAuthAccessTokenRuleID = "agent-guard-gcp-oauth-access-token"

// The vendor prefix is a literal, so this is a cheap, high-precision rule and
// the keyword prefilter below keeps it off every scan that cannot match.
//
// Body class is base64url (\w covers [0-9A-Za-z_]) plus '.', which Google uses
// as an internal separator, plus '/' and '+' so a classic-base64 variant is
// not missed. 20 is far below any real token (hundreds of characters) but far
// above anything that turns up in prose, and it keeps the entropy floor below
// off the log2(n) bound: 25 characters can carry up to log2(25) = 4.6 bits, so
// a 3.5 floor is a real filter here rather than an unreachable one.
//
// No trailing boundary, deliberately: requiring one is exactly the mistake
// that makes generic-api-key blind to this token. Greedy and unbounded, so the
// whole token is captured however long it grows; the class excludes
// whitespace and quotes, so the match still stops at the end of the literal.
// RE2: no lookarounds, and repeat counts cap at 1000.
const gcpOAuthAccessTokenPattern = `\bya29\.[\w./+-]{20,}`

// Lowercase to match the keyword prefilter, which lowercases the scanned text
// before the Aho-Corasick pass.
const gcpOAuthAccessTokenKeyword = "ya29."

// gcpOAuthAccessTokenFilter builds the rule's filter expression. A filter
// returns true to SKIP the finding, false to keep it.
//
// 3.5 clears a real token by a wide margin (a base64url body over the full
// alphabet sits near 5.9) while dropping the documentation placeholders that
// share the prefix — a padded ya29.AAAA... stub is under 1.0. Placeholders
// written with punctuation the body class rejects, such as ya29.<ACCESS_TOKEN>,
// never reach the filter because the regex does not match them at all.
func gcpOAuthAccessTokenFilter() string {
	return `entropy(finding["secret"]) <= 3.5`
}

// addGCPOAuthAccessTokenRule registers the rule on an already-parsed config.
//
// A no-op if upstream has shipped a rule under the same ID, so bumping the
// betterleaks dependency silently retires this file's effect rather than
// producing duplicate findings on the same span.
func addGCPOAuthAccessTokenRule(cfg *config.Config) error {
	if _, exists := cfg.Rules[gcpOAuthAccessTokenRuleID]; exists {
		return nil
	}

	re, err := regexp.Compile(gcpOAuthAccessTokenPattern)
	if err != nil {
		return err
	}

	rule := config.Rule{
		RuleID:      gcpOAuthAccessTokenRuleID,
		Description: "Google OAuth2 access token.",
		Regex:       re,
		// No capture group: the whole match is the credential, so redaction
		// must cover all of it.
		SecretGroup: 0,
		Keywords:    []string{gcpOAuthAccessTokenKeyword},
		// Filter, not the deprecated Entropy/Allowlists fields. Those are
		// translated into filter expressions during TOML parsing, which a rule
		// added afterwards never goes through, leaving them silently inert.
		// Compiled lazily on first use (detect.go: rule.FilterProgram()).
		Filter: gcpOAuthAccessTokenFilter(),
		Tags:   []string{"agent-guard-local"},
		// Explicit rather than the zero value, and unlike the deliberately
		// generic authenticated-url rule: a vendor-prefixed token is as
		// specific as any upstream provider rule, so it should win an
		// overlapping span rather than yield.
		Specificity: config.DefaultRuleSpecificity,
	}

	if cfg.Rules == nil {
		cfg.Rules = map[string]config.Rule{}
	}
	cfg.Rules[gcpOAuthAccessTokenRuleID] = rule
	// Keyworded, so registration goes through the prefilter tables rather than
	// NoKeywordRules. Config.Keywords seeds the Aho-Corasick automaton, which
	// detect.NewDetectorContext compiles once at construction, and
	// KeywordToRules maps a hit back to this rule; miss either and the rule is
	// simply never evaluated.
	if cfg.Keywords == nil {
		cfg.Keywords = map[string]struct{}{}
	}
	cfg.Keywords[gcpOAuthAccessTokenKeyword] = struct{}{}
	if cfg.KeywordToRules == nil {
		cfg.KeywordToRules = map[string][]string{}
	}
	cfg.KeywordToRules[gcpOAuthAccessTokenKeyword] = append(
		cfg.KeywordToRules[gcpOAuthAccessTokenKeyword], gcpOAuthAccessTokenRuleID)
	cfg.OrderedRules = append(cfg.OrderedRules, gcpOAuthAccessTokenRuleID)
	return nil
}
