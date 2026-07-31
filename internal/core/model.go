// Package core implements Agent Guard's host-independent payload extraction,
// secret detection, and verified redaction policy.
package core

// Finding is one betterleaks hit. Secret is the matched secret text (may be
// empty if the report omits it, in which case the whole output is replaced).
// AllowKey is the stable, position-independent one-way key a human can add to
// ~/.config/agent-guard/allow to vet a false positive; empty when there is no
// secret text to key on.
//
// Start and End are the half-open byte range of the match in the ORIGINAL
// scanned text, which is what redaction targets. Secret is not usable for
// that: with decode depth five, a finding from a base64/hex/percent pass
// carries the DECODED value, a string that never appears in the raw text, so
// substring replacement silently no-ops and ships the secret. Start/End stay
// in raw coordinates in that case and cover the encoded chunk. The zero value
// (0, 0) is an empty range and is rejected by redact, so a Finding built
// without a span fails closed onto whole-output replacement.
type Finding struct {
	Rule     string
	Secret   string
	AllowKey string
	Start    int
	End      int
}

// Verdict is the policy outcome of a review. The zero value allows.
type Verdict struct {
	Block  bool
	Reason string
}

func block(reason string) Verdict { return Verdict{Block: true, Reason: reason} }

// Decision is the complete host-independent result consumed by an integration
// adapter. Replacement is valid only when HasReplacement is true.
// StructuredReplacement is a schema-preserving clone of the scanned output
// with only detected spans rewritten. It is valid only when
// HasStructuredReplacement is true.
type Decision struct {
	Mode                     string
	Verdict                  Verdict
	Replacement              string
	HasReplacement           bool
	StructuredReplacement    any
	HasStructuredReplacement bool
}

// findingSummary formats one finding for the human-facing block message,
// including the allow-key so a human can vet and allowlist that value. A
// finding with no secret text (AllowKey empty) has nothing to key on, so the
// allowlist clause is omitted for it.
func findingSummary(f Finding) string {
	if f.AllowKey == "" {
		return "betterleaks: " + f.Rule
	}
	return "betterleaks: " + f.Rule + "; allow-key: " + f.AllowKey
}
