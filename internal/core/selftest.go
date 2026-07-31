package core

import (
	"fmt"
	"strings"
)

// SelfTestCheck is one deterministic scanner diagnostic.
type SelfTestCheck struct {
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// SelfTest initializes the real embedded scanner, proves a synthetic secret is
// denied, then proves post-output redaction is accepted only after a clean
// verifying re-scan. It performs no network or filesystem reads.
func SelfTest() (checks []SelfTestCheck) {
	defer func() {
		if recovered := recover(); recovered != nil {
			checks = []SelfTestCheck{{
				ID:      "scanner-initialization",
				OK:      false,
				Message: fmt.Sprintf("embedded scanner initialization failed: %v", recovered),
			}}
		}
	}()

	guard, err := NewGuard()
	if err != nil {
		return []SelfTestCheck{{
			ID:      "scanner-initialization",
			OK:      false,
			Message: "embedded scanner initialization failed: " + err.Error(),
		}}
	}
	synthetic := "sk_" + "live_" + "4eC39HqLyj" + "WDarjtT1zdp7dc"
	pre := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_input":      map[string]any{"command": "printf %s " + synthetic},
	}
	preDecision := guard.Review(pre, "pre", nil)
	detectionOK := preDecision.Verdict.Block &&
		strings.Contains(preDecision.Verdict.Reason, "stripe-access-token")
	checks = append(checks, SelfTestCheck{
		ID:      "scanner-detection",
		OK:      detectionOK,
		Message: chooseMessage(detectionOK, "synthetic secret detected", "synthetic secret was not detected"),
	})

	safePrefix := "self-test prefix"
	post := map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_response":   map[string]any{"output": safePrefix + "\ntoken: " + synthetic + "\nself-test suffix"},
	}
	postDecision := guard.Review(post, "post", nil)
	residual, scanErr := scan(guard.detector, postDecision.Replacement, nil)
	redactionOK := postDecision.Verdict.Block &&
		postDecision.HasReplacement &&
		!strings.Contains(postDecision.Replacement, synthetic) &&
		strings.Contains(postDecision.Replacement, safePrefix) &&
		scanErr == nil &&
		len(residual) == 0
	checks = append(checks, SelfTestCheck{
		ID:      "verified-redaction",
		OK:      redactionOK,
		Message: chooseMessage(redactionOK, "redaction verified by a clean re-scan", "redaction self-test failed"),
	})
	return checks
}

func chooseMessage(ok bool, passed, failed string) string {
	if ok {
		return passed
	}
	return failed
}
