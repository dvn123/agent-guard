package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/detect"
)

// Guard owns the embedded scanner used for one CLI invocation.
type Guard struct {
	detector *detect.Detector
}

// NewGuard initializes the embedded Betterleaks detector. Betterleaks reports
// some construction failures through a fatal callback, so this boundary
// converts both ordinary panics and the overridden fatal callback into an
// error that callers can render through the active host protocol.
func NewGuard() (guard *Guard, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			guard = nil
			err = fmt.Errorf("%v", recovered)
		}
	}()
	return &Guard{detector: buildDetector()}, nil
}

// ParsePayload requires one JSON object. JSON null, arrays, scalars, and
// malformed input are rejected rather than treated as empty hook payloads.
func ParsePayload(raw []byte) (map[string]any, error) {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("hook payload is not a JSON object: %w", err)
	}
	payload, ok := decoded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("hook payload is not a JSON object (got %T)", decoded)
	}
	return payload, nil
}

// HookMode returns pre, post, or an empty string for an unguarded event.
func HookMode(payload map[string]any) string {
	return hookMode(payload)
}

// Review applies the host-independent guard policy. Any scanner panic becomes
// a blocking decision so a host adapter can still render its native protocol.
func (g *Guard) Review(payload map[string]any, mode string, allowed map[string]struct{}) (decision Decision) {
	decision.Mode = mode
	defer func() {
		if recovered := recover(); recovered != nil {
			decision.Verdict = block(fmt.Sprintf("fail closed: %v", recovered))
			decision.Replacement = ""
			decision.HasReplacement = false
			decision.StructuredReplacement = nil
			decision.HasStructuredReplacement = false
		}
	}()

	switch mode {
	case "pre":
		findings, err := scan(g.detector, preText(payload), allowed)
		if err != nil {
			decision.Verdict = block(fmt.Sprintf("fail closed: scan deadline exceeded: %v", err))
		} else if len(findings) > 0 {
			decision.Verdict = block(
				fmt.Sprintf("tool input contains a likely secret value (%s)", findingSummary(findings[0])),
			)
		}
		return decision
	case "post":
		// The scan and verifying re-scan share one deadline, so verification
		// does not receive a second full budget. Betterleaks cancellation is
		// cooperative, so this does not guarantee a hard host-timeout bound.
		ctx, cancel := context.WithTimeout(context.Background(), scanDeadline)
		defer cancel()

		text := postText(payload)
		findings, err := scanWithContext(ctx, g.detector, text, allowed)
		if err != nil {
			decision.Verdict = block(fmt.Sprintf("fail closed: scan deadline exceeded: %v", err))
			return decision
		}
		if len(findings) == 0 {
			return decision
		}

		decision.Verdict = block(
			fmt.Sprintf("tool output contains a likely secret value (%s)", findingSummary(findings[0])),
		)
		if response, ok := toolResponse(payload); ok &&
			text == strings.Join(walkStrings(response, nil, nil), "\n") {
			structured, replacement, verified := redactStructuredVerified(
				ctx,
				g.detector,
				response,
				findings,
				allowed,
			)
			if verified {
				decision.Replacement = replacement
				decision.HasReplacement = true
				decision.StructuredReplacement = structured
				decision.HasStructuredReplacement = true
				return decision
			}
		}
		decision.Replacement, decision.HasReplacement = redactVerified(
			ctx,
			g.detector,
			text,
			findings,
			allowed,
		)
		return decision
	default:
		decision.Verdict = block("fail closed: invalid guarded event mode")
		return decision
	}
}

// FailClosed creates a host-independent blocking decision for application
// failures outside the scanner review itself.
func FailClosed(mode, message string) Decision {
	return Decision{Mode: mode, Verdict: block("fail closed: " + message)}
}
