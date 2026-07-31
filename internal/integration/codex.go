package integration

import "github.com/dvn123/agent-guard/internal/core"

// codexAdapter uses exit 2 and stderr for both pre-call denial and post-call
// replacement. Codex replaces the tool result with post-hook stderr.
type codexAdapter struct{}

func (codexAdapter) Emit(_ map[string]any, decision core.Decision) Output {
	if !decision.Verdict.Block {
		return Output{}
	}
	if decision.Mode == "post" {
		return Output{
			Stderr:   reason(decision) + "\n" + replacement(decision) + "\n",
			ExitCode: 2,
		}
	}
	return Output{Stderr: reason(decision) + "\n", ExitCode: 2}
}
