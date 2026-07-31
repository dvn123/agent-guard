package integration

import "github.com/dvn123/agent-guard/internal/core"

// openCodeAdapter uses the subprocess contract consumed by the JavaScript
// plugin: any non-zero pre-call result is thrown, while post-call stderr is
// assigned to output.output.
type openCodeAdapter struct{}

func (openCodeAdapter) Emit(_ map[string]any, decision core.Decision) Output {
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
