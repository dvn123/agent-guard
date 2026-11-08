package integration

import "github.com/dvn123/agent-guard/internal/core"

// pluginAdapter uses the subprocess contract consumed by the in-process
// JavaScript plugins of OpenCode and Pi: any non-zero pre-call result blocks
// the call, while post-call stderr replaces the tool result.
type pluginAdapter struct{}

func (pluginAdapter) Emit(_ map[string]any, decision core.Decision) Output {
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
