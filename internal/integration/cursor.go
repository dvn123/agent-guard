package integration

import (
	"encoding/json"

	"github.com/dvn123/agent-guard/internal/core"
)

// cursorAdapter returns JSON allow/deny decisions for pre-call hooks. Cursor's
// afterShellExecution hook is observational, so post-call findings can only
// warn after the model has already received the output.
type cursorAdapter struct{}

func (cursorAdapter) Emit(_ map[string]any, decision core.Decision) Output {
	if decision.Mode == "post" {
		if decision.Verdict.Block {
			return Output{Stderr: reason(decision) + "\n"}
		}
		return Output{}
	}

	permission := "allow"
	body := map[string]string{"permission": permission}
	if decision.Verdict.Block {
		message := reason(decision)
		body = map[string]string{
			"permission":    "deny",
			"user_message":  message,
			"agent_message": message,
		}
	}
	encoded, _ := json.Marshal(body)
	return Output{Stdout: string(encoded) + "\n"}
}
