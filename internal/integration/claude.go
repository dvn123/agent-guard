package integration

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/dvn123/agent-guard/internal/core"
)

// claudeAdapter denies pre-call input with exit 2. Post-call output must use
// updatedToolOutput and exit 0 because a plain exit 2 leaves the original tool
// output in Claude Code's transcript.
type claudeAdapter struct{}

func (claudeAdapter) Emit(payload map[string]any, decision core.Decision) Output {
	if !decision.Verdict.Block {
		return Output{}
	}
	if decision.Mode != "post" {
		return Output{Stderr: reason(decision) + "\n", ExitCode: 2}
	}
	body, _ := json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "PostToolUse",
			"updatedToolOutput": claudeUpdatedOutput(payload, decision),
		},
	})
	return Output{Stdout: string(body) + "\n"}
}

// Claude validates updatedToolOutput against the original tool output's shape;
// a plain string is ignored for structured built-in tools, exposing the
// original output. Prefer the core's verified schema-preserving clone, which
// changes only detected spans and leaves every other field intact. The
// output-field fallback is used only when review failed before it could build
// that clone.
func claudeUpdatedOutput(payload map[string]any, decision core.Decision) any {
	if decision.HasStructuredReplacement {
		return decision.StructuredReplacement
	}
	clean := replacement(decision)
	original, ok := payload["tool_response"]
	if !ok {
		original, ok = payload["toolResponse"]
	}
	if !ok {
		return clean
	}
	if toolName, _ := payload["tool_name"].(string); toolName == "Agent" || toolName == "Task" {
		if updated, ok := claudeAgentFallback(original, clean); ok {
			return updated
		}
	}
	inserted := false
	updated := replaceClaudeStrings(original, clean, &inserted, "", false)
	if !inserted {
		return clean
	}
	return updated
}

// Agent has two discriminated response schemas. A background response has no
// generic output/content field, so the fallback must explicitly preserve its
// status and metadata while replacing the three free-form strings. Task is
// accepted as the legacy tool name for the same response shape.
func claudeAgentFallback(original any, clean string) (any, bool) {
	response, ok := original.(map[string]any)
	if !ok {
		return nil, false
	}
	updated := make(map[string]any, len(response))
	for key, value := range response {
		updated[key] = value
	}
	switch response["status"] {
	case "completed":
		if _, ok := response["content"]; !ok {
			return nil, false
		}
		updated["content"] = []any{map[string]any{"type": "text", "text": clean}}
	case "async_launched":
		replaced := false
		for _, key := range []string{"description", "prompt", "outputFile"} {
			if _, ok := response[key]; ok {
				updated[key] = clean
				replaced = true
			}
		}
		if !replaced {
			return nil, false
		}
	default:
		return nil, false
	}
	return updated, true
}

func replaceClaudeStrings(value any, clean string, inserted *bool, key string, output bool) any {
	switch value := value.(type) {
	case string:
		if !output || isClaudeDiscriminator(key, value) {
			return value
		}
		if !*inserted {
			*inserted = true
			return clean
		}
		return ""
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			left, right := claudeOutputKeyRank(keys[i]), claudeOutputKeyRank(keys[j])
			if left != right {
				return left < right
			}
			return keys[i] < keys[j]
		})
		updated := make(map[string]any, len(value))
		for _, childKey := range keys {
			childOutput := output || claudeOutputKeyRank(childKey) < 100
			updated[childKey] = replaceClaudeStrings(value[childKey], clean, inserted, childKey, childOutput)
		}
		return updated
	case []any:
		updated := make([]any, len(value))
		for index, child := range value {
			updated[index] = replaceClaudeStrings(child, clean, inserted, key, output)
		}
		return updated
	default:
		return value
	}
}

func claudeOutputKeyRank(key string) int {
	normalized := strings.ToLower(strings.ReplaceAll(key, "_", ""))
	for rank, outputKey := range []string{"output", "stdout", "content", "text", "result", "response", "message", "stderr"} {
		if normalized == outputKey {
			return rank
		}
	}
	return 100
}

func isClaudeDiscriminator(key, value string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "_", ""))
	if normalized == "mediatype" || normalized == "tooluseid" {
		return true
	}
	if normalized != "type" {
		return false
	}
	switch value {
	case "text", "image", "tool_result", "tool_use", "base64":
		return true
	default:
		return false
	}
}
