package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dvn123/agent-guard/internal/core"
)

func TestClaudePostReplacementPreservesStructuredOutputShape(t *testing.T) {
	secret := "sk_" + "live_" + "4eC39HqLyj" + "WDarjtT1zdp7dc"
	payload := map[string]any{
		"tool_response": map[string]any{
			"stdout":      "token: " + secret,
			"stderr":      "warning",
			"interrupted": false,
			"isImage":     false,
		},
	}
	guard, err := core.NewGuard()
	if err != nil {
		t.Fatal(err)
	}
	decision := guard.Review(payload, "post", nil)
	if !decision.HasStructuredReplacement {
		t.Fatalf("decision = %#v", decision)
	}

	var body map[string]map[string]any
	output := (claudeAdapter{}).Emit(payload, decision)
	if output.ExitCode != 0 || json.Unmarshal([]byte(output.Stdout), &body) != nil {
		t.Fatalf("Claude output = %#v", output)
	}
	updated, ok := body["hookSpecificOutput"]["updatedToolOutput"].(map[string]any)
	if !ok {
		t.Fatalf("updatedToolOutput = %#v", body["hookSpecificOutput"]["updatedToolOutput"])
	}
	serialized, _ := json.Marshal(updated)
	if strings.Contains(string(serialized), secret) {
		t.Fatalf("structured replacement leaked the synthetic secret: %s", serialized)
	}
	if !strings.Contains(updated["stdout"].(string), "[REDACTED:") || updated["stderr"] != "warning" {
		t.Fatalf("structured strings = %#v", updated)
	}
	if updated["interrupted"] != false || updated["isImage"] != false {
		t.Fatalf("structured scalar fields changed: %#v", updated)
	}
}

func TestClaudePostReplacementRetainsContentDiscriminator(t *testing.T) {
	secret := "sk_" + "live_" + "4eC39HqLyj" + "WDarjtT1zdp7dc"
	payload := map[string]any{
		"tool_response": map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": "token: " + secret},
			},
			"status":        "completed",
			"agentId":       "agent-123",
			"resolvedModel": "claude-sonnet-4-5",
		},
	}
	guard, err := core.NewGuard()
	if err != nil {
		t.Fatal(err)
	}
	decision := guard.Review(payload, "post", nil)
	updated := claudeUpdatedOutput(payload, decision)
	response := updated.(map[string]any)
	block := response["content"].([]any)[0].(map[string]any)
	if block["type"] != "text" || !strings.Contains(block["text"].(string), "[REDACTED:") {
		t.Fatalf("content block = %#v", block)
	}
	for key, want := range map[string]string{
		"status":        "completed",
		"agentId":       "agent-123",
		"resolvedModel": "claude-sonnet-4-5",
	} {
		if response[key] != want {
			t.Fatalf("%s = %#v, want %q", key, response[key], want)
		}
	}
}

func TestClaudeFailureFallbackPreservesBackgroundAgentSchema(t *testing.T) {
	secret := "sk_" + "live_" + "4eC39HqLyj" + "WDarjtT1zdp7dc"
	payload := map[string]any{
		"tool_name": "Agent",
		"tool_response": map[string]any{
			"status":        "async_launched",
			"agentId":       "agent-123",
			"description":   "finding " + secret,
			"prompt":        "inspect " + secret,
			"outputFile":    "/tmp/" + secret,
			"resolvedModel": "claude-sonnet-4-5",
		},
	}
	decision := core.FailClosed("post", "scanner deadline exceeded")
	response := claudeUpdatedOutput(payload, decision).(map[string]any)

	for key, want := range map[string]string{
		"status":        "async_launched",
		"agentId":       "agent-123",
		"resolvedModel": "claude-sonnet-4-5",
	} {
		if response[key] != want {
			t.Fatalf("%s = %#v, want %q", key, response[key], want)
		}
	}
	serialized, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), secret) {
		t.Fatalf("background Agent fallback leaked the synthetic secret: %s", serialized)
	}
	for _, key := range []string{"description", "prompt", "outputFile"} {
		if !strings.Contains(response[key].(string), "blocked by agent-guard") {
			t.Fatalf("%s = %#v, want blocking replacement", key, response[key])
		}
	}
}
