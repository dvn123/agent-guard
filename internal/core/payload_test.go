package core

import (
	"strings"
	"testing"
)

func TestToolInputSelectsPresentKeyOverTruthiness(t *testing.T) {
	// The INPUT chain selects on key PRESENCE, not truthiness: an empty
	// tool_input is a valid selection and must not fall through to a later
	// key in the payload.
	payload := map[string]any{
		"tool_input": map[string]any{},
		"arguments":  map[string]any{"command": "should not be selected"},
	}
	got := toolInput(payload)
	m, ok := got.(map[string]any)
	if !ok || len(m) != 0 {
		t.Fatalf("toolInput = %#v, want empty map (tool_input wins on presence)", got)
	}
}

func TestToolInputKeyChainPriority(t *testing.T) {
	for _, key := range []string{"tool_input", "toolInput", "input", "arguments", "parameters"} {
		payload := map[string]any{key: map[string]any{"command": "echo hi"}}
		got := toolInput(payload)
		m, ok := got.(map[string]any)
		if !ok || m["command"] != "echo hi" {
			t.Errorf("toolInput with key %q = %#v, want command echoed", key, got)
		}
	}
}

func TestToolInputCursorFlatShellPayload(t *testing.T) {
	// Cursor's beforeShellExecution has no tool_name concept; the command
	// sits at the payload's top level.
	payload := map[string]any{"hook_event_name": "beforeShellExecution", "command": "cat secrets.env", "cwd": "/tmp"}
	got := toolInput(payload).(map[string]any)
	if got["command"] != "cat secrets.env" {
		t.Fatalf("toolInput = %#v, want flat command captured", got)
	}
}

func TestToolInputCursorFlatReadPayload(t *testing.T) {
	payload := map[string]any{"hook_event_name": "beforeReadFile", "file_path": "/tmp/notes.txt", "content": "key=abc"}
	got := toolInput(payload).(map[string]any)
	if got["file_path"] != "/tmp/notes.txt" || got["content"] != "key=abc" {
		t.Fatalf("toolInput = %#v, want file_path+content captured", got)
	}
}

func TestToolInputEmptyWhenNothingMatches(t *testing.T) {
	got := toolInput(map[string]any{"hook_event_name": "PreToolUse"})
	m, ok := got.(map[string]any)
	if !ok || len(m) != 0 {
		t.Fatalf("toolInput = %#v, want empty map", got)
	}
}

func TestPreTextWalksNestedStrings(t *testing.T) {
	payload := map[string]any{
		"tool_input": map[string]any{
			"command": "echo hi",
			"nested":  map[string]any{"list": []any{"a", "b"}},
		},
	}
	text := preText(payload)
	for _, want := range []string{"echo hi", "a", "b"} {
		if !strings.Contains(text, want) {
			t.Errorf("preText(%q) missing %q", text, want)
		}
	}
}

func TestPreTextSkipsTranscriptPath(t *testing.T) {
	// transcript_path is Claude Code plumbing, never a tool argument; it must
	// never be scanned even though it can contain arbitrary filesystem paths.
	payload := map[string]any{
		"tool_input": map[string]any{
			"transcript_path": "/should/not/appear/anywhere",
			"command":         "echo hi",
		},
	}
	text := preText(payload)
	if strings.Contains(text, "should/not/appear") {
		t.Fatalf("preText(%q) leaked transcript_path", text)
	}
}

func TestPostTextOutputContainerSkipsEchoedInputOutsideContainer(t *testing.T) {
	// A top-level "command" key mirrors tool input and must be skipped when
	// it sits OUTSIDE an output container.
	payload := map[string]any{
		"tool_name": "Bash",
		"command":   "cat ~/.ssh/id_rsa",
		"tool_response": map[string]any{
			"output": "some clean stdout",
		},
	}
	text := postText(payload)
	if strings.Contains(text, "id_rsa") {
		t.Fatalf("postText(%q) leaked the echoed top-level command", text)
	}
	if !strings.Contains(text, "some clean stdout") {
		t.Fatalf("postText(%q) missing real output", text)
	}
}

func TestPostTextScansNestedKeyNamedCommandInsideOutputContainer(t *testing.T) {
	// Once inside a recognized output container, everything is genuine
	// output, including a nested key that happens to be named "command".
	payload := map[string]any{
		"tool_response": map[string]any{
			"output": map[string]any{"command": "this looks like input but IS output"},
		},
	}
	text := postText(payload)
	if !strings.Contains(text, "this looks like input but IS output") {
		t.Fatalf("postText(%q) dropped nested output value under a skip-shaped key", text)
	}
}

func TestPostTextFallsBackToWholePayloadMinusSkipKeys(t *testing.T) {
	// OpenCode's tool.execute.after payload has no recognized output
	// container key at all in some shapes; the fallback walk must still
	// surface real content while excluding echoed-input keys.
	payload := map[string]any{
		"tool_input": map[string]any{"cmd": "cat file"},
		"title":      "a genuine output field",
	}
	text := postText(payload)
	if strings.Contains(text, "cat file") {
		t.Fatalf("postText(%q) leaked skip-key content via fallback", text)
	}
	if !strings.Contains(text, "a genuine output field") {
		t.Fatalf("postText(%q) missing fallback content", text)
	}
}

func TestHookModeMapsEventsAcrossTools(t *testing.T) {
	cases := map[string]string{
		"PreToolUse":           "pre",
		"preToolUse":           "pre",
		"beforeShellExecution": "pre",
		"beforeReadFile":       "pre",
		"PostToolUse":          "post",
		"postToolUse":          "post",
		"afterShellExecution":  "post",
		"SessionStart":         "",
		"Stop":                 "",
		"":                     "",
	}
	for event, want := range cases {
		got := hookMode(map[string]any{"hook_event_name": event})
		if got != want {
			t.Errorf("hookMode(%q) = %q, want %q", event, got, want)
		}
	}
}

func TestHookModeReadsCamelCaseEventName(t *testing.T) {
	// Cursor's payload uses hookEventName, not hook_event_name.
	got := hookMode(map[string]any{"hookEventName": "beforeShellExecution"})
	if got != "pre" {
		t.Fatalf("hookMode(camelCase) = %q, want pre", got)
	}
}
