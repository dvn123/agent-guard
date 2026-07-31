// Hook-payload plumbing: tool-input extraction and output-container walking,
// ported from the Python guard's payload.py.
//
// The output-container semantics: postSkipKeys exempts a payload's
// echoed-input fields, but only OUTSIDE output containers — a nested response
// key that happens to be named "command" is genuinely tool output and must be
// scanned.
package core

import (
	"cmp"
	"sort"
	"strings"
)

var postOutputKeys = keySet(
	"content", "message", "output", "result", "response",
	"stderr", "stdout", "text", "tooloutput", "toolresponse",
)

var postSkipKeys = keySet(
	"arguments", "cmd", "command", "cwd", "input",
	"parameters", "toolinput", "transcriptpath",
)

var preSkipKeys = keySet("transcriptpath")

func keySet(keys ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		set[key] = struct{}{}
	}
	return set
}

func normalizedKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "_", ""))
}

// toolInput selects the tool-call input from the hook payload. The key chain
// selects on key PRESENCE, not truthiness: an empty tool_input is a valid
// selection and must not fall through to a later key.
func toolInput(payload map[string]any) any {
	for _, key := range []string{"tool_input", "toolInput", "input", "arguments", "parameters"} {
		if value, ok := payload[key]; ok {
			return value
		}
	}
	// Cursor's shell hooks have no tool_name concept at all — the hook is
	// inherently shell-scoped and the command sits at the payload's top
	// level; its beforeReadFile likewise carries top-level file_path/content.
	if command, ok := payload["command"].(string); ok {
		return map[string]any{"command": command}
	}
	if _, ok := payload["file_path"].(string); ok {
		input := map[string]any{}
		for _, key := range []string{"file_path", "content"} {
			if value, ok := payload[key]; ok {
				input[key] = value
			}
		}
		return input
	}
	return map[string]any{}
}

func walkStrings(value any, skip map[string]struct{}, out []string) []string {
	switch v := value.(type) {
	case string:
		out = append(out, v)
	case map[string]any:
		for _, key := range sortedKeys(v) {
			if _, skipped := skip[normalizedKey(key)]; skipped {
				continue
			}
			out = walkStrings(v[key], skip, out)
		}
	case []any:
		for _, item := range v {
			out = walkStrings(item, skip, out)
		}
	}
	return out
}

func sortedKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// preText is the pre-scan input: every string leaf of the tool input.
func preText(payload map[string]any) string {
	return strings.Join(walkStrings(toolInput(payload), preSkipKeys, nil), "\n")
}

func outputStrings(value any, out []string) []string {
	switch v := value.(type) {
	case map[string]any:
		for _, key := range sortedKeys(v) {
			item := v[key]
			normalized := normalizedKey(key)
			if _, skipped := postSkipKeys[normalized]; skipped {
				continue
			}
			if _, isOutput := postOutputKeys[normalized]; isOutput {
				// No skip keys inside an output container: everything under
				// stdout/output/... is genuinely tool output.
				out = walkStrings(item, nil, out)
			} else {
				out = outputStrings(item, out)
			}
		}
	case []any:
		for _, item := range v {
			out = outputStrings(item, out)
		}
	}
	return out
}

// postText is the post-scan input: the string leaves under recognized output
// containers, falling back to the whole payload minus echoed-input keys when
// that yields nothing.
func postText(payload map[string]any) string {
	if text := strings.Join(outputStrings(payload, nil), "\n"); text != "" {
		return text
	}
	return strings.Join(walkStrings(payload, postSkipKeys, nil), "\n")
}

func toolResponse(payload map[string]any) (any, bool) {
	for _, key := range []string{"tool_response", "toolResponse"} {
		if value, ok := payload[key]; ok {
			return value, true
		}
	}
	return nil, false
}

// hookMode maps the event name to "pre"/"post"; "" means the event is not
// guarded (SessionStart, Stop, ...) and the guard must exit 0, not block.
func hookMode(payload map[string]any) string {
	event, _ := payload["hook_event_name"].(string)
	camel, _ := payload["hookEventName"].(string)
	switch cmp.Or(event, camel) {
	case "PreToolUse", "preToolUse", "beforeShellExecution", "beforeReadFile":
		return "pre"
	case "PostToolUse", "postToolUse", "afterShellExecution":
		return "post"
	}
	return ""
}
