// Package integration translates host-independent core decisions into each
// coding agent's hook protocol.
package integration

import (
	"fmt"

	"github.com/dvn123/agent-guard/internal/core"
)

// Output is the complete process contract returned to a hook host.
type Output struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Metadata is the canonical integration registry entry used by CLI help,
// diagnostics, documentation tests, and adapter lookup.
type Metadata struct {
	ID              string
	DisplayName     string
	ProtocolVersion string
	Adapter         Adapter
}

// Adapter renders one core decision for a host protocol.
type Adapter interface {
	Emit(map[string]any, core.Decision) Output
}

var registry = []Metadata{
	{ID: "claude", DisplayName: "Claude Code", ProtocolVersion: "hooks-v1", Adapter: claudeAdapter{}},
	{ID: "codex", DisplayName: "Codex", ProtocolVersion: "hooks-v1", Adapter: codexAdapter{}},
	{ID: "cursor", DisplayName: "Cursor", ProtocolVersion: "hooks-v1", Adapter: cursorAdapter{}},
	{ID: "opencode", DisplayName: "OpenCode", ProtocolVersion: "plugin-v1", Adapter: openCodeAdapter{}},
}

// All returns a copy of the ordered integration registry.
func All() []Metadata {
	return append([]Metadata(nil), registry...)
}

// Lookup resolves one stable integration ID.
func Lookup(id string) (Metadata, error) {
	for _, entry := range registry {
		if entry.ID == id {
			return entry, nil
		}
	}
	return Metadata{}, fmt.Errorf("unsupported tool %q", id)
}

func reason(decision core.Decision) string {
	return "agent-guard: " + decision.Verdict.Reason
}

func replacement(decision core.Decision) string {
	if decision.HasReplacement {
		return decision.Replacement
	}
	return "[blocked by " + reason(decision) + "]"
}
