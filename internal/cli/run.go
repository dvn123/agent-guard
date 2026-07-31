// Package cli implements Agent Guard's process-level command routing.
package cli

import (
	"fmt"
	"io"

	"github.com/dvn123/agent-guard/internal/core"
	"github.com/dvn123/agent-guard/internal/integration"
	"github.com/dvn123/agent-guard/internal/version"
)

// Run executes one CLI invocation and returns its process exit code.
func Run(argv []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			fmt.Fprintf(stderr, "agent-guard: fail closed: %v\n", recovered)
			code = 2
		}
	}()

	if len(argv) > 0 {
		switch argv[0] {
		case "doctor":
			return runDoctor(argv[1:], stdout, stderr)
		case "hook":
			return runHook(argv[1:], stdin, stdout, stderr)
		case "version", "--version", "-V":
			fmt.Fprintf(stdout, "agent-guard %s (%s, %s)\n", version.Version, version.Commit, version.Date)
			return 0
		case "help", "--help", "-h":
			printHelp(stdout)
			return 0
		}
		if argv[0] != "--tool" {
			fmt.Fprintf(stderr, "agent-guard: unknown command %q\n", argv[0])
			printHelp(stderr)
			return 1
		}
	}

	// Preserve the original hook entrypoint used by existing host configs:
	// agent-guard --tool <host>. The explicit `hook` command is equivalent.
	return runHook(argv, stdin, stdout, stderr)
}

func runHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	tool, err := parseTool(args)
	if err != nil {
		fmt.Fprintf(stderr, "agent-guard: fail closed: %v\n", err)
		return 2
	}
	entry, err := integration.Lookup(tool)
	if err != nil {
		fmt.Fprintf(stderr, "agent-guard: fail closed: %v\n", err)
		return 2
	}

	raw, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "agent-guard: fail closed: reading stdin: %v\n", err)
		return 2
	}
	payload, err := core.ParsePayload(raw)
	if err != nil {
		fmt.Fprintf(stderr, "agent-guard: fail closed: %v\n", err)
		return 2
	}
	mode := core.HookMode(payload)
	if mode == "" {
		return 0
	}

	allowed, err := core.LoadAllowlist(core.DefaultAllowlistPath())
	if err != nil {
		return writeOutput(entry.Adapter.Emit(payload, core.FailClosed(mode, "reading allowlist: "+err.Error())), stdout, stderr)
	}
	guard, err := core.NewGuard()
	if err != nil {
		return writeOutput(entry.Adapter.Emit(payload, core.FailClosed(mode, "initializing scanner: "+err.Error())), stdout, stderr)
	}
	return writeOutput(entry.Adapter.Emit(payload, guard.Review(payload, mode, allowed)), stdout, stderr)
}

func parseTool(args []string) (string, error) {
	if len(args) == 0 {
		return "codex", nil
	}
	if len(args) != 2 || args[0] != "--tool" || args[1] == "" {
		return "", fmt.Errorf("usage: agent-guard [hook] --tool {claude,codex,cursor,opencode}")
	}
	return args[1], nil
}

func writeOutput(output integration.Output, stdout, stderr io.Writer) int {
	if output.Stdout != "" {
		fmt.Fprint(stdout, output.Stdout)
	}
	if output.Stderr != "" {
		fmt.Fprint(stderr, output.Stderr)
	}
	return output.ExitCode
}

func printHelp(writer io.Writer) {
	fmt.Fprintln(writer, "Usage:")
	fmt.Fprintln(writer, "  agent-guard --tool {claude,codex,cursor,opencode}")
	fmt.Fprintln(writer, "  agent-guard hook --tool {claude,codex,cursor,opencode}")
	fmt.Fprintln(writer, "  agent-guard doctor [--json]")
	fmt.Fprintln(writer, "  agent-guard version")
}
