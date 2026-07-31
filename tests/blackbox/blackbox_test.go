// Package blackbox exercises only source-built candidates behind copied
// launchers and throwaway HOME directories. It never reads installed Agent
// Guard artifacts or administrative state.
package blackbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	testBinary string
	repoRoot   string
)

type result struct {
	stdout   string
	stderr   string
	exitCode int
}

func TestMain(m *testing.M) {
	var err error
	repoRoot, err = filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	testBinary = os.Getenv("AGENT_GUARD_TEST_BINARY")
	var buildDir string
	if testBinary == "" {
		buildDir, err = os.MkdirTemp("", "agent-guard-blackbox-build-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		testBinary = filepath.Join(buildDir, "agent-guard")
		command := exec.Command("go", "build", "-mod=vendor", "-trimpath", "-o", testBinary, "./cmd/agent-guard")
		command.Dir = repoRoot
		command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "CGO_ENABLED=0")
		if output, buildErr := command.CombinedOutput(); buildErr != nil {
			fmt.Fprintf(os.Stderr, "build black-box candidate: %v\n%s", buildErr, output)
			os.RemoveAll(buildDir)
			os.Exit(1)
		}
	}
	code := m.Run()
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

func TestLauncherExitNormalization(t *testing.T) {
	tests := []struct {
		name       string
		binaryBody string
		wantCode   int
		wantError  string
	}{
		{name: "zero", binaryBody: "exit 0", wantCode: 0},
		{name: "block", binaryBody: "exit 2", wantCode: 2},
		{name: "unexpected", binaryBody: "exit 137", wantCode: 2, wantError: "fail closed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := newHome(t, false)
			writeExecutable(t, filepath.Join(home, ".local/bin/agent-guard"), "#!/bin/sh\n"+test.binaryBody+"\n")
			got := runLauncher(t, home, []string{"--tool", "codex"}, "{}")
			if got.exitCode != test.wantCode {
				t.Fatalf("exit = %d, want %d (%s)", got.exitCode, test.wantCode, got.stderr)
			}
			if test.wantError != "" && !strings.Contains(got.stderr, test.wantError) {
				t.Errorf("stderr = %q, want %q", got.stderr, test.wantError)
			}
		})
	}
}

func TestLauncherFailsClosedWhenBinaryMissing(t *testing.T) {
	home := newHome(t, false)
	got := runLauncher(t, home, []string{"--tool", "codex"}, cleanPayload())
	if got.exitCode != 2 || !strings.Contains(got.stderr, "is missing") {
		t.Fatalf("missing binary = (%d, %q), want fail-closed exit 2", got.exitCode, got.stderr)
	}
}

func TestLauncherResolvesUnsetHomeFromUserDatabase(t *testing.T) {
	launcher, err := os.ReadFile(filepath.Join(repoRoot, "integrations/launcher/run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, ok := strings.Cut(string(launcher), "\nSENTINEL=")
	if !ok {
		t.Fatal("launcher no longer has an independently testable HOME preamble")
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	command := exec.Command("/bin/sh")
	command.Stdin = strings.NewReader(prefix + "\nprintf '%s\\n' \"$HOME\"\n")
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "HOME=") {
			command.Env = append(command.Env, variable)
		}
	}
	got := runCommand(t, command)
	if got.exitCode != 0 || strings.TrimSpace(got.stdout) != current.HomeDir {
		t.Fatalf("resolved HOME = (%d, %q, %q), want %q", got.exitCode, got.stdout, got.stderr, current.HomeDir)
	}
}

func TestNativeSnippetCommandsResolveHomeSafely(t *testing.T) {
	paths := []string{
		"integrations/claude/settings.snippet.json",
		"integrations/codex/config.snippet.toml",
		"integrations/cursor/hooks.snippet.json",
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	for _, relative := range paths {
		commands := snippetCommands(t, filepath.Join(repoRoot, relative))
		if len(commands) == 0 {
			t.Fatalf("%s contains no hook commands", relative)
		}
		for index, hookCommand := range commands {
			name := fmt.Sprintf("%s/%d", relative, index)
			t.Run(name+"/whitespace-home", func(t *testing.T) {
				home := filepath.Join(t.TempDir(), "home with spaces")
				launcher := filepath.Join(home, ".config/agent-guard/run.sh")
				if err := os.MkdirAll(filepath.Dir(launcher), 0o700); err != nil {
					t.Fatal(err)
				}
				writeExecutable(t, launcher, "#!/bin/sh\nprintf '%s|%s\\n' \"$HOME\" \"$*\"\n")

				command := exec.Command("/bin/sh", "-c", hookCommand)
				command.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C"}
				got := runCommand(t, command)
				if got.exitCode != 0 || !strings.HasPrefix(got.stdout, home+"|--tool ") {
					t.Fatalf("snippet command = (%d, %q, %q)", got.exitCode, got.stdout, got.stderr)
				}
			})

			t.Run(name+"/unset-home", func(t *testing.T) {
				const prefix = "/bin/sh -c '"
				if !strings.HasPrefix(hookCommand, prefix) || !strings.HasSuffix(hookCommand, "'") {
					t.Fatalf("snippet command lacks the expected shell bootstrap: %q", hookCommand)
				}
				script := strings.TrimSuffix(strings.TrimPrefix(hookCommand, prefix), "'")
				execIndex := strings.Index(script, `exec "$HOME/.config/agent-guard/run.sh"`)
				if execIndex < 0 {
					t.Fatalf("snippet command lacks a quoted launcher exec: %q", hookCommand)
				}
				script = script[:execIndex] + `printf '%s\n' "$HOME"`

				command := exec.Command("/bin/sh", "-c", script)
				for _, variable := range os.Environ() {
					if !strings.HasPrefix(variable, "HOME=") {
						command.Env = append(command.Env, variable)
					}
				}
				got := runCommand(t, command)
				if got.exitCode != 0 || strings.TrimSpace(got.stdout) != current.HomeDir {
					t.Fatalf("snippet resolved HOME = (%d, %q, %q), want %q", got.exitCode, got.stdout, got.stderr, current.HomeDir)
				}
			})
		}
	}
}

func TestLauncherDisableSentinelAndExpiry(t *testing.T) {
	t.Run("active", func(t *testing.T) {
		home := newHome(t, false)
		writeExecutable(t, filepath.Join(home, ".local/bin/agent-guard"), "#!/bin/sh\nexit 2\n")
		sentinel := filepath.Join(home, ".config/agent-guard/disabled")
		writeFile(t, sentinel, "")
		got := runLauncher(t, home, []string{"--tool", "codex"}, secretPrePayload())
		if got.exitCode != 0 {
			t.Fatalf("active sentinel exit = %d, want 0", got.exitCode)
		}
	})

	t.Run("cursor-active", func(t *testing.T) {
		home := newHome(t, false)
		writeExecutable(t, filepath.Join(home, ".local/bin/agent-guard"), "#!/bin/sh\nexit 2\n")
		writeFile(t, filepath.Join(home, ".config/agent-guard/disabled"), "")
		got := runLauncher(t, home, []string{"--tool", "cursor"}, secretPrePayload())
		var body map[string]string
		if got.exitCode != 0 || json.Unmarshal([]byte(got.stdout), &body) != nil || body["permission"] != "allow" {
			t.Fatalf("Cursor disabled result = (%d, %q, %q)", got.exitCode, got.stdout, got.stderr)
		}
	})

	t.Run("expired", func(t *testing.T) {
		home := newHome(t, false)
		writeExecutable(t, filepath.Join(home, ".local/bin/agent-guard"), "#!/bin/sh\nexit 2\n")
		sentinel := filepath.Join(home, ".config/agent-guard/disabled")
		writeFile(t, sentinel, "")
		old := time.Now().Add(-9 * time.Hour)
		if err := os.Chtimes(sentinel, old, old); err != nil {
			t.Fatal(err)
		}
		got := runLauncher(t, home, []string{"--tool", "codex"}, secretPrePayload())
		if got.exitCode != 2 {
			t.Fatalf("expired sentinel exit = %d, want underlying exit 2", got.exitCode)
		}
		if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
			t.Fatalf("expired sentinel still exists: %v", err)
		}
	})
}

func TestDoctorRunsRealDetectionAndRedactionThroughLauncher(t *testing.T) {
	home := newHome(t, true)
	// Diagnostic commands are never bypassed by the hook-only sentinel.
	writeFile(t, filepath.Join(home, ".config/agent-guard/disabled"), "")
	got := runLauncher(t, home, []string{"doctor", "--json"}, "")
	if got.exitCode != 0 {
		t.Fatalf("doctor exit = %d: %s", got.exitCode, got.stderr)
	}
	var report struct {
		SchemaVersion int `json:"schema_version"`
		OK            bool
		Checks        []struct {
			ID     string
			Status string
		}
	}
	if err := json.Unmarshal([]byte(got.stdout), &report); err != nil {
		t.Fatalf("doctor JSON: %v (%q)", err, got.stdout)
	}
	if report.SchemaVersion != 1 || !report.OK {
		t.Fatalf("doctor report = %#v", report)
	}
	statuses := map[string]string{}
	for _, check := range report.Checks {
		statuses[check.ID] = check.Status
	}
	for _, id := range []string{"scanner-detection", "verified-redaction", "supported-platform"} {
		if statuses[id] != "ok" {
			t.Errorf("doctor check %q = %q, want ok", id, statuses[id])
		}
	}
}

func TestRealScannerContractsThroughLauncher(t *testing.T) {
	home := newHome(t, true)

	clean := runLauncher(t, home, []string{"--tool", "codex"}, cleanPayload())
	if clean.exitCode != 0 || clean.stdout != "" || clean.stderr != "" {
		t.Fatalf("clean input = %#v", clean)
	}

	null := runLauncher(t, home, []string{"--tool", "codex"}, "null")
	if null.exitCode != 2 || !strings.Contains(null.stderr, "fail closed") {
		t.Fatalf("null input = %#v", null)
	}

	unguarded := runLauncher(
		t,
		home,
		[]string{"--tool", "codex"},
		`{"hook_event_name":"SessionStart"}`,
	)
	if unguarded.exitCode != 0 {
		t.Fatalf("unguarded event exit = %d", unguarded.exitCode)
	}
}

func TestPreBlockMatrixThroughLauncher(t *testing.T) {
	home := newHome(t, true)
	for _, tool := range []string{"claude", "codex", "cursor", "opencode"} {
		t.Run(tool, func(t *testing.T) {
			got := runLauncher(t, home, []string{"--tool", tool}, secretPrePayload())
			if tool == "cursor" {
				var body map[string]string
				if got.exitCode != 0 || json.Unmarshal([]byte(got.stdout), &body) != nil || body["permission"] != "deny" {
					t.Fatalf("Cursor denial = %#v", got)
				}
				return
			}
			if got.exitCode != 2 || !strings.Contains(got.stderr, "stripe-access-token") {
				t.Fatalf("%s denial = %#v", tool, got)
			}
		})
	}
}

func TestPostRedactionMatrixThroughLauncher(t *testing.T) {
	home := newHome(t, true)
	secret := syntheticSecret()
	for _, tool := range []string{"claude", "codex", "cursor", "opencode"} {
		t.Run(tool, func(t *testing.T) {
			got := runLauncher(t, home, []string{"--tool", tool}, secretPostPayload())
			switch tool {
			case "claude":
				var body map[string]map[string]any
				if got.exitCode != 0 || json.Unmarshal([]byte(got.stdout), &body) != nil {
					t.Fatalf("Claude post result = %#v", got)
				}
				replacement, err := json.Marshal(body["hookSpecificOutput"]["updatedToolOutput"])
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(replacement), secret) || !strings.Contains(string(replacement), "build ok") {
					t.Fatalf("Claude replacement = %q", replacement)
				}
			case "cursor":
				if got.exitCode != 0 || !strings.Contains(got.stderr, "stripe-access-token") {
					t.Fatalf("Cursor post result = %#v", got)
				}
			default:
				if got.exitCode != 2 || strings.Contains(got.stderr, secret) || !strings.Contains(got.stderr, "build ok") {
					t.Fatalf("%s post result = %#v", tool, got)
				}
			}
		})
	}
}

func TestAllowlistIsConfinedToThrowawayHome(t *testing.T) {
	home := newHome(t, true)
	blocked := runLauncher(t, home, []string{"--tool", "codex"}, secretPrePayload())
	if blocked.exitCode != 2 {
		t.Fatalf("unallowlisted secret exit = %d, want 2", blocked.exitCode)
	}

	sum := sha256.Sum256([]byte(syntheticSecret()))
	writeFile(
		t,
		filepath.Join(home, ".config/agent-guard/allow"),
		hex.EncodeToString(sum[:])+"\n",
	)
	allowed := runLauncher(t, home, []string{"--tool", "codex"}, secretPrePayload())
	if allowed.exitCode != 0 {
		t.Fatalf("isolated allowlisted secret exit = %d: %s", allowed.exitCode, allowed.stderr)
	}

	otherHome := newHome(t, true)
	stillBlocked := runLauncher(t, otherHome, []string{"--tool", "codex"}, secretPrePayload())
	if stillBlocked.exitCode != 2 {
		t.Fatalf("allowlist leaked across homes: exit = %d", stillBlocked.exitCode)
	}
}

func TestConcurrentInvocationsAndStartupBudget(t *testing.T) {
	home := newHome(t, true)
	var samples []time.Duration
	for range 7 {
		start := time.Now()
		got := runLauncher(t, home, []string{"--tool", "codex"}, cleanPayload())
		samples = append(samples, time.Since(start))
		if got.exitCode != 0 {
			t.Fatalf("clean invocation exit = %d", got.exitCode)
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	if median := samples[len(samples)/2]; median >= 250*time.Millisecond {
		t.Fatalf("startup p50 %s exceeds 250ms", median)
	}

	start := time.Now()
	codes := make([]int, 20)
	var wait sync.WaitGroup
	for i := range codes {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			payload := cleanPayload()
			if i%3 == 0 {
				payload = secretPrePayload()
			}
			codes[i] = runLauncher(t, home, []string{"--tool", "codex"}, payload).exitCode
		}(i)
	}
	wait.Wait()
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("20 concurrent invocations took %s", elapsed)
	}
	for i, code := range codes {
		want := 0
		if i%3 == 0 {
			want = 2
		}
		if code != want {
			t.Errorf("invocation %d exit = %d, want %d", i, code, want)
		}
	}
}

func TestInstallerIsAtomicAndDoesNotMergeHostConfig(t *testing.T) {
	home := t.TempDir()
	installed := runInstaller(t, home, testBinary)
	if installed.exitCode != 0 {
		t.Fatalf("installer exit = %d: %s", installed.exitCode, installed.stderr)
	}
	got := runLauncher(t, home, []string{"doctor", "--json"}, "")
	if got.exitCode != 0 {
		t.Fatalf("installed doctor exit = %d: %s", got.exitCode, got.stderr)
	}
	for _, path := range []string{
		".claude",
		".codex",
		".cursor",
		".config/opencode",
	} {
		if _, err := os.Stat(filepath.Join(home, path)); !os.IsNotExist(err) {
			t.Errorf("installer unexpectedly created %s: %v", path, err)
		}
	}

	destination := filepath.Join(home, ".local/bin/agent-guard")
	before, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	badCandidate := filepath.Join(t.TempDir(), "agent-guard")
	writeExecutable(t, badCandidate, "#!/bin/sh\nexit 1\n")
	failed := runInstaller(t, home, badCandidate)
	if failed.exitCode == 0 {
		t.Fatal("installer accepted a candidate whose doctor failed")
	}
	after, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed install replaced the last-known-good binary")
	}
}

func TestInstallerBuildFailurePreservesLastKnownGood(t *testing.T) {
	home := t.TempDir()
	destination := filepath.Join(home, ".local/bin/agent-guard")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, destination, "#!/bin/sh\nexit 0\n")
	before, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}

	fakeBin := t.TempDir()
	writeExecutable(t, filepath.Join(fakeBin, "go"), "#!/bin/sh\nexit 42\n")
	command := exec.Command(filepath.Join(repoRoot, "scripts/install.sh"))
	command.Env = []string{
		"HOME=" + home,
		"PATH=" + fakeBin + ":/usr/bin:/bin",
		"TMPDIR=" + t.TempDir(),
		"LANG=C",
	}
	failed := runCommand(t, command)
	if failed.exitCode == 0 {
		t.Fatal("installer accepted a failed source build")
	}
	after, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed source build replaced the last-known-good binary")
	}
	for _, pattern := range []string{
		filepath.Join(home, ".local/bin/.agent-guard.install.*"),
		filepath.Join(home, ".config/agent-guard/.run.sh.*"),
	} {
		if matches, err := filepath.Glob(pattern); err != nil || len(matches) != 0 {
			t.Fatalf("temporary install artifacts for %q = %v, %v", pattern, matches, err)
		}
	}
}

func TestReleaseBundleInstallerUsesPackagedBinary(t *testing.T) {
	bundle := t.TempDir()
	for _, directory := range []string{"scripts", "integrations/launcher"} {
		if err := os.MkdirAll(filepath.Join(bundle, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(t, filepath.Join(repoRoot, "scripts/install.sh"), filepath.Join(bundle, "scripts/install.sh"), 0o755)
	copyFile(
		t,
		filepath.Join(repoRoot, "integrations/launcher/run.sh"),
		filepath.Join(bundle, "integrations/launcher/run.sh"),
		0o755,
	)
	copyFile(t, testBinary, filepath.Join(bundle, "agent-guard"), 0o755)

	home := t.TempDir()
	command := exec.Command(filepath.Join(bundle, "scripts/install.sh"))
	command.Env = []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"TMPDIR=" + t.TempDir(),
		"LANG=C",
	}
	installed := runCommand(t, command)
	if installed.exitCode != 0 {
		t.Fatalf("release-bundle installer exit = %d: %s", installed.exitCode, installed.stderr)
	}
	got := runLauncher(t, home, []string{"doctor", "--json"}, "")
	if got.exitCode != 0 {
		t.Fatalf("release-bundle doctor exit = %d: %s", got.exitCode, got.stderr)
	}
}

func newHome(t *testing.T, installCandidate bool) string {
	t.Helper()
	home := t.TempDir()
	configDir := filepath.Join(home, ".config/agent-guard")
	binDir := filepath.Join(home, ".local/bin")
	for _, path := range []string{configDir, binDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(t, filepath.Join(repoRoot, "integrations/launcher/run.sh"), filepath.Join(configDir, "run.sh"), 0o755)
	if installCandidate {
		copyFile(t, testBinary, filepath.Join(binDir, "agent-guard"), 0o755)
	}
	return home
}

func runLauncher(t *testing.T, home string, args []string, stdin string) result {
	t.Helper()
	command := exec.Command(filepath.Join(home, ".config/agent-guard/run.sh"), args...)
	command.Stdin = strings.NewReader(stdin)
	command.Env = []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"TMPDIR=" + t.TempDir(),
		"LANG=C",
	}
	return runCommand(t, command)
}

func runInstaller(t *testing.T, home, binary string) result {
	t.Helper()
	command := exec.Command(filepath.Join(repoRoot, "scripts/install.sh"), "--binary", binary)
	command.Env = []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"TMPDIR=" + t.TempDir(),
		"LANG=C",
	}
	return runCommand(t, command)
}

func runCommand(t *testing.T, command *exec.Cmd) result {
	t.Helper()
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", command.Args, err)
		}
		exitCode = exit.ExitCode()
	}
	return result{stdout: stdout.String(), stderr: stderr.String(), exitCode: exitCode}
}

func snippetCommands(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(path) == ".toml" {
		var commands []string
		for line := range strings.Lines(string(data)) {
			value, ok := strings.CutPrefix(strings.TrimSpace(line), "command = ")
			if !ok {
				continue
			}
			command, err := strconv.Unquote(value)
			if err != nil {
				t.Fatalf("%s: invalid command string: %v", path, err)
			}
			commands = append(commands, command)
		}
		return commands
	}

	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var commands []string
	var walk func(any)
	walk = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, nested := range value {
				if key == "command" {
					if command, ok := nested.(string); ok {
						commands = append(commands, command)
					}
					continue
				}
				walk(nested)
			}
		case []any:
			for _, nested := range value {
				walk(nested)
			}
		}
	}
	walk(decoded)
	return commands
}

func copyFile(t *testing.T, source, target string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, mode); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func syntheticSecret() string {
	return "sk_" + "live_" + "4eC39HqLyj" + "WDarjtT1zdp7dc"
}

func cleanPayload() string {
	return `{"hook_event_name":"PreToolUse","tool_input":{"command":"printf hello"}}`
}

func secretPrePayload() string {
	body, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_input":      map[string]any{"command": "printf %s " + syntheticSecret()},
	})
	return string(body)
}

func secretPostPayload() string {
	body, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_response": map[string]any{
			"output": "build ok\ntoken: " + syntheticSecret() + "\ndone",
		},
	})
	return string(body)
}
