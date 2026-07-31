package integration

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dvn123/agent-guard/internal/core"
)

type hostContract struct {
	Tool                string `json:"tool"`
	Mode                string `json:"mode"`
	HostContract        string `json:"host_contract"`
	FixtureSource       string `json:"fixture_source"`
	ContractSource      string `json:"contract_source"`
	SourceCheckedAt     string `json:"source_checked_at"`
	HostVersion         string `json:"host_version"`
	ContainsSecret      bool   `json:"contains_secret"`
	ExpectedExit        int    `json:"expected_exit"`
	ExpectedStderr      string `json:"expected_stderr"`
	ExpectedPermission  string `json:"expected_permission"`
	ExpectUpdatedOutput bool   `json:"expect_updated_output"`
	RedactsSecret       bool   `json:"redacts_secret"`
	Preserves           string `json:"preserves"`
}

func TestVersionedHostContracts(t *testing.T) {
	paths, err := filepath.Glob("testdata/contracts/*/*/*/contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no host contract fixtures found")
	}

	synthetic := "sk_" + "live_" + "4eC39HqLyj" + "WDarjtT1zdp7dc"
	for _, contractPath := range paths {
		contractPath := contractPath
		t.Run(filepath.ToSlash(filepath.Dir(contractPath)), func(t *testing.T) {
			var contract hostContract
			decodeFixture(t, contractPath, &contract)
			if contract.HostContract == "" || contract.FixtureSource == "" || contract.HostVersion == "" {
				t.Fatal("fixture must identify its host contract, imported source, and host version")
			}
			source, err := url.ParseRequestURI(contract.ContractSource)
			if err != nil || source.Scheme != "https" || source.Host == "" {
				t.Fatalf("contract_source = %q, want an authoritative HTTPS URL", contract.ContractSource)
			}
			if _, err := time.Parse(time.DateOnly, contract.SourceCheckedAt); err != nil {
				t.Fatalf("source_checked_at = %q: %v", contract.SourceCheckedAt, err)
			}

			inputPath := filepath.Join(filepath.Dir(contractPath), "input.json")
			input, err := os.ReadFile(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			raw := strings.ReplaceAll(string(input), "__AGENT_GUARD_TEST_SECRET__", synthetic)
			payload, err := core.ParsePayload([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if got := core.HookMode(payload); got != contract.Mode {
				t.Fatalf("HookMode = %q, want %q", got, contract.Mode)
			}

			guard, err := core.NewGuard()
			if err != nil {
				t.Fatal(err)
			}
			entry, err := Lookup(contract.Tool)
			if err != nil {
				t.Fatal(err)
			}
			output := entry.Adapter.Emit(payload, guard.Review(payload, contract.Mode, nil))
			if output.ExitCode != contract.ExpectedExit {
				t.Errorf("exit = %d, want %d", output.ExitCode, contract.ExpectedExit)
			}
			if contract.ExpectedStderr != "" && !strings.Contains(output.Stderr, contract.ExpectedStderr) {
				t.Errorf("stderr = %q, want %q", output.Stderr, contract.ExpectedStderr)
			}

			delivered := output.Stderr
			if contract.ExpectedPermission != "" || contract.ExpectUpdatedOutput {
				var body map[string]any
				if err := json.Unmarshal([]byte(output.Stdout), &body); err != nil {
					t.Fatalf("stdout is not JSON: %v (%q)", err, output.Stdout)
				}
				if contract.ExpectedPermission != "" {
					if got := body["permission"]; got != contract.ExpectedPermission {
						t.Errorf("permission = %v, want %q", got, contract.ExpectedPermission)
					}
				}
				if contract.ExpectUpdatedOutput {
					specific, ok := body["hookSpecificOutput"].(map[string]any)
					if !ok {
						t.Fatalf("hookSpecificOutput = %#v", body["hookSpecificOutput"])
					}
					updated := specific["updatedToolOutput"]
					original := payload["tool_response"]
					if reflect.TypeOf(updated) != reflect.TypeOf(original) {
						t.Fatalf("updatedToolOutput type = %T, want original type %T", updated, original)
					}
					serialized, err := json.Marshal(updated)
					if err != nil {
						t.Fatalf("updatedToolOutput: %v", err)
					}
					delivered = string(serialized)
				}
			}
			if contract.RedactsSecret && strings.Contains(delivered, synthetic) {
				t.Fatalf("delivered output leaked the synthetic secret: %q", delivered)
			}
			if contract.Preserves != "" && !strings.Contains(delivered, contract.Preserves) {
				t.Errorf("delivered output dropped %q: %q", contract.Preserves, delivered)
			}
		})
	}
}

func TestRegistryHasOneAdapterPerSupportedHost(t *testing.T) {
	entries := All()
	if len(entries) != 4 {
		t.Fatalf("registry has %d entries, want 4", len(entries))
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.ID == "" || entry.DisplayName == "" || entry.ProtocolVersion == "" || entry.Adapter == nil {
			t.Fatalf("incomplete registry entry: %#v", entry)
		}
		if seen[entry.ID] {
			t.Fatalf("duplicate registry ID %q", entry.ID)
		}
		seen[entry.ID] = true
	}
}

func decodeFixture(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}
