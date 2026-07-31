package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"

	"github.com/dvn123/agent-guard/internal/core"
	"github.com/dvn123/agent-guard/internal/integration"
	"github.com/dvn123/agent-guard/internal/version"
)

type doctorReport struct {
	SchemaVersion int               `json:"schema_version"`
	OK            bool              `json:"ok"`
	Version       versionInfo       `json:"version"`
	Runtime       runtimeInfo       `json:"runtime"`
	Integrations  []integrationInfo `json:"integrations"`
	Checks        []doctorCheck     `json:"checks"`
}

type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

type runtimeInfo struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	Go     string `json:"go_version"`
}

type integrationInfo struct {
	ID              string `json:"id"`
	DisplayName     string `json:"display_name"`
	ProtocolVersion string `json:"protocol_version"`
}

type doctorCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func runDoctor(args []string, stdout, stderr io.Writer) int {
	jsonOutput := false
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Fprintln(stdout, "Usage: agent-guard doctor [--json]")
			return 0
		default:
			fmt.Fprintf(stderr, "agent-guard doctor: unknown option %q\n", arg)
			return 1
		}
	}

	report := collectDoctorReport()
	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(stderr, "agent-guard doctor: writing JSON: %v\n", err)
			return 1
		}
	} else {
		status := "OK"
		if !report.OK {
			status = "FAILED"
		}
		fmt.Fprintf(stdout, "Agent Guard doctor: %s\n", status)
		fmt.Fprintf(stdout, "Version: %s (%s)\n", report.Version.Version, report.Version.Commit)
		fmt.Fprintf(stdout, "Runtime: %s/%s %s\n", report.Runtime.GOOS, report.Runtime.GOARCH, report.Runtime.Go)
		for _, check := range report.Checks {
			fmt.Fprintf(stdout, "- %s: %s: %s\n", check.ID, check.Status, check.Message)
		}
	}
	if report.OK {
		return 0
	}
	return 1
}

func collectDoctorReport() doctorReport {
	report := doctorReport{
		SchemaVersion: 1,
		OK:            true,
		Version: versionInfo{
			Version: version.Version,
			Commit:  version.Commit,
			Date:    version.Date,
		},
		Runtime: runtimeInfo{
			GOOS:   runtime.GOOS,
			GOARCH: runtime.GOARCH,
			Go:     runtime.Version(),
		},
	}
	for _, entry := range integration.All() {
		report.Integrations = append(report.Integrations, integrationInfo{
			ID:              entry.ID,
			DisplayName:     entry.DisplayName,
			ProtocolVersion: entry.ProtocolVersion,
		})
	}

	supported := (runtime.GOOS == "darwin" && runtime.GOARCH == "arm64") ||
		(runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"))
	report.Checks = append(report.Checks, doctorCheck{
		ID:      "supported-platform",
		Status:  status(supported),
		Message: platformMessage(supported),
	})
	report.OK = report.OK && supported

	for _, check := range core.SelfTest() {
		report.Checks = append(report.Checks, doctorCheck{
			ID:      check.ID,
			Status:  status(check.OK),
			Message: check.Message,
		})
		report.OK = report.OK && check.OK
	}
	return report
}

func status(ok bool) string {
	if ok {
		return "ok"
	}
	return "failure"
}

func platformMessage(supported bool) string {
	if supported {
		return "runtime platform is supported"
	}
	return "supported platforms are darwin/arm64, linux/amd64, and linux/arm64"
}
