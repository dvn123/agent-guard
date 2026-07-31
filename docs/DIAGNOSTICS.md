# Diagnostics

Run diagnostics through the installed launcher:

```sh
~/.config/agent-guard/run.sh doctor
~/.config/agent-guard/run.sh doctor --json
```

The human and JSON renderers consume the same report. Exit 0 means every check
passed, exit 1 means a check or command option failed, and exit 2 is reserved
for an unexpected application or launcher failure.

## Checks

| Stable ID | Evidence |
| --- | --- |
| `supported-platform` | Runtime is macOS ARM64, Linux AMD64, or Linux ARM64 |
| `scanner-detection` | The embedded scanner identifies a runtime-assembled synthetic secret and its expected rule |
| `verified-redaction` | Post-output replacement removes that value, preserves safe context, and passes a clean second scan |

The self-test constructs the real embedded detector. It is not a startup-only
parse check. It performs no network request or filesystem read.

## JSON contract

The top-level `schema_version` is currently `1`. Consumers should reject an
unsupported schema rather than guess at renamed fields.

```json
{
  "schema_version": 1,
  "ok": true,
  "version": {
    "version": "dev",
    "commit": "unknown",
    "date": "unknown"
  },
  "runtime": {
    "goos": "darwin",
    "goarch": "arm64",
    "go_version": "go1.26.5"
  },
  "integrations": [
    {
      "id": "codex",
      "display_name": "Codex",
      "protocol_version": "hooks-v1"
    }
  ],
  "checks": [
    {
      "id": "scanner-detection",
      "status": "ok",
      "message": "synthetic secret detected"
    }
  ]
}
```

`ok` is the aggregate result. Each check status is `ok` or `failure`.
Integrations are emitted in registry order.

## Scope

`doctor` deliberately ignores the disable sentinel and does not load the live
hash allowlist. It remains available during break-glass recovery and cannot
expose administrative state.

The command proves the candidate's scanner and redaction path, registered
adapters, runtime, and stable launcher compatibility. It does not inspect or
modify host configuration and therefore does not claim that Claude Code,
Codex, Cursor, or OpenCode has loaded the supplied snippet.
