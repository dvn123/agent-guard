# Agent Guard

Agent Guard is an offline secret-scanning boundary for configured coding-agent
hook events. It scans guarded tool input before execution and tool output
before the model consumes it, using an embedded Betterleaks ruleset and one
additional authenticated-URL rule.

The project supports Claude Code, Codex, Cursor, and OpenCode without sharing
their protocol logic. A stable launcher normalizes failures and provides an
eight-hour human-controlled disable sentinel; the staged installer preserves
the last-known-good binary.

## Security contract

- Runtime scanning is offline. Rules and dependencies are embedded or vendored.
- The core returns a blocking decision on malformed input, scanner errors,
  deadlines, and panics. The launcher converts missing binaries and unexpected
  hook exit codes into failures instead of silently continuing.
- Post-output replacement is accepted only after the replacement passes a
  second scan.
- False-positive exceptions are SHA-256 hashes of matched values, not plaintext
  secrets.
- Host behavior is part of the boundary. The adapters use each host's strongest
  available response; Cursor post hooks are observational, and dense matches
  can outlive Agent Guard's cooperative deadline. Read
  [Security](SECURITY.md), [Threat model](docs/THREAT_MODEL.md), and
  [Limitations](docs/LIMITATIONS.md) before relying on the guard.

Agent Guard reduces accidental secret exposure. It is not a sandbox, an access
control system, or a replacement for credential rotation.

## Install

The installer builds from the vendored module unless given a release binary:

```sh
scripts/install.sh
# or, from an extracted release archive:
scripts/install.sh --binary ./agent-guard
```

It stages the candidate, exercises the real scanner through an isolated copy of
the launcher, and replaces the installed binary only after `doctor` succeeds.
It installs:

```text
~/.local/bin/agent-guard
~/.config/agent-guard/run.sh
```

The installer does not read, merge, or modify coding-agent configuration.
Manually merge exactly one reusable snippet from [`integrations/`](integrations/)
as described in [Integrations](docs/INTEGRATIONS.md). Every hook must call the
stable launcher, never the versioned or installed binary directly.

Source installation is explicit: rerun `scripts/install.sh` after changing any
source, module, or vendored dependency. There is no dotfiles-specific change
trigger in this repository.

## Diagnose

Run diagnostics through the launcher:

```sh
~/.config/agent-guard/run.sh doctor
~/.config/agent-guard/run.sh doctor --json
```

`doctor` reports a versioned schema, supported-platform status, the registered
host integrations, actual synthetic-secret detection, and verified redaction.
It does not inspect the live allowlist or disable sentinel and does not use the
network. The complete contract is in [Diagnostics](docs/DIAGNOSTICS.md).

## Develop

Agent Guard requires Go 1.26.5. OpenCode adapter tests run under Node 26.5.1
and Bun 1.3.14 to cover both Desktop and CLI plugin runtimes.

```sh
GOTOOLCHAIN=local go test -mod=vendor -count=1 ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go tool govulncheck ./...
scripts/test-integrations.sh
scripts/build-all.sh ./dist/builds
```

The supported build targets are macOS ARM64, Linux AMD64, and Linux ARM64.
See [Architecture](docs/ARCHITECTURE.md), [Contributing](CONTRIBUTING.md), and
[Releasing](docs/RELEASING.md).
