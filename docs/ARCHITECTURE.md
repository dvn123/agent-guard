# Architecture

Agent Guard is one Go application with explicit host integrations:

```text
cmd/agent-guard
    │
    ▼
internal/cli ──► internal/core ──► embedded Betterleaks
    │
    └─────────► internal/integration/{claude,codex,cursor,opencode}
                                      │
                                      ▼
                               native host protocol
```

## Boundaries

1. `internal/core` owns payload classification, scanning, hash allowlisting,
   span-preserving redaction, the verifying re-scan, and the real scanner
   self-test. It does not know how a host represents allow, denial, or output
   replacement.
2. `internal/integration` contains one thin adapter per host. The registry is
   the only mapping from stable integration IDs to protocol versions and
   adapters.
3. `internal/cli` owns process arguments, standard streams, diagnostics, and
   the fixed runtime allowlist path. It renders every core decision through the
   selected adapter.
4. `cmd/agent-guard` only converts the CLI result into a process exit code.
5. `integrations/launcher/run.sh` is the stable installed entrypoint. It
   handles the disable sentinel, missing binaries, and host-sensitive exit
   normalization before delegating to the Go binary.
6. `integrations/opencode/agent-guard.js` translates OpenCode plugin events
   into the same launcher contract. The other hosts invoke the launcher
   directly from configuration.

## Scanner lifetime and failures

Each hook invocation constructs one detector from Betterleaks' embedded default
configuration and the local authenticated-URL rule. The detector performs no
runtime network access. Its maximum decode depth is five, and inline
`gitleaks:allow` or `betterleaks:allow` comments are ignored because an agent
could forge them.

Betterleaks reports some initialization failures with Zerolog `Fatal`.
Zerolog's default fatal callback calls `os.Exit`; Go panic recovery cannot catch
`os.Exit`. Agent Guard therefore replaces `zerolog.FatalExitFunc` with a panic
callback only around detector construction and restores the previous callback
with `defer`. The CLI panic boundary then converts that panic to a native
fail-closed host response.

Scanning uses a three-second context. The context detects truncation and denies
the event, but it is not a hard execution bound because Betterleaks checks
cancellation between phases. See [Limitations](LIMITATIONS.md).

## Output redaction

Post-tool findings include source byte spans. Agent Guard replaces only the
matched spans, merges overlaps deterministically, and preserves surrounding
output. Decoded findings or invalid coordinates trigger whole-output
replacement rather than an unverifiable partial rewrite.

The initial scan and verifying re-scan share one deadline. A replacement is
emitted only if it contains no remaining findings and the re-scan finishes
without error. Otherwise the adapter emits a host-native blocking replacement.

Claude Code validates `updatedToolOutput` against the original tool output's
shape. During review, the core maps each detected span back to its originating
string leaf and builds a verified clone of the original tool response. Maps,
slices, non-string scalars, schema discriminators, identifiers, and unaffected
strings remain unchanged. The Claude adapter emits that clone, avoiding a
schema-invalid replacement that Claude would ignore. If review fails before a
verified clone exists, the adapter uses explicit schema-valid fallbacks for
current Bash, completed Agent, and background Agent responses.

## Contracts and fixtures

Versioned fixtures live under:

```text
internal/integration/testdata/contracts/<host>/<protocol>/<case>/
```

Each fixture records its host contract, exact imported source revision,
authoritative contract URL, source-check date, and known host version
separately from the test input. Synthetic secret placeholders are assembled
only at test runtime.
`contracts_test.go` applies the real scanner and checks exit codes, JSON shape,
redaction, and preserved safe output.

Black-box tests build a candidate and invoke it only through a copied launcher
inside a throwaway `HOME`. The OpenCode adapter tests use the same isolation
under both Node, matching Desktop's Electron runtime, and Bun, matching the
CLI. Neither suite consults installed Agent Guard artifacts.

## Installation boundary

`scripts/install.sh` stages the binary and launcher, runs `doctor --json`
through the staged launcher in a throwaway home directory, and then performs
the cutover. Moving the launcher first is backward-compatible; failure to move
the candidate binary leaves the last-known-good binary in place.

Host configuration ownership remains outside this project. Installer code does
not parse or merge generated Claude, Codex, Cursor, or OpenCode configuration.
