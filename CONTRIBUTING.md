# Contributing

Agent Guard is a security boundary. Keep changes small, preserve native host
contracts, and provide executable evidence for behavior claims.

## Environment

- Go 1.26.5 with `GOTOOLCHAIN=local`
- Bun 1.3.14 for the OpenCode adapter tests
- Vendored module builds with `-mod=vendor`

Do not add a runtime network dependency, external scanner configuration, or a
host-config merger. Do not execute recovery or allowlisting helpers from tests
or coding-agent automation.

## Layout

- `internal/core`: host-independent policy and scanner behavior
- `internal/cli`: commands, streams, and diagnostics
- `internal/integration`: thin native host adapters and versioned fixtures
- `integrations`: launcher, configuration snippets, and the OpenCode bridge
- `tests/blackbox`: launcher-mediated subprocess coverage
- `scripts`: install, verification, build, and human recovery primitives

## Tests

Run:

```sh
GOTOOLCHAIN=local go test -mod=vendor -count=1 ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go tool govulncheck ./...
scripts/test-integrations.sh
scripts/build-all.sh ./dist/builds
```

Tests must use throwaway home directories and copied candidates. They must not
read, mutate, or depend on installed artifacts under the developer's home
directory. Black-box hook invocations must go through the copied stable
launcher.

When changing a host contract, add or version its fixture under
`internal/integration/testdata/contracts`. Record the contract source and check
date, verify native JSON or exit semantics, and exercise both pre- and
post-output behavior where the host supports them.

## Dependencies

Dependencies require a deliberate provenance review. Update `go.mod` and
`go.sum`, regenerate `vendor/`, and inspect all three diffs. Never edit vendored
code directly. Betterleaks changes require explicit scanner recall,
false-positive, fatal-initialization, dense-match, and verified-redaction
review.

## Change quality

1. Reproduce defects before fixing them.
2. Preserve fail-closed behavior for every recognized guarded event.
3. Keep core decisions independent of host rendering.
4. Test actual security behavior, not only JSON parsing or framework code.
5. Update architecture, threat-model, limitation, and integration documents
   when the boundary changes.
6. Inspect the complete diff and remove nonessential code before requesting
   review.
