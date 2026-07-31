#!/bin/sh
# Run deterministic launcher, host-contract, installer, and OpenCode adapter
# tests without reading installed Agent Guard artifacts.
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/agent-guard-integrations.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

(
	cd "$repo_root"
	GOTOOLCHAIN=local CGO_ENABLED=0 go build \
		-mod=vendor \
		-trimpath \
		-o "$tmp_dir/agent-guard" \
		./cmd/agent-guard
	AGENT_GUARD_TEST_BINARY="$tmp_dir/agent-guard" \
		GOTOOLCHAIN=local \
		go test -mod=vendor -count=1 ./tests/blackbox
	AGENT_GUARD_TEST_BINARY="$tmp_dir/agent-guard" \
		node --test ./integrations/opencode/agent-guard.test.js
	AGENT_GUARD_TEST_BINARY="$tmp_dir/agent-guard" \
		bun test ./integrations/opencode/agent-guard.test.js
)
