#!/bin/sh
# Install a source-built or packaged Agent Guard binary without modifying any
# coding-agent configuration. The candidate is exercised through an isolated
# launcher before the last-known-good binary is replaced.
set -eu

usage() {
	cat <<'EOF'
Usage: scripts/install.sh [--binary /path/to/agent-guard]

Without --binary, build from the repository's vendored Go module.
This installs:
  $HOME/.local/bin/agent-guard
  $HOME/.config/agent-guard/run.sh

Host configuration remains the caller's responsibility.
EOF
}

binary_source=
while [ "$#" -gt 0 ]; do
	case "$1" in
	--binary)
		[ "$#" -ge 2 ] || {
			echo "agent-guard install: --binary requires a path" >&2
			exit 1
		}
		binary_source=$2
		shift 2
		;;
	--help | -h)
		usage
		exit 0
		;;
	*)
		echo "agent-guard install: unknown option: $1" >&2
		usage >&2
		exit 1
		;;
	esac
done

if [ -z "${HOME:-}" ]; then
	echo "agent-guard install: HOME must be set" >&2
	exit 1
fi
case "$HOME" in
/*) ;;
*)
	echo "agent-guard install: HOME must be an absolute path" >&2
	exit 1
	;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(dirname "$script_dir")
launcher_source="$repo_root/integrations/launcher/run.sh"
install_dir="$HOME/.local/bin"
config_dir="$HOME/.config/agent-guard"

# Release archives place the packaged binary beside scripts/. Source trees
# have go.mod instead and build from the checked-in vendor directory.
if [ -z "$binary_source" ] && [ ! -f "$repo_root/go.mod" ] && [ -x "$repo_root/agent-guard" ]; then
	binary_source="$repo_root/agent-guard"
fi

umask 077
mkdir -p "$install_dir" "$config_dir"
chmod 0755 "$install_dir"
chmod 0700 "$config_dir"

tmp_dir=$(mktemp -d "$install_dir/.agent-guard.install.XXXXXX")
launcher_candidate=$(mktemp "$config_dir/.run.sh.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
	rm -f "$launcher_candidate"
}
trap cleanup EXIT HUP INT TERM

candidate="$tmp_dir/agent-guard"
if [ -n "$binary_source" ]; then
	if [ ! -f "$binary_source" ]; then
		echo "agent-guard install: binary not found: $binary_source" >&2
		exit 1
	fi
	cp "$binary_source" "$candidate"
else
	if ! command -v go >/dev/null 2>&1; then
		echo "agent-guard install: Go is required for a source install" >&2
		exit 1
	fi
	(
		cd "$repo_root"
		GOTOOLCHAIN=local CGO_ENABLED=0 go build \
			-mod=vendor \
			-trimpath \
			-ldflags="-s -w" \
			-o "$candidate" \
			./cmd/agent-guard
	)
fi
chmod 0755 "$candidate"

cp "$launcher_source" "$launcher_candidate"
chmod 0755 "$launcher_candidate"
/bin/sh -n "$launcher_candidate"

# Prove scanner initialization, actual secret detection, verified redaction,
# and launcher compatibility in a throwaway HOME before any live cutover.
test_home="$tmp_dir/test-home"
mkdir -p "$test_home/.local/bin" "$test_home/.config/agent-guard"
cp "$candidate" "$test_home/.local/bin/agent-guard"
cp "$launcher_candidate" "$test_home/.config/agent-guard/run.sh"
chmod 0755 "$test_home/.local/bin/agent-guard" "$test_home/.config/agent-guard/run.sh"
HOME="$test_home" "$test_home/.config/agent-guard/run.sh" doctor --json >/dev/null

# The launcher is backward-compatible with the previous binary, so install it
# first. If the final binary rename fails, the last-known-good binary remains.
mv -f "$launcher_candidate" "$config_dir/run.sh"
mv -f "$candidate" "$install_dir/agent-guard"
echo "Agent Guard installed. Merge one integration snippet manually; no host configuration was modified."
