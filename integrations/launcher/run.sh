#!/bin/sh
# Fail-closed launcher for agent-guard. All four coding agents' hooks call
# this stable path so guard cutovers swap the implementation, never the
# wiring (a re-pointed hook config once locked out a whole session).
#
# Exit normalization: the tools treat exit 2 as "block" and other non-zero
# exits as a non-blocking hook error (Claude Code silently continues), so a
# missing or crashing guard binary would fail OPEN without this wrapper. Any
# exit other than 0/2 becomes 2 with an actionable message.
#
# Human-only recovery helpers ship in the source and release bundle under
# scripts/. The disabled sentinel expires after eight hours so forgotten
# break-glass state cannot disable hooks permanently.

# Cursor's GUI hook process may omit HOME. Resolve it from the user database
# before deriving paths; other clients keep their existing HOME unchanged.
if [ -z "${HOME:-}" ]; then
	HOME=$(cd ~ 2>/dev/null && pwd) || HOME=
	case "$HOME" in
	/*) export HOME ;;
	*)
		cat >/dev/null 2>&1 || true
		echo "agent-guard: fail closed: cannot resolve the current user's home directory" >&2
		exit 2
		;;
	esac
fi

SENTINEL="$HOME/.config/agent-guard/disabled"
BIN="$HOME/.local/bin/agent-guard"
TTL_MINUTES=480

is_hook=false
cursor_hook=false
if [ "${1:-}" = "--tool" ]; then
	is_hook=true
	[ "${2:-}" = "cursor" ] && cursor_hook=true
elif [ "${1:-}" = "hook" ] && [ "${2:-}" = "--tool" ]; then
	is_hook=true
	[ "${3:-}" = "cursor" ] && cursor_hook=true
fi

if $is_hook && [ -e "$SENTINEL" ]; then
	if [ -n "$(find "$SENTINEL" -mmin +$TTL_MINUTES 2>/dev/null)" ]; then
		rm -f "$SENTINEL" 2>/dev/null || true
	else
		cat >/dev/null 2>&1 || true # drain the payload the hook harness wrote
		if $cursor_hook; then
			printf '%s\n' '{"permission":"allow"}'
		fi
		exit 0
	fi
fi

if [ -x "$BIN" ]; then
	"$BIN" "$@"
	code=$?
	if ! $is_hook || [ "$code" -eq 0 ] || [ "$code" -eq 2 ]; then
		exit "$code"
	fi
	echo "agent-guard: fail closed: guard exited $code; ask a human to run scripts/guard-repair from the Agent Guard source or release bundle" >&2
	exit 2
fi

cat >/dev/null 2>&1 || true
echo "agent-guard: fail closed: $BIN is missing; ask a human to run scripts/guard-repair from the Agent Guard source or release bundle" >&2
exit 2
