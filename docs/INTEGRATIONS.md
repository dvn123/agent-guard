# Integrations

Install Agent Guard first, then merge the relevant snippet into the host's
existing configuration. These files are reusable fragments, not complete
configuration ownership:

| Host | Snippet or adapter | Pre-tool contract | Post-tool contract |
| --- | --- | --- | --- |
| Claude Code | `integrations/claude/settings.snippet.json` | exit 2 and stderr deny | exit 0 with `updatedToolOutput` |
| Codex | `integrations/codex/config.snippet.toml` | exit 2 and stderr deny | exit 2; stderr becomes replacement |
| Cursor | `integrations/cursor/hooks.snippet.json` | shell/file-read allow/deny JSON | shell-output warning only |
| OpenCode | `integrations/opencode/agent-guard.js` | plugin throws on denial | plugin replaces `output.output` |

Do not overwrite generated or unrelated configuration. Preserve existing hooks,
features, plugins, and host-specific settings while merging the fragment.

## Stable entrypoint

Every host must invoke:

```text
$HOME/.config/agent-guard/run.sh --tool <host>
```

The `hook --tool <host>` form is equivalent, but the shipped snippets retain
the legacy form for installation compatibility. The snippets wrap that path in
a quoted `/bin/sh` bootstrap so unset `HOME` and home paths containing spaces
resolve before the launcher starts. Do not configure a host to call
`~/.local/bin/agent-guard` directly.

## Claude Code

Merge the `hooks.PreToolUse` and `hooks.PostToolUse` entries from
`integrations/claude/settings.snippet.json` into the appropriate settings file.
If a matching event already has hooks, append the command hook instead of
replacing the array.

## Codex

Merge `integrations/codex/config.snippet.toml` into Codex configuration. If
`[features]` already exists, add or update only `hooks = true`; do not add a
second table. Append the two hook entries while retaining existing hooks. The
snippet follows the Codex command-hook schema checked against the current
manual on 2026-07-27.

## Cursor

Merge the entries from `integrations/cursor/hooks.snippet.json` into the
existing version 1 hooks file. The pre hooks set `failClosed: true`. Cursor's
post hook cannot replace output, so a finding produces a warning only.

## OpenCode

Copy `integrations/opencode/agent-guard.js` into the user's OpenCode plugin
directory without removing existing plugins:

```text
~/.config/opencode/plugin/agent-guard.js
```

The adapter invokes the stable launcher through `node:child_process` for every
call. That API works in both the Bun-based CLI and Electron's Node runtime,
unlike the Bun-only global process API. It forwards the current environment
explicitly so the launcher and binary resolve the same home directory.

## Contract updates

Host hook protocols are version-sensitive. A protocol change requires:

1. updating only that host's adapter or JavaScript bridge;
2. adding a new versioned fixture directory rather than silently rewriting the
   existing protocol label;
3. recording the source and check date in `contract.json`;
4. running the full isolated integration suite.
