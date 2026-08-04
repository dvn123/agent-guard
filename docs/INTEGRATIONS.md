# Integrations

Install Agent Guard first, then register the host adapter. Prefer each host's
native plugin surface; the older snippets remain manual merge fallbacks:

| Host | Preferred adapter | Fallback | Pre-tool contract | Post-tool contract |
| --- | --- | --- | --- | --- |
| Claude Code | `integrations/claude/marketplace/` | `settings.snippet.json` | exit 2 and stderr deny | exit 0 with `updatedToolOutput` |
| Codex | `integrations/codex/marketplace/` | `config.snippet.toml` | exit 2 and stderr deny | exit 2; stderr becomes replacement |
| Cursor | `integrations/cursor/plugin/` | `hooks.snippet.json` | shell/file-read allow/deny JSON | shell-output warning only |
| OpenCode | `integrations/opencode/agent-guard.js` | (same file) | plugin throws on denial | plugin replaces `output.output` |

Do not overwrite generated or unrelated configuration. Preserve existing hooks,
features, plugins, and host-specific settings while merging a fallback snippet.

## Stable entrypoint

Every host must invoke:

```text
$HOME/.config/agent-guard/run.sh --tool <host>
```

The `hook --tool <host>` form is equivalent, but the shipped adapters retain
the legacy form for installation compatibility. Commands wrap that path in a
quoted `/bin/sh` bootstrap so unset `HOME` and home paths containing spaces
resolve before the launcher starts. Do not configure a host to call
`~/.local/bin/agent-guard` directly.

## Claude Code

Prefer the Claude Code plugin under
`integrations/claude/marketplace/`. Register the marketplace, install
`agent-guard@coding-agents`, and enable it. The plugin's `hooks/hooks.json`
calls the stable launcher; it does not edit `settings.json` hook arrays.

`integrations/claude/settings.snippet.json` remains the manual merge fallback
when a host cannot use plugins. If a matching event already has hooks, append
the command hook instead of replacing the array.

## Codex

Prefer the Codex marketplace under `integrations/codex/marketplace/`. Add the
marketplace root with `codex plugin marketplace add`, install
`agent-guard@coding-agents`, and keep `features.plugin_hooks = true`. The
plugin's `hooks/hooks.json` calls the stable launcher.

Codex skips plugin-bundled hooks until you review and trust them with `/hooks`.
Do not bypass that review with `--dangerously-bypass-hook-trust` for Agent
Guard.

`integrations/codex/config.snippet.toml` remains the manual merge fallback.
If `[features]` already exists, add or update only `hooks = true`; do not add a
second table. Append the two hook entries while retaining existing hooks.

## Cursor

Prefer the Cursor plugin under `integrations/cursor/plugin/`. Deliver it to
`~/.cursor/plugins/local/agent-guard/`. Cursor Agent CLI does not auto-load
that directory (only `--plugin-dir`), so also deliver
`integrations/cursor/hooks.snippet.json` as `~/.cursor/hooks.json` for CLI
coverage. Desktop may load both sources; matching hooks all run.

`integrations/cursor/hooks.snippet.json` remains the manual merge fallback
when only a user hooks file is available. The pre hooks set `failClosed: true`.
Cursor's post hook cannot replace output, so a finding produces a warning only.

## OpenCode

Copy `integrations/opencode/agent-guard.js` into the user's OpenCode plugin
directory without removing existing plugins:

```text
~/.config/opencode/plugin/agent-guard.js
```

That file is OpenCode's native plugin surface. The adapter invokes the stable
launcher through `node:child_process` for every call. That API works in both
the Bun-based CLI and Electron's Node runtime, unlike the Bun-only global
process API. It forwards the current environment explicitly so the launcher
and binary resolve the same home directory.

## Contract updates

Host hook protocols are version-sensitive. A protocol change requires:

1. updating only that host's adapter or JavaScript bridge;
2. adding a new versioned fixture directory rather than silently rewriting the
   existing protocol label;
3. recording the source and check date in `contract.json`;
4. running the full isolated integration suite.
