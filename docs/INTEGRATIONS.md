# Integrations

Install Agent Guard first, then register the host adapter. Each host has one
adapter, on the latest host release:

| Host | Adapter | Pre-tool contract | Post-tool contract |
| --- | --- | --- | --- |
| Claude Code | `integrations/marketplace/` | exit 2 and stderr deny | exit 0 with `updatedToolOutput` |
| Codex | `integrations/marketplace/` | exit 2 and stderr deny | exit 2; stderr becomes replacement |
| Cursor | `integrations/cursor/hooks.json` | shell/file-read allow/deny JSON | shell-output warning only |
| OpenCode | `integrations/opencode-pi/agent-guard/` | plugin throws on denial | plugin replaces the tool result |
| Pi | `integrations/opencode-pi/agent-guard/` | extension returns `block` | extension replaces the content |

Do not overwrite generated or unrelated configuration. Preserve existing hooks,
features, plugins, and host-specific settings while merging the Cursor file.

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

## Claude Code and Codex

One marketplace serves both hosts. Its root carries Claude's
`.claude-plugin/marketplace.json` and Codex's `.agents/plugins/marketplace.json`,
and its one plugin carries a manifest per host: Claude reads
`.claude-plugin/plugin.json`, which names `hooks/claude.json`, and Codex reads
`.codex-plugin/plugin.json` first, which names `hooks/codex.json`. The two hook
files differ in `--tool` because the hosts replace post-tool output
differently. Neither may be named `hooks/hooks.json`: Claude would merge it
into its own hooks.

Register the marketplace with each host and install `agent-guard@coding-agents`:

```sh
claude plugin marketplace add <marketplace> --scope user
claude plugin install agent-guard@coding-agents --scope user
codex plugin marketplace add <marketplace>
codex plugin add agent-guard@coding-agents
```

Codex skips plugin-bundled hooks until you review and trust them with `/hooks`.
Do not bypass that review with `--dangerously-bypass-hook-trust` for Agent
Guard.

Cursor's "Include Third-Party Plugins, Skills, and Other Configs" setting,
which is on by default, also loads enabled Claude Code plugins, and their
hooks would run in Cursor with Claude's protocol. Turn it off in Cursor
Settings when both hosts are configured.

## Cursor

Merge `integrations/cursor/hooks.json` into `~/.cursor/hooks.json`, appending
to any event that already has hooks. Desktop and the Agent CLI both load that
file, while the CLI does not load `~/.cursor/plugins/local`, so a plugin would
reach Desktop alone. The pre hooks set `failClosed: true`. Cursor's post hook
cannot replace output, so a finding produces a warning only.

## OpenCode and Pi

Both hosts run JavaScript plugins in-process, so they share one bridge,
`guard.js`, which invokes the stable launcher through `node:child_process`
for every call. That API works in the Bun-based OpenCode CLI, in Electron's
Node runtime for OpenCode Desktop, and in Pi. The bridge forwards the current
environment explicitly so the launcher and binary resolve the same home
directory. Copy the whole directory to each host:

```text
~/.config/opencode/plugins/agent-guard/
~/.pi/agent/extensions/agent-guard/
```

OpenCode resolves a plugin directory's server entry to `server.js` before
`index.js`; Pi loads `index.js`. A throw from OpenCode's pre-call hook, or a
`{ block: true }` from Pi's `tool_call`, rejects that tool call and shows the
reason to the model. Post-call, OpenCode replaces both the `content` parts and
the typed `output` value of `event.result`, and Pi returns new `content`,
which also drops the structured content, since a secret in either has already
left the sandbox.

## Contract updates

Host hook protocols are version-sensitive. A protocol change requires:

1. updating only that host's adapter or JavaScript bridge;
2. adding a new versioned fixture directory rather than silently rewriting the
   existing protocol label;
3. recording the source and check date in `contract.json`;
4. running the full isolated integration suite.
