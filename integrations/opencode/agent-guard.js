// OpenCode wiring for Agent Guard. Loaded automatically from
// ~/.config/opencode/plugin/ (the config plugin loader globs
// {plugin,plugins}/*.{ts,js}).
//
// tool.execute.before: a throw blocks the call and its message becomes the
// tool result the model sees. OpenCode has no plugin path to the native ask
// tool.execute.after: mutating output.output replaces the tool result the
// model sees. The host contract is covered by isolated adapter fixtures.
// Fail closed: if agent-guard itself cannot run, before throws and after
// replaces the output.

import { spawn } from "node:child_process";

export const AgentGuard = async ({ directory }) => {
	const run = (payload) =>
		new Promise((resolve, reject) => {
			// Resolve HOME for each call because OpenCode may initialize plugins before
			// its final process environment is available.
			const bin = `${process.env.HOME}/.config/agent-guard/run.sh`;
			// OpenCode CLI uses Bun, while Desktop loads plugins in Electron's Node
			// runtime where the Bun global does not exist.
			const proc = spawn(bin, ["--tool", "opencode"], {
				env: process.env,
				stdio: ["pipe", "ignore", "pipe"],
			});
			let stderr = "";
			proc.stderr.setEncoding("utf8");
			proc.stderr.on("data", (chunk) => (stderr += chunk));
			proc.on("error", reject);
			proc.on("close", (code) =>
				// A signal exit has no numeric code and must not read as an allow.
				resolve({ code: code ?? 1, message: stderr.trim() }),
			);
			// The exit code decides. A launcher that exits before draining stdin can
			// produce EPIPE here, which is not itself a guard failure.
			proc.stdin.on("error", () => {});
			proc.stdin.end(JSON.stringify(payload));
		});

	return {
		"tool.execute.before": async (input, output) => {
			let result;
			try {
				result = await run({
					hook_event_name: "PreToolUse",
					tool_name: input.tool,
					tool_input: output.args,
					cwd: directory,
				});
			} catch (error) {
				throw new Error(`agent-guard: fail closed: ${error}`);
			}
			if (result.code !== 0) {
				throw new Error(result.message || "agent-guard: blocked");
			}
		},
		"tool.execute.after": async (input, output) => {
			let result;
			try {
				result = await run({
					hook_event_name: "PostToolUse",
					tool_name: input.tool,
					tool_input: input.args,
					tool_response: { output: output.output, title: output.title },
				});
			} catch (error) {
				output.output = `[agent-guard: fail closed: ${error}]`;
				return;
			}
			if (result.code !== 0) {
				output.output = result.message || "[agent-guard: tool output blocked]";
			}
		},
	};
};
