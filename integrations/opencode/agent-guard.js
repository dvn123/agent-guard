// OpenCode wiring for Agent Guard. Loaded automatically from
// ~/.config/opencode/plugin/ (both runtimes glob {plugin,plugins}/*.{ts,js},
// and OpenCode 2 still admits a standalone file there).
//
// One default export serves both runtimes, which is required while `opencode`
// (V1) and `opencode2` (V2) are installed side by side:
//
//   V1 calls server() and uses the returned hook map.
//   V2 reads id + setup() and ignores the extra server key.
//
// V1 also invokes setup(), but with a partial context that has no tool domain,
// so setup() must detect that and no-op instead of throwing.
//
// Blocking differs per runtime but is verified in both: a throw from the
// pre-call hook rejects that tool call and the message becomes the tool result
// the model sees. Post-call, V1 replaces output.output while V2 replaces the
// content parts of event.result. OpenCode has no plugin path to the native ask
// prompt in either runtime. Fail closed: if agent-guard itself cannot run, the
// pre-call hook throws and the post-call hook replaces the output.

import { spawn } from "node:child_process";

// Resolve HOME for each call because OpenCode may initialize plugins before
// its final process environment is available.
const run = (payload) =>
	new Promise((resolve, reject) => {
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

// Throws to block. Shared by both runtimes so they cannot drift apart.
async function screenCall({ tool, input, cwd }) {
	let result;
	try {
		result = await run({
			hook_event_name: "PreToolUse",
			tool_name: tool,
			tool_input: input,
			cwd,
		});
	} catch (error) {
		throw new Error(`agent-guard: fail closed: ${error}`);
	}
	if (result.code !== 0) {
		throw new Error(result.message || "agent-guard: blocked");
	}
}

// Returns replacement text when the output must not reach the model, and
// undefined when it may pass through unchanged.
async function screenOutput({ tool, input, response }) {
	let result;
	try {
		result = await run({
			hook_event_name: "PostToolUse",
			tool_name: tool,
			tool_input: input,
			tool_response: response,
		});
	} catch (error) {
		return `[agent-guard: fail closed: ${error}]`;
	}
	if (result.code !== 0) {
		return result.message || "[agent-guard: tool output blocked]";
	}
	return undefined;
}

// V2 result payloads are typed per tool: content holds the parts the model
// reads, while output carries the tool's structured value. Scan both, because
// a secret in either one has already left the sandbox.
const resultText = (result) =>
	[
		...(result?.content ?? [])
			.filter((part) => part?.type === "text")
			.map((part) => part.text),
		typeof result?.output === "string"
			? result.output
			: result?.output === undefined
				? ""
				: JSON.stringify(result.output),
	]
		.filter(Boolean)
		.join("\n");

export default {
	id: "agent-guard",

	// OpenCode 2.
	async setup(ctx) {
		// V1 also calls setup(), passing a context without the tool domain.
		// Returning here leaves V1 to the server() hooks below.
		if (typeof ctx?.tool?.hook !== "function") return;

		const cwd = ctx.location?.directory;

		await ctx.tool.hook("execute.before", (event) =>
			screenCall({ tool: event.tool, input: event.input, cwd }),
		);

		await ctx.tool.hook("execute.after", async (event) => {
			if (event.status !== "completed") return;
			const replacement = await screenOutput({
				tool: event.tool,
				input: event.input,
				response: { output: resultText(event.result), title: event.tool },
			});
			if (replacement === undefined) return;
			// Replace the structured value as well as the visible parts so the
			// original text cannot survive in the tool's typed output.
			event.result = {
				...event.result,
				output: replacement,
				content: [{ type: "text", text: replacement }],
			};
		});
	},

	// OpenCode 1.
	async server({ directory }) {
		return {
			"tool.execute.before": (input, output) =>
				screenCall({ tool: input.tool, input: output.args, cwd: directory }),
			"tool.execute.after": async (input, output) => {
				const replacement = await screenOutput({
					tool: input.tool,
					input: input.args,
					response: { output: output.output, title: output.title },
				});
				if (replacement === undefined) return;
				output.output = replacement;
			},
		};
	},
};
