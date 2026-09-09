import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
	chmodSync,
	copyFileSync,
	mkdirSync,
	mkdtempSync,
	renameSync,
	rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import AgentGuard from "./agent-guard.js";

const here = dirname(fileURLToPath(import.meta.url));
const launcherSource = join(here, "..", "launcher", "run.sh");
const originalHome = process.env.HOME;

let isolatedHome;
let plugin;
let v2;

before(async () => {
	const binary = process.env.AGENT_GUARD_TEST_BINARY;
	if (!binary) {
		throw new Error(
			"AGENT_GUARD_TEST_BINARY must name a source-built candidate",
		);
	}
	isolatedHome = makeHome(binary);
	process.env.HOME = isolatedHome;
	plugin = await AgentGuard.server({ directory: isolatedHome });
	v2 = await setupV2({ directory: isolatedHome });
});

// Minimal stand-in for the OpenCode 2 plugin context, capturing the hooks the
// plugin registers so they can be driven with real host event shapes.
async function setupV2({ directory }) {
	const hooks = {};
	await AgentGuard.setup({
		location: { directory },
		tool: {
			hook: (name, callback) => {
				hooks[name] = callback;
				return Promise.resolve({ dispose: () => Promise.resolve() });
			},
		},
	});
	return hooks;
}

after(() => {
	if (originalHome === undefined) {
		delete process.env.HOME;
	} else {
		process.env.HOME = originalHome;
	}
	if (isolatedHome) rmSync(isolatedHome, { recursive: true, force: true });
});

describe("OpenCode adapter host contract", () => {
	test("allows clean input through the stable launcher", async () => {
		assert.equal(
			await plugin["tool.execute.before"](
				{ tool: "bash" },
				{ args: { command: "printf hello" } },
			),
			undefined,
		);
	});

	test("throws before execution when the scanner detects a secret", async () => {
		await assert.rejects(
			plugin["tool.execute.before"](
				{ tool: "bash" },
				{ args: { command: `printf %s ${syntheticSecret()}` } },
			),
			/stripe-access-token/,
		);
	});

	test("replaces post-call output with verified redaction", async () => {
		const output = {
			output: `build ok\ntoken: ${syntheticSecret()}\ndone`,
			title: "build",
		};
		await plugin["tool.execute.after"](
			{ tool: "bash", args: { command: "build" } },
			output,
		);
		assert.match(output.output, /build ok/);
		assert.match(output.output, /\[REDACTED:/);
		assert.doesNotMatch(output.output, new RegExp(syntheticSecret()));
	});

	test("fails closed when the isolated binary is missing", async () => {
		const binary = join(isolatedHome, ".local", "bin", "agent-guard");
		const heldBinary = `${binary}.held`;
		renameSync(binary, heldBinary);
		try {
			const direct = await runProcess(
				join(isolatedHome, ".config", "agent-guard", "run.sh"),
				["--tool", "opencode"],
				{
					hook_event_name: "PreToolUse",
					tool_input: { command: "printf hello" },
				},
			);
			assert.equal(direct.code, 2);
			assert.match(direct.stderr, /is missing/);

			await assert.rejects(
				plugin["tool.execute.before"](
					{ tool: "bash" },
					{ args: { command: "printf hello" } },
				),
				/fail closed/,
			);

			const output = { output: "original", title: "test" };
			await plugin["tool.execute.after"](
				{ tool: "bash", args: { command: "test" } },
				output,
			);
			assert.match(output.output, /fail closed/);
			assert.notEqual(output.output, "original");
		} finally {
			renameSync(heldBinary, binary);
		}
	});

	test("no-ops under a V1 context that has no tool domain", async () => {
		// V1 invokes setup() too. It must not throw, and must register nothing.
		assert.equal(
			await AgentGuard.setup({
				agent: {},
				catalog: {},
				options: {},
			}),
			undefined,
		);
	});

	test("fails closed when the isolated launcher cannot spawn", async () => {
		const launcher = join(isolatedHome, ".config", "agent-guard", "run.sh");
		const heldLauncher = `${launcher}.held`;
		renameSync(launcher, heldLauncher);
		try {
			await assert.rejects(
				plugin["tool.execute.before"](
					{ tool: "bash" },
					{ args: { command: "printf hello" } },
				),
				/fail closed.*ENOENT/,
			);

			const output = { output: "original", title: "test" };
			await plugin["tool.execute.after"](
				{ tool: "bash", args: { command: "test" } },
				output,
			);
			assert.match(output.output, /fail closed.*ENOENT/);
			assert.notEqual(output.output, "original");
		} finally {
			renameSync(heldLauncher, launcher);
		}
	});
});

describe("OpenCode 2 adapter host contract", () => {
	test("allows clean input through the stable launcher", async () => {
		assert.equal(
			await v2["execute.before"]({
				tool: "shell",
				input: { command: "printf hello" },
			}),
			undefined,
		);
	});

	test("throws before execution when the scanner detects a secret", async () => {
		await assert.rejects(
			v2["execute.before"]({
				tool: "shell",
				input: { command: `printf %s ${syntheticSecret()}` },
			}),
			/stripe-access-token/,
		);
	});

	test("replaces post-call result with verified redaction", async () => {
		const event = {
			tool: "shell",
			input: { command: "build" },
			status: "completed",
			result: {
				output: { exit: 0, output: `token: ${syntheticSecret()}` },
				content: [
					{ type: "text", text: `build ok\ntoken: ${syntheticSecret()}\ndone` },
				],
			},
		};
		await v2["execute.after"](event);
		const text = event.result.content.map((part) => part.text).join("\n");
		assert.match(text, /\[REDACTED:/);
		assert.doesNotMatch(text, new RegExp(syntheticSecret()));
		// The typed value must not retain the original text either.
		assert.doesNotMatch(
			JSON.stringify(event.result.output),
			new RegExp(syntheticSecret()),
		);
	});

	test("leaves a clean post-call result untouched", async () => {
		const result = {
			output: { exit: 0, output: "build ok" },
			content: [{ type: "text", text: "build ok" }],
		};
		const event = {
			tool: "shell",
			input: { command: "build" },
			status: "completed",
			result,
		};
		await v2["execute.after"](event);
		assert.equal(event.result, result);
	});

	test("ignores a failed call, which produced no output to screen", async () => {
		const event = {
			tool: "shell",
			input: { command: "build" },
			status: "error",
			error: { message: syntheticSecret() },
		};
		assert.equal(await v2["execute.after"](event), undefined);
	});
});

function runProcess(command, args, payload) {
	return new Promise((resolve, reject) => {
		const proc = spawn(command, args, {
			env: process.env,
			stdio: ["pipe", "ignore", "pipe"],
		});
		let stderr = "";
		proc.stderr.setEncoding("utf8");
		proc.stderr.on("data", (chunk) => (stderr += chunk));
		proc.on("error", reject);
		proc.on("close", (code) => resolve({ code: code ?? 1, stderr }));
		proc.stdin.on("error", () => {});
		proc.stdin.end(JSON.stringify(payload));
	});
}

function makeHome(binary) {
	const home = mkdtempSync(join(tmpdir(), "agent-guard-opencode-"));
	const configDir = join(home, ".config", "agent-guard");
	const binDir = join(home, ".local", "bin");
	mkdirSync(configDir, { recursive: true });
	mkdirSync(binDir, { recursive: true });
	copyFileSync(launcherSource, join(configDir, "run.sh"));
	chmodSync(join(configDir, "run.sh"), 0o755);
	if (binary) {
		copyFileSync(binary, join(binDir, "agent-guard"));
		chmodSync(join(binDir, "agent-guard"), 0o755);
	}
	return home;
}

function syntheticSecret() {
	return "sk_" + "live_" + "4eC39HqLyj" + "WDarjtT1zdp7dc";
}
