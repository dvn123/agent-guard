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
import { AgentGuard } from "./agent-guard.js";

const here = dirname(fileURLToPath(import.meta.url));
const launcherSource = join(here, "..", "launcher", "run.sh");
const originalHome = process.env.HOME;

let isolatedHome;
let plugin;

before(async () => {
	const binary = process.env.AGENT_GUARD_TEST_BINARY;
	if (!binary) {
		throw new Error(
			"AGENT_GUARD_TEST_BINARY must name a source-built candidate",
		);
	}
	isolatedHome = makeHome(binary);
	process.env.HOME = isolatedHome;
	plugin = await AgentGuard({ directory: isolatedHome });
});

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
