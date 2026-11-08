import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import piExtension from "./agent-guard/index.js";
import openCodePlugin from "./agent-guard/server.js";

const here = dirname(fileURLToPath(import.meta.url));
const launcherSource = join(here, "..", "launcher", "run.sh");
const originalHome = process.env.HOME;

let isolatedHome;
let openCode;
let pi;

before(async () => {
  const binary = process.env.AGENT_GUARD_TEST_BINARY;
  if (!binary) {
    throw new Error("AGENT_GUARD_TEST_BINARY must name a source-built candidate");
  }
  isolatedHome = makeHome(binary);
  process.env.HOME = isolatedHome;
  openCode = await setupOpenCode({ directory: isolatedHome });
  pi = setupPi();
});

after(() => {
  if (originalHome === undefined) {
    delete process.env.HOME;
  } else {
    process.env.HOME = originalHome;
  }
  if (isolatedHome) rmSync(isolatedHome, { recursive: true, force: true });
});

// Minimal stand-in for the OpenCode 2 plugin context, capturing the hooks the
// plugin registers so they can be driven with real host event shapes.
async function setupOpenCode({ directory }) {
  const hooks = {};
  await openCodePlugin.setup({
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

// Minimal stand-in for Pi's ExtensionAPI, capturing the event handlers.
function setupPi() {
  const handlers = {};
  piExtension({ on: (name, handler) => (handlers[name] = handler) });
  return handlers;
}

describe("OpenCode adapter host contract", () => {
  test("allows clean input through the stable launcher", async () => {
    assert.equal(await openCode["execute.before"]({ tool: "shell", input: { command: "printf hello" } }), undefined);
  });

  test("throws before execution when the scanner detects a secret", async () => {
    await assert.rejects(
      openCode["execute.before"]({ tool: "shell", input: { command: `printf %s ${syntheticSecret()}` } }),
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
        content: [{ type: "text", text: `build ok\ntoken: ${syntheticSecret()}\ndone` }],
      },
    };
    await openCode["execute.after"](event);
    const text = event.result.content.map((part) => part.text).join("\n");
    assert.match(text, /build ok/);
    assert.match(text, /\[REDACTED:/);
    assert.doesNotMatch(text, new RegExp(syntheticSecret()));
    // The typed value must not retain the original text either.
    assert.doesNotMatch(JSON.stringify(event.result.output), new RegExp(syntheticSecret()));
  });

  test("leaves a clean post-call result untouched", async () => {
    const result = {
      output: { exit: 0, output: "build ok" },
      content: [{ type: "text", text: "build ok" }],
    };
    const event = { tool: "shell", input: { command: "build" }, status: "completed", result };
    await openCode["execute.after"](event);
    assert.equal(event.result, result);
  });

  test("ignores a failed call, which produced no output to screen", async () => {
    const event = {
      tool: "shell",
      input: { command: "build" },
      status: "error",
      error: { message: syntheticSecret() },
    };
    assert.equal(await openCode["execute.after"](event), undefined);
  });
});

describe("Pi adapter host contract", () => {
  test("allows clean input through the stable launcher", async () => {
    assert.equal(
      await pi.tool_call({ toolName: "bash", input: { command: "printf hello" } }, { cwd: isolatedHome }),
      undefined,
    );
  });

  test("blocks before execution when the scanner detects a secret", async () => {
    const decision = await pi.tool_call(
      { toolName: "bash", input: { command: `printf %s ${syntheticSecret()}` } },
      { cwd: isolatedHome },
    );
    assert.equal(decision.block, true);
    assert.match(decision.reason, /stripe-access-token/);
  });

  test("replaces a result with verified redaction, error results included", async () => {
    const patch = await pi.tool_result({
      toolName: "bash",
      input: { command: "build" },
      content: [{ type: "text", text: `build ok\ntoken: ${syntheticSecret()}\ndone` }],
      structuredContent: { output: syntheticSecret() },
      isError: true,
    });
    const text = patch.content.map((part) => part.text).join("\n");
    assert.match(text, /build ok/);
    assert.match(text, /\[REDACTED:/);
    assert.doesNotMatch(text, new RegExp(syntheticSecret()));
  });

  test("leaves a clean result untouched", async () => {
    assert.equal(
      await pi.tool_result({
        toolName: "bash",
        input: { command: "build" },
        content: [{ type: "text", text: "build ok" }],
      }),
      undefined,
    );
  });
});

describe("shared bridge", () => {
  test("fails closed when the isolated binary is missing", async () => {
    const binary = join(isolatedHome, ".local", "bin", "agent-guard");
    const heldBinary = `${binary}.held`;
    renameSync(binary, heldBinary);
    try {
      const direct = await runProcess(join(isolatedHome, ".config", "agent-guard", "run.sh"), ["--tool", "pi"], {
        hook_event_name: "PreToolUse",
        tool_input: { command: "printf hello" },
      });
      assert.equal(direct.code, 2);
      assert.match(direct.stderr, /is missing/);
      await assertFailsClosed(/fail closed/);
    } finally {
      renameSync(heldBinary, binary);
    }
  });

  test("fails closed when the isolated launcher cannot spawn", async () => {
    const launcher = join(isolatedHome, ".config", "agent-guard", "run.sh");
    const heldLauncher = `${launcher}.held`;
    renameSync(launcher, heldLauncher);
    try {
      await assertFailsClosed(/fail closed.*ENOENT/);
    } finally {
      renameSync(heldLauncher, launcher);
    }
  });
});

async function assertFailsClosed(pattern) {
  const command = { command: "printf hello" };
  await assert.rejects(openCode["execute.before"]({ tool: "shell", input: command }), pattern);
  const event = {
    tool: "shell",
    input: command,
    status: "completed",
    result: { content: [{ type: "text", text: "original" }] },
  };
  await openCode["execute.after"](event);
  assert.match(event.result.content[0].text, pattern);

  const decision = await pi.tool_call({ toolName: "bash", input: command }, { cwd: isolatedHome });
  assert.equal(decision.block, true);
  assert.match(decision.reason, pattern);
  const patch = await pi.tool_result({
    toolName: "bash",
    input: command,
    content: [{ type: "text", text: "original" }],
  });
  assert.match(patch.content[0].text, pattern);
}

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
  const home = mkdtempSync(join(tmpdir(), "agent-guard-js-plugins-"));
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
