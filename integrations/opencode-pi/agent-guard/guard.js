// The launcher bridge shared by the OpenCode plugin (server.js) and the Pi
// extension (index.js). Both hosts run JavaScript plugins in-process, so both
// speak the same subprocess contract: a Claude-shaped payload on stdin, and a
// non-zero exit with the reason (pre-call) or the replacement (post-call) on
// stderr. Fail closed: if agent-guard itself cannot run, the call is blocked
// and the output replaced.

import { spawn } from "node:child_process";

export function createGuard(tool) {
  // Resolve HOME for each call because a host may initialize plugins before
  // its final process environment is available.
  const run = (payload) =>
    new Promise((resolve, reject) => {
      const bin = `${process.env.HOME}/.config/agent-guard/run.sh`;
      // OpenCode Desktop loads plugins in Electron's Node runtime, where the
      // Bun global does not exist, so spawn through node:child_process.
      const proc = spawn(bin, ["--tool", tool], {
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
    // Resolves to a reason when the call must not run, undefined otherwise.
    async blockReason({ toolName, input, cwd }) {
      let result;
      try {
        result = await run({
          hook_event_name: "PreToolUse",
          tool_name: toolName,
          tool_input: input,
          cwd,
        });
      } catch (error) {
        return `agent-guard: fail closed: ${error}`;
      }
      return result.code === 0 ? undefined : result.message || "agent-guard: blocked";
    },

    // Resolves to replacement text when the output must not reach the model,
    // undefined when it may pass through unchanged.
    async outputReplacement({ toolName, input, output }) {
      let result;
      try {
        result = await run({
          hook_event_name: "PostToolUse",
          tool_name: toolName,
          tool_input: input,
          tool_response: { output, title: toolName },
        });
      } catch (error) {
        return `[agent-guard: fail closed: ${error}]`;
      }
      return result.code === 0 ? undefined : result.message || "[agent-guard: tool output blocked]";
    },
  };
}

// Both hosts return the text the model reads as content parts, beside a
// structured value. Scan both, because a secret in either one has already
// left the sandbox.
export const resultText = (content, structured) =>
  [
    ...(content ?? []).filter((part) => part?.type === "text").map((part) => part.text),
    typeof structured === "string" ? structured : structured === undefined ? "" : JSON.stringify(structured),
  ]
    .filter(Boolean)
    .join("\n");
