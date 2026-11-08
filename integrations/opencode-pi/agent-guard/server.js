// OpenCode wiring for Agent Guard, loaded from ~/.config/opencode/plugins/
// agent-guard/: OpenCode resolves a plugin directory's server entry to
// server.js before index.js, which is the Pi extension.
//
// A throw from the pre-call hook rejects that tool call, and its message
// becomes the tool result the model sees. OpenCode has no plugin path to the
// native ask prompt.

import { createGuard, resultText } from "./guard.js";

const guard = createGuard("opencode");

export default {
  id: "agent-guard",

  async setup(ctx) {
    const cwd = ctx.location?.directory;

    await ctx.tool.hook("execute.before", async (event) => {
      const reason = await guard.blockReason({ toolName: event.tool, input: event.input, cwd });
      if (reason !== undefined) throw new Error(reason);
    });

    await ctx.tool.hook("execute.after", async (event) => {
      // A failed call produced no output to screen.
      if (event.status !== "completed") return;
      const replacement = await guard.outputReplacement({
        toolName: event.tool,
        input: event.input,
        output: resultText(event.result?.content, event.result?.output),
      });
      if (replacement === undefined) return;
      // Replace the typed value as well as the visible parts so the original
      // text cannot survive in the tool's structured output.
      event.result = {
        ...event.result,
        output: replacement,
        content: [{ type: "text", text: replacement }],
      };
    });
  },
};
