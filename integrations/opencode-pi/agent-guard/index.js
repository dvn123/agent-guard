// Pi wiring for Agent Guard, loaded from ~/.pi/agent/extensions/agent-guard/
// index.js. server.js beside it is the OpenCode plugin, which Pi ignores.
//
// A tool_call handler blocks by returning { block, reason }, and a tool_result
// handler replaces what the model reads by returning new content. Replacing
// content also drops the structured content, so the original cannot survive
// there. Error results are screened too: a failed command's output can carry
// a secret.

import { createGuard, resultText } from "./guard.js";

const guard = createGuard("pi");

export default function agentGuard(pi) {
  pi.on("tool_call", async (event, ctx) => {
    const reason = await guard.blockReason({ toolName: event.toolName, input: event.input, cwd: ctx?.cwd });
    if (reason !== undefined) return { block: true, reason };
  });

  pi.on("tool_result", async (event) => {
    const replacement = await guard.outputReplacement({
      toolName: event.toolName,
      input: event.input,
      output: resultText(event.content, event.structuredContent),
    });
    if (replacement !== undefined) return { content: [{ type: "text", text: replacement }] };
  });
}
