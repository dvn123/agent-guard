# Limitations

## Dense-match denial of service

The authenticated-URL rule has no keyword prefilter because credentials in a
URL have no reliable fixed literal. Betterleaks builds a surrounding context
window for every match before applying the rule filter, so its cost is
quadratic in match count rather than proportional only to input bytes.

Measurements taken on 2026-07-25 found ordinary output at tens of milliseconds
even at 4 MB and approximately 275 ms for 512 KB of verbose package-manager
output containing an authenticated URL every other line. A maximally dense
corpus with one URL-shaped match per 18 bytes crossed the three-second context
deadline near 290 KB and took approximately nine seconds at 512 KB.

The deadline is cooperative, not a hard wall. Betterleaks can continue work
until its next cancellation check. When scanning returns, Agent Guard sees the
expired context and denies the event, but the intervening CPU and latency remain
a denial-of-service vector. A host may abandon a post hook before Agent Guard
returns and expose the original tool output. Do not describe this case as
"blocks, never leaks."

Bounding input would provide a hard Agent Guard work limit but create an
unscanned suffix or force unconditional denial of large benign output. The
project currently preserves full-input recall and documents the resulting
availability and host-contract risk.

## Host protocols

- Claude Code pre hooks deny with exit 2. Post hooks must exit 0 with
  `updatedToolOutput`; exit 2 alone leaves the original output visible.
  Structured built-in output must retain its original shape or Claude ignores
  the replacement. Agent Guard patches only detected spans in the original
  response clone and tests current Bash plus completed and background Agent
  response shapes, including scanner-failure fallbacks. A future incompatible
  host schema can still invalidate that contract.
- Codex pre hooks deny with exit 2 and stderr. Codex post hooks use stderr as
  the replacement result on exit 2. The included TOML matches the Codex hook
  manual checked on 2026-07-27 and must be revalidated when that contract
  changes.
- Cursor pre hooks can return explicit allow or deny JSON. Cursor
  `afterShellExecution` is observational, so Agent Guard can warn but cannot
  retract output already delivered to the model.
- The shipped Cursor snippet guards `beforeShellExecution` and
  `beforeReadFile`; it does not register generic `preToolUse` or
  `beforeMCPExecution`. MCP calls and other Cursor tools are therefore outside
  Agent Guard's boundary.
- Cursor has an acknowledged `beforeReadFile` bypass when the target file is
  already open in the editor: the renderer reads its in-memory buffer without
  reaching the hook layer. Use `.cursorignore` and Cursor permissions as the
  complementary sensitive-file boundary. See the
  [upstream acknowledgement](https://forum.cursor.com/t/beforefileread-hook-not-invoked-if-file-is-open/161031).
- Cursor has an acknowledged race in which a fast-exiting command hook's
  stdout can be partially or completely dropped, including a pre-tool deny.
  Concurrent shell calls widen the window. A short exit delay is only a
  mitigation, not a hard guarantee, so Cursor's built-in command controls must
  remain the primary hard-enforcement layer until the host fixes the race. See
  the [upstream acknowledgement](https://forum.cursor.com/t/race-condition-silently-disables-hooks-that-exit-quickly/165818/7).
- OpenCode uses a JavaScript adapter under Bun in the CLI and Electron's Node
  runtime in Desktop. Pre failures throw; post failures mutate `output.output`.
  A breaking plugin API change can invalidate that boundary.

Unknown event names intentionally pass through without initializing the
scanner. This preserves compatibility but means newly introduced host events
are unguarded until added and tested.

## Detection

Secret detection is heuristic. False positives and false negatives remain
possible. The local authenticated-URL rule ignores low-entropy and placeholder
values, which improves precision but cannot identify every credential.

Hash allowlisting is exact-value based. It suppresses a value everywhere and
therefore weakens future protection for that value until the hash is removed.
The hash is non-reversible in normal use but still represents sensitive policy
state.

## Operational recovery

The disable sentinel intentionally bypasses guarded hooks for at most eight
hours. It does not bypass `doctor`. Recovery and allowlisting scripts are
human-only primitives and must not be invoked by coding agents or automation.

The stable launcher protects against a missing or crashing binary only when the
host actually calls the launcher. Direct host configuration of
`~/.local/bin/agent-guard` removes this protection and is unsupported.
