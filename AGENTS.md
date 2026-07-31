# Agent Guard agent instructions

Agent Guard tests and tooling must use throwaway home directories and staged
artifacts. Do not inspect or mutate live Agent Guard state under
`~/.config/agent-guard`.

Do not run `scripts/guard-repair`, `scripts/guard-disable`, or
`scripts/guard-allow`. Those are human-only recovery and policy primitives.

Do not configure or invoke a hook binary directly. Black-box hook invocations
must pass through a copied `integrations/launcher/run.sh`.

Treat host configuration as externally owned. Provide or update reusable
snippets and installer primitives, but do not add code that overwrites or
merges generated Claude, Codex, Cursor, or OpenCode configuration.

Runtime behavior must remain offline and built from the vendored dependency
tree. Recognized guarded events fail closed. Preserve native host protocol
differences and verify any post-output redaction with a clean re-scan.
