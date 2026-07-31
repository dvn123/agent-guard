# Threat model

## Assets

Agent Guard protects secret values that appear in coding-agent tool arguments,
tool input, or tool output before they reach an external process or return to
the model. Examples include provider tokens, private keys, connection strings,
and credentials embedded in URLs.

## Adversary and failure model

The boundary assumes tool payloads and model-produced text are untrusted. A
payload may be malformed, may forge scanner suppression comments, may trigger
an engine bug, or may attempt to exhaust scanning resources. The installed
binary may also be missing, crash, or return an exit code that a host normally
treats as non-blocking.

Agent Guard also treats accidental operational failures as security-relevant:
an unreadable allowlist, detector initialization failure, incomplete
redaction, and an expired scan context produce a fail-closed core decision.

## Guarantees

For a recognized pre-tool or post-tool event that reaches Agent Guard:

- Betterleaks is the sole secret-value authority. Its rules and dependencies
  are embedded or vendored, and runtime scanning is offline.
- Inline scanner-suppression comments are disabled.
- A readable allowlist can suppress only the exact SHA-256 hash of a detected
  value.
- Scanner errors and recovered panics become fail-closed core decisions,
  rendered as the strongest response the host contract supports.
- A partial post-output redaction is returned only after a clean verifying
  re-scan.
- The launcher converts missing binaries and unexpected hook exit codes into
  exit 2. Cursor pre hooks receive explicit deny JSON where required; Cursor
  post hooks can only warn.
- A candidate installation replaces the last-known-good binary only after an
  isolated launcher-mediated self-test succeeds.

## Trust boundaries

The user and local administrator remain trusted. They can change the binary,
launcher, integration configuration, hash allowlist, or disable sentinel. File
permissions reduce accidental modification but do not defend against an
attacker with the same account.

The coding-agent host is also part of the enforcement boundary. Agent Guard
can emit the documented protocol result; it cannot force a host to wait for a
hook, honor denial, or replace already-delivered output.

Release workflows, repository administration, GitHub Actions, the Go toolchain,
GoReleaser, and pinned dependencies form the build-time supply-chain boundary.
Checksums and GitHub artifact attestations provide artifact integrity and build
identity; they do not prove the source is vulnerability-free.

## Out of scope

Agent Guard does not:

- prevent a model from revealing a secret already present in its context;
- revoke or rotate a disclosed credential;
- sandbox tools, constrain filesystem access, or authorize commands;
- scan network traffic or arbitrary host UI content;
- protect unrecognized hook events, hosts without a blocking contract, or
  hooks that are not wired through the stable launcher;
- defend local state from the account owner or a same-user compromise;
- guarantee fixed runtime under adversarially dense matches.

Known host and resource-exhaustion consequences are detailed in
[Limitations](LIMITATIONS.md).
