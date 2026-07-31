# Security policy

## Reporting

Report a suspected secret-scanning bypass, unsafe post-output behavior,
launcher fail-open condition, or supply-chain compromise through GitHub private
vulnerability reporting:

<https://github.com/dvn123/agent-guard/security/advisories/new>

If private reporting is unavailable, open a minimal issue requesting a private
contact path. Do not include a real credential, private repository content,
allowlist state, or exploit payload that could expose a secret.

False positives, documentation errors, and compatibility bugs that contain no
sensitive data may use the public issue tracker.

## Report contents

Provide the affected version and host, operating system and architecture,
guarded event type, observed protocol result, and the smallest synthetic
reproduction. Use an obviously fake test value or construct it at runtime.
State whether the host called the stable launcher.

Do not test against another person's account or data. Revoke and rotate any
real credential that may have been exposed before preparing a report.

## Supported versions

Until the first release, only the current `main` source is maintained. After
releases begin, security fixes target the latest release and `main`; older
versions may require upgrading.

## Security boundary

The enforceable guarantees and trusted components are defined in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Known host limitations and the
dense-match denial-of-service condition are public in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). A result already documented there
is still reportable when behavior is worse than stated.
