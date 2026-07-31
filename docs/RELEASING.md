# Releasing

No release command should run without explicit maintainer authorization. The
repository scaffolds draft, provenance-aware releases but does not create a
remote, tag, or publication by itself.

## Publication gate

The source material did not contain a repository license. This migration does
not invent a legal grant. Before any public release, the maintainer must choose
and add the intended license, generate appropriate third-party notices from the
vendored dependency licenses, and include both in the release archive.

## Locked inputs

- Module path: `github.com/dvn123/agent-guard`
- Go language version: 1.26
- Go toolchain: 1.26.5
- Vulnerability scanner: `govulncheck` 1.6.0 as a vendored Go tool
- Dependencies: exact versions in `go.mod` and `go.sum`
- Build dependency tree: checked-in `vendor/`
- OpenCode Desktop test runtime: Node 26.5.1
- OpenCode test runtime: Bun 1.3.14
- GoReleaser: 2.17.1
- Local tool artifacts: checksummed for all supported platforms in `mise.lock`;
  GoReleaser entries additionally require GitHub artifact provenance
- GitHub Actions: pinned to full commit SHAs with version comments

Go builds use `GOTOOLCHAIN=local`, `CGO_ENABLED=0`, `-mod=vendor`, and
`-trimpath`. Release archives cover only macOS ARM64, Linux AMD64, and Linux
ARM64.

## Pre-release verification

Run from a clean checkout:

```sh
GOTOOLCHAIN=local go mod verify
GOTOOLCHAIN=local go test -mod=vendor -count=1 ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go tool govulncheck ./...
scripts/test-integrations.sh
scripts/build-all.sh ./dist/builds
mise x goreleaser@2.17.1 -- goreleaser check
```

`scripts/test-integrations.sh` requires Node 26.5.1 and Bun 1.3.14 for the
OpenCode adapter.
The Mise invocation enforces the locked GoReleaser URL, checksum, and available
artifact provenance. Review `git status`, the complete diff, module and tool
locks, vendored changes, workflow action pins, and generated archive contents
before authorizing a tag.

## Draft release workflow

A `v*` tag in `dvn123/agent-guard` starts
`.github/workflows/release.yml`. The workflow reruns all vendored and isolated
integration tests, builds wrapped tar archives, creates `checksums.txt`, opens
a draft GitHub release, and uses GitHub's OIDC-backed artifact attestation for
every checksummed archive.

Draft status is deliberate. A maintainer must inspect checks, archives,
checksums, and attestations before publishing. Never move an existing release
tag or force-push release history.

## Artifact verification

After downloading an archive and `checksums.txt` from the same release:

```sh
sha256sum -c checksums.txt --ignore-missing
gh attestation verify agent-guard_VERSION_OS_ARCH.tar.gz \
  --repo dvn123/agent-guard \
  --signer-workflow dvn123/agent-guard/.github/workflows/release.yml
```

On macOS, use `shasum -a 256` to compare the archive against its line in
`checksums.txt`. The attestation command constrains both the repository and the
workflow identity rather than checking only that some GitHub workflow produced
the artifact.

## Dependency updates

Treat source review, artifact publisher, build process, dependency locking, and
artifact provenance as separate checks. For an intentional dependency update:

1. verify the canonical module and current stable version;
2. inspect upstream release notes, source changes, build/release identity, and
   unresolved security reports;
3. update `go.mod` and `go.sum`, then regenerate `vendor/`;
4. review the lock and vendored diff, especially embedded Betterleaks rules;
5. rerun scanner recall, redaction, fixture, black-box, adapter, and cross-build
   verification.

Do not download dependencies at runtime or replace the vendored build with an
unlocked source fetch.
