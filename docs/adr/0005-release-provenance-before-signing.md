# Correct release identity before enabling keyless artifact signing

Status: accepted for current forward execution

Date: 2026-07-11

## Context

FWD-004 found that the public `v1.0.0` source tag points to a source tree whose package and manifest identify `0.1.0`, while the separate GitHub release tarball identifies `1.0.0` but omits the lockfile required by its documented `npm ci` smoke path. The uploaded assets have GitHub-provided SHA-256 digests, but the source, tag, manifest, and runnable package do not form one reproducible identity chain.

Signing the current assets would authenticate a broken release relationship rather than repair it.

## Decision

1. Defer artifact signing until FWD-004 remediation produces one exact source commit, version tag, manifest, SBOM, npm tarball, and Docker build identity that passes two clean installs.
2. Preserve the current GitHub asset SHA-256 digests as temporary integrity checks; do not describe them as signatures or provenance.
3. After remediation, implement keyless Sigstore/cosign signing in the protected release workflow for:
   - npm tarball;
   - release manifest;
   - SBOM;
   - published Docker image when a registry image is distributed.
4. Bind keyless signing to the protected GitHub release environment and tag workflow, not to a maintainer workstation.
5. Publish verification instructions and test both a valid artifact and a tampered-artifact rejection.

## Threats addressed

- release asset replacement;
- tag/source/package mismatch;
- compromised maintainer workstation key;
- untraceable Docker image provenance;
- stale or cross-version manifest reuse.

## Temporary controls

- GitHub asset digest verification;
- release manifest SHA-256 verification;
- public release and stage identifiers;
- no living Pilot #1 acceptance until FWD-004 passes;
- no claim that the current assets are signed.

## Trigger and deadline

- Trigger: approval and completion of the public-artifact remediation.
- Signing implementation deadline: before Pilot #1 acceptance or any corrected public release is offered to a living partner.
- Decision review date: 2026-07-18, or immediately when the release owner chooses retag versus corrective release.

## Ownership

- Accountable: Release owner.
- Security approver: Security owner.
- External mutation approval: Founder/Product.

## Consequences

- FWD-005 has a clear time-bounded deferral and implementation path.
- FWD-004 remains the hard prerequisite for living-pilot acceptance.
- Release correction must not silently rewrite public history without an explicit owner decision.

## Implementation follow-up (2026-07-11)

After FWD-004 remediation passed two clean public installs:

1. Digest verifier shipped: `actantosd/scripts/verify-release-artifacts.mjs` (+ unit test).
2. Operator docs: `actantosd/docs/artifact-verification.md`.
3. Keyless cosign workflow added for the public release repository:
   `.github/workflows/sign-release-assets.yml` (OIDC, sign-blob bundles for tarball/manifest/SBOM).
4. Temporary digest control remains valid until `.sigstore` bundles are attached to the GitHub Release via workflow run.

