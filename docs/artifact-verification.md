# Artifact verification (v1.0.0 Quiet Open-Core)

## What users can authenticate today

| Artifact | Integrity method | Provenance / signature |
| --- | --- | --- |
| Git tag `v1.0.0` | Git object identity | Tag points at release-repo commit |
| `actantosd-1.0.0.tgz` | SHA-256 in `release-manifest.json` + GitHub asset digest | Keyless Sigstore/cosign when release workflow has produced a bundle |
| `release-manifest.json` | GitHub asset digest | Signed as a blob when workflow runs |
| `security-sbom.cdx.json` | GitHub asset digest | Signed as a blob when workflow runs |
| Docker image | Not published to a public registry by default | Sign when/if a registry image is distributed |

Temporary control (pre-signature or offline): **manifest SHA-256 comparison**. Do not call digests “signatures.”

## Download

```bash
gh release download v1.0.0 --repo kotobuki09/actantos-releases \
  --pattern "actantosd-1.0.0.tgz" \
  --pattern "release-manifest.json" \
  --pattern "security-sbom.cdx.json" \
  --pattern "*.bundle" \
  --pattern "*.sig"
```

Or use the GitHub UI for [v1.0.0](https://github.com/kotobuki09/actantos-releases/releases/tag/v1.0.0).

## Digest verification (required)

From the download directory:

```bash
node path/to/actantosd/scripts/verify-release-artifacts.mjs --dir .
```

Expected output includes `VERIFY_PASS` and matching tarball SHA-256.

The same script rejects a tampered tarball (hash mismatch).

## Keyless signature verification (when bundles exist)

Requires [cosign](https://docs.sigstore.dev/cosign/system_config/installation/).

```bash
cosign verify-blob \
  --bundle actantosd-1.0.0.tgz.sigstore \
  --certificate-identity-regexp \
    'https://github.com/kotobuki09/actantos-releases/.github/workflows/sign-release-assets.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  actantosd-1.0.0.tgz
```

Or:

```bash
node path/to/actantosd/scripts/verify-release-artifacts.mjs --dir . --require-cosign
```

Signatures are produced by the GitHub Actions release workflow using **keyless OIDC** identity for `github.com/kotobuki09/actantos-releases`, not a long-lived maintainer private key.

## Identity checklist

1. Tag `v1.0.0` dereferences to the published source commit.
2. `actantosd/package.json` version is `1.0.0`.
3. `release-manifest.json` has `release_version: "v1.0.0"` and `stage: "quiet-open-core"`.
4. Tarball SHA-256 matches `manifest.npm_package.sha256`.
5. Optional: cosign bundle verifies for the same tarball bytes.

## Residual risk

Until a cosign bundle is attached to the release, authenticity rests on GitHub account/repo controls plus digests. Pilot partners should pin the tag commit and record the verified SHA-256.
