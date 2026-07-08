# Security Review Checklist

Review date: `2026-07-07`

This checklist is the Milestone 5 release gate for `v0.6.0-security-beta`.

## Release gate

- [x] Threat model exists and is current: [`docs/threat-model.md`](./threat-model.md)
- [x] Fail-closed tests cover dependency and verification failures
- [x] Decision-token abuse cases are covered for server and Docker execution paths
- [x] Approval replay after decision is rejected
- [x] SSRF tests cover private IPv4, metadata, link-local, and private IPv6 targets
- [x] Audit-chain tamper detection is implemented and tested
- [x] Preview redaction covers env secrets, GitHub tokens, bearer tokens, AWS access-key IDs, and PEM private keys
- [x] Docker sandbox flags are tested for non-root, read-only, capability drop, no-new-privileges, memory, CPU, PID, and network controls
- [x] `npm audit --omit=dev` reports `0` known production vulnerabilities
- [x] CycloneDX SBOM generated: [`docs/security-sbom.cdx.json`](./security-sbom.cdx.json)
- [x] Full validation passes: `npm test`, `npm run build`, `npm run policy:regression`

## Known residual risks

- [ ] Seccomp profile enforcement is not wired yet
- [ ] AppArmor profile enforcement is not wired yet
- [ ] DNS rebinding defenses are still policy and hostname based, not resolver-attested
- [ ] Secret redaction remains pattern based and should not be treated as a substitute for least-privilege output design

## Milestone 5 disposition

No open P0 or P1 issues were identified by the current test suite, dependency audit, or the implemented milestone checks above. The next production slice should start at `M6-01 Pilot onboarding guide`.
