# Pilot Go/No-Go Review

Review date: `2026-07-07`

## Product readiness

- [x] Self-host setup documented
- [x] Fresh install smoke path exists
- [x] Demo expresses the pilot acceptance scenario
- [x] Policy templates are included
- [x] Usage metrics are visible through product surfaces
- [x] Incident evidence can be exported
- [x] Support runbook exists
- [x] Release notes exist

## Security readiness

- [x] Milestone 5 checklist completed
- [x] Webhook delivery signs outbound payloads
- [x] Operator metrics do not bypass API-key protection
- [x] Evidence export remains operator mediated

## Residual risks

- [ ] Seccomp/AppArmor enforcement still pending
- [ ] Automatic webhook subscriptions not implemented
- [ ] Partner-specific identity/auth integration still out of scope

## Recommendation

`Go` for a controlled design-partner pilot, with the residual risks above called out explicitly during onboarding.
