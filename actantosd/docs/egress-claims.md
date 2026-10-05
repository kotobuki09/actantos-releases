# Egress claim integrity (A-05)

## What is enforced today (Mode A)

| Control | Classification | Evidence |
|---|---|---|
| Docker `network_mode=none` | Runtime sandbox enforced | `docker-executor.ts` passes `--network none` |
| Docker `network_mode=egress_proxy` | Runtime sandbox network **selection** only | Creates/uses bridge network `actantos_egress` — **not** a policy proxy |
| URL / SSRF application guard | Application-level checks | `url-target-guard.ts` blocks localhost, RFC1918, link-local, cloud metadata hostnames on tool URLs |
| Authenticated connect-time destination proxy | **Conditional / Mode B PQ-03** | Not implemented as production claim |

## Naming

The wire/API value `egress_proxy` is a **legacy identifier** for “use the ActantOS egress Docker network”. It must **not** be marketed as:

- an HTTP/HTTPS intercepting proxy
- DNS-aware authenticated allowlisting
- redirect-safe connect-time enforcement

Prefer human language: **“sandbox egress network mode”** or **“Docker network selection”**.

## Claim levels (truth source)

Update `release-maturity-truth.json` claim `egress-destination-enforcement` remains `unsupported` until PQ-03.

## Claim-Regression Search Gate

To ensure overstated egress proxy claims do not regress into marketing or documentation, run the following search gate before major releases:

```bash
git grep -i "proxy" actantosd/README.md actantosd/docs/
```

Fail the gate if any result equates `network_mode=egress_proxy` to a destination-enforcing HTTP/HTTPS proxy.
