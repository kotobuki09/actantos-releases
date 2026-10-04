# Open waivers — properties this repository does not verify

A waiver is not a place to record something that turned out to be untestable. It is a place to
record a gap that **was measured, cannot be closed on any host reachable from here, and would
change what the system claims if it were closed**.

Nothing in this file is signed. An unsigned waiver is an open item, not a concession, and the
substrate entries in `scripts/security-fabric-state.mjs` still read `NOT_IMPLEMENTED`.

---

## W-001 — Confidential computing (substrate `confidential-computing`)

**Status:** open, unsigned.
**Requested by:** implementation work on the v2 agent security fabric.
**Blocks:** nothing that currently runs. It blocks one sentence in the project's own scope.

### What is not claimed

That the policy bundle signing key or an active policy lease is unreadable by anything outside an
enclave — including the host kernel, the hypervisor, and an attacker with root on the host.

Every other substrate in this repository defends against a compromised *agent*. This is the only
one that would defend against a compromised *host*, and it is the only one with no code.

### Why it cannot be closed here

Measured on this machine with `cpuid`, not inferred from the product name:

| Capability | Where it is read | Value on this host | Meaning |
|---|---|---|---|
| Intel TDX | CPUID leaf 7 subleaf 0, ECX bit 20 | `0` (ECX = `0x00400784`) | not advertised |
| Intel TME | CPUID leaf 7 subleaf 0, ECX bit 5 | `0` | **absent** — TDX is built on TME |
| AMD SEV / SEV-SNP | CPUID leaf `0x8000001F` | leaf unsupported (max = `0x80000008`) | no AMD capability on this part |
| VT-x exposure | `Win32_Processor.VirtualizationFirmwareEnabled` | `False` | no virtualization presented to the OS |

The CPU is a 12th Gen Intel Core i7-12700K, family 6 model 151 stepping 2 (Raptor Lake). The TME
result matters more than the generation: TDX is not merely a generation too early, the substrate
feature it depends on is not implemented on this part at all. There is therefore no configuration,
no boot parameter and no hypervisor setting that would make it appear.

Separately verified, not assumed: there is no SEV, TDX or attestation code, test or configuration
anywhere in the tree. The only matches for those terms are this documentation and unrelated
`CONFIDENTIAL` `data_clearance` values in the security context envelope.

### Reproducing this

The table above was measured with a compiled CPUID program. That program is not checked in, so on
its own this file would ask an owner to accept a number nobody can re-run — which is the one thing
this repository's evidence standard exists to prevent. A portable pre-check is therefore checked
in so that the premise is falsifiable by anyone:

```
npm run confidential:probe
```

It reads the kernel's or hypervisor's own advertisement of the same features, and it was run on
this host from both sides: under Linux it reports `absent` for all four of `tdx_host_platform`,
`sev`, `sev_es` and `sev_snp`, and under Windows it reports `VirtualizationFirmwareEnabled =
false`. That corroborates the CPUID measurement from a second, independent source.

It is explicitly **weaker** than the CPUID table, and the script says so about itself. Node cannot
execute CPUID, so on Windows it can only report *cannot determine* for the four feature bits —
absence of an advertisement is not an absent capability, and the script refuses to state it as
one. It also reports, rather than suppresses, a host that *does* advertise a capability, because
that falsifies the stated reason this waiver is unreachable from here.

### What closing it would require

1. A machine with AMD EPYC 9004 (Milan, SEV-SNP) or Intel Sapphire Rapids (TDX), with the
   confidential-VM feature enabled in firmware.
2. A confidential guest whose owner policy is attested **before** any guest code executes.
3. A launch measurement bound to that policy, so a policy change produces a different measurement.
4. An attestation client in this repository that verifies the certificate chain to an AMD or Intel
   root of trust, and **refuses to start the policy path** when verification fails.
5. A test that asserts the negative property directly: the signing key and the policy lease are
   not readable from outside the enclave, including with root on the host.

Item 4 is the part most likely to be got wrong, and it is the part this repository would be worst
placed to review. A verifier that fails open is worse than no verifier, because it converts an
absent capability into a claimed one.

### What the project claims instead, unchanged

> Baseline v2 does not claim protection after host-kernel or root compromise.

This sentence stands. Confidential computing is the only technology that would change it, and
until item 1 through item 5 exist, nothing in this repository should suggest otherwise.

### Signature

Waiving W-001 means accepting the gap above knowingly. It does **not** license any change to the
stated scope: the protection is not claimed, it is absent, and signing here records that the
absence is a decision rather than an oversight.

| | |
|---|---|
| Owner | |
| Date | |
| Accepts the gap as described | ☐ |
