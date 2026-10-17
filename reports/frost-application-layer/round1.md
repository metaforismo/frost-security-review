# Application-layer review — Round 1 (historical candidate record)

*17 October 2026. Reviewed `frost-tools` main as of 14 October 2026; its `frost-core` dependency was 2.2.0, not the separately reviewed v3.0.0.*

> **Read [the errata and evidence status](../../ERRATA-AND-EVIDENCE.md) first.** This round was static triage, not a list of confirmed vulnerabilities. The original Noise_K peer-impersonation and missing-cheater-detection claims were **withdrawn** in Round 2. The original absolute claims about nonce reuse and comprehensive security assurance were also too strong.

## Candidate summary after Round 2

| Area | Current status |
| --- | --- |
| `frostd::send` unbounded recipient fan-out | Source path confirmed; original Linux report records RSS growth and allocator-failure abort. See [issue #611](https://github.com/ZcashFoundation/frost-tools/issues/611) and [PoC report](round2-workerB-pocs.md). |
| Noise_K peer impersonation | **Withdrawn.** The original Round 1 reasoning assumed a transmitted static-key token that Noise_K does not send. The claimed impersonation path requires the victim's private key. |
| Missing cheater detection | **Withdrawn.** `frost-core` 2.2.0 had `cheater-detection` in its default features; the tested error identified a culprit. |
| DKG wait loops, phantom sessions, socket/CLI behavior | Candidate observations in demo/reference tooling; not established as independent confirmed exploits by the published artifacts. See the component notes for the original reasoning. |
| `zcash-sign` / participant confirmations | Later CLI signer prompts display opaque hex. This is a design observation for the reviewed CLI path; the earlier Ywallet planning screen can show transaction details. No deployed wallet exploit was demonstrated. |

The upstream project describes `frostd` as demo/reference code. The work did not identify a critical vulnerability in its examined scope, but does not establish comprehensive absence of other flaws.

## Original component notes

- [Relay](frostd-audit.md)
- [Coordinator](coordinator-audit.md)
- [Participant](participant-audit.md)
- [DKG and zcash-sign](dkg-zcashsign-audit.md)

These are historical working notes. Their candidate assessments must be read with [Round 2](round2.md) and the [errata](../../ERRATA-AND-EVIDENCE.md); original statements about “no disclosure” refer to the time before the public [issue](https://github.com/ZcashFoundation/frost-tools/issues/611) and [discussion](https://github.com/ZcashFoundation/frost/discussions/1102).
