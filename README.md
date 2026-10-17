# FROST Security Review — Independent Audit (October 2026)

Independent, in-depth security audit of **FROST v3** (Flexible Round-Optimized Schnorr Threshold Signatures) as specified for Zcash shielded multisig in **ZIP-312**. Work completed October 2026 by an independent researcher, before any grant application.

## Headline result

**No critical vulnerability was found.** The FROST v3 codebase is in excellent shape — this audit confirms it across 21+ investigated leads, each chased to a documented kill reason or a demonstrated proof-of-concept. That assurance itself is the primary deliverable: the ecosystem is standardizing shielded multisig on this code (IETF track, ZIP-312 finalization).

## Concrete outputs

1. **One confirmed denial-of-service** in `frostd` — memory exhaustion (~63 KB per recipient, linear to SIGABRT at 29,000 recipients), demonstrated with a measured, executed PoC. See [`poc/frostd-dos/`](poc/frostd-dos/).
2. **~1,237-request fuzzing campaign** against the frostd HTTP state machine (release + debug builds): zero crashes, zero panics — a documented negative result. See [`poc/fuzzing/`](poc/fuzzing/).
3. **Blind-signing design gap** documented end-to-end across the FROST signing flow — every human checkpoint displays only opaque hex. Relevant to all future wallet integrators.
4. **Two false positives rigorously debunked** with independent double verification — published as evidence of methodological rigor.

## Reports

| Report | Scope | Verdict |
|---|---|---|
| [`reports/frost-library/AUDIT-REPORT-2026-10-17.md`](reports/frost-library/AUDIT-REPORT-2026-10-17.md) | `frost-core` v3.0.0: nonces, signing, DKG, refresh, RedPallas ciphersuite | 14 leads killed, code excellent |
| [`reports/frost-application-layer/round1.md`](reports/frost-application-layer/round1.md) + sub-reports | `frost-tools`: frostd, coordinator, participant, DKG, zcash-sign | 0 key forgery; 7 demo-code candidates |
| [`reports/frost-application-layer/round2.md`](reports/frost-application-layer/round2.md) + sub-reports | ywallet/Zallet integration check, PoCs, fuzzing, chaining | 1 confirmed DoS, 2 debunked, chaining negative |

## Methodology

AI-assisted analysis with a strict protocol: **no lead is closed without a proof-of-concept or a formal kill reason.** Findings that could not be demonstrated were killed with documented reasoning — including leads that initially looked promising. Two Round-1 candidates were later debunked by the same methodology; this is published as evidence of rigor, not hidden.

## Scope (audited code, not specs)

- `ZcashFoundation/frost`, `frost-core` v3.0.0 (`0966bd1`): round1, round2, aggregate, cheater detection, DKG, refresh, identifiers
- `frost-rerandomized` v3.0.0 (ZIP-312 mechanism)
- RedPallas/RedJubjub FROST ciphersuites (`reddsa` pre-removal commit `3a1533b`)
- `frost-tools` (frostd, coordinator, participant, zcash-sign) @ 2026-10-14
- ywallet / Zallet / FROST Book flow (production integration check)

## What this is not

- Not a critical vulnerability disclosure. The confirmed DoS is in demo/reference code (`frostd`); no production system was at risk.
- Not a finding against any deployed wallet: ywallet and Zallet contain no FROST signing code as of October 2026.

## Researcher

Francesco Giannicola — independent security researcher (elliptic-curve cryptography, co-author of ECDSA.Fail, secp256k1 research). AI-assisted methodology; all findings human-verified with executed proofs-of-concept.

## License

Reports: CC-BY-4.0. PoC code: MIT.
