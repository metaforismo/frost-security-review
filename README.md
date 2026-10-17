# FROST Security Review — Research Notes (October 2026)

Independent, AI-assisted review notes on selected FROST v3 components, a historical RedPallas/RedJubjub ciphersuite snapshot, and the `frost-tools` application layer.

**Read [ERRATA-AND-EVIDENCE.md](ERRATA-AND-EVIDENCE.md) first.** A subsequent source and artifact review found incorrect reasoning and overstated assurances in the original notes. The corrected files and evidence note supersede those statements. These materials do not establish the absence of critical vulnerabilities or complete audit coverage.

## Outputs and current evidence

1. **Relay memory-exhaustion mechanism:** upstream `frostd::send` caps each message at 65,535 bytes but clones it for every recipient without a total queue-byte bound. The original Linux report records RSS measurements and an allocator-failure abort under a memory limit; those historical measurements have not been independently rerun. See [PoC](poc/frostd-dos/poc1_dos.rs), [report](reports/frost-application-layer/round2-workerB-pocs.md), and [issue #611](https://github.com/ZcashFoundation/frost-tools/issues/611).
2. **HTTP/state-machine testing:** the original report describes release and debug campaigns with no crashes or panics. It records 1,237 JSONL lines for the final debug run; this is not an exact HTTP-request count. Raw logs and the XEdDSA helper source are not currently included. See [report](reports/frost-application-layer/round2-workerC-fuzzing.md).
3. **CLI signing-confirmation observations:** the reviewed CLI checkpoints display a sighash/message as hex rather than rendering transaction details. This concerns those signing checkpoints; the initial Ywallet planning UI can display amounts and recipients. No deployed wallet exploit has been demonstrated.
4. **Withdrawn candidates and corrections:** Round 2 withdraws the earlier Noise_K impersonation and missing-cheater-detection claims. Additional corrections address nonce reuse, randomizer derivation, and evidence limits. Candidate notes are not validated vulnerabilities.

## Reports

| Report | Recorded scope | Reading status |
|---|---|---|
| [Library notes](reports/frost-library/AUDIT-REPORT-2026-10-17.md) | `frost-core` v3.0.0, DKG, refresh, historical ciphersuite snapshot | Nonce/randomization reasoning corrected; see errata |
| [Round 1](reports/frost-application-layer/round1.md) | `frostd`, coordinator, participant, DKG, `zcash-sign` | Historical candidate notes; several claims superseded |
| [Round 2](reports/frost-application-layer/round2.md) | Reported PoCs, HTTP testing, integration and chaining analysis | Read with evidence limits and errata |

Some original notes retain language such as “private” or “no disclosure”; these describe their original working state. The public issue and discussion below record subsequent publication.

## Reviewed snapshots

- `ZcashFoundation/frost`, `frost-core` and `frost-rerandomized` v3.0.0, ref `0966bd1`.
- Historical RedPallas/RedJubjub implementation in `ZcashFoundation/reddsa`, ref `3a1533b`.
- `ZcashFoundation/frost-tools` main as of 2026-10-14, commit `53df99c2bd61f7cb60a0d1f634822a76be3799cf`. Its dependency versions differ from the separate v3 library review.
- Wallet/source observations are scoped to the snapshots identified in their reports. They do not establish that no production deployment exists.

## Upstream communication and acceptance

- [DoS issue: frost-tools#611](https://github.com/ZcashFoundation/frost-tools/issues/611).
- [Request for technical feedback: frost#1102](https://github.com/ZcashFoundation/frost/discussions/1102).

Publication is complete. Maintainer validation or acceptance of the work has not been established.

## Researcher and methodology

Francesco Giannicola ([@metaforismo](https://github.com/metaforismo)), co-author of the [ECDSA.Fail paper](https://arxiv.org/abs/2609.09582).

AI-assisted source review and test artifacts. The original reports describe local executions; the scope of later independent checks and unavailable artifacts is stated in the evidence note. The earlier blanket claim that every finding was human-verified is withdrawn.

## License declaration

Original report text and analysis: [MIT or CC BY 4.0, at your choice](LICENSE-REPORTS.md). PoC, harness, and verification code: [MIT](LICENSE). Quoted third-party material retains its original rights and licenses.
