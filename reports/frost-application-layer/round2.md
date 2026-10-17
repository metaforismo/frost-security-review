# Application-layer review — Round 2 (evidence-qualified summary)

*17 October 2026; later evidence review and corrections incorporated. The tools snapshot depends on `frost-core` 2.2.0 and must not be conflated with the separate v3.0.0 library review.*

> [Errata and evidence status](../../ERRATA-AND-EVIDENCE.md) distinguishes what was independently checked later from results reported by the original workers. Raw Linux OOM and fuzzing logs are not included here.

## Results

1. **Relay fan-out:** `frostd::send` clones a message per recipient without an aggregate queue-byte cap. The original [PoC report](round2-workerB-pocs.md) records 31.6/63.1/126.1 **MiB** RSS growth for 500/1,000/2,000 recipients on a debug build and an allocator-failure `SIGABRT` at 29,000 recipients under a Linux virtual-memory limit. The later bounded local check confirmed queued copies, not that crash or RSS slope. See [issue #611](https://github.com/ZcashFoundation/frost-tools/issues/611).
2. **Withdrawn candidates:** the earlier Noise_K impersonation and missing-cheater-detection claims were wrong. The Noise_K initiator does not transmit a static-key token; the claimed path requires the victim's private key. `cheater-detection` was already a default feature in `frost-core` 2.2.0. See [PoC notes](round2-workerB-pocs.md) and [chaining review](round2-workerD-chaining.md).
3. **Fuzzing:** the [report](round2-workerC-fuzzing.md) describes release and debug campaigns with no crash or panic. The final debug `results.jsonl` has 1,237 records, including test events and liveness checks; this is not an exact HTTP-request count. The raw JSONL and XEdDSA helper source are unavailable in this repository.
4. **Signing flow:** the [wallet/source review](round2-workerA-ywallet-flow.md) found opaque hex at later CLI signing confirmations. The initial Ywallet planning screen can display amounts and recipients. No production wallet exploit or deployment-wide absence was established.
5. **Other candidate paths:** the [chaining notes](round2-workerD-chaining.md) discuss possible combinations and negative reasoning. They are research notes, not a proof that all combinations or nonce misuse are impossible. No fund or key compromise was demonstrated by the published artifacts.

The original research reports and code remain public for inspection. This summary does not claim formal verification, exhaustive coverage, maintainer acceptance, or a measured production security outcome. Feedback was requested in [FROST discussion #1102](https://github.com/ZcashFoundation/frost/discussions/1102).
