# Separate frostd HTTP replay — 17 October 2026

This is a **new** local execution of the published HTTP/state-machine harness with a reconstructed XEdDSA helper. It is not the missing historical release/debug campaign described in the original report.

- Target: `ZcashFoundation/frost-tools` commit `53df99c2bd61f7cb60a0d1f634822a76be3799cf`, debug `frostd`, listening only on `127.0.0.1` on macOS.
- Runner: [`poc/fuzzing/run.sh`](../../poc/fuzzing/run.sh), phases `0 1 2 3 4`; helper source and build instructions are in [`poc/fuzzing/README.md`](../../poc/fuzzing/README.md).
- Result: process exit 0; 1,245 JSONL **records**, including 477 liveness checks, all reporting the process alive. No `SERVER_DEAD`, phase exception, saved crash, or phase-2 invariant anomaly appeared. The server log had no panic or allocator-abort text.
- Phase 1: 422 malformed-input mutations; 338 returned HTTP 500. Those responses may warrant separate API error-handling review and are not evidence of a relay process crash.
- Phase 2: 400 generated operations; zero harness-reported invariant anomalies. Phase 3 exercised six race scenarios, including 200 sends drained as 200 received. Phase 4 completed its boundary cases and drain check.
- Limits: phase 5 was not run; this replay did not test the historical OOM claim, release build, or Linux memory consumption. The macOS `/proc` probe recorded `rss_kb=-1`, which is **not** a memory measurement. JSONL rows are not HTTP-request counts. This run does not establish exhaustive security coverage.

The new raw logs are retained locally rather than published. Their SHA-256 identifiers are `d1a63b4904f96d8837400e2e002dde1a389506c31edfed35bd07129078383687` (`results.jsonl`) and `5d98b15e32d776b390e64851c14dd7efdc64a0ec9d6275c90c2cd6755310e994` (server log). The historical raw files remain unavailable.
