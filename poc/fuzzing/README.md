# Reproduce the frostd HTTP checks locally

This directory contains the original Python HTTP/state-machine harness plus a **newly reconstructed** XEdDSA signer helper and a safe local runner. The historical campaign's raw JSONL files and original signer source are unavailable; running these files produces new evidence, not a recreation of those missing records.

Use a disposable clone of the reviewed [`frost-tools` commit](https://github.com/ZcashFoundation/frost-tools/commit/53df99c2bd61f7cb60a0d1f634822a76be3799cf). The script starts only a locally bound `frostd` process and terminates only that process. Do not point it at a public relay.

Requirements: Rust/Cargo, Python 3 with `requests`, `curl` and a local `frostd` binary. Build the helper with:

```sh
cargo build --release --manifest-path poc/fuzzing/xsign/Cargo.toml
```

Build `frostd` in the separate `frost-tools` clone, then run a small sanity phase from this repository's root:

```sh
FROSTD_BIN=/absolute/path/to/frost-tools/target/debug/frostd poc/fuzzing/run.sh 0
```

By default the runner executes phases `0 1 2 3 4`. Pass phase numbers to choose a subset, or add `5` for the bounded memory phase. Set `FUZZ_OUTDIR` for a separate output directory; otherwise new logs go under ignored `poc/fuzzing/run-artifacts/`. `FROSTD_PORT` changes the local port; `PYTHON` selects a Python executable with `requests` installed. On macOS, the harness's Linux `/proc` RSS probe returns `-1`; do not interpret that as measured memory usage. The runner does not impose an operating-system memory limit. Phase 5 can queue tens of MiB, so use a disposable instance and choose a suitable resource limit outside this script if needed.

The harness records events and liveness checks as well as requests. A count of JSONL lines is **not** a count of HTTP requests. Review `results.jsonl`, the server log and the runner's exit status together; a completed run cannot prove the absence of vulnerabilities.
