# Bounded macOS RSS checks — 17 October 2026

I ran two fresh, bounded debug-build checks against `frostd` at `frost-tools` commit `53df99c` on macOS. Each sample started a separate localhost relay, self-registered one sender, created a session with N fake recipient keys, sent one 65,535-byte message to N recipients, measured server RSS with `ps`, and stopped only that process. N was capped at 2,000; **no crash or OOM test was attempted**. The [driver](bounded_rss_macos.py) and [first](bounded_rss_macos_run1.jsonl) and [second](bounded_rss_macos_run2.jsonl) raw result files are included.

| Recipients | Calculated queued payload | Run 1 RSS delta | Run 2 RSS delta |
| ---: | ---: | ---: | ---: |
| 500 | 31.250 MiB | 31.406 MiB | 30.234 MiB |
| 1,000 | 62.499 MiB | 1.641 MiB | 61.750 MiB |
| 2,000 | 124.998 MiB | 106.266 MiB | 5.594 MiB |

All six `send` calls returned successfully and the local relay remained alive. The **RSS readings vary sharply**, so this macOS measurement method did not independently establish a reliable slope. The calculated payload column comes from N × 65,535 bytes; it is not measured RSS or proof that every entry stayed resident. The historical Linux RSS values and 29,000-recipient allocator abort therefore remain reported observations with unavailable raw logs, not results reproduced here. No cause for the low macOS readings was established.

To repeat the bounded check, build a debug `frostd` from the pinned commit and the [XEdDSA helper](../../poc/fuzzing/README.md), install Python `requests`, then run `python3 verification/2026-10-17/bounded_rss_macos.py /absolute/path/to/frostd /absolute/path/to/xsign`. The script listens only on `127.0.0.1`, uses ports 27600–27602 by default (`FROSTD_RSS_PORT_BASE` overrides the first port), and caps recipients at 2,000.
