# Socket coordinator queue overflow (local PoC)

Target: [`ZcashFoundation/frost-tools` `53df99c`](https://github.com/ZcashFoundation/frost-tools/commit/53df99c2bd61f7cb60a0d1f634822a76be3799cf), `frost-client/src/coordinator/comms/socket.rs`. The socket mode is demo code and accepts framed TCP messages without authentication. The listener forwards each message into a bounded 2,000-entry Tokio channel using `try_send(...).unwrap()`.

Copy [`socket_queue_poc.rs`](socket_queue_poc.rs) to `frost-client/tests/socket_queue_poc.rs` in a **disposable** clone of that commit. Run it only on localhost:

```sh
SOCKET_POC_PORT=27504 cargo test -p frost-client --test socket_queue_poc -- --exact unauthenticated_socket_queue_overflow_panics_listener_task --nocapture
```

The PoC creates the coordinator socket transport with its input receiver deliberately idle, connects an unauthenticated local peer, and sends 3,000 one-byte framed messages. In the observed run, the listener task panicked at `socket.rs:63` with `Err` value `Full(..)`, and the PoC printed `listener_full_queue_panic=true`. It exits the test process explicitly after observation because the demo's synchronous listener loop does not shut down cleanly inside this isolated Tokio test. An exit code of zero plus that marker, rather than a normal Rust test summary, is the expected observation.

The PoC proves the full-queue panic in this setup. It does not show that the coordinator **process** exits, that an active signing ceremony always stalls, or that funds or keys are exposed. Those claims require separate end-to-end evidence. The initial unmodified source path and the local test show an availability risk in a demo transport, not a critical vulnerability.
