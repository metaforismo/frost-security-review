use frost_client::coordinator::comms::socket::SocketComms;
use frost_ed25519::Ed25519Sha512;
use message_io::{network::Transport, node};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_socket_queue_overflow_panics_listener_task() {
    let observed = Arc::new(AtomicBool::new(false));
    let observed_in_hook = observed.clone();
    let prior_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(loc) = info.location() {
            if loc.file().ends_with("coordinator/comms/socket.rs") && loc.line() == 63 {
                observed_in_hook.store(true, Ordering::SeqCst);
            }
        }
        prior_hook(info);
    }));

    let port = std::env::var("SOCKET_POC_PORT").unwrap_or_else(|_| "27504".into());
    let _coordinator = SocketComms::<Ed25519Sha512>::new("127.0.0.1".into(), port.clone());
    let (client, listener) = node::split::<()>();
    let _client_events = std::thread::spawn(move || listener.for_each(|_| {}));
    let (endpoint, _) = client
        .network()
        .connect(Transport::FramedTcp, format!("127.0.0.1:{port}"))
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    for _ in 0..3_000 {
        client.network().send(endpoint, b"x");
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let listener_panicked = observed.load(Ordering::SeqCst);
    eprintln!("listener_full_queue_panic={listener_panicked}");
    // The demo's synchronous message-io loop is spawned inside Tokio and does
    // not shut down cleanly in this isolated harness. Exit after observation.
    std::process::exit(if listener_panicked { 0 } else { 1 });
}
