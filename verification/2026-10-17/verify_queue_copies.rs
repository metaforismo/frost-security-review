//! Bounded localhost check of frostd recipient fan-out.
//!
//! Run this as a frostd example from frost-tools commit 53df99c after starting
//! a local relay. The driver caps recipient entries at 64, sends one message,
//! and checks that receive returns every copy. It does not measure RSS or
//! attempt resource exhaustion.

use frost_client::api::*;
use xeddsa::Sign as _;

fn rss_kb(_pid: u32) -> Option<u64> { None }

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

    // --- Session for the local key ------------------------------------------
    assert!(n <= 64, "this check deliberately caps fan-out at 64");
    let pubkeys = vec![pubkey.clone()];
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
    println!("session {} created with {} pubkeys", sess.session_id, pubkeys.len());

    let invalid = client.post(format!("{base}/send"))
        .bearer_auth(&token)
        .json(&SendArgs { session_id: sess.session_id, recipients: vec![pubkey.clone()], msg: vec![0x41; MAX_MSG_SIZE + 1] })
        .send().await?;
    assert!(!invalid.status().is_success());
    println!("oversize_message_rejected=true status={}", invalid.status());

    let before = rss_kb(pid);
    println!("server RSS before send: {:?}", before.map(|k| format!("{} kB", k)));

    // --- Bounded send, then receive each queued copy -------------------------
    let msg = vec![0x41u8; msg_size];
    let t0 = std::time::Instant::now();
    let resp = client
        .post(format!("{base}/send"))
        .bearer_auth(&token)
        .json(&SendArgs {
            session_id: sess.session_id,
            recipients: vec![pubkey.clone(); n],
            msg,
        })
        .send()
        .await?;
    let dt = t0.elapsed();
    println!("send status: {} (took {:?})", resp.status(), dt);
    let body = resp.text().await?;
    println!("send body (truncated): {}", &body[..body.len().min(200)]);

    let received: ReceiveOutput = client.post(format!("{base}/receive"))
        .bearer_auth(&token)
        .json(&ReceiveArgs { session_id: sess.session_id, as_coordinator: false })
        .send().await?.error_for_status()?.json().await?;
    assert_eq!(received.msgs.len(), n);
    assert!(received.msgs.iter().all(|m| m.msg.len() == msg_size && m.msg.iter().all(|b| *b == 0x41)));
    println!("queued_copies_verified={} queued_payload_bytes={}", received.msgs.len(), n * msg_size);

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
        _ => println!("RSS measurement intentionally omitted in queue-copy check"),
    }
    Ok(())
}

