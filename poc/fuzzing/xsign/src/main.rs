use std::{env, error::Error};
use xeddsa::Sign as _;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, command] if command == "gen" => {
            let builder = snow::Builder::new("Noise_K_25519_ChaChaPoly_BLAKE2s".parse()?);
            let keypair = builder.generate_keypair()?;
            println!(
                "{}",
                serde_json::json!({
                    "privkey": hex::encode(keypair.private),
                    "pubkey": hex::encode(keypair.public),
                })
            );
        }
        [_, command, private_key, message] if command == "sign" => {
            let key: [u8; 32] = hex::decode(private_key)?.try_into().map_err(|_| "private key must be 32 bytes")?;
            let msg = hex::decode(message)?;
            let signature: [u8; 64] =
                xeddsa::xed25519::PrivateKey(key).sign(&msg, &mut rand::thread_rng());
            println!("{}", hex::encode(signature));
        }
        _ => return Err("usage: xsign gen | xsign sign <private-key-hex> <message-hex>".into()),
    }
    Ok(())
}
