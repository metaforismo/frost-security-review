use std::collections::BTreeMap;
use frost_ed25519 as frost;
use rand::{CryptoRng, RngCore};

struct ConstantRng;
impl RngCore for ConstantRng {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, dest: &mut [u8]) { dest.fill(0); }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest); Ok(())
    }
}
impl CryptoRng for ConstantRng {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let (shares, _) = frost::keys::generate_with_dealer(
        3, 2, frost::keys::IdentifierList::Default, &mut rng)?;
    let mut entries = shares.iter();
    let (id_a, share_a) = entries.next().unwrap();
    let (id_b, share_b) = entries.next().unwrap();
    let key_a: frost::keys::KeyPackage = share_a.clone().try_into()?;
    let key_b: frost::keys::KeyPackage = share_b.clone().try_into()?;
    let mut broken_rng = ConstantRng;
    let nonce_a = frost::round1::SigningNonces::new(key_a.signing_share(), &mut broken_rng);
    let nonce_a_again = frost::round1::SigningNonces::new(key_a.signing_share(), &mut broken_rng);
    assert_eq!(nonce_a, nonce_a_again);
    let nonce_b = frost::round1::SigningNonces::new(key_b.signing_share(), &mut rng);
    let mut commitments = BTreeMap::new();
    commitments.insert(*id_a, frost::round1::SigningCommitments::from(&nonce_a));
    commitments.insert(*id_b, frost::round1::SigningCommitments::from(&nonce_b));
    let package_a = frost::SigningPackage::new(commitments.clone(), b"local synthetic test A");
    let package_b = frost::SigningPackage::new(commitments, b"local synthetic test B");
    frost::round2::sign(&package_a, &nonce_a, &key_a)?;
    frost::round2::sign(&package_b, &nonce_a, &key_a)?;
    println!("constant_rng_repeats_nonce=true");
    println!("same_nonce_and_commitments_sign_two_messages=true");
    println!("scope=frost-ed25519 2.1.0 / frost-core 2.2.0; synthetic ephemeral keys only");
    Ok(())
}

