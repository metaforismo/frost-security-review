//! F1 signing-oracle execution PoC — Lane A2.
//!
//! Promotes Lane A finding F1 (ZIP-312 threat-model guarantee vs. specified
//! participant checks) from consistency-checked to independently reproduced.
//!
//! Scenario (from the Lane A walkthrough): 2-of-3, coordinator C malicious,
//! honest P1/P2 run *conforming* participant software that performs EXACTLY
//! the checks the two specs require and then signs — the honest model of a
//! server-side cosigner (ZIP-312's own motivating deployment, Motivation
//! L50-52: "users and third-party services sharing custody of a wallet").
//!
//! Specified checks performed by the participant (nothing more):
//!   1. Commitment list well-formedness — each group Element deserializes,
//!      abort otherwise (RFC 9591 §5.2 L979-981). MUST.
//!   2. Self-membership — own identifier and round-one commitments appear in
//!      the list (RFC 9591 §5.2 L983). MUST.
//!   3. SIGHASH consistency — recompute SIGHASH from the accompanying
//!      transaction bytes and compare with the given msg (ZIP-312 L188-190).
//!      MUST (conditional on data being sent — here it IS sent).
//!   NOT performed: any authorization/approval decision (ZIP-312: "the
//!      specific mechanism for that process is outside the scope of this ZIP").
//!
//! Ciphersuite note: ZIP-312 specifies RedPallas/RedJubjub; this PoC
//! instantiates the same ciphersuite-generic randomized FROST mechanics with
//! Ed25519Sha512 (impl RandomizedCiphersuite in frost-ed25519). The ceremony
//! logic under test (commit → sign_with_randomizer_seed → aggregate → verify
//! under VK+αG) is identical across ciphersuites — code-confirmed in
//! frost-rerandomized/src/lib.rs, which is generic over C: RandomizedCiphersuite.
//!
//! SIGHASH note: real Zcash SIGHASH is a domain-specific hash; here it is
//! SHA-256(tx_bytes) as a stand-in. The participant check under test is
//! syntactic (recompute-and-compare), so any deterministic hash demonstrates it.
//!
//! Evidence labels per verify_before_publish/SKILL.md:
//!   - the end-to-end run below: INDEPENDENTLY REPRODUCED (executed here).
//!   - "a conforming implementation performs exactly these checks":
//!     CONSISTENCY-CHECKED (spec text vs. library code paths).
//!   - frost-core v3.0.0 @ 0966bd1: CODE-CONFIRMED (git rev-parse HEAD).

use std::collections::BTreeMap;

use frost_core::{
    keys::{generate_with_dealer, IdentifierList, KeyPackage, PublicKeyPackage},
    round1, round2, Identifier, Signature, SigningPackage, VerifyingKey,
};
use frost_ed25519::Ed25519Sha512;
use frost_rerandomized::{aggregate, sign_with_randomizer_seed, RandomizedParams};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

type C = Ed25519Sha512;

/// Stand-in for Zcash's SIGHASH(tx): deterministic, recomputable by the signer.
fn sighash(tx_bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(tx_bytes).to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// What the coordinator sends each participant in Round 2, over the
/// confidential+authenticated channel (ZIP-312 L182-184).
struct Round2Msg {
    /// `from_label` models the channel peer as the participant perceives it.
    /// NOTE: no specified participant check consults this value (F2).
    from_label: String,
    randomizer_seed: Vec<u8>,
    /// msg = SIGHASH(T)
    msg: Vec<u8>,
    /// (participant id, serialized SigningCommitments) as sent on the wire
    commitment_wire: Vec<(u16, Vec<u8>)>,
    /// "more data ... possibly the transaction itself" (ZIP-312 L187-190)
    tx_bytes: Vec<u8>,
}

struct ConformingParticipant {
    id: Identifier<C>,
    id_num: u16,
    key_package: KeyPackage<C>,
    nonces: round1::SigningNonces<C>,
    /// Own round-one commitments (for the RFC 9591 L983 self-membership check)
    commitments: round1::SigningCommitments<C>,
    /// Application-level authorization: NOT specified by ZIP-312.
    /// `None` = conforming (auto-sign). `Some(allowlist)` = extra, out-of-spec
    /// check, used only for the negative control.
    extra_authorization: Option<Vec<Vec<u8>>>,
}

impl ConformingParticipant {
    /// Runs EXACTLY the specified checks, then signs. Returns the share or
    /// aborts with the check that failed.
    fn handle_round2(&self, m: &Round2Msg) -> Result<round2::SignatureShare<C>, String> {
        println!(
            "  [P{}] received Round 2 package (channel peer labelled '{}')",
            self.id_num, m.from_label
        );

        // ---- CHECK 1 (RFC 9591 §5.2 L979-981, MUST): commitment list
        // well-formedness — deserialize each group Element; abort on failure.
        // (SigningCommitments::deserialize fails iff any Element fails to
        // deserialize — the library path performs the per-element check.)
        let mut commitments: BTreeMap<Identifier<C>, round1::SigningCommitments<C>> =
            BTreeMap::new();
        for (id_num, bytes) in &m.commitment_wire {
            let id = Identifier::<C>::try_from(*id_num).map_err(|_| {
                format!("CHECK 1 FAILED: bad identifier {} on the wire", id_num)
            })?;
            let sc = round1::SigningCommitments::<C>::deserialize(bytes)
                .map_err(|e| format!("CHECK 1 FAILED: commitment element deserialization failed: {:?}", e))?;
            commitments.insert(id, sc);
        }
        println!("  [P{}] CHECK 1 (commitment well-formedness, RFC 9591 L979-981): PASS", self.id_num);

        // ---- CHECK 2 (RFC 9591 §5.2 L983, MUST): self-membership — own
        // identifier and round-one commitments appear in the list.
        match commitments.get(&self.id) {
            Some(c) if *c == self.commitments => {
                println!("  [P{}] CHECK 2 (self-membership, RFC 9591 L983): PASS", self.id_num)
            }
            _ => {
                return Err(format!(
                    "[P{}] CHECK 2 FAILED: own identifier/commitments missing from list",
                    self.id_num
                ))
            }
        }

        // ---- CHECK 3 (ZIP-312 L188-190, MUST): SIGHASH consistency —
        // recompute the SIGHASH from the accompanying data and compare.
        if sighash(&m.tx_bytes) != m.msg {
            return Err(format!(
                "[P{}] CHECK 3 FAILED: recomputed SIGHASH does not match msg",
                self.id_num
            ));
        }
        println!("  [P{}] CHECK 3 (SIGHASH consistency, ZIP-312 L188-190): PASS", self.id_num);

        // ---- NOT SPECIFIED: authorization / approval decision.
        // ZIP-312: "the specific mechanism for that process is outside the
        // scope of this ZIP." A conforming implementation performs NO check here.
        if let Some(allowlist) = &self.extra_authorization {
            // Negative control only: an application-level check the spec never
            // requires.
            if !allowlist.iter().any(|t| *t == m.tx_bytes) {
                return Err(format!(
                    "[P{}] EXTRA (out-of-spec) authorization check: transaction not allowlisted -> ABORT (control)",
                    self.id_num
                ));
            }
        } else {
            println!(
                "  [P{}] authorization decision: NONE SPECIFIED (ZIP-312: out of scope) -> auto-sign",
                self.id_num
            );
        }

        // All specified checks passed: contribute the share (randomized signing).
        let signing_package = SigningPackage::new(commitments, &m.msg);
        sign_with_randomizer_seed(&signing_package, &self.nonces, &self.key_package, &m.randomizer_seed)
            .map_err(|e| format!("[P{}] signing failed: {:?}", self.id_num, e))
    }
}

/// Malicious coordinator per the Lane A walkthrough. `label` is "C" (the
/// threat model's rogue coordinator) or "A" (F2: imposter over a
/// weakly-authenticated channel). The code path is IDENTICAL in both cases —
/// that is the F2 point: no specified check distinguishes them.
fn malicious_coordinator_round(
    label: &str,
    participants: &[ConformingParticipant],
    pubkeys: &PublicKeyPackage<C>,
    t_attack: &[u8],
    rng_seed: u64,
) -> Result<(Signature<C>, VerifyingKey<C>, Vec<u8>), String> {
    let mut rng = ChaCha8Rng::seed_from_u64(rng_seed);
    println!("\n[{}] step 1: craft T_attack (pays the attacker)", label);
    println!("[{}] T_attack = {:?}", label, String::from_utf8_lossy(t_attack));

    // Round 1: participants send commitments (public values) to the coordinator.
    let mut commitments: BTreeMap<Identifier<C>, round1::SigningCommitments<C>> = BTreeMap::new();
    let mut commitment_wire: Vec<(u16, Vec<u8>)> = Vec::new();
    for p in participants {
        commitments.insert(p.id, p.commitments);
        let bytes = p.commitments.serialize().map_err(|e| format!("serialize: {:?}", e))?;
        commitment_wire.push((p.id_num, bytes));
    }
    println!("[{}] step 2: Round 1 complete ({} commitments collected)", label, commitments.len());

    // Round 2: coordinator generates the randomizer (honestly or not —
    // immaterial to the finding) and sends α seed + SIGHASH(T_attack) +
    // commitment list + the REAL T_attack bytes.
    let msg = sighash(t_attack);
    let (randomized_params, randomizer_seed) =
        RandomizedParams::new_from_commitments(pubkeys.verifying_key(), &commitments, &mut rng)
            .map_err(|e| format!("randomizer: {:?}", e))?;
    println!("[{}] step 3: randomizer generated; msg = SIGHASH(T_attack) = {}", label, hex(&msg));

    let mut shares: BTreeMap<Identifier<C>, round2::SignatureShare<C>> = BTreeMap::new();
    for p in participants {
        let r2 = Round2Msg {
            from_label: label.to_string(),
            randomizer_seed: randomizer_seed.clone(),
            msg: msg.clone(),
            commitment_wire: commitment_wire.clone(),
            tx_bytes: t_attack.to_vec(),
        };
        // NOTE: the coordinator does NOT lie about the transaction content —
        // it sends the real T_attack bytes, and the syntactic checks still pass.
        let share = p.handle_round2(&r2)?;
        println!("  [P{}] share contributed", p.id_num);
        shares.insert(p.id, share);
    }

    // Aggregate (also verifies each share — coordinator-side, RFC 9591).
    let signing_package = SigningPackage::new(commitments, &msg);
    let sig = aggregate(&signing_package, &shares, pubkeys, &randomized_params)
        .map_err(|e| format!("aggregate: {:?}", e))?;
    println!("[{}] step 4: shares aggregated -> (R, z)", label);

    let randomized_vk = *randomized_params.randomized_verifying_key();
    Ok((sig, randomized_vk, msg))
}

fn setup() -> (Vec<ConformingParticipant>, PublicKeyPackage<C>) {
    // Trusted-dealer keygen — ZIP-312 L98/L115 defers to RFC 9591, whose only
    // normative guidance is the trusted-dealer appendix ([9] = RFC 9591 App B/C).
    let mut rng = ChaCha8Rng::seed_from_u64(0xF1A2);
    let (secret_shares, pubkeys) =
        generate_with_dealer(3, 2, IdentifierList::Default, &mut rng).expect("keygen");
    let mut participants = Vec::new();
    for id_num in 1u16..=2 {
        let id = Identifier::<C>::try_from(id_num).unwrap();
        let key_package = KeyPackage::try_from(secret_shares.get(&id).unwrap().clone()).unwrap();
        let (nonces, commitments) =
            round1::commit(key_package.signing_share(), &mut ChaCha8Rng::seed_from_u64(0xB000 + id_num as u64));
        participants.push(ConformingParticipant {
            id,
            id_num,
            key_package,
            nonces,
            commitments,
            extra_authorization: None,
        });
    }
    (participants, pubkeys)
}

fn main() {
    println!("=== F1 signing-oracle execution PoC (Lane A2) ===");
    println!("frost-core v3.0.0 @ 0966bd1 · ciphersuite Ed25519Sha512 (randomized FROST mechanics identical to ZIP-312's)\n");

    // The attacker's transaction. In the ZIP's motivating deployment this is a
    // real Zcash transaction paying the coordinator/attacker.
    let t_attack = b"ZCASH-TX: in=shielded-input(wallet-vk) out=100.0 ZEC -> t1ATTACKERxyz (coordinator-controlled)";

    // ---- Run 1: F1 — malicious coordinator C (the threat model's own rogue coordinator)
    let (participants, pubkeys) = setup();
    println!("--- RUN 1: F1 — rogue coordinator C + conforming auto-signing P1/P2 ---");
    let (sig, randomized_vk, msg) =
        malicious_coordinator_round("C", &participants, &pubkeys, t_attack, 0xC001)
            .expect("F1 walkthrough must complete");
    randomized_vk
        .verify(&msg, &sig)
        .expect("aggregate signature MUST verify under VK+alphaG");
    println!("\n>>> RUN 1 RESULT: signature VERIFIES under randomized VK (VK+alphaG)");
    println!(">>> for SIGHASH(T_attack). Every specified check passed on P1 and P2.");
    println!(">>> F1 CONFIRMED-BY-EXECUTION: valid signature on attacker-chosen transaction from");
    println!(">>> honest, conforming participants. No check was skipped; none is specified beyond the three.");

    // ---- Run 2: F1 x F2 — imposter coordinator over weakly-authenticated channel.
    // The ONLY difference: the channel peer label. Participants run the
    // identical check set — no specified check consults coordinator identity.
    let (participants2, pubkeys2) = setup();
    println!("\n--- RUN 2: F1 x F2 — imposter 'coordinator' A (no compromise of real C) ---");
    println!("(participants' check set is unchanged; 'authenticated' channel has no specified identity model)");
    let (sig2, rvk2, msg2) =
        malicious_coordinator_round("A(imposter)", &participants2, &pubkeys2, t_attack, 0xA002)
            .expect("F2 walkthrough must complete");
    rvk2.verify(&msg2, &sig2).expect("must verify");
    println!("\n>>> RUN 2 RESULT: identical acceptance, signature VERIFIES.");
    println!(">>> F2 composition CONFIRMED-BY-EXECUTION: no coordinator compromise needed;");

    // ---- Run 3 (negative control): participants WITH an out-of-spec
    // authorization check refuse. Proves the spec's check set is the binding
    // constraint — only non-required checks stop the attack.
    let (mut participants3, pubkeys3) = setup();
    let t_honest = b"ZCASH-TX: in=shielded-input(wallet-vk) out=1.0 ZEC -> t1USERabc (user-intended)";
    for p in participants3.iter_mut() {
        p.extra_authorization = Some(vec![t_honest.to_vec()]);
    }
    println!("\n--- RUN 3 (negative control): participants WITH out-of-spec authorization ---");
    match malicious_coordinator_round("C", &participants3, &pubkeys3, t_attack, 0xC003) {
        Ok(_) => println!(">>> UNEXPECTED: attack succeeded despite authorization check"),
        Err(e) => println!(">>> EXPECTED: ceremony aborted -> {}\n>>> Control holds: only non-specified checks stop the attack.", e),
    }

    println!("\n=== DONE ===");
}
