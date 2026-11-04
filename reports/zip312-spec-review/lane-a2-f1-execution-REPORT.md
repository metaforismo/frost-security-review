# Lane A2 — F1 Execution: Signing-Oracle Walkthrough, Independently Reproduced

*2026-11-04. Research only — nothing published, filed, or sent.*
*Follow-up to Round 4 Lane A (spec review); promotes finding F1 from
consistency-checked to independently reproduced.*

## Verdict

**F1 CONFIRMED-BY-EXECUTION.** A malicious coordinator obtained a valid
threshold signature on an attacker-chosen transaction from two honest
participants running *conforming* software — every check specified by RFC 9591
§5.2 and ZIP-312 Round Two passed; no specified check was skipped, and no
check beyond the specified three exists to skip. The resulting `(R, z)`
verifies under the randomized verifying key `VK + αG` for `SIGHASH(T_attack)`.

**F1 × F2 composition CONFIRMED-BY-EXECUTION.** The identical walkthrough run
by an *imposter* coordinator (no compromise of the real coordinator) is
accepted identically by the participants and yields a verifying signature —
no specified participant check consults coordinator identity.

**Negative control holds.** Participants augmented with an *out-of-spec*
application-level authorization check (transaction allowlist) abort the
ceremony. The spec's check set is therefore the binding constraint: only
non-required checks stop the attack.

## What was executed

Rust workspace at `lane-a2-f1-execution/` (this directory):
- `Cargo.toml` — path dependencies on the vendored frost checkout
  `~/workspace/bounty/reports/zcash-audit/frost/frost`, **code-confirmed**
  at commit `0966bd1` (frost-core v3.0.0) via `git rev-parse HEAD`.
- `src/main.rs` — full end-to-end ceremony (see below).
- `run.sh` — offline build + run; `run.log` — captured output
  (deterministic: two consecutive runs byte-identical).

### Conforming participant (the honest model of a server-side cosigner)

`ConformingParticipant::handle_round2` performs exactly:

1. **CHECK 1** — commitment-list well-formedness: each wire-encoded
   `SigningCommitments` deserialized; abort on element failure
   (RFC 9591 §5.2 L979–981, MUST). Code-confirmed: the library's
   deserialization path fails iff a group Element fails to deserialize.
2. **CHECK 2** — self-membership: own identifier present and received
   commitments equal to own round-one commitments (RFC 9591 §5.2 L983,
   MUST). (The library's `round2::sign` redundantly enforces
   MissingCommitment/IncorrectCommitment — defense in depth, same requirement.)
3. **CHECK 3** — SIGHASH consistency: recompute `SIGHASH(tx_bytes)` and
   compare with `msg` (ZIP-312 L188–190, MUST — conditional on data being
   sent; here the coordinator *does* send the real transaction bytes).
4. **No authorization decision** — ZIP-312: "the specific mechanism for that
   process is outside the scope of this ZIP." The participant auto-signs.

Then `frost_rerandomized::sign_with_randomizer_seed` (non-deprecated API;
participant re-derives α from seed + commitments, hedging coordinator RNG).

### Malicious coordinator (Lane A walkthrough, step by step)

1. Trusted-dealer keygen 2-of-3 (`generate_with_dealer` — the keygen guidance
   ZIP-312 L98/L115 defers to, i.e. RFC 9591 Appendix B/C).
2. Crafts `T_attack` paying the attacker; `msg = SIGHASH(T_attack)`.
3. Round 1: collects the two public commitments.
4. Generates the randomizer via `RandomizedParams::new_from_commitments`
   (honestly — immaterial); sends each participant: α seed, `msg`,
   commitment list, **the real `T_attack` bytes** (no lying needed — the
   checks are syntactic).
5. Collects shares; `frost_rerandomized::aggregate` (verifies shares
   coordinator-side per RFC 9591) → `(R, z)`.
6. Verification: `randomized_verifying_key().verify(msg, sig)` → **OK**.

### F2 variant

Same coordinator code path, different channel-peer label (`A(imposter)`).
Participants' check set is byte-identical; acceptance is identical; the
signature verifies. Demonstrated fact: nothing in the specified checks
distinguishes the real coordinator from an imposter — the "confidential and
authenticated channel" (ZIP-312 L182) has no specified identity model.

## Fidelity notes (honest caveats)

- **Ciphersuite substitution** (code-confirmed): ZIP-312 specifies
  RedPallas/RedJubjub; the PoC uses Ed25519Sha512, which implements
  `RandomizedCiphersuite`. The ceremony mechanics under test
  (commit → sign_with_randomizer_seed → aggregate → verify under VK+αG) are
  ciphersuite-generic — `frost-rerandomized` is generic over
  `C: RandomizedCiphersuite`. A RedPallas instantiation would exercise the
  same code paths with different group arithmetic.
- **SIGHASH stand-in**: SHA-256(tx_bytes) instead of Zcash's real SIGHASH.
  The check under test is syntactic (recompute-and-compare); any
  deterministic hash demonstrates it. Labeled as stand-in in code and log.
- **Channel model**: direct function calls stand in for the
  confidential+authenticated channel. The F2 claim tested is precisely that
  the *specified participant checks* do not consult peer identity — which the
  code demonstrates by construction (the check set never reads `from_label`).
- Deterministic RNGs (seeded ChaCha8) make the run reproducible; this does
  not weaken the finding (randomness quality is orthogonal to the check set).

## Evidence labels (per verify_before_publish/SKILL.md)

| Claim | Label |
|---|---|
| End-to-end walkthrough completes; signature verifies under VK+αG for SIGHASH(T_attack) | **independently reproduced** (executed here, `run.log`) |
| All three specified checks pass on honest participants; none skipped | **independently reproduced** (log shows each check) |
| Imposter coordinator accepted identically | **independently reproduced** |
| Out-of-spec authorization is the only thing that stops it | **independently reproduced** (negative control) |
| frost-core v3.0.0 @ 0966bd1 | **code-confirmed** (`git rev-parse HEAD`) |
| "A conforming implementation performs exactly these three checks" | **consistency-checked** (spec text vs. library code paths) |
| Ciphersuite-genericity of the randomized flow | **code-confirmed** (generic over `C: RandomizedCiphersuite`) |

## What this changes

Lane A's F1 moves from "the spec's checks are insufficient (by reading)" to
"the spec's checks are insufficient (by execution against the reference
implementation's current APIs)." The attack uses only specified behavior, the
coordinator does not even need to lie about the transaction content, and the
composition with F2 removes the need to compromise the real coordinator.
This is the spec-level root of Round 3's implementation-level blind-signing
gap, now demonstrated end-to-end.

Suggested repair (unchanged from Lane A): make sending transaction data a
MUST with minimum content, define "approval" as an explicit required
participant-side authorization decision, and state that auto-signing
implementations do not meet the threat model.
