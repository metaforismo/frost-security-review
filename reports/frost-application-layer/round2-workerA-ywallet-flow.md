# Round 2 — Worker A: FROST integration in the real wallet flow (Zcash)

*Depth audit, 2026-10-17. Static analysis + live verification of repos and docs. No disclosure, no submission.*
> These are historical working notes. See [ERRATA-AND-EVIDENCE.md](../../ERRATA-AND-EVIDENCE.md) for corrections and the distinction between source observations and deployment claims. The initial Ywallet transaction-planning UI can display transaction details; the opaque-hex concern is about the later CLI signing-confirmation steps. The signing-oracle risk had already been raised in upstream [#333](https://github.com/ZcashFoundation/frost-tools/issues/333) and [#475](https://github.com/ZcashFoundation/frost-tools/issues/475); the trace below is not a novel vulnerability report.

*Scope: ywallet (hhanh00/zwallet @ `865dc0e`), Zallet (zcash/zallet @ main 2026-10-17), frost-tools (ZcashFoundation/frost-zcash-demo @ `53df99c`), ZF FROST Book, OpenPGP Wallet forum design.*

**Revised scope:** searches of the named wallet snapshots did not find a complete FROST signing flow. The documented Ywallet JSON-plan route into `zcash-sign` appears disabled in the reviewed source, while a separate external-PCZT CLI signing route displays opaque hex at later signer confirmations. This is a design observation for those tools, not proof that all wallet checkpoints are blind or that no deployment exists. No production wallet exploit was demonstrated.

---

## 1. ywallet: no hidden FROST — verified

Repo: `~/workspace/hunt/frost-client-audit/ywallet` @ `865dc0e` ("Update README to reflect Zcash deprecation (#274)").

Full-repo case-insensitive grep for `frost|threshold|shamir|\bdkg\b|multisig` over all tracked files (Dart, Rust, Kotlin/Java, Swift, configs):

| Match | Location | Verdict |
|---|---|---|
| "Automatic shielding above configurable **threshold**" | `README.md:45` | Balance threshold for auto-shielding. Unrelated. |
| `supportsMultisig` getter | `lib/coin/coin.dart:32` (+ `ycash.dart`, `ycashtest.dart` = true; `zcash.dart`, `zcashtest.dart` = false) | Declared but **never read** anywhere in `lib/` — dead capability flag (transparent P2SH-style multisig concept, not threshold crypto). |
| pack-file hit | `.git/objects/pack/*.pack` | Compressed copy of the README match above. |
| `welcome.png` | `assets/` | Binary false positive. |

Additional sweeps, all **zero hits**:
- `secret.?shar|shamir|distributed.?key|threshold.?sig` over `lib/ rust/ android/ ios/`
- `pczt` over `lib/ rust/` — ywallet neither produces nor consumes PCZTs
- `git log --all -S 'frost' -i` — no commit in history ever touched FROST (only the README line at HEAD)
- The 5 Rust files (`rust/src/api/*`, `db.rs`, `lib.rs`, `frb_generated.rs`) are the `flutter_rust_bridge` WarpApi binding — no crypto beyond what WarpApi exposes

**Confirmed: ywallet has no FROST code in any language, no FFI threshold path, no PCZT handling.**

### What ywallet *does* provide (the actual integration surface)

Ywallet's offline-signing UI is the entire touchpoint, all in `lib/pages/accounts/`:

1. **Plan (human-readable — the only such checkpoint in the whole flow):** `TxPlanPage` (`txplan.dart`) renders `WarpApi.transactionReport(coin, plan)` — amounts, recipients, fee — and offers the snowflake button → `ExportUnsignedTxPage` (`submit.dart`) → floppy-disk → saves the **JSON plan** to file (`exportRaw` → route `/account/export_raw_tx`).
2. **Broadcast (blind):** "More → Broadcast" → `SubmitTxPage(txBin:)` → `WarpApi.broadcast(coin, txBin)` — broadcasts a raw hex tx with **zero content verification and zero linkage to the exported plan**. Any bytes broadcast.

So Ywallet's role is: view-only account from the FROST group's UFVK → user builds a tx against it → sees a readable plan → exports JSON → (external signing happens) → pastes back raw signed bytes → broadcast. Ywallet never checks that the broadcast bytes correspond to the plan it displayed.

---

## 2. Zallet: no FROST — verified

Repo: `zcash/zallet` ("An RPC wallet designed to replace the deprecated `zcashd` embedded wallet"), main tarball 2026-10-17. (Note: `ZcashFoundation/zallet` 404s — the correct repo is `zcash/zallet`.)

- `frost|shamir|\bdkg\b` over all `.rs/.toml/.md`: hits only in `supply-chain/config.toml`, `deny.toml`, `backends/zebra/supply-chain/config.toml`.
- `supply-chain/config.toml:500-504`: `[[exemptions.frost-core]]` / `[[exemptions.frost-rerandomized]]` — cargo-deny **license exemptions**, not usage.
- `deny.toml:29`: `{ name = "bc-shamir", allow = ["BSD-2-Clause-Patent"] }` — preemptive license allow; `bc-shamir` is **not** in `Cargo.lock` (zero functional presence).
- Reverse-dep walk of `Cargo.lock`: `frost-core 3.0.0` and `frost-rerandomized 3.0.0` are pulled **only** by `reddsa 0.5.2`'s `frost` module (RedPallas signature support — the same reason any Orchard wallet transitively depends on frost crates).
- `threshold|multisig` hits in `.rs`: chain-sync `lock_threshold`, `TX_EXPIRING_SOON_THRESHOLD` — unrelated.
- Zero occurrences of `reddsa::frost` or `frost::` paths in zallet's own source.

**Confirmed: Zallet has no FROST threshold-signing code paths. The frost crates are transitive via reddsa, same as any Orchard-capable wallet.**

---

## 3. The real architecture (as of HEAD) — and the stale-book gap

### 3a. What the FROST Book documents

`https://frost.zfnd.org/zcash/ywallet-demo.html` (fetched live 2026-10-17) documents:

1. DKG/trusted-dealer → 2-of-3 group → `zcash-sign generate --ak <ak>` → UFVK → import into Ywallet as view-only account.
2. Fund the Orchard address. Build tx in Ywallet → plan screen → snowflake → floppy disk → save **`tx-plan.json`**.
3. `zcash-sign sign --tx-plan tx-plan.json --ufvk <ufvk> -o tx-signed.raw` → prints `SIGHASH` + `Randomizer`, prompts for signature.
4. `frost-client coordinator … -m - -r -` ← paste sighash + randomizer; `frost-client participant` on two terminals → y/n each → aggregate → paste sig back into `zcash-sign`.
5. Ywallet "More → Broadcast" the raw file.

### 3b. What HEAD actually does — the flow is broken at step 3

Commit `36df5d2` ("zcash-sign: add PCZT support (#574)", 2026-05-20) **disabled the Ywallet path**:

- `zcash-sign/src/main.rs`: `sign` tries `Pczt::parse(&tx_plan)`; on failure parses as Ywallet JSON → `Input::YwalletTxPlan` → `sign()` match arm hits `#[cfg(false)] sign_ywallet(...)` → **`Err("Ywallet signing is disabled")`**.
- `zcash-sign/src/sign_ywallet.rs`: `#![cfg(false)]` — entire module compiled out (276 lines dead).
- Workspace-wide grep: **no** `pczt::roles::{creator,constructor,updater,combiner}` usage anywhere; `frost-client` and `frostd` never touch `pczt` at all.

**There is no JSON-plan → PCZT constructor anywhere in the ZF stack.** The Book's `tx-plan.json` step cannot work with HEAD `zcash-sign`. The documented Ywallet demo flow is stale since #574 (May 2026).

The flow that *does* run in HEAD:

```
[external PCZT producer — NOT in this repo]          (Constructor role, ZIP 374)
        │  PCZT file (out-of-band: USB, QR, file…)
        ▼
zcash-sign sign --tx-plan <pczt>                     (Signer-1 / assembler operator)
  ├─ sighash_for_pczt(): prints "SIGHASH: <hex>"
  ├─ prints "Randomizer #<i> (<pool>): <hex>" per spend
  └─ prompts "Input hex-encoded signature #<i> (<pool>):" per spend
        │  operator pastes sighash+randomizers into coordinator…
        ▼
frost-client coordinator -m <sighash-hex> -r <alpha-hex>   (untrusted relay via frostd)
        │  SigningPackage{commitments, message=sighash} per participant
        ▼
frost-client participant  × N                        (each: "Message to be signed
        │   (hex-encoded):\n<64 hex>\nDo you want to sign it? (y/n)")
        │  signature shares → coordinator aggregates
        ▼
operator pastes aggregate sig into zcash-sign
  └─ apply_signature(): verifies each sig against (rk_spend from PCZT, sighash)
        │  writes raw tx bytes
        ▼
Ywallet "More → Broadcast"  (or any node) — WarpApi.broadcast, no checks
```

Note the irony: `zcash-sign`'s `--tx-plan` flag still *names* the Ywallet plan, but only accepts a PCZT. The "Ywallet integration" today is: Ywallet as a **dumb broadcast pipe** for bytes it never inspected.

---

## 4. Per-handoff verification matrix

| # | Handoff | Receiver verifies | Receiver assumes (takes for granted) |
|---|---|---|---|
| 1 | Ywallet plan screen → exported `tx-plan.json` | Human sees amounts/recipients/fee in `transactionReport` | That whatever is later signed matches this plan — **no cryptographic binding** (JSON has no sighash; nothing downstream reads it) |
| 2 | (missing) JSON plan → PCZT | — | **No converter exists.** Whoever builds the PCZT does so with unaudited, out-of-repo tooling |
| 3 | PCZT file → `zcash-sign` operator | `sighash_for_pczt` recomputes the sighash from the PCZT's effects (v5/v6 dispatch pinned by test); `apply_signature` verifies each returned signature against **(rk_spend read from the PCZT, sighash)** — replay onto a different spend fails (different rk), wrong-tx sig fails (different sighash) | That the PCZT file on disk is the transaction the user *intended*. The operator is shown **only** `SIGHASH: <hex>` + `Randomizer #i (<pool>): <hex>` — no amounts, recipients, fee. A substituted PCZT is indistinguishable at this checkpoint |
| 4 | `zcash-sign` stdout → coordinator stdin | Coordinator operator pastes hex strings | That the pasted sighash/alpha correspond to the honest PCZT. The coordinator accepts **arbitrary 32-byte messages and arbitrary randomizers** (`read_messages`/`read_randomizers` from file or stdin hex, no validation, no display) |
| 5 | Coordinator → participant (via frostd) | FROST lib: PoK/identifiers, share validity | **Human:** nothing. `confirm_message` (cli.rs:127, http.rs:313, socket.rs:140) prints `Message to be signed (hex-encoded):\n<hex>\nDo you want to sign it? (y/n)`. The **randomizer is not even displayed**. A sighash is computationally hiding — no human can distinguish the honest 64 hex chars from an attacker's |
| 6 | Signed raw tx → Ywallet broadcast | Nothing. `WarpApi.broadcast` sends bytes | That the bytes are the tx the user planned. No plan↔tx linkage |

**Net: exactly one human-readable checkpoint exists (Ywallet's plan screen), and it is cryptographically disconnected from everything downstream. Every signing checkpoint is opaque hex.**

---

## 5. FOCUS — blind-signing composition: the malicious-coordinator diversion

### 5a. Sighash trace, end to end

1. PCZT → `sighash_for_pczt` (`zcash-sign/src/sign.rs:66`): `into_effects()` → `TxIdDigester` → v5/v6 `signature_hash(Shielded)` → 32 bytes. Printed as hex.
2. Per-spend `alpha` extracted from the PCZT (`collect_randomizers`), printed as hex. These alphas are the rerandomization scalars: each spend's `rk = ak·alpha` is already committed in the PCZT.
3. Coordinator (`frost-client/src/coordinator/cli.rs:45`): `SigningPackage::new(commitments, message)` with the pasted message; `frost_rerandomized::RandomizedParams::from_randomizer(randomizer, pubkeys)` with the pasted alpha.
4. Participant (`participant/cli.rs` → `comms.confirm_message`): sees `hex(message)` only → y/n → `round2::sign` / `frost_rerandomized::sign` with the **coordinator-supplied** randomizer.
5. Coordinator aggregates → RedPallas sig valid under `RK = RandomizedPubkey(ak, alpha)`.
6. `apply_signature` (`sign.rs:177`): `redpallas::Signature::from(sig)` checked against `(rk_spend, sighash)` **read from the PCZT the operator loaded**. This is the one real backstop — but see below.

### 5b. The diversion (no crypto broken)

Threat model: coordinator is malicious (or compromised); two honest participants hold shares. This is squarely ZIP 312's motivating scenario ("a group of people managing shared funds").

1. Attacker picks `alpha'_i` per spend, computes `rk'_i = ak·alpha'_i` (`ak` = group pubkey, public).
2. Attacker builds **PCZT_A** paying themselves, embedding `rk'_i` as the spends' randomized keys. (Building a PCZT is unauthenticated — ZIP 374 has Creator/Constructor roles with no trust assumptions.)
3. Attacker-as-coordinator sends `message = sighash(PCZT_A)`, `randomizer = alpha'_i` to Alice and Bob.
4. Alice and Bob see 64 hex chars + `y/n`. They type `y` — they **cannot** distinguish `sighash(PCZT_A)` from `sighash(PCZT_honest)`. The veto is informationally vacuous.
5. Attacker aggregates → signatures valid under `rk'_i`.
6. Attacker loads PCZT_A into `zcash-sign` (or is the assembler): `apply_signature` verifies `(rk'_i, sighash_A)` — **passes**. Raw tx written, broadcast. Funds diverted.

**Who would notice? Nobody.** Not the participants (blind hex), not `zcash-sign`'s checks (they verify self-consistency of the attacker's PCZT, not intent), not Ywallet's broadcast (no checks at all), not frostd (opaque relay).

### 5c. Why the existing checks don't save you

- **FROST unforgeability** holds — the attacker never forges; the victims *willingly sign* the attacker's message. The protocol's guarantee ("coordinator can't forge messages signers didn't sign") is satisfied and irrelevant.
- **`apply_signature`'s (rk, sighash) check** (Round 1's "crypto closes the real holes") binds the signature to *the PCZT the assembler loaded* — it does not bind the PCZT to *user intent*. If assembler = attacker, it verifies the attack. If assembler is honest but the PCZT file was substituted before loading (step 3's blind checkpoint), the honest assembler unknowingly assembles the attacker's tx.
- **The y/n prompt** exists to give humans a veto, but displays a computationally-hiding value. Defense-in-depth credit: zero.

### 5d. Honest-but-fragile variants (no malice needed)

- **Stale-book operator error:** following the Book with HEAD tools fails closed ("Ywallet signing is disabled") — annoying, not dangerous.
- **Wrong-file assembly:** an honest assembler with two PCZTs (e.g. `tx-a.pczt`, `tx-b.pczt`) cannot tell which sighash belongs to which intent — both print as hex. Signing the wrong one produces a *valid, broadcastable* transaction the user didn't want. `apply_signature` passes (self-consistent), participants already said y.
- **Coordinator alpha substitution:** participants never see the randomizer, so a coordinator that pairs the honest sighash with wrong alphas produces signatures that fail `apply_signature` — fail-closed, but only detected at assembly, after two humans already authorized.

---

## 6. OpenPGP Wallet — the correct comparison model

Forum: ["FROST 2-of-3 between a user's own devices for shielded ZEC (Ironwood)"](https://forum.zcashcommunity.com/t/frost-2-of-3-between-a-users-own-devices-for-shielded-zec-ironwood/58164) (Khadim, ~2026-10-14, 3 days before this audit).

- **Status: design only.** "Code will be published open source in the coming weeks. Nothing has been audited by an independent firm yet." White paper v0.2 PDF published; project site confirms "Design settled. Development ahead." **No public code to audit.**
- **The model** (the right one): the phone is the second signer **and the trusted screen**. Signing flow: computer commits → derives α → builds the PCZT (ZIP 374) → signs its share → phone **decodes and checks the transaction and the computer's share itself, then co-signs**. The phone runs the **ZIP 374 signer checks**: nullifiers against the FVK, `cmx` against `recipient`/`value`/`rseed`, `user_address` against `recipient` — and **refuses redacted PCZTs**. Site copy: *"The phone shows the real recipient and the real amount, even if the computer lies."*
- Notably, their interim randomizer approach (builder picks α, external-randomizer path `ZcashFoundation/frost#1094` until `zcash/orchard#571`) mirrors what `zcash-sign` does — but the phone's independent PCZT verification is what makes it safe.

### Gap table: Ywallet+frost-client vs OpenPGP Wallet model

| Property | Ywallet + frost-client (HEAD) | OpenPGP Wallet (design) |
|---|---|---|
| Signer sees amounts/recipients | **No in the reviewed CLI signing confirmations** — sighash/message hex; the earlier Ywallet planning UI can display details | Yes — native confirmation screen on the phone |
| Independent per-signer tx verification | **No** — only the PCZT builder (out-of-band) ever sees content | Yes — phone re-parses PCZT, runs ZIP 374 signer checks |
| Redacted-PCZT policy | No concept (signer can't inspect anyway) | Refused |
| Binding: what-you-saw ↔ what-you-signed | **None** — plan screen disconnected from sighash | Phone signs the exact PCZT it displayed |
| Coordinator trust required | Total (message + randomizer, arbitrary) | None — no server, no third-party coordinator; QR E2E channel |
| Malicious-coordinator diversion | **Undetectable** (§5b) | Phone would display the attacker's recipient/amount → user declines |

**The gap is the entire WYSIWYS layer.** frost-client would need, per participant: receive the full PCZT (not just the sighash), parse it, render amounts/recipients/fee human-readably, and run the ZIP 374 signer checks against the group's viewing key *before* the y/n prompt. That is precisely the `TODO: replace with callback` in `http.rs:confirm_message` — currently a stub that shows hex.

---

## 7. Other findings (minor)

1. **Stale documentation (design gap, low):** the FROST Book's Ywallet demo page still instructs `zcash-sign sign --tx-plan tx-plan.json` with a JSON file; HEAD rejects it. Anyone following the official tutorial hits a dead end. The Book should be updated to the PCZT-only flow (or the JSON→PCZT constructor should be specified — currently it exists nowhere).
2. **`--tx-plan` flag name is now misleading** (`args.rs`): it accepts a PCZT, and its help text still says "The file containing the JSON Ywallet transaction plan".
3. **Ywallet `supportsMultisig` dead flag** (`lib/coin/coin.dart:32`): declared, never read — not FROST-related, noted for completeness.
4. **No quantum-recoverability concern introduced** by this flow beyond what Round 1 noted (`generate.rs` dummy-sapling path is explicit and documented).

---

## 8. Final verdict

- **ywallet:** no FROST code, any language, any bridge. Confirmed by exhaustive grep + git history. Its only role is plan-display (human-readable, disconnected) and blind broadcast.
- **Zallet:** no FROST signing code. frost crates are transitive via `reddsa 0.5.2` only.
- **Real flow (HEAD):** external PCZT → `zcash-sign` (blind hex checkpoints) → `frost-client` coordinator/participants (blind hex + vacuous y/n) → `zcash-sign` assembly (`apply_signature` = self-consistency only) → blind broadcast. The Book's Ywallet-JSON step is dead since #574.
- **Composition gap (the finding):** a malicious coordinator can substitute an arbitrary PCZT; honest co-signers cannot detect it — the sighash is computationally hiding and no participant ever parses the transaction. Full diversion path traced in §5b. Crypto intact; WYSIWYS absent.
- **Production impact:** no production wallet exploit was demonstrated in the reviewed snapshots; deployment-wide absence was not established. The documented Ywallet path appears disabled in the reviewed source. Per task protocol: **no private draft, no STOP**. This is a demo-tooling design gap that must be closed (per-signer PCZT parsing + ZIP 374 signer checks before the y/n prompt, à la OpenPGP Wallet's phone model) before any production integration carries real funds.

*Files referenced: `~/workspace/hunt/frost-client-audit/ywallet` @865dc0e, `/tmp/zallet-main` (zcash/zallet main, 2026-10-17), `~/workspace/hunt/frost-client-audit/frost-tools` @53df99c. Prior reports: `~/workspace/bounty/reports/zcash-audit/frost-client/AUDIT-REPORT-2026-10-17.md`, `dkg-zcashsign-audit.md`.*
