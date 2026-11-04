# Lane A — ZIP-312 Adversarial Spec Review

*2026-11-04. Research only — nothing published, filed, or sent.*
*Lane: specification review of ZIP-312 (not the implementation). Rounds 1–3 audited the code by execution; this lane attacks the ceremony security model as specified.*

## Method and evidence labels

Per `~/workspace/custom-skills/verify_before_publish/SKILL.md`:

- This lane performed **no code execution**. All claims below are **consistency-checked**: exact quoted text from ZIP-312 compared against exact quoted text from RFC 9591, with the logical consequences walked step by step. Nothing here is labeled "verified" or "independently reproduced."
- Where a claim relies on prior lanes' executed work (Rounds 1–3), it is labeled **as-reported** from that lane.
- Normative FROST citations are to **RFC 9591** (June 2024), the published successor of draft-irtf-cfrg-frost-15. The draft was consulted only via Round 3's prior analysis (as-reported); no claim hinges on a draft-vs-RFC delta.
- Each claim ends **CONFIRMED** (with the exact spec text and, where applicable, the attack walkthrough) or **KILLED** (with the refuting spec text), and is classified per the task taxonomy: (a) genuine spec flaw — the ZIP mandates/permits something unsafe; (b) spec silence pushing security to implementations without stating the consequence; (c) my misunderstanding.

## Corpus read

- ZIP-312 in full (447 lines, fetched 2026-11-04; Status: **Draft**, `Created: 2022-08-dd`, with template remnants — e.g. `{Edit this to reflect the key words that are actually used.}` in Terminology — i.e. spec-level review is timely, the text is not final).
- RFC 9591: §5.2 (round two / `sign` / participant validation), §5.3–5.4 (aggregation, cheater identification), §7 Security Considerations (threat model L1892–1899, §7.7 message validation L2035–2065).
- Round 3 consolidated report (context; blind-signing gap and Noise_K impersonation as-reported from those lanes).

## Reference points (exact quotes used throughout)

**ZIP-312, Threat Model (L87–88):**
> "The Coordinator is trusted with the privacy of the transaction (which includes the unlinkability property). A rogue Coordinator will be able to break unlinkability and privacy, but should not be able to create signed transactions without the approval of `MIN_PARTICIPANTS` participants, as specified in FROST."

**ZIP-312, Round Two (L186–190):**
> "In Zcash, the message that needs to be signed is actually the SIGHASH transaction hash, which does not convey enough information for the signers to decide if they want to authorize the transaction or not. Therefore, in practice, more data is needed to be sent (over the same encrypted, authenticated channel) from the Coordinator to the signers, possibly the transaction itself, openings of value commitments, decryption of note ciphertexts, etc.; and the signers MUST check that the given SIGHASH matches the data sent from the Coordinator, or compute the SIGHASH themselves from that data. However, the specific mechanism for that process is outside the scope of this ZIP."

**ZIP-312, Round Two (L182–184):**
> "In Round Two, the Coordinator generates a random scalar `randomizer` by calling `randomizer_generate` and sends it to each signer, over a confidential and authenticated channel, along with the message and the set of signing commitments. (Note that this differs from regular FROST which just requires an authenticated channel.)"

**ZIP-312, Key Generation (L98 / L115):**
> "Like the FROST specification [3], this ZIP does not specify a key generation procedure; but refer to that specification for guidelines."
> "While key generation is out of scope for this ZIP and the FROST spec [3], it needs to be consistent with FROST, see [9] for guidance." — where [9] is RFC 9591 Appendix B/C, *trusted-dealer* key generation.

**RFC 9591, Security Considerations (L1896 / L1898–1899):**
> "The Coordinator and at most `(MIN_PARTICIPANTS-1)` participants may be corrupted."
> "Note that the Coordinator is not trusted with any private information, and communication at the time of signing can be performed over a public channel as long as it is authenticated and reliable."

**RFC 9591, §5.2 participant validation (L976–983):**
> "The Coordinator begins by sending each participant the message to be signed along with the set of signing commitments for all participants in the participant list. Each participant MUST validate the inputs before processing the Coordinator's request. In particular, the signer MUST validate commitment_list, deserializing each group Element in the list using DeserializeElement… If deserialization fails, the signer MUST abort the protocol. Moreover, each participant MUST ensure that its identifier and commitments (from the first round) appear in commitment_list."

**RFC 9591, §5.2 application input validation (L985–991):**
> "Applications that restrict participants from processing arbitrary input messages are also required to perform relevant application-layer input validation checks; see Section 7.7 for more details."

**RFC 9591, §7.7 (L2035–2043, L2061–2065):**
> "Message validation varies by application… In digital currency applications, wherein multiple participants may collectively sign a transaction, it is reasonable to require each participant to check that the input message is a syntactically valid transaction."
> "In general, input message validation is an application-specific consideration that varies based on the use case and threat model. However, it is RECOMMENDED that applications take additional precautions and validate inputs so that participants do not operate as signing oracles for arbitrary messages."

---

## What a participant actually sees and verifies before contributing a share

Complete inventory, from the two specs combined (consistency-checked). Before running the (randomized) `sign`, a ZIP-312 participant is specified to check exactly:

1. **Commitment list well-formedness** — each Element deserializes; abort otherwise (RFC 9591 L979–981). MUST.
2. **Self-membership** — its own identifier and round-one commitments appear in the list (RFC 9591 L983). MUST.
3. **SIGHASH consistency** — the SIGHASH matches the accompanying data, or the signer recomputes the SIGHASH from that data itself (ZIP-312 L188–190). MUST — *conditional on data being sent* (see F1).
4. **Application-layer input validation** — only via RFC 9591's general hook (L985–991, §7.7 RECOMMENDED anti-signing-oracle precautions). ZIP-312 instantiates none of it.

**Not specified anywhere in ZIP-312:** any check on the randomizer α (opaque by construction — participants cannot recompute it, the coordinator's `rng_randomizer` is secret, L156–166); any authorization/approval decision procedure or its required properties; any authentication of *who* the coordinator is beyond the bare word "authenticated"; any session/ceremony identifier or transcript binding across rounds; any policy whatsoever on transaction content. The word "approval" (threat model L88) is never defined.

---

## Findings

### F1 — CONFIRMED (class b, high teeth): the threat model's anti-rogue-coordinator guarantee is not delivered by the specified mechanisms

**The guarantee** (ZIP-312 L87–88): a rogue coordinator "should not be able to create signed transactions without the approval of `MIN_PARTICIPANTS` participants, as specified in FROST."

**Why it does not transfer.** "As specified in FROST" invokes RFC 9591's unforgeability: adversary = corrupt coordinator + ≤ t−1 corrupt participants cannot forge (RFC L1896). In that model, "approval" means *share contribution by an uncorrupted participant*, and uncorrupted participants are expected to also perform application-level message validation (RFC L985–991; §7.7's RECOMMENDED anti-oracle precautions). ZIP-312 then introduces a message-opacity problem FROST does not have: the message is a SIGHASH which "does not convey enough information for the signers to decide if they want to authorize the transaction or not" (ZIP L186–187). Its repair (ZIP L187–190) has three structural defects:

1. **The extra data is not actually required.** "More data is needed to be sent" is stated as a practical necessity ("in practice"), not as an RFC 2119 requirement — and the ZIP's Terminology section (L30–31) explicitly adopts RFC 2119 keywords, so a bare "needed" is descriptive, not normative. What data ("possibly the transaction itself") is likewise optional even descriptively.
2. **The MUST check is syntactic and conditional.** "The signers MUST check that the given SIGHASH matches the data sent" — a consistency check, not an authorization check. If the coordinator sends only the SIGHASH, there is no data to check against and the MUST is vacuous; "or compute the SIGHASH themselves from that data" is impossible without the data.
3. **The authorization decision itself is unspecified.** "The specific mechanism for that process is outside the scope of this ZIP" — no decision procedure, no required properties, no definition of "approval."

**Consequence:** a fully conforming implementation — satisfying every MUST/SHOULD in ZIP-312 — can operate as a **signing oracle** for a malicious coordinator. The attack walkthrough below uses only specified behavior. The delegation to applications is explicit ("outside the scope"), but its security consequence — *conformance does not imply the threat-model guarantee, and the guarantee's operative term is undefined* — is never stated. That unstated consequence is precisely class (b).

**Attack walkthrough — malicious coordinator + the blind-signing gap (consistency-checked, no execution):**
Setup: 2-of-3; coordinator C malicious; honest P1, P2 run conforming participant software that performs exactly the specified checks and then signs (e.g. a server-side cosigner — precisely the ZIP's own motivating deployment, "users and third-party services sharing custody of a wallet," Motivation L50–52).

1. C crafts `T_attack` paying C; computes `SIGHASH(T_attack)`.
2. Round 1: P1, P2 send commitments to C (RFC §5.1, unmodified by the ZIP).
3. Round 2: C computes α = `randomizer_generate(...)` (honestly or not — immaterial), and sends each Pi, over the confidential+authenticated channel: α, `msg = SIGHASH(T_attack)`, the commitment list, and the bytes of `T_attack`.
4. Each Pi verifies: commitments well-formed and self present (RFC L979–983 ✓); recomputed SIGHASH matches `msg` (ZIP MUST ✓). **No other check is specified.** Pi computes `z_i = d_i + e_i·ρ_i + λ_i·c·(sk_i + α)` and returns it.
5. C verifies the shares (valid), aggregates → `(R, z)` valid under `VK + αG` for `SIGHASH(T_attack)` (ZIP Rationale L322–333 mechanics). C publishes `T_attack`.

Result: a valid, signed, attacker-chosen transaction; every specified check passed. Note the composition subtlety: **C does not even need to lie** — it shows the real attack transaction, and the spec's checks are syntactic, so content-honesty is no defense. The only defense is participant software making an authorization decision the specification never requires.

**Hostile objections, answered:**
- *"RFC 9591 already leaves message validation to applications (§7.7, RECOMMENDED); a ZIP can't specify UIs."* — Conceded: UIs are out of scope. The finding is not "the ZIP lacks a UI spec." It is that the ZIP (i) introduces a message-opacity problem FROST doesn't have, (ii) phrases its threat model as a guarantee in "approval" language, (iii) leaves the operative term undefined and its enforcement unrequired. RFC 9591 is the honest one here: it RECOMMENDS anti-oracle precautions and never promises coordinator-resistance in approval language. The ZIP promises more and specifies less; the delta is the finding.
- *"‘More data is needed to be sent' is clearly intended as a requirement."* — In a document with an RFC 2119 Terminology section, bare "needed" in an "in practice" sentence is not a requirement; and the walkthrough works even when data *is* sent (step 3 sends the real `T_attack` bytes — the syntactic check passes).
- *"A rogue coordinator is inside FROST's model and unforgeability holds."* — Unforgeability holds against forgery *without* t shares. This attack obtains t shares from honest participants running conforming software; it doesn't break unforgeability, it bypasses the approval premise the threat model layers on top. FROST's theorem never claimed protection against honest participants signing attacker-presented messages; the ZIP's threat-model sentence does, in "approval" language.
- *"This is just Round 3's blind-signing gap."* — Round 3 documented it at **implementation** level (frostd/zcash-sign don't bind signing context; as-reported). This lane's result is strictly stronger: **the gap survives full, faithful implementation of the specification.** That reclassifies it from "demo code didn't implement the check" to "the specification's checks are insufficient to deliver its own threat-model guarantee" — the spec-level, grant-relevant form.

**Suggested repair (concrete):** make the data-sending a MUST with minimum content requirements (the transaction bytes sufficient to recompute the SIGHASH); define "approval" as an explicit, required participant-side authorization decision with minimum properties (e.g. the decision must be a function of the full transaction semantics, not just SIGHASH consistency); and state plainly that implementations whose participants auto-sign after the syntactic check do not meet the threat model.

### F2 — CONFIRMED (class b, softer): no identity model for the "confidential and authenticated channel"

ZIP-312 L182 requires the coordinator→signer channel to be "confidential and authenticated" but specifies no identities, no authentication mechanism, no binding between a FROST identifier `i` and a channel peer, no session identifier, and no transcript binding across rounds.

- **Consequence 1 (live via F1):** "authenticated" is satisfiable by channel constructions with weak or no peer-identity verification. A network attacker accepted as coordinator feeds participants attacker-chosen transactions — F1 fires with no compromise of the real coordinator. This is the spec-level root of Round 3's Noise_K impersonation finding (as-reported): an implementation instance of this exact silence.
- **Consequence 2 (bounded):** no session binding means cross-ceremony confusion is unspecified — but it is **fail-closed for forgery**: each share commits to the exact `(commitment_list, msg)` the participant saw (binding factors via `compute_binding_factors(group_public_key, commitment_list, msg)`; challenge via `compute_challenge(group_commitment, group_public_key, msg)` — RFC §5.2 L1035–1063), so equivocated views do not combine into a valid signature (RFC L1177–1179: "subsets of valid signature shares will not yield a valid aggregate signature"; coordinator MUST abort on invalid shares, L1097–1099). Residual is liveness/griefing, which FROST explicitly concedes (RFC L1901–1903, L1915–1917).

**Hostile objection:** *"FROST also just says ‘authenticated' (RFC L1898–1899) — inherited, standard."* — True, but ZIP-312 makes the channel load-bearing for *more*: confidentiality of α is a ZIP-added requirement (L182–184 explicitly notes the deliberate difference from FROST), because α secrecy ↔ unlinkability. The silence is inherited; the stakes are raised. Class (b), softer than F1.

### F3 — CONFIRMED (class b): threat model enumerates coordinator and participants but not the key-generation phase it defers to

- ZIP-312 L98/L115: key generation out of scope; "needs to be consistent with FROST, see [9] for guidance" — and [9] is RFC 9591's **trusted-dealer** appendix. So the ZIP's only normative keygen guidance installs a dealer who learns the full `ask`.
- The Zcash-specific threat model (L85–91) analyzes rogue coordinator and rogue share-holders only. Dealer compromise = full `ask` recovery = total spend authority, yet the dealer appears nowhere in it, and the model's guarantee ("should not be able to create signed transactions without the approval of MIN_PARTICIPANTS") is false under dealer corruption — a party the ZIP's own guidance creates.
- **Hostile objection:** *"Keygen is explicitly out of scope in both specs; you can't fault a threat model for out-of-scope phases."* — RFC 9591 lists "signer key shares are generated and distributed securely" as an explicit security assumption (L1892). The ZIP dropped that assumption-listing while adding a Zcash-specific threat model. The precise, quotable gap: the threat model should scope its guarantee with the secure-keygen assumption, or enumerate the dealer. It does neither.

### F4 — KILLED: coordinator-generated randomizer breaks the Rationale's uniformity claim → no integrity impact

- The Rationale (L335–338) claims `randomizer_generate` produces α "uniformly at random as required by `RedDSA.GenRandom`." Under the threat model's own rogue coordinator, α is adversarially chosen — the uniformity premise fails exactly in the contemplated adversarial case.
- **Kill:** the consequences are linkability/privacy only, which the threat model explicitly concedes to a rogue coordinator (L87–88: "will be able to break unlinkability and privacy"). No forgery amplification exists: α is an additive key offset visible to all signers; choosing it gives the coordinator no signing power it lacks (it doesn't know `sk`); per-participant α equivocation is fail-closed at share verification/aggregation (RFC L1097–1099 coordinator MUST abort on invalid share; L1171–1179 invalid subsets don't aggregate). Refuting text: ZIP L87–88 concession + RFC L1097–1099 + L1177–1179.
- Noted tension (not a finding): the Rationale's unlinkability argument assumes honest generation by the distrusted party; consistent only via the privacy concession.

### F5 — KILLED: mid-ceremony coordinator compromise grants new powers

- **Kill:** compromise yields exactly the static corrupt-coordinator powers RFC 9591 already models (L1896: "The Coordinator and at most (MIN_PARTICIPANTS-1) participants may be corrupted"). In-flight shares are bound to the ceremony's `(commitment_list, msg)` via binding factors and challenge (RFC §5.2 `sign()`, L1035–1072); the attacker cannot retarget them to a new message (new challenge → old shares invalid), cannot complete a different ceremony's aggregate, and learns α → linkability of this transaction only (conceded, ZIP L87–88). No new capability; the spec's silence is covered by FROST's model.

### F6 — KILLED: commitment-list equivocation across participants yields forgery or confused-deputy signing

- **Kill:** fail-closed, per F2's Consequence 2 analysis. Shares bind to the exact list each participant saw; equivocated views don't combine (RFC L1177–1179); the coordinator's own verification catches it (RFC L1097–1099, L1171–1175). No participant-side cross-check is needed for unforgeability. (This also kills the "session confusion → attacker-chosen transaction" variant: to get a share on `T_attack` the coordinator must present `T_attack` or a SIGHASH collision — which reduces to F1.)

### F7 — KILLED: `encode_signing_package` MAY-alternative encodings create interop/safety risk

- ZIP L127–129 permits implementations to choose their own unambiguous encoding of `(msg, commitment_list)` inside `randomizer_generate`.
- **Kill:** α is generated by one coordinator per ceremony and consumed opaquely by participants — they cannot recompute it (coordinator's `rng_randomizer` is secret, L156–166), and no cross-implementation verification of α exists. Divergent encodings therefore have no interop or security consequence; the binding properties the ZIP needs (freshness, commitment-binding) hold for any unambiguous encoding.

### F8 — KILLED: coordinator abort / selective subset / share withholding as spec flaw

- **Kill:** liveness only. FROST's DoS posture is explicit and inherited honestly: security against DoS assumes a non-DoS coordinator (RFC L1901–1903); robustness is explicitly not a goal (L1915–1917). The coordinator's power to choose the signing subset (RFC L969–970) and withhold aggregation is within the conceded model. No funds-at-risk.

### F9 — noted, KILLED as flaw: `ask`-derivation vs DKG deployment tension

- ZIP L116–119: `ask` is "usually derived from the spending key `sk`, though that is not required. Not doing so allows using distributed key generation, since the key it generates is unpredictable. Note however that not deriving `ask` from `sk` prevents using seed phrases to recover the original secret."
- Operational consequence the text doesn't draw: for signatures to authorize an *existing* Zcash account, `ask` must be that account's `ask`; DKG's unpredictable key therefore forces either fund-a-new-account or trusted-dealer resharing of the existing key — compounding F3 (the dealer learns the full `ask` at setup). The text is honest about the seed-recovery half; KILLED as a spec flaw, kept as a deployment consideration.

### F10 — KILLED: non-requirements contradict the unlinkability goal

- L94 (no coordinator removal) and L96 ("does not prevent key share holders from linking the signing operation to a transaction in the blockchain") are honest scoping. The Abstract's unlinkability requirement vs L96 is consistent because the threat model explicitly trusts holders with privacy (L90). No contradiction.

---

## Composition matrix (spec-level)

| Composition | Result |
|---|---|
| F1 × malicious/compromised coordinator (threat-model's own scenario) | **Valid signatures on attacker-chosen transactions from honest, conforming participants.** The ZIP's central guarantee defeated within the letter of the spec. |
| F1 × F2 (channel impersonation, no coordinator compromise) | Same outcome without touching the real coordinator — widens the attacker population to network position. |
| F1 × Motivation deployment ("users and third-party services sharing custody," L50–52) | The vulnerable deployment is the ZIP's *motivating* one, not an exotic corner: the third-party service is coordinator, the user's devices are auto-signing co-signers. |
| F1 × proof-generator colocation (threat model L78–80: tx creator = coordinator = participant) | The party presenting the transaction for "approval" is the party whose transaction it is; "approval" by the other participants is vacuous by construction when they auto-sign. |
| F4 × rogue coordinator | Privacy/linkability break only — already conceded (L87–88). No escalation. |
| F5/F6 × corrupt coordinator | Covered by FROST's model / fail-closed. No escalation. |

## Verdict

- **One substantive spec-level finding: F1 (class b).** ZIP-312's threat model promises that a rogue coordinator "should not be able to create signed transactions without the approval of MIN_PARTICIPANTS participants," but the specification (i) never defines "approval," (ii) requires only a syntactic, conditional SIGHASH-consistency check whose trigger (sending transaction data) is not itself a requirement, and (iii) explicitly leaves the authorization mechanism "outside the scope of this ZIP." A fully conforming participant implementation can therefore operate as a signing oracle, and the full attack walkthrough uses only specified behavior. This elevates Round 3's implementation-level blind-signing gap to its spec-level root: **even a perfect implementation of ZIP-312 does not deliver the ZIP's own threat-model guarantee.**
- **Two supporting class-(b) findings: F2** (no identity/session model for the load-bearing confidential+authenticated channel — the spec root of Round 3's Noise_K impersonation) and **F3** (threat model omits the key-generation/dealer phase its own guidance creates).
- **Seven killed** (F4–F10) with refuting text, including the two most tempting overclaims (randomizer-uniformity vs rogue coordinator; mid-ceremony compromise).
- **Not a cryptographic break.** The FROST core (unforgeability with corrupt coordinator + t−1 corrupt participants) is untouched; the finding is a spec-assurance gap at the ceremony/authorization layer. Impact if realized is nevertheless total for the affected wallet: valid signatures on attacker-chosen transactions = full spend authority up to the wallet balance, in the ZIP's own motivating deployment.
- **Grant relevance:** F1 is production-grade by this task's definition (a spec flaw changes the narrative, not just the code), it is novel relative to Rounds 1–3 (they showed the code doesn't bind context; this shows the spec doesn't require it), and it comes with a concrete, quotable repair. F2/F3 are honest hardening notes for the same spec revision.

## What would strengthen this lane

- Demonstrating a *conforming* auto-signing participant against the reference implementation (frost-rerandomized + a minimal coordinator) executing the F1 walkthrough end-to-end would promote F1 from consistency-checked to independently reproduced. That is implementation work belonging to a follow-up lane, not this spec review.
- A line-by-line diff of draft-irtf-cfrg-frost-15 §7 against RFC 9591 §7 was not performed; no claim above depends on it (all FROST citations are to the published RFC).
