# Deep Audit — FROST v3 / ZIP-312 / DKG (RedPallas)

*Audit crittografico profondo, 2026-10-17. NESSUNA submission, NESSUNA disclosure — solo analisi.
Report privato per coordinazione parent.*

## Target

| Componente | Versione / commit |
|---|---|
| `ZcashFoundation/frost`, `frost-core` | **v3.0.0** (`0966bd1`) |
| `frost-rerandomized` | v3.0.0 (workspace) |
| RedPallas/RedJubjub FROST ciphersuite (`reddsa`) | pre-rimozione, commit `3a1533b` (frost rimosso da reddsa il 25/09/2026, in migrazione verso repo `frost`) |
| ZIP-312 | Draft (zips.z.cash/zip-0312) |
| RFC 9591 | FROST standard di riferimento |

File analizzati integralmente: `frost-core/src/{round1,round2,lib,signature,keys,keys/dkg,keys/refresh,keys/repairable,identifier,traits,signing_key}.rs`, `frost-rerandomized/src/lib.rs`, `reddsa@3a1533b:src/frost/{redpallas,redjubjub}.rs` + `rerandomized.rs` + `keys/dkg.rs`, `frost-secp256k1-tr/src/lib.rs` (hook custom, per confronto), CHANGELOG.

## Verdetto

**NESSUN FINDING SOTTOMETTTIBILE.** Il codice è in forma eccellente: ogni superficie prioritaria è risultata solida o con difese complete e verificate. Questo è un verdetto onesto dopo depth-first reale, non un passaggio superficiale — ogni lead sotto è stato inseguito fino a una ragione di chiusura.

La classe "threshold signature" è notoriamente sottile, ma questa implementazione beneficia di: spec RFC 9591 matura, due audit esterni precedenti (NCC 2021 sul frost originale in reddsa), BlockSec (fix refresh 2.2.0), e l'iterazione v3 che ha reso il cheater detection default-on.

---

## Superficie 1 — Nonce management ✅ SOLIDA

**Generazione** (`round1.rs::Nonce::new`): `H3(random_bytes[32] || secret_share)` — hedged nonce generation per RFC 9591 `nonce_generate(secret)`. Se l'RNG è rotto (output costante), il nonce resta `H3(costante || secret)`: deterministico ma dipendente dal segreto, imprevedibile per gli altri, unico per partecipante. L'hedge funziona come progettato.

**Hiding + binding**: due nonce indipendenti (due chiamate RNG separate). Il binding factor lega i nonce a `(VK_gruppo || H4(msg) || H5(commitments) || id)` — verificato in `binding_factor_preimages` (lib.rs:413). Corretto per RFC 9591, previene gli attacchi Drijvers-style.

**Check in `sign()`** (round2.rs): prima di firmare, verifica che `signer_nonces.commitments == signing_package.commitments[id]` → `Error::IncorrectCommitment`. Impedisce al coordinator malevolo di sostituire i commitment del firmatario. ✅ (Questo è il check citato nel commento di round1.rs.)

**Lead killato — riuso nonce**: `SigningNonces::from_nonces` è pubblico e il riuso tra sessioni diverse è un MUST NOT documentato (leak della chiave con analisi standard). È responsabilità dell'applicazione, documentata esplicitamente. Non è un bug della libreria. *Killed: by design, documented.*

**Lead killato — batch `preprocess()`**: genera N coppie nonce/commitment; se l'app perde il tracking di quale è stata usata, il `sign()` fallisce chiuso (`IncorrectCommitment`), non firma con nonce riusati. Fail-closed. *Killed.*

## Superficie 2 — DKG robustness ✅ SOLIDA (con 1 nota)

**Proof of Knowledge** (`keys/dkg.rs::compute_proof_of_knowledge`): Schnorr `σ=(R,μ)`, `μ = k + a_{i0}·c`, `c = HDKG(id || φ_{i0} || R)` con personalizzazione `"FROST_RedPallasD"` (domain separation verificata). Verifica: `R =? g^μ − φ₀^c`. Standard, corretta. Difesa rogue-key presente come da FROST paper Fig.1 (necessaria per `t ≥ n/2`).

**Verifica share in `part3`**: ogni share `f_ℓ(i)` è verificata contro il VSS commitment del mittente, con identificazione del colpevole (`InvalidSecretShare { culprit: Some }`) — questo è il cheater detection DKG, attivo di default in v3. ✅

**Consistenza parametri**: `part2`/`part3` controllano numero pacchetti, `min_signers` uniforme tra i commitment, corrispondenza identificatori round1/round2. ✅

**Lead killato — PoK skippata nel refresh DKG**: `refresh_dkg_part2` NON verifica le proof of knowledge ("We don't need to verify the proof of knowledge"). Sembra allarmante, ma è **sound**, per tre ragioni concatenate:
1. Nel refresh ogni partecipante condivide il polinomio costante **0**; il commitment inviato ha l'identità (`g⁰`) **rimossa**, e il ricevente la **ri-aggiunge** (`identity_commitment.chain(...)`).
2. Un partecipante malevolo che usasse segreto `s ≠ 0` dovrebbe inviare `t−1` commitment; il ricevente li interpreta come `[1, g^s, g^{a₁}, …]` e verifica gli share contro il polinomio con termine costante **0**. Gli share del malevolo (calcolati sul suo vero polinomio con costante `s`) **falliscono** la verifica VSS con probabilità schiacciante — non può alterare la chiave di gruppo.
3. Il rogue-key attack classico (scegliere il commitment in funzione di quelli onesti per conoscere il DL della chiave di gruppo) è strutturalmente impossibile qui: il termine costante è forzato a 0 dal protocollo, non scelto dal partecipante.

*Killed: sound by construction.* **NOTA (non-finding)**: il commento nel codice non spiega *perché* è sicuro saltare la verifica. Gap di documentazione — un futuro manutentore potrebbe "correggerlo" reintroducendo una verifica che fallirebbe (la PoK del refresh è calcolata su un commitment inconsistente: `a₀=0` contro `φ=g^{a₁}`, vedi analisi sotto). Vale un commento esplicativo upstream.

**Sub-nota**: la PoK calcolata in `refresh_dkg_part1` è matematicamente inconsistente (`μ = k + 0·c` verificato contro `φ = g^{a₁}`): fallirebbe se verificata. È morta per design (mai verificata), ma è codice che *sembra* fare una cosa e ne fa un'altra. Non è un vuln, è un smell.

**Lead killato — DKG bias (last-broadcaster advantage)**: noto e accettato. In Pedersen DKG l'ultimo a pubblicare vede i commitment onesti prima di scegliere il proprio polinomio. Per Schnorr/FROST il bias ottenibile in un singolo shot è trascurabile (la somma onesta è uniforme e i DL sono nascosti). Il FROST paper lo tratta come limitazione nota, non vulnerabilità. *Killed: known limitation, not exploitable for Schnorr.*

**Lead killato — replay di round1 package tra sessioni DKG**: il commitment contiene coefficienti freschi; riusare un vecchio package impegna al vecchio polinomio, di cui l'attaccante non conosce i coefficienti → non può produrre share validi in round 2. *Killed.*

## Superficie 3 — Binding e contesto ✅ SOLIDA

- **Challenge**: `H2(R || VK || msg)`; per RedPallas `H2 = HStar::<SpendAuth>::default()` = BLAKE2b-512(`"Zcash_RedPallasH"`) — **verificato** contro `reddsa/src/orchard.rs:70`. È esattamente `H^⊛` della Zcash spec come richiede ZIP-312. ✅
- **Domain separation completa**: H1 `FROST_RedPallasR`, H3 `FROST_RedPallasN`, H4 `FROST_RedPallasM`, H5 `FROST_RedPallasC`, HDKG `FROST_RedPallasD`, HID `FROST_RedPallasI`, HR `FROST_RedPallasA`. Nessuna collisione tra contesti. ✅
- **Header di serializzazione**: ogni tipo porta `Header { version, ciphersuite_id }` validato in deserializzazione — niente cross-ciphersuite confusion. ✅
- **Re-randomization** (`frost-rerandomized`): `randomizer = HR(seed || encode(commitments))`, seed inviata su canale confidenziale; i partecipanti **rigenerano** invece di fidarsi del RNG del coordinator (hedge documentato). `KeyPackage::randomize` marca il package come monouso. ✅
- **Lead killato — coordinator malevolo che riusa il seed**: se il coordinator riusa lo stesso seed tra sessioni, le chiavi randomizzate coincidono → firme linkabili. Ma il threat model di ZIP-312 lo accetta esplicitamente: "A rogue Coordinator will be able to break unlinkability and privacy, but should not be able to create signed transactions". Il forgery resta impossibile (servono le share). *Killed: accepted in threat model.*

## Superficie 4 — Rogue-key attacks ✅ DIFESE COMPLETE

- **DKG**: PoK Schnorr su `a_{i0}` per ogni partecipante (vedi sopra). Completa per `t ≥ n/2`.
- **Trusted dealer**: il dealer è trusted per definizione; i partecipanti verificano gli share (`SecretShare::verify`: `g^{s_i} =? ∏ φ_j^{i^j}`).
- **Taproot (`frost-secp256k1-tr`)**: `post_dkg` applica un tweak unspendable (`Q = P + H(P)G` per BIP-341) per impedire rogue tapscript tweak. Difesa specifica presente. ✅
- **Lead killato — `split()` + EvenY**: `split()` permette di suddividere una chiave esistente (es. da seed phrase); se la chiave ha Y dispari, `post_generate` nega tutto → la chiave di gruppo è **−VK**, non la VK originale. Chi si aspetta di spendere dalla chiave originale resta sorpreso. È comportamento richiesto da ZIP-312 (even Y obbligatorio), non un vuln — ma è un footgun API. *Killed: by spec, API hazard noted.*

## RedPallas ciphersuite — analisi custom (la zona a più rischio)

Seguendo la lezione dell'audit Mina (gli override dei ciphersuite sono dove si concentrano i rischi):

**EvenY** (`into_even_y`): se la chiave di gruppo ha Y dispari, nega share firmanti, share verificanti, chiave di gruppo e (nel trusted dealer) i coefficienti VSS. Verificata la coerenza algebrica: `−s_i` è share valida di `−sk`; il commitment VSS negato verifica correttamente (`g^{−s_i} = ∏ (−φ_j)^{i^j}`). In DKG tutti i partecipanti calcolano lo stesso `is_even` dagli stessi broadcast commitment → coerenza tra partecipanti. ✅
- Assunzione encoding: `serialized[31] & 0x80 == 0 ⟺ Y pari` per `pallas::Point::to_bytes()`. È l'encoding compresso standard di Pallas (x + sign bit; il top bit è libero perché x < p < 2^255). Codice scritto e testato dal team ZF. *Rischio residuo: basso.*
- `SecretShare::into_even_y` fa roundtrip serializzazione con `.expect("none of the coefficient commitments are the identity")` → panic se un coefficiente è 0. Nel trusted dealer onesto è trascurabile; è comunque un `expect` su dato derivabile. *Non-finding (robustness nit).*

**Hook analysis**: tutti i default di `frost-core` sono identity; RedPallas fa override solo di `post_generate`/`post_dkg` (EvenY) — nessun hook di signing toccato. Il fix v3 (`verify_signature_share` ora chiama `pre_commitment_aggregate`) non impatta RedPallas (non fa override). ✅

**Taproot cross-check** (per validare il metodo): `compute_signature_share` nega i nonce se `R` ha Y dispari; `verify_share` nega il commitment share alle stesse condizioni; `pre_sign`/`pre_aggregate` negano le chiavi se la VK ha Y dispari; `challenge` usa solo coordinate x (BIP-340). Simmetria sign↔verify verificata a mano: coerente. ✅ (Questo è esattamente il tipo di invariante che l'audit Mina ha trovato rotto altrove — qui regge.)

## Refresh (trusted dealer + DKG) ✅ SOLIDO

- Il fix BlockSec 2.2.0 (`min_signers` validato, non riducibile via refresh) è presente e completo: `compute_refreshing_shares` legge `min_signers` dal package, `refresh_share` e `refresh_dkg_shares` lo confrontano. ✅
- `refresh_dkg_shares` NON chiama `post_dkg`: corretto, perché la chiave di gruppo non cambia (costante 0) e la proprietà even-Y è preservata. ✅
- **Nit (non-finding)**: `refresh_dkg_shares` non identifica il colpevole su share invalido (`secret_share.verify()?` senza mapping a `culprit: Some`, a differenza di `dkg::part3`). Solo robustness.

## Altri lead killati

- **Identifier zero**: rifiutato in `new`, `deserialize`, `TryFrom<u16>`. `derive` usa HID domain-separated. ✅
- **`aggregate`/`aggregate_custom`**: check cardinalità + appartenenza identificatori; verifica la firma aggregata e solo in caso di fallimento corre il cheater detection (efficiente e corretto). `detect_cheater` non raggiungibile a sproposito. ✅
- **`SigningKey::new`**: `random_nonzero`. `ZeroizeOnDrop` ovunque sui segreti; i `Debug` redigono. ✅
- **Serialization**: lunghezze esatte controllate (`default_deserialize`), niente trailing bytes. ✅

## Cosa resta (profondità futura, non coperta qui)

1. **`frost-client` / demo wallet** (ywallet): la superficie applicativa sopra la libreria — gestione dei canali confidenziali, storage dei nonce, coordinazione. È dove i bug di integrazione vivono.
2. **Il nuovo repo dei ciphersuite** (migrazione da reddsa a `frost` in corso): quando il codice RedPallas verrà re-integrato, ricontrollare che gli override siano identici.
3. **Analisi formale del refresh-DKG senza PoK**: la mia argomentazione di soundness meriterebbe una seconda coppia di occhi (ideale: Francesco, è teoria dei protocolli).
4. **Fuzzing differenziale** dei ciphersuite contro vettori RFC 9591 / test ZIP-312.

## Note operative

- DKG bias e coordinator-trust sono limitazioni documentate/accettate, non finding.
- Se mai emergesse un finding serio: disclosure responsabile coordinata con ZF (embargo + fix) PRIMA di qualsiasi submission al grant Q4 (finestra 30 ott–13 nov). Il grant premia lavoro completato + disclosure corretta.
- Questo report è privato. Niente disclosure pubblica.

*Lead killati totali: 14. Finding sottomessibili: 0. Nit/robustness: 3 (tutti non-security).*
