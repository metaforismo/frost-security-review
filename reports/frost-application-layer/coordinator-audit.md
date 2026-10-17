# Security Audit — `frost-client` coordinator

*Sub-audit del depth track frost-client, 2026-10-17. Analisi statica, nessuna disclosure. Librerie verificate dai sorgenti crates.io: frost-core 2.2.0, frost-rerandomized 2.1.0, snow 0.9.6.*

## F1 — Noise_K non verifica l'identità del peer: relay malevolo può impersonare chiunque (DoS/disruption, NON forgery)

**File:** `frost-client/src/cipher.rs:234-243` (`Cipher::decrypt`); causa radice in `Cipher::new` (`:150-190`).

Il commento nel codice è **falso**: *"Note that this authenticates the `sender` in the `Msg` struct; if the sender is tampered with, the message would fail to decrypt."* Verificato sui sorgenti di snow 0.9.6: il builder responder pre-popola `rs` con la `remote_public_key` attesa, ma durante l'handshake la chiave statica trasmessa dall'initiator **sovrascrive `rs` senza confronto** (`handshakestate.rs:390`). Il codice non chiama mai `get_remote_static()` per confrontarla con `msg.sender`.

**PoC concettuale:** l'operatore del relay (unico attore che può forgiare `sender`, impostato server-side post-login) completa un handshake Noise_K verso la comm-pubkey pubblica del coordinator iniettando `Msg { sender: <pubkey vittima>, msg: <handshake> }`. Il decrypt seleziona `recv_noise_map[vittima]`; l'handshake riesce crittograficamente. Il relay invia poi commitment scelti da lui attribuiti alla vittima (`session.rs:117`); i messaggi veri della vittima falliscono il decrypt (state consumato); se la vittima ricevesse il package, `sign()` fallisce `IncorrectCommitment` → fail-closed.

**Impatto onesto:** rottura dell'autenticità mittente del canale E2E, ma solo availability (DoS/disruption + slot-squatting). Niente forgery (l'attaccante non ha le key share), confidenzialità E2E intatta. Fix: confrontare `get_remote_static()` con `msg.sender` dopo l'handshake.

## F2 — Nessuna cheater detection: share invalida = abort cieco, griefing non attribuibile

**File:** `frost-client/src/coordinator/cli.rs:79-92`; `frost-client/Cargo.toml` (frost-core **senza** feature `cheater-detection`).

`aggregate()` fallisce il verify Schnorr finale → senza la feature ritorna `InvalidSignature` generico (frost-core `src/lib.rs:633`), senza identificare il colpevole. Il coordinator non può escluderlo e riprovare: deve riavviare l'intera cerimonia bruciando i nonce di round 1 di tutti. Griefing a costo quasi zero, non attribuibile. `verify_signature_share` (pubblica, non feature-gated in 2.2.0) non è mai chiamata — il fix è a una riga, e il commento in `coordinator/main.rs` ("signature shares must be validated first") descrive un intento mai implementato.

## F3 — Socket comms: identifier autodichiarati, nessun membership check (demo transport)

**File:** `frost-client/src/coordinator/comms/socket.rs:72-115`. `_public_key_package` ignorato; identifier dal peer; primi N che connettono occupano gli slot; secondo messaggio con stesso identifier sovrascrive endpoint+commitment dell'onesto. Plaintext TCP senza auth. Impatto: DoS/esclusione, niente forgery. Scoping onesto: path di produzione è HTTP/Noise_K; il README dichiara demo/WIP.

## Split-view / equivocation — KILLATO formalmente (nessun forgery)

Nel codice onesto non c'è equivocation (stesso `SendSigningPackageArgs` per tutti i recipient). Con coordinator malevolo che equivoca: ogni share è legata al package visto dal firmatario (`ρ_i = H1(i,m,L)`, `c = H2(R,vk,m)`); share su package diversi non aggregano mai a una firma valida. L'attacco Drijvers-style richiede doppio-firma con stesso nonce sotto binding diversi — impossibile: nonce freschi per sessione, un solo package consumato per sessione. È l'avversario delle prove TS-SUF di FROST; il design regge.

## Assemblaggio package — fail-closed

`SigningPackage::new` non valida nulla, ma: CLI valida membership + anti-duplicato (`comms/cli.rs:175-184`); HTTP valida membership/conteggio in `session.rs:103-117`; commitment inventati per onesti → `IncorrectCommitment` prima di ogni computo (entrambi i path plain/rerandomized); package con < min_signers → `IncorrectNumberOfCommitments`. Nessun percorso "firma comunque".

## Scelta partecipanti / messaggio / rerandomized

- Scelta firmatari: operatore del coordinator. Impatto solo liveness.
- Messaggio: scelto arbitrariamente dall'operatore (`coordinator/args.rs:151`); il partecipante lo vede (hex + y/n, stesso oggetto dal prompt alla firma — nessun TOCTOU, nessun bait-and-switch). Per sighash Zcash nessun umano può validare l'hex — threat model implicito.
- Rerandomized: nessun riuso accidentale nel codice (randomizer = puro input operatore); ma bypassa `RandomizedParams::new` (che legherebbe il randomizer al package) e non controlla freschezza/unicità. **Downgrade silenzioso**: redpallas senza `--randomizer` → FROST non-rerandomized, firma sotto vk di lungo periodo (invalida per spend Zcash → fail-closed a consensus, nessun furto, ma senza warning).

## Note minori

- N1: `process_signature` è no-op — la firma finale non viene rispedita ai partecipanti (contrario al README).
- N2: `--signers` vuoto → `num_signers=0` → poll infinito su `receive`.
- N3: `aux_msg` sempre `None` nel binario standalone.

## Lead killati

Forgery via commitment inventati / split-view / rogue identifier / message substitution / replay commitment / riuso randomizer / share malevola→firma sbagliata — tutti killati con ragione formale.
