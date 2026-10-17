# Security Audit — `frost-client` coordinator

*Sub-audit del depth track frost-client, 2026-10-17. Analisi statica, nessuna disclosure. Librerie verificate dai sorgenti crates.io: frost-core 2.2.0, frost-rerandomized 2.1.0, snow 0.9.6.*

> **Historical notes; see [errata](../../ERRATA-AND-EVIDENCE.md).** The original F1 (Noise_K impersonation) and F2 (missing cheater detection) were **withdrawn**. Noise_K has no transmitted static-key token in its first message, and frost-core 2.2.0 enabled cheater detection by default. The original detailed claims and proposed fixes are available in Git history; they must not be treated as current findings.

## F3 — Socket comms: identifier autodichiarati, nessun membership check (demo transport)

**File:** `frost-client/src/coordinator/comms/socket.rs:72-115`. `_public_key_package` ignorato; identifier dal peer; primi N che connettono occupano gli slot; secondo messaggio con stesso identifier sovrascrive endpoint+commitment dell'onesto. Plaintext TCP senza auth. Impatto: DoS/esclusione, niente forgery. Scoping onesto: path di produzione è HTTP/Noise_K; il README dichiara demo/WIP.

## Split-view / equivocation — no forgery demonstrated in this review

The reviewed signing paths bind shares to message, commitments and group key. The original note asserted that nonce reuse was impossible because a package is consumed once; that assertion was too broad. The library checks commitment consistency but does not itself track previous nonce use. This report does not establish a forgery, nor does it prove all application-level reuse paths absent. See [errata](../../ERRATA-AND-EVIDENCE.md).

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

## Earlier candidate disposition

The original blanket assertion that all listed candidates were formally eliminated is withdrawn. Refer to the component reasoning and [errata](../../ERRATA-AND-EVIDENCE.md); no exploit for those candidates was demonstrated in the published artifacts.
