# Deep Audit — frost-client / application layer sopra FROST (Round 1)

*2026-10-17. NESSUNA disclosure, NESSUNA submission. Report privato per il parent.*
*Questo è il **Round 1** del track FROST/Zcash — non una chiusura. Vedi "Round 2" in fondo.*

## Target

| Componente | Stato |
|---|---|
| `ZcashFoundation/frost-tools` (main, aggiornato al 2026-10-14) | clonato e auditato |
| `frostd` — relay server (axum) | audit completo |
| `frost-client` — coordinator / participant / dkg / trusted-dealer (CLI) | audit completo |
| `zcash-sign` — tool firma transazioni Zcash (PCZT) | audit completo |
| Libreria effettiva nel workspace | **frost-core 2.2.0** (non 3.0.0 — discrepanza col brief del round precedente) |

**Calibrazione onesta**: tutto il repo dichiara "for demo purposes only and should not be used in production". I finding sotto sono reali ma pesati di conseguenza.

## Verdetto Round 1

**NESSUN finding di forgery o compromissione chiavi.** Le difese del protocollo reggono ovunque: `IncorrectCommitment` fail-closed, binding factor anti-split-view (analisi formale: equivocation del coordinator → solo DoS), nonce freschi one-shot, PoK anti-replay cross-sessione, blame DKG propagato.

**7 candidati** (tutti availability/design-gap/hardening, nessuno sopra "medio"):

### 1. frostd — Memory exhaustion via fan-out illimitato (DoS, il più grave)
`frostd/src/functions.rs:196-237`. Nessun limite su `recipients`, nessuna quota, nessun rate limit. Singola request: ~29k recipients × 64 KiB ≈ **1,9 GB**. Ripetibile → OOM-kill del relay (tutte le cerimonie). Variante mirata: `recipients` vuoto → coda del Coordinator seppellibile da qualsiasi partecipante. Dettagli: `frostd-audit.md`.

### 2. coordinator — Noise_K non verifica l'identità del peer (autenticità rotta, impatto availability)
`frost-client/src/cipher.rs:234-243`. Il commento *"this authenticates the sender"* è **falso** (verificato su snow 0.9.6: la chiave statica dell'initiator sovrascrive `rs` senza confronto; `get_remote_static()` mai chiamato). Un relay malevolo può impersonare qualsiasi partecipante/coordinator → commitment attribuiti a vittime, sessioni disruptate. Niente forgery (fail-closed a `sign()`), confidenzialità E2E intatta. Fix: confrontare `get_remote_static()` con `msg.sender`. Dettagli: `coordinator-audit.md` (F1).

### 3. coordinator — Nessuna cheater detection (griefing non attribuibile)
`frost-client/src/coordinator/cli.rs:79-92`; frost-core senza feature `cheater-detection`. Share invalida → `InvalidSignature` generico, colpevole ignoto, cerimonia da rifare bruciando i nonce di tutti. `verify_signature_share` (pubblica, non feature-gated) mai chiamata; il commento in `coordinator/main.rs` descrive un intento mai implementato. Fix a una riga. Dettagli: `coordinator-audit.md` (F2).

### 4. DKG — Griefing indefinito (liveness)
`frost-client/src/dkg/comms/http.rs` (~213, ~264, ~320): wait-loop senza timeout; il SESSION_TIMEOUT server (24h) è rinnovabile all'infinito da un membro con duplicati cifrati (overwrite silenzioso). Un membro tiene il DKG bloccato per sempre a costo ~zero. Dettagli: `dkg-zcashsign-audit.md` (F1).

### 5. frostd — Phantom session + enqueue non richiesto (spoofing/DoS)
Chiunque crea sessioni con pubkey arbitrarie; il client fa auto-join di `list_sessions()[0]` → DoS della cerimonia legittima ("more than one FROST session active") o join in sessione attaccante (fermato solo dall'address-book check). Impatto limitato dal cifrario E2E. Dettagli: `frostd-audit.md` (#2).

### 6. zcash-sign — Blind signing (hardening)
`zcash-sign/src/sign.rs`: mostra solo `SIGHASH: <hex>`, zero riepilogo (importi, destinatari, fee) prima di assemblare firme per un PCZT arbitrario. La crypto chiude le falle (verifica per-rk, nessun TOCTOU, nessun broadcast), ma l'operatore firma alla cieca. Dettagli: `dkg-zcashsign-audit.md` (Z1).

### 7. Minori confermati
- participant: DoS da insider (abort su sender sconosciuto invece di skip), coordinator-identity = qualsiasi pubkey in rubrica, SocketComms plaintext (nessun binario shipped lo usa), `confirm_message` hex+y/n unica difesa vs coordinator malevolo.
- coordinator: socket identifier autodichiarati (demo transport); downgrade silenzioso a non-rerandomized per redpallas senza `--randomizer`; `process_signature` no-op.
- frostd: cleanup timeout incoerente per il coordinator; token bearer non bound (drain distruttivo via `receive`).
- DKG: share in chiaro su stdout (demo); commento Noise_K ottimistico; flag `-S` inesistente in un errore.

## Lead killati importanti (con ragione)

- **Split-view/equivocation → forgery**: killato formalmente (binding su `(R,c)` per-package + nonce freschi + singolo package consumato = avversario delle prove TS-SUF).
- **Riuso nonce nel participant**: killato — one-shot by construction (ma safety implicita, non defense-in-depth).
- **Blame DKG inghiottito**: killato — propagato fino al main, colpevole risalibile via `(session_id ‖ pubkey)`.
- **Replay cross-sessione DKG**: killato — identifier session-bound + PoK lega l'identifier.
- **Commitment inventati per onesti**: killato — `IncorrectCommitment` fail-closed prima di ogni computo.
- **Message substitution / bait-and-switch**: killato — stesso oggetto dal prompt alla firma.
- **Share distribuzione in chiaro**: killato — cifratura per-destinatario / solo locale.
- Auth challenge-response frostd: corretta (single-use atomico). Spoofing `sender`: impossibile (server-side). Race challenge: nessuna.

## Valutazione onesta per il grant

Nessun candidato ha il peso di una submission da solo: sono DoS/liveness/design-gap in codice esplicitamente demo. Il cluster "il reference implementation ha 7 gap di availability/autenticità" potrebbe diventare un contributo utile (soprattutto #2 — garanzia di sicurezza documentata e falsa — e #3 — fix a una riga con commento che promette ciò che non fa), ma va presentato come hardening del reference, non come vulnerabilità critica. **Decisione submission: al parent.**

## Round 2 — angoli non ancora scavati (non è una chiusura)

1. **ywallet integration** — il wallet reale che usa FROST per ZIP-312. Non toccato. Priorità alta: è codice production, non demo.
2. **PoC pratici** dei candidati #1/#2/#3: confermare exploitability (relay impersonation, memory exhaustion misurata, griefing) invece di restare sullo statico.
3. **Fuzzing delle state machine** HTTP (`session.rs` handlers, loop coordinator/participant) — input malevoli dal relay.
4. **Migrazione ciphersuite**: quando RedPallas ri-atterra nel nuovo repo `frost`, re-verificare gli override (lezione audit Mina).
5. **È frostd deployato da qualcuno in produzione?** Se sì, la severità di #1/#2 sale.
6. **Rivisitare i killati con tecniche nuove**: il finding Noise_K (#2) suggerisce di ricontrollare ogni assunzione "autenticato" nel codebase; l'analisi split-view merita un secondo paio d'occhi (ideale: Francesco).

*Lead killati Round 1: ~30. Candidati: 7 (max severità: medio). Finding di forgery: 0.*
*Sub-report: `frostd-audit.md`, `coordinator-audit.md`, `participant-audit.md`, `dkg-zcashsign-audit.md`.*
