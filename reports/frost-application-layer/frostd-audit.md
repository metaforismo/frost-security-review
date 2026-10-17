# Security Audit — `frostd` (FROST message relay server)

*Sub-audit del depth track frost-client, 2026-10-17. Analisi statica, nessuna disclosure.*

## CANDIDATO-FINDING #1 — Memory exhaustion via fan-out illimitato in `send` (DoS)

**File:** `frostd/src/functions.rs:196-237`

- `send` controlla solo la dimensione del singolo messaggio (`args.msg.len() > MAX_MSG_SIZE`, 65535 byte).
- Nessun limite sul numero di `recipients`, nessuna quota per utente/sessione, nessun rate limiting (router in `lib.rs:19-41` monta solo `TraceLayer`).
- Per ogni recipient il server clona l'intero messaggio (`msg: args.msg.clone()` in loop) in `VecDeque<Msg>` senza bound.
- `create_new_session` accetta pubkey arbitrarie senza validazione né limiti di numero.
- Ogni `send` rinnova il timeout (24h), quindi l'attaccante mantiene le sessioni vive con ping periodici.

**PoC concettuale:** login self-registered → `create_new_session` con ~29k pubkey fasulle → `send` con 29k recipients × 64 KiB ≈ **1,9 GB da una singola richiesta HTTP**. Ripetibile → OOM-kill.
Variante mirata: `recipients` vuoto → coda `SessionParticipant::Coordinator`; qualsiasi partecipante può seppellire la coda del coordinator → liveness kill su cerimonia altrui.

**Impatto:** availability del relay (tutte le cerimonie). FROST resta *safe*, ma nessuna firma si completa a relay morto. Demo code ("not for production") → valore submission basso, bug reale.

## CANDIDATO-FINDING #2 — Phantom session + enqueue non richiesto

**File:** `frostd/src/functions.rs:112-160`, `224-235`; client `frost-client/src/participant/comms/http.rs:202-212`

- Chiunque autenticato crea sessioni con pubkey arbitrarie (anche di vittime non consenzienti); l'id appare nel `list_sessions` della vittima.
- L'attaccante, da coordinator della sessione fantasma, accoda `Msg` nella coda `Participant(victim)` della vittima.
- Il client, senza `-S` esplicito, fa **auto-join di `list_sessions()[0]`**: (a) se la vittima aveva 1 sessione legittima → errore "more than one FROST session active" → DoS cerimonia legittima; (b) se non ne aveva → entra nella sessione attaccante, fermata solo dal check "coordinator not in address book" (`http.rs:227`).
- Caveat: messaggi E2E cifrati (Noise) → impatto certo = spoofing/DoS, non compromissione chiavi.

## Minore confermato — Cleanup timeout incoerente per il coordinator

`state.rs:95-106` vs `functions.rs:299-307`: lo sweep alla scadenza rimuove lo session-id dai set dei partecipanti ma non da quello del coordinator → `list_sessions` mostra sessioni morte + crescita lenta unbounded. Robustness.

## Lead killati

- Race su `challenges.remove`: killato — remove atomico sotto write-lock, single-use reale.
- Spoofing `sender`: killato — impostato server-side da identità autenticata.
- Lettura coda Coordinator da partecipante: killato — richiede `pubkey == coordinator_pubkey && as_coordinator`.
- Token scaduto: non-issue — HashMapDelay 1h + sweep continuo.
- Equivocation/drop dal server: fuori threat model (relay fidato per liveness; FROST safe).
- `close_session` malevolo: solo liveness, coordinator fidato nel modello.
- Challenge non legato al richiedente: by design (freshness-only).

## Note informative

- Token bearer non bound (no IP/TLS binding, no rotation); rubato (es. `--no_tls_very_insecure`) = impersonificazione ≤1h; `receive` fa `drain(..)` → l'attaccante distrugge i messaggi della vittima.
- `receive` drena senza redelivery: crash client = messaggi persi, cerimonia riparte.
