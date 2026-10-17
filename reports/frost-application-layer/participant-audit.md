# Security Audit — `frost-client` participant (il firmatario)

*Sub-audit del depth track frost-client, 2026-10-17. Analisi statica, nessuna disclosure.*

## Verdetto domanda centrale: riuso nonce — GESTITO CORRETTAMENTE (by construction)

Il flusso `participant()` (`participant/cli.rs:84-114`) è one-shot per processo:
- `cli.rs:91-96`: `message_count` nonce freschi da `thread_rng`, wrappati in `Zeroizing`, solo in memoria — nessuno stato persistente, nessun pool, nessun file.
- `cli.rs:104-114`: un solo passaggio — get package → confirm → sign → send share → return. Nessun loop.
- Su errore (commitment sbagliati, utente annulla): l'errore propaga, il processo esce, nonce droppati/zeroizzati. Nonce mai riusati.
- `generate_signature` (`cli.rs:26-57`): zip per indice nonce↔package; `round2::sign` fallisce con `IncorrectCommitment` se il package non contiene i commitment di quei nonce.

**Nota architetturale**: la safety è implicita (one-shot), non difesa in profondità. Se un futuro maintainer trasforma `participant()` in daemon long-lived con pool di nonce, il classico leak appare silenziosamente. Da documentare.

## F1 — DoS da insider: abort su qualsiasi messaggio non dal coordinator (low, liveness)

- `participant/comms/http.rs:250-259`: il loop prende `msgs[0]` e fa `cipher.decrypt(...)?` → hard fail.
- `cipher.rs:207-212`: `recv_noise_map` contiene solo la pubkey del coordinator → qualsiasi altro sender → `Error::UnkownSender` → abort del processo.
- `frostd/src/functions.rs:207-232`: qualsiasi membro autenticato della sessione può accodare messaggi nella coda di un altro partecipante.
- Impatto: insider uccide il tentativo di firma della vittima con un singolo messaggio; `receive` fa `drain(..)` ma il client guarda solo `msgs[0]` → il package legittimo in posizione 1 viene perso.
- Non scala a forgery (sender autenticato al login + address book). Fix: saltare sender sconosciuti invece di abortire.

## F2 — Identità coordinator = "qualsiasi pubkey in rubrica" (low-medium, design)

- `cli/participant.rs:100-105`: `comm_coordinator_pubkey_getter` confronta la coordinator_pubkey dichiarata dal server con tutti i partecipanti in `group.participant`. Qualsiasi membro del gruppo passa — incluso insider che si autonomina coordinator.
- Nessun binding con "il coordinator atteso per questa sessione" (nessun campo config). Sfruttamento richiede comunque `y` al prompt. Threat-model gap.

## F3 — `SocketComms` plaintext non autenticato (low)

- `participant/comms/socket.rs:44-47,133-137,159-162`: JSON su TCP grezzo, nessun TLS/Noise/auth; accetta il primo messaggio che arriva. `socket.rs:66` fa `println!` dei bytes di rete.
- Mitigante: nessun binario shipped lo usa (`participant/main.rs` usa solo CLIComms). Chi adotta l'API pubblica eredita il trasporto insicuro.

## F4 — `confirm_message` (hex + y/n) unica difesa vs coordinator malevolo (info)

Tutte e tre le implementazioni chiedono conferma; nessuna auto-firma. Ma un coordinator malevolo può sollecitare firme su messaggi arbitrari e l'unico gate è un umano che legge hex. Threat model implicito (signing oracle manuale) — corretto per demo, da esplicitare per chi riusa.

## Lead killati (10)

Riuso nonce tra invocazioni / crash tra round / invocazioni parallele / sign() fallita→riuso / replay stesso package / coordinator riusa commitment tra package / forgery via Noise_K anonimo / sessioni concorrenti / randomizer malevolo / race sul pool nonce — tutti killati con ragione (vedi report completo nel handoff).

## Note

- **Discrepanza versione**: il workspace frost-tools usa **frost-core 2.2.0** (Cargo.toml:24), non 3.0.0 come nel brief del round precedente. Il check `IncorrectCommitment` esiste comunque in 2.2.0.
- Igiene chiavi buona: `Drop` zeroizza `comm_privkey`, `ProcessedArgs: Zeroize`, nonce in `Zeroizing`.
- Loop attesa package HTTP senza timeout (`http.rs:246-260`): coordinator silenzioso = hang indefinito (liveness nit).
