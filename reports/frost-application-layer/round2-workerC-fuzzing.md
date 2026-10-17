# Round 2 — Worker C: fuzzing della state machine HTTP di `frostd`

*Depth audit frost-client, 2026-10-17. NESSUNA disclosure, NESSUNA submission. Solo test locali su `127.0.0.1`.*

## Verdetto

**Negativo onesto: nessun crash, nessun panic, nessun bypass, nessuna inconsistenza di stato.**
Il server è sopravvissuto a ~1.270 richieste fuzzate (malformate, sequenze, race, boundary) restando sempre vivo e consistente — **sia con il build release che con il build debug** (quest'ultimo con overflow checks e `debug_assertions` attivi: 0 panic anche lì). Unico comportamento confermato: la crescita memoria lineare e unbounded del fan-out in `send`, che è il meccanismo del finding #1 già registrato nell'audit (`frostd-audit.md`) — qui solo riverificato in forma bounded, non un nuovo finding.

## Setup

- Repo: `~/workspace/hunt/frost-client-audit/frost-tools`.
- **Run 1 (release):** binario `frostd` compilato da Worker C con `CARGO_TARGET_DIR=~/workspace/hunt/frost-client-audit/target-workerC` (~24 min di build).
- **Run 2 (debug):** binario centrale `~/workspace/hunt/frost-client-audit/target-central/debug/frostd` (già compilato, non ricompilato) — con overflow checks e debug assertions attivi. Risultati identici al run release, 0 panic.
- Server lanciato su `127.0.0.1:27499` con `--no-tls-very-insecure`, sotto `ulimit -v 4000000` (cap 4 GB virtuali), log in `fuzz-frostd/frostd-server.log`.
- Fuzzer: `~/workspace/hunt/frost-client-audit/fuzz-frostd/frostd_fuzz.py` (Python + requests), runner `run.sh` (supporta `FROSTD_BIN` per scegliere il binario), risultati grezzi in `results.jsonl`.
- **Dettaglio critico per il login:** il server verifica la firma via `xeddsa::xed25519::PublicKey::verify`, che interpreta la pubkey come **chiave X25519 Montgomery** e la converte in Edwards prima della verifica Ed25519 standard. Una chiave Ed25519 pura (pynacl) viene quindi rifiutata. Ho costruito `fuzz-frostd/xsign/` (piccolo binario Rust su xeddsa 1.0.2, stessi dep del workspace) per keygen/firma XEdDSA corrette; il fuzzer lo usa per tutti i login.

## Copertura

| Fase | Cosa | Volume | Esito |
|---|---|---|---|
| 0 | Sanity: challenge→login→create→send→receive→drain→close | 1 roundtrip | OK |
| 1 | Input malformati: 25 raw-mutation (JSON invalido, UTF-8 invalido, nesting 5000, array 200k elem, NaN/Inf, 2 MB string, CT sbagliato/mancante…) + 21 field-mutation (tipi errati, campi mancanti/null/extra, UUID malformati, int enormi/negativi/float, `message_count` 10³⁰…) × 9 endpoint; + 8 mutazioni header auth + 6 metodi HTTP | 422 richieste | 0 crash; status solo in {200, 400, 413, 415, 422, 500}; tutti i 500 con body `LowError` ben formato, **zero stack trace** |
| 2 | Walk randomici della state machine (4 utenti): create/send/receive/close/list/info/double-close/send-su-chiusa/receive-senza-send/logout-reuse/challenge-replay/cross-token/bad-token, con check di invarianti | 400 op × 2 seed | 0 anomalie, 0 eccezioni; challenge-replay 32/32 → primo 200, secondo 500 |
| 3 | Race: challenge riusata da 16 thread; storm di 80 create; 16 close concorrenti sulla stessa sessione; 200 send concorrenti + drain (check no-loss/no-dup); logout vs uso token; 8 receive concorrenti sulla coda coordinator | 6 scenari | challenge: esattamente 1 vince; close: esattamente 1×200; send: 200 inviati = 200 ricevuti; coordinator drain: 50/50, nessun duplicato/perso |
| 4 | Boundary: sessioni inesistenti/malformate, recipients vuoto/self/duplicati/outsider, sender outsider, `as_coordinator` da non-coordinator, msg 0 / 65535 / 65536 / 1 MB / 3 MB, `create` con pubkeys vuote/duplicate/500, `message_count` 0/255, login con pubkey/firma vuote/corte/lunghe/challenge bogus, logout senza token e doppio | 38 casi | tutti come atteso (dettagli sotto) |
| 5 | Memoria bounded: 5 send da 100 recipients × 64 KiB; 20 sessioni × 200 pubkeys; 200 login; 2000 challenge | — | RSS 13,0 → 40,9 MB dopo fan-out (+27,9 MB ≈ lineare); +1,3 MB sessioni; +44 KB token; +228 KB challenge |

Negative-login mirati (challenge valida): firma garbage, firma di altra chiave, firma su messaggio diverso, firma troncata (63 B → `InvalidArgument`), firma con bit flippato → tutti 500 rifiutati; login valido → 200. **Verifica firma enforced correttamente.**

## Dettagli boundary (fase 4)

- `msg` 65535 byte → 200 (limite inclusivo, `>` in `functions.rs`); 65536 → 500 `InvalidArgument("msg is too big")`; 1 MB → 500; 3 MB → **413** (limite body 2 MB di default di axum — difesa in profondità contro i bomb JSON).
- `create_new_session` con `pubkeys: []` → 200 (accettato, coerente con finding #2 dell'audit); `message_count: 0` → 500; 255 → 200; 500 pubkeys → 200.
- Outsider su send/receive/info/close → 500 (`NotInSession`/`SessionNotFound`/`NotCoordinator`); nessun leak: `get_session_info` da outsider dà `SessionNotFound`, non i dati.
- Doppio `close_session` → 200 poi 500; `send`/`receive` su sessione chiusa → 500.
- `receive` con `as_coordinator: true` da non-coordinator → 200 ma drena la coda *participant* (by design, nessun accesso alla coda coordinator).
- Drain accounting verificato: dopo i casi, c2=2, coordinator=0, self=1 — tutti spiegati dai casi precedenti (un receive intermedio aveva drenato).
- Metodi non-POST → 405; auth malformata (vuota, schema errato, token non-UUID, 100 KB) → 500 `Unauthorized`.

## Fase 5 — memoria (bounded, nessun OOM)

Conferma il meccanismo del finding #1 dell'audit senza far esplodere la VM: ogni `send` clona il messaggio per ogni recipient senza bound; +27,9 MB per 5 send da 100×64 KiB, lineare. Token e challenge: crescita piccola e con expiry (1h / 10s); nessun leak unbounded rapido lì.

## Note informative (non finding)

1. **Tutti gli errori mappano a HTTP 500**, inclusi errori client (`InvalidArgument`, `Unauthorized`, `SessionNotFound`). Il body è sempre il `LowError` strutturato — nessuno stack trace leak — ma l'igiene degli status code è scarsa.
2. `/challenge` ignora completamente il body (nessun extractor) → 200 anche con garbage. By design, ma superficie strana.
3. Nessun rate limiting osservato (coerente con audit: solo `TraceLayer`).

## Lead killati da questo round

- Panic su input malformato (422 casi × 2 build): killato — 0 panic nel server log sia in release che in debug (overflow checks attivi).
- Info leak via 500/stack trace: killato — tutti i 500 sono `LowError`.
- Challenge replay concorrente: killato — `remove` atomico, esattamente 1 vince su 16.
- Race close/send/receive: killato — accounting esatto, nessun messaggio perso/duplicato.
- Auth bypass via firma invalida: killato — 5/5 varianti rifiutate con challenge valida.
- Lock poisoning via panic sotto lock: killato — nessun input causa panic, lock mai avvelenati.
- Unbounded challenge/token spray: killato in forma rapida — crescita modesta + expiry; il vettore memoria reale resta il fan-out di `send` (finding #1 esistente).

## Artefatti

- Fuzzer: `~/workspace/hunt/frost-client-audit/fuzz-frostd/frostd_fuzz.py`
- Runner: `~/workspace/hunt/frost-client-audit/fuzz-frostd/run.sh`
- Helper firma XEdDSA: `~/workspace/hunt/frost-client-audit/fuzz-frostd/xsign/`
- Risultati grezzi: `~/workspace/hunt/frost-client-audit/fuzz-frostd/results.jsonl` (1.237 righe, run finale = build debug centrale, seed 9877) + `debugrun.log`, `fullrun.log`, `frostd-server.log`
- `crashes/`: vuota — nessun crash trovato, nessun PoC da salvare.

## Stato binario 1

Nessun nuovo finding inviabile da questo round. La superficie HTTP/state-machine di `frostd` risulta robusta agli input malevoli e alle race; resta valido il finding #1 (DoS via fan-out, già in `frostd-audit.md`).
