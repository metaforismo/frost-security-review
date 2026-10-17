# Security Audit — `frost-client` DKG orchestration + `zcash-sign`

*Sub-audit del depth track frost-client, 2026-10-17. Analisi statica, nessuna disclosure.*

**Nota versione**: il workspace frost-tools pinna **frost-core 2.2.0** (Cargo.toml:24), non 3.0.0. Verifiche libreria fatte contro la 2.2.0 effettiva.

## F1 — Griefing DKG indefinito: wait-loop senza timeout + session timeout rinnovabile (liveness, medio-bassa)

- I tre loop di attesa in `frost-client/src/dkg/comms/http.rs` (~213, ~264, ~320) non hanno alcun timeout: `loop { receive; sleep(2s); if has_packages break; }`. Un partecipante che non invia mai blocca tutti a tempo indeterminato, senza dire chi manca.
- Il bound apparente (SESSION_TIMEOUT 24h, `frostd/src/state.rs:16-17`) è aggirabile: `send` rinnova il timeout incondizionatamente (`frostd/src/functions.rs:236`), e i duplicati sono assorbiti come overwrite silenzioso (`session.rs`: "Currently ignores the possibility of overwriting previous values").
- **Un qualsiasi membro può tenere il DKG bloccato per sempre** inviando periodicamente un duplicato cifrato del proprio package. DoS-only, costo quasi zero. Fix: timeout client-side + abort esplicito con report di chi non ha risposto.

## Z1 — zcash-sign: blind signing (hardening, medio-bassa)

- `sign_pczt` (`zcash-sign/src/sign.rs`) mostra solo `SIGHASH: <hex>` prima di chiedere le firme su stdin. Nessun importo, destinatario, fee, riepilogo.
- La crypto chiude le falle vere: `apply_signature` verifica ogni firma contro `(rk_spend, sighash)`; replay su altro spend fallisce (rk diversa); nessun TOCTOU (file letto una volta); dispatch v5/v6 pinnato da test; il tool non broadcasta.
- Sfruttamento richiede produttore PCZT malevolo + firmatario che autorizza senza ispezione. Gap UX genuino per un signing tool: stampare riepilogo human-readable prima di `prompt_for_signatures`.

## Verificati sicuri (lead killati)

- **Blame propagation**: `dkg/cli.rs` propaga `InvalidSecretShare { culprit }` senza catch fino al main; libreria 2.2.0 popola davvero il colpevole; in HTTP l'identifier deriva da `(session_id ‖ comm_pubkey)` → risalibile al pubkey.
- **Replay cross-sessione**: identifier session-bound + PoK lega l'identifier nel challenge → replay sotto nuovo identifier fallisce con `InvalidProofOfKnowledge`.
- **Distribuzione share**: DKG round2 cifra per singolo destinatario (Noise); trusted dealer distribuisce solo in locale (stdout/file, "intended for tests only").
- **Threshold discordi**: `part2` controlla `commitment.len() == min_signers` → fail-closed, niente chiavi deboli silenziose. `min > max` catturato in `part1`.
- **close_session**: richiede `coordinator_pubkey` → joiner non può killare sessioni altrui.

## Note minori

- Secret share stampate in chiaro su stdout (`dkg/cli.rs`, trusted_dealer) — esposizione via scrollback/CI log; coerente con status demo.
- Commento `cipher.rs::decrypt` ottimistico: Noise_K non autentica l'initiator; il sender-auth dipende dal relay fidato. Documentation gap.
- Messaggio d'errore cita flag `-S` inesistente (`dkg/comms/http.rs`).
- `.unwrap()` su input utente in `zcash-sign/src/main.rs` (panic = DoS locale).
- `sign_ywallet.rs` è `#![cfg(false)]` — superficie morta.
- `generate.rs` usa costruttore non-quantum-recoverable deliberato (frost-tools#591, indicazione ZF) — sound.
