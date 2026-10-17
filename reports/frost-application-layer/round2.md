# DEPTH AUDIT — FROST/Zcash Round 2: ywallet + PoC + fuzzing + chaining

*2026-10-17. NESSUNA disclosure, NESSUNA submission. Report privato per il parent.*
*Continuazione del Round 1 — non una chiusura. Dottrina applicata: chaining sistematico + niente verdetti prematuri.*

## Verdetto Round 2

**1 finding confermato con PoC misurato. 2 headline smentiti con doppia verifica indipendente. Chaining: nessuna escalation. Fuzzing: negativo onesto. ywallet: nessuna integrazione FROST.**

Questo round ha fatto ciò che il Round 1 non poteva: **eseguire** invece di leggere. Il risultato più importante non è un finding — è che due dei tre candidati principali del Round 1 erano sbagliati, e lo abbiamo dimostrato con prove, non con opinioni.

## Scoreboard cumulativo

| Round | Superficie | Verdetto |
|---|---|---|
| R1 (lib) | frost-core v3.0.0, DKG, RedPallas ciphersuite | 0 finding, codice eccellente |
| R1b (tools) | frostd, frost-client, zcash-sign (statico) | 0 forgery, 7 candidati DoS/design-gap in codice demo |
| **R2-A** | ywallet / Zallet / flusso PCZT | Nessuna integrazione FROST in production; gap blind-signing documentato (design, non exploitable) |
| **R2-B** | PoC #1/#2/#3 | **#1 CONFERMATO** (OOM misurato + kill); #2 SMENTITO (×2 indipendenti); #3 SMENTITO |
| **R2-C** | Fuzzing HTTP state machine frostd | Negativo onesto (release + debug, ~1.270 richieste, 0 crash) |
| **R2-D** | Chaining 7 candidati + revisit killati | Nessuna catena scala a fondi; #2-refutation uccide le catene; kill confermati |

## R2-A — Integrazione wallet reale: il vuoto

[round2-workerA-ywallet-flow.md](sandbox://workspace/bounty/reports/zcash-audit/frost-client/round2-workerA-ywallet-flow.md)

- **ywallet (hhanh00/zwallet): zero FROST**, verificato esaustivamente (grep su Dart/Rust/Android/iOS/config per frost/threshold/shamir/dkg/multisig — solo rumore). La history git conferma: mai toccato.
- **Zallet: zero FROST signing code.** `frost-core` appare solo come dipendenza transitiva di `reddsa` (supporto RedPallas), come in qualsiasi wallet Orchard.
- **Il flusso documentato è rotto in HEAD**: il commit `36df5d2` (#574) ha disabilitato il signing del JSON-plan Ywallet (`sign_ywallet.rs` è `#![cfg(false)]`) senza fornire un costruttore JSON→PCZT. Il tutorial del FROST Book non gira.
- **Gap reale (design, non finding)**: tracciato il sighash end-to-end — ogni checkpoint umano mostra solo hex opaco (zcash-sign: `SIGHASH: <hex>`; coordinator: hex arbitrario; participant: y/n su 64 char hex). Un coordinator malevolo può far firmare un PCZT attaccante a co-firmatari onesti senza che se ne accorgano. Ma **nessun wallet production consuma questo flusso** → nessun path su fondi veri → nessun draft, per protocollo. Il modello corretto esiste ed è quello di OpenPGP Wallet (telefono ri-parsa il PCZT, ZIP 374 signer checks, rifiuta PCZT redatti) — ancora solo design, codice "nelle prossime settimane".

## R2-B — PoC: uno confermato, due smentiti

[round2-workerB-pocs.md](sandbox://workspace/bounty/reports/zcash-audit/frost-client/round2-workerB-pocs.md)

### #1 frostd memory exhaustion — CONFERMATO ✅
Driver `frostd/examples/poc1_dos.rs`: login reale → sessione con N pubkey fasulle → un `send` con N recipients × 65535 B, RSS misurata via `/proc`, server sotto `ulimit -v 800000`.

| recipients | RSS growth | per-recipient |
|---|---|---|
| 500 | 31,6 MB | 63,2 KB |
| 1000 | 63,1 MB | 63,1 KB |
| 2000 | 126,1 MB | 63,1 KB |

Linearità perfetta. Kill test: 29000 recipients → `memory allocation of 65535 bytes failed` → SIGABRT → **server morto**. DoS da singola richiesta autenticata, dimostrato. Onesto: serve login self-registered, codice demo → valore submission basso, bug reale.

### #2 Noise_K impersonation — SMENTITO ❌ (doppia verifica indipendente)
Il Round 1 aveva applicato la logica del pattern Noise **X** al pattern **K**. Nei sorgenti reali di snow 0.9.6: in K l'initiator **non trasmette alcuna chiave statica**; il token `Dh(Ss)` richiede la private key corrispondente alla `rs` pre-configurata. Impersonare senza la comm-privkey della vittima è crittograficamente impossibile. Worker D (analisi + test `noise_k_impersonation.rs`, 3/3) e Worker B (PoC indipendente `poc2.rs`, derivato prima di conoscere D) **convergono**. La fix proposta dal Round 1 ("confrontare `get_remote_static()`") era una tautologia — ritirata. Residuo reale: replay dell'handshake K → slot-squat DoS (finestra = restart coordinator), severità bassa/nota.

### #3 Missing cheater detection — SMENTITO ❌ (il Round 1 aveva torto sui fatti)
`frost-core 2.2.0` ha `cheater-detection` nei **default features**; nessun membro del workspace la disabilita (`cargo tree -e features` conferma). Con la configurazione reale: `InvalidSignatureShare { culprit: Identifier("02…") }` — **il colpevole viene identificato**. Il "griefing non attribuibile" non esiste. Residuo debole: il coordinator non agisce sull'attribuzione (no exclusion/retry).

**Lezione metodologica**: verificare sempre i default features prima di affermare "senza feature X"; non applicare la logica di un pattern Noise a un altro.

## R2-C — Fuzzing: negativo onesto, due build

[round2-workerC-fuzzing.md](sandbox://workspace/bounty/reports/zcash-audit/frost-client/round2-workerC-fuzzing.md)

~1.270 richieste su frostd (malformate, sequenze state machine, race, boundary) — **0 crash, 0 panic, 0 bypass, 0 inconsistenze**, sia in release che in debug (overflow checks + debug_assertions attivi). Dettaglio notevole: il login verifica la firma via `xeddsa` (X25519-Montgomery → Edwards) — una Ed25519 pura viene rifiutata; il worker ha costruito un signer XEdDSA corretto per fuzzare il login reale. Tutti i 500 sono `LowError` strutturati, zero stack trace. Race: challenge esattamente 1 vincitore su 16, accounting messaggi esatto. Unico comportamento confermato: il fan-out unbounded di `send` (#1, già noto).

## R2-D — Chaining: la risposta brutale è NO

[round2-workerD-chaining.md](sandbox://workspace/bounty/reports/zcash-audit/frost-client/round2-workerD-chaining.md)

Matrice sistematica delle composizioni:
- **#2+#3, #2+#7, #5+#2**: crollano con la premessa (#2 smentito).
- **#1+#4**: ridondanza, non composizione (#1 sussume il DKG).
- **#5+insider+blind-confirm**: unico scenario che tocca i fondi — ma il primitivo è già il blind-signing (F4), #5 aggiunge solo un trigger alternativo. Boundary documentato, non nuova finding.
- **#6+coordinator malevolo**: zcash-sign è file-based, nessuna iniezione remota.

**Nessuna catena scala da DoS/design-gap a fondi/chiavi.** Il core FROST regge contro coordinator+relay combinati (ri-derivazione formale: binding ρ/c, Drijvers bloccato dal one-shot). Revisit killati: split-view confermato killato anche nel caso combinato; nonce-reuse confermato killato (nessun lock esiste né serve).

## Cosa resta in piedi (onesto)

1. **#1 frostd OOM** — confermato con PoC misurato. DoS reale, codice demo, submission value basso.
2. **#4 DKG griefing** — wait-loop senza timeout, non PoC-testato in questo round.
3. **#5 phantom session** — spoofing/DoS, non PoC-testato.
4. **#6 zcash-sign blind signing** — gap UX reale, nessun trigger remoto.
5. **#7 minori** — insider DoS, token drain, ecc.
6. **Gap blind-signing end-to-end** (R2-A) — design gap documentato, in attesa di un consumer production.

## Valutazione grant (onesta)

Nessun finding ha il peso di una submission critica da solo. Il pacchetto "hardening del reference implementation FROST" (DoS #1 dimostrato + fuzzing negativo + gap blind-signing documentato + due false-positive smentiti rigorosamente) è un **contributo di hardening coerente**, non una vulnerabilità da $1.5M. La decisione spetta al parent: presentarlo come hardening del reference (soprattutto #1 + gap blind-signing) oppure continuare a scavare.

## Prossimi angoli (non una chiusura)

1. **#4 e #5 con PoC** — i due candidati DoS non ancora eseguiti. Stesso rigore di #1.
2. **RedPallas ciphersuite migration** — quando ri-atterra nel repo `frost`, re-verificare gli override (lezione audit Mina).
3. **frost-client/wallet layer** — track parallelo già attivo (altro worker).
4. **HashSmash** — competizione AI-vs-hash, costo d'ingresso basso, dalla mappa.
5. **Monitorare OpenPGP Wallet** — quando pubblicano il codice, il loro modello (ZIP 374 checks sul telefono) è il confronto per validare il gap blind-signing.

*Sub-report: `round2-workerA-ywallet-flow.md`, `round2-workerB-pocs.md`, `round2-workerC-fuzzing.md`, `round2-workerD-chaining.md`.*
*Artefatti PoC: `~/workspace/hunt/frost-client-audit/frost-tools/frostd/examples/poc1_dos.rs`, `poc-noise/`, `poc-nocheat/`, `~/workspace/hunt/frost-client-audit/fuzz-frostd/`.*
