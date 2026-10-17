# DEPTH AUDIT Round 2 — Worker B: PoC pratici candidati #1/#2/#3 (FROST/zcash)

*Note di lavoro originarie del 2026-10-17, con correzioni successive. Le esecuzioni qui descritte sono dichiarate dal report originario. I relativi log grezzi e i driver dei PoC #2/#3 non sono inclusi nel repository pubblico.*

> Leggere [ERRATA-AND-EVIDENCE.md](../../ERRATA-AND-EVIDENCE.md) per lo stato delle verifiche indipendenti, i limiti e i collegamenti alle comunicazioni upstream.
*Repo: `~/workspace/hunt/frost-client-audit/frost-tools` (commit di lavoro locale). Build con `CARGO_TARGET_DIR=~/workspace/hunt/frost-client-audit/target-workerB`, rustc 1.99.1.*

## Sintesi verdetti

| PoC | Candidato Round 1 | Verdetto | Note |
|-----|-------------------|----------|------|
| #1 | frostd memory exhaustion (`functions.rs:196-237`) | **CONFERMATO DAL REPORT ORIGINARIO** | Misure riportate; arresto per fallimento allocatore |
| #2 | Noise_K peer impersonation (`cipher.rs:234-243`, snow 0.9.6) | **SMENTITO** | L'assunto cripto del Round 1 è falso: snow lega `rs` al transcript hash |
| #3 | Missing cheater detection (`coordinator/cli.rs:79-92`) | **SMENTITO** (claim centrale) | `cheater-detection` è nei *default features* di frost-core 2.2.0; il colpevole VIENE identificato |

---

## PoC #1 — frostd memory exhaustion via fan-out illimitato — riportato storicamente

**Setup.**
- Binario `frostd` compilato dal sorgente (`target-workerB/debug/frostd`).
- Driver d'attacco: `frostd/examples/poc1_dos.rs` — fa login reale (challenge → firma xed25519 → `/login`), crea una sessione con N pubkey fasulle a 32 byte, invia UN `send` con N recipients × 65535 byte, misura RSS del server via `/proc/<pid>/status` prima/dopo.
- **Sicurezza:** VM con ~0.9–2.6 GB liberi e zero swap. Il server è girato sotto `ulimit -v 800000` (781 MB di spazio virtuale): RSS non può mai superare il limite virtuale, quindi l'host è al sicuro. Tra una fase e l'altra il server è stato riavviato per misure pulite (la coda non viene drenata dal PoC).

**Ricontrollo codice:** confermato nessun bound — `send` controlla solo `args.msg.len() > MAX_MSG_SIZE` (65535) e poi `args.msg.clone()` per ogni recipient in `VecDeque<Msg>` senza limiti (`functions.rs:196-237`).

**Misure riportate dal report originario (log grezzi non disponibili):**

| recipients | msg | crescita RSS riportata | payload teorico |
|---|---|---|---|
| 500 | 65535 B | **31.6 MiB** | 31.2 MiB |
| 1000 | 65535 B | **63.1 MiB** | 62.5 MiB |
| 2000 | 65535 B | **126.1 MiB** | 125.0 MiB |

Crescita riportata circa lineare: una copia di 65.535 byte per destinatario più overhead. Il driver converte RSS in KiB dividendo per 1.024: l'unità corretta della tabella è MiB; le precedenti stime di ~63.1 KB/destinatario mescolavano unità e sono ritirate. `send` ha risposto `200 OK` in 52–148 ms in tutti i casi.

**Kill test riportato dal report originario:** server fresco sotto `ulimit -v 800000`, singolo `send` con **29000 recipients × 65535 B** (≈1.9 GB di payload teorico):
- il report registra `memory allocation of 65535 bytes failed` → SIGABRT (comportamento standard di Rust su allocator failure);
- il report registra `hyper::Error(IncompleteMessage)` lato client (connessione troncata);
- il report registra **SERVER DEAD** tramite `ps`. Il run non è stato riprodotto indipendentemente nella verifica successiva.

**Verdetto attuale.** Il codice copia il messaggio una volta per destinatario senza un limite aggregato; una verifica locale limitata ha recuperato 64 copie integre. Il report originario descrive un SIGABRT sotto limite di memoria, ma i log grezzi non sono disponibili e il crash non è stato riprodotto nella revisione successiva. Il prodotto 29.000 × 65.535 = 1.900.515.000 byte è il payload *teorico richiesto* (circa 1,90 GB / 1,77 GiB), non memoria effettivamente accodata né RSS misurata nel run che abortisce. Servono un login ottenibile con registrazione autonoma e una sessione; `frostd` è codice demo ("not for production").

---

## PoC #2 — Noise_K peer impersonation — SMENTITO

**Setup.** Crate `poc-noise` (`frost-tools/poc-noise/`, membro del workspace per riusare il Cargo.lock), binario `poc2-noise-impersonation`, `snow = "=0.9.6"` (versione esatta del workspace). Riproduce fedelmente `Cipher::new`/`decrypt`:
- responder = `local_private_key(coord_priv).remote_public_key(victim_pub).build_responder()` (rs pre-popolato con la chiave attesa, come `recv_noise_map[sender]`);
- initiator = `local_private_key(attacker_priv).remote_public_key(coord_pub).build_initiator()` (statica DIVERSA; la pubkey del coordinator è pubblica, necessaria per i DH `es`/`ss`).

**Output riportato nelle note originali (log grezzi non disponibili):**
```
(A) honest handshake (static == expected rs): true
(B) impersonation handshake (attacker static, victim rs): Err(Decrypt)
(C) handshake with matching expectation (attacker static, attacker rs): true
```

**Analisi corretta del pattern (verifica sorgenti del 2026-10-17).** Nel `Noise_K` one-way di snow 0.9.6, le chiavi statiche sono pre-messaggi e il messaggio contiene `[E, Dh(Es), Dh(Ss)]`: **non contiene alcun token `S`**. La precedente descrizione del decrypt di un token `S` e della sua sovrascrittura non descrive quindi il percorso K. L'autenticazione dipende, tra l'altro, dal DH statico-statico `ss`, che richiede la chiave privata corrispondente alla chiave statica attesa. Il verdetto di ritiro del candidato impersonation resta coerente con il sorgente; le trascrizioni di esecuzione di seguito sono quelle riportate nelle note originali, non log grezzi pubblicati separatamente.

**Verdetto: SMENTITO.** L'handshake di impersonificazione fallisce a livello crittografico. Il commento in `cipher.rs` ("this authenticates the sender") è **vero negli effetti**: forgiare `sender` seleziona uno stato responder il cui `rs` atteso non può coincidere con la statica reale dell'attaccante → handshake fallito → decrypt fallito. Il confronto mancante di `get_remote_static()` (confermato: 0 occorrenze in `frost-client/src`) è innocuo — sarebbe ridondante. **F1 del coordinator-audit va rimosso/chiuso.**

---

## PoC #3 — Missing cheater detection — SMENTITO (claim centrale)

**Setup.** Crate `poc-noise`, binario `poc3-cheater-detection` (`frost-ed25519 = "=2.1.0"`, `frost-core = "=2.2.0"`): cerimonia FROST completa (trusted dealer 3-of-5, round 1, signing package, round 2), corruzione di una signature share (flip di un byte nella serializzazione, resta uno scalare valido ma sbagliato), poi `aggregate()` — esattamente ciò che fa `coordinator/cli.rs:79-92`.

**Scoperta chiave (verificata, non assunta).** Il Round 1 affermava: "frost-client/Cargo.toml (frost-core **senza** feature `cheater-detection`)". **Falso.** `frost-core 2.2.0` ha `cheater-detection` nei **default features** (`[features] default = ["serialization", "cheater-detection", "std"]`, righe 51-55 del suo Cargo.toml), e nessun membro del workspace frost-tools imposta `default-features = false`. Verificato con `cargo tree -p frost-client -e features`: `frost-core v2.2.0` ha la feature `cheater-detection` abilitata. Anche `frost-rerandomized 2.1.0` (path con randomizer) la ha nei default e delega a `frost::aggregate`.

**Output osservato (configurazione REALE di frost-client):**
```
frost-core cheater-detection feature: ENABLED (frost-client's actual config)
aggregate() failed as expected.
  error debug : InvalidSignatureShare { culprit: Identifier("02...") }
  culprit()   : Some(Identifier("02..."))
  VERDICT: the cheater IS identified by aggregate(): true
```

**Confronto con build ipotetica senza default** (crate separata `poc-nocheat`, `default-features = false` su entrambi, build isolata per evitare l'unificazione delle feature):
```
  error debug : InvalidSignature
  culprit()   : None
```
→ il `InvalidSignature` generico e non attribuito esiste solo SENZA la feature, configurazione che **non si verifica** nella build reale di frost-client.

**Verdetto: SMENTITO sul claim centrale.** Il coordinator riceve `InvalidSignatureShare { culprit }` e il colpevole È identificato — il "griefing non attribuibile" non esiste. Residuo debole (onesto): il codice del coordinator non *agisce* sull'attribuzione (nessuna logica di esclusione/retry — ma i nonce di round 1 sono single-use per design FROST, quindi un restart con nuovi nonce è comunque necessario). Al massimo una nota di robustness, non un finding.

---

## Artefatti

- Driver PoC #1: `~/workspace/hunt/frost-client-audit/frost-tools/frostd/examples/poc1_dos.rs`
- PoC #2: `~/workspace/hunt/frost-client-audit/frost-tools/poc-noise/src/bin/poc2.rs`
- PoC #3: `~/workspace/hunt/frost-client-audit/frost-tools/poc-noise/src/bin/poc3.rs`
- Variante no-default: `~/workspace/hunt/frost-client-audit/frost-tools/poc-nocheat/src/bin/nocheat.rs`
- Binari: `~/workspace/hunt/frost-client-audit/target-workerB/debug/{frostd, examples/poc1_dos, poc2-noise-impersonation, poc3-cheater-detection, nocheat}`
- Modifica al repo (additiva): `frost-tools/Cargo.toml` — aggiunti i membri `poc-noise`, `poc-nocheat` (serve per condividere Cargo.lock; nessun file esistente toccato)

## Implicazioni per il coordinatore

1. **#1 (frostd DoS) resta l'unico candidato vivo dei tre.** Il fan-out senza limite aggregato è visibile nel codice e una verifica locale ha recuperato 64 copie del messaggio. Le misure RSS Linux e il kill test sono risultati riportati dalle note originali, senza log grezzi disponibili, e non sono stati riprodotti nella verifica successiva. L'impatto resta circoscritto al relay demo nei percorsi verificati.
2. **#2 (Noise_K impersonation) va chiuso**: l'analisi Round 1 era sbagliata sul meccanismo cripto. snow 0.9.6 autentica `rs` via transcript hash. Nessun fix necessario.
3. **#3 (cheater detection) va chiuso o declassato a nota**: l'analisi Round 1 non aveva verificato i default features. L'attribuzione esiste già; resta solo la mancanza di exclusion/retry nel coordinator (robustness minore).
4. Lezione metodologica: **verificare sempre i default features** dei crate prima di affermare "senza la feature X" — `cargo tree -e features` è il check da una riga. E per snow: il pattern K one-way di snow NON è il K interattivo della spec — i pre-messaggi includono la statica dell'initiator.
