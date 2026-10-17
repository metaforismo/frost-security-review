# Round 2 — Worker D: chaining sistematico + revisit lead killati (FROST)

> **Historical research notes.** Read [errata and evidence status](../../ERRATA-AND-EVIDENCE.md) before using any candidate finding, absolute safety claim, deployment claim, or test count below. The later review did not independently rerun every claim. In particular, the original blanket conclusion that nonce reuse was impossible or that all chains to funds were formally eliminated is withdrawn. Original draft/privacy references describe the working state before publication.

*2026-10-17. NESSUNA disclosure, NESSUNA submission. Report privato per il parent.*
*Dottrina chaining: per ogni coppia/tripla, scenario concreto + verdetto onesto (scala / non scala + perché).*

## 0. CORREZIONE CRITICA al Round 1 — il meccanismo di #2 (Noise_K) non regge

Prima di concatenare, riverifica del mattone #2 contro i sorgenti reali di `snow 0.9.6`
(estratto dal cargo cache, non dai ricordi):

- `patterns.rs`: il pattern **K** è `([S] premsg_i, [S] premsg_r, [[E, Dh(Es), Dh(Ss)]])`.
  L'initiator **non trasmette alcuna chiave statica**: non c'è nessun token `S` nel
  messaggio. La chiave statica dell'initiator è un *premessage* (pre-configurata su
  entrambi i lati).
- `handshakestate.rs:374` (il `Token::S => { ... self.rs.enable() }` citato dal
  Round 1 come riga 390) **non è nel path del pattern K**. Il Round 1 ha applicato
  la logica del pattern X a K — lettura sbagliata.
- Il token `Dh(Ss)` (static-static DH) richiede all'initiator la **private key**
  corrispondente alla `rs` pre-configurata dal responder. Il payload è
  AEAD-cifranto sotto una chaining key che include `ss`: senza la privkey della
  vittima il `decrypt_and_mix_hash` finale **fallisce** → handshake rigettato.
- `get_remote_static()` non è mai chiamato nel codebase (verificato con grep), ma la
  fix proposta dal Round 1 ("confrontare `get_remote_static()` con `msg.sender`")
  sarebbe comunque una **tautologia**: restituirebbe lo stesso valore usato per la
  lookup in `recv_noise_map`. Da ritirare.

**Test empirico** (`frost-client/tests/noise_k_impersonation.rs`, sul `Cipher` reale —
`cargo test -p frost-client --test noise_k_impersonation`, 3/3 passati):

```
[attack] decrypt ok? false    <- relay senza privkey vittima, sender forgiato: RIGETTATO
[control] real victim decrypt ok? true
[tamper] decrypt ok? false    <- handshake genuino con sender manomesso: RIGETTATO
[replay] replayed handshake decrypt ok? true    <- replay handshake K: ACCETTATO
[replay] victim fresh handshake after squat ok? false  <- vittima vera poi LOCKED OUT
```

**Conseguenze per #2:**

1. L'impersonation Noise_K **senza la comm-privkey della vittima è impossibile**.
   Il commento nel codice ("this authenticates the sender") è, per K, **vero** —
   il Round 1 lo dichiarava falso per la ragione sbagliata. L'auth lega
   `msg.sender` → pubkey pre-configurata in rubrica → prova di possesso della
   privkey via `ss`. Tamperare `sender` = `ss` mismatch = decrypt fallito.
2. Il relay malevolo **non** può iniettare contenuto cifrato come vittima. Può:
   drop/delay (fuori threat model), forgiare `sender` a livello transport su byte
   spazzatura (il decrypt del coordinator fallisce → abort, vedi sotto), e fare
   **replay di handshake genuini** dopo un restart del coordinator → slot-squatting
   → lockout della vittima (DoS stretto, finestra = restart coordinator).
3. #2 declassato: da "impersonation" a "K-handshake replay → slot-squat DoS
   (stretto)" + documentation gap rientrato. **Tutte le catene che usano #2 come
   impersonation crollano con la premessa.**

---

## 1. Matrice delle composizioni

### #2 + #3 — framing via share invalida a nome della vittima
**Scenario ipotizzato:** relay impersona V (via #2), inietta share invalida come V →
`aggregate()` fallisce `InvalidSignature` → senza cheater detection (#3) il
coordinator non identifica il colpevole → V appare come griefer; oppure: l'attaccante
brucia i nonce di tutti senza essere identificato.

**Verdetto: NON SCALA — premessa morta.** Con #2 corretto, il relay non può
completare l'handshake come V (serve la privkey di V). Cosa può fare davvero il
relay: iniettare byte spazzatura con `sender=V` forgiato server-side → il
`cipher.decrypt(msg)?` del coordinator (`coordinator/comms/http.rs:156`)
fallisce con `SnowError` → **abort immediato della cerimonia**, non
`InvalidSignature` attribuito a V. Quindi: (a) nessun framing — l'errore è
distinguibile (decrypt-fail vs bad-share); (b) il griefing resta un DoS grezzo,
non "non attribuibile" nel senso di #3. Il griefing non attribuibile con
bruciatura nonce esiste già come **#3 standalone** (insider autenticato che manda
share invalida) — la composizione non aggiunge nulla.

### #2 + #7 — token bearer rubato + impersonation + drain
**Scenario ipotizzato:** ladro del bearer token (es. via `--no_tls_very_insecure`)
impersona V via Noise_K (#2) E drena la sua coda via `receive` (#7) → V
completamente silenziata senza saperlo.

**Verdetto: NON SCALA — sostituti, non moltiplicatori.** Analisi per attore:
- *Token thief (senza privkey di V):* il token dà già tutto a livello transport —
  `send` imposta `sender=user.pubkey` (= V) server-side, `receive` fa `drain(..)`
  distruttivo. Ma il thief **non può** completare l'handshake Noise_K come V
  (serve la comm-privkey per `ss`, il token non basta; il login stesso richiede
  firma della challenge con la privkey). Quindi #2 non aggiunge nulla al thief:
  può fare DoS grezzo (garbage → decrypt-fail → abort; drain → silenzio) ma non
  iniettare contenuto cifrato credibile come V. Paradossalmente Noise_K qui
  *limita* l'attaccante, non lo aiuta.
- *Relay operator:* non ha bisogno del token (controlla già `sender`).
I due vettori sono **percorsi alternativi** alla stessa capacità transport-level,
in mano ad attori diversi. Nessuna escalation composizionale. Resta valido #7
standalone: thief → `receive` come V → coda drenata → il participant di V resta
appeso su "Waiting for coordinator..." all'infinito (hang, non crash — il client
non se ne accorge).

### #1 + #4 — OOM del relay + DKG griefing indefinito
**Scenario:** #1 uccide il relay (1.9 GB da singola request, ripetibile) mentre #4
tiene il DKG bloccato per sempre via wait-loop senza timeout.

**Verdetto: NON SCALA — ridondanza, non composizione.** #1 da solo uccide già
*tutte* le cerimonie incluse quelle DKG (stesso relay, stesso processo). #4
aggiunge solo: "anche dopo aver fixato/riavviato il relay, il DKG resta bloccato
dal griefer". È defense-in-depth del DoS, non un salto di severità. Nessun path
ai fondi: il DKG o completa con chiave valida o abortisce; il griefing non
indebolisce le chiavi (blame/PoK reggono).

### #5 + #2 — phantom session + impersonation
**Scenario ipotizzato:** vittima fa auto-join nella sessione dell'attaccante;
con #2 l'attaccante spinge oltre l'impersonation.

**Verdetto: #2 IRRILEVANTE — #5 sta da solo.** Nella sessione fantasma l'attaccante
È il coordinator legittimo: non deve impersonare nessuno. L'unico gate è
l'address-book check (`participant/comms/http.rs`: "coordinator not in address
book") — un insider ce l'ha già passato. Traccia precisa di cosa ottiene
l'attaccante (vittima NON insider, nessun share dell'attaccante nel gruppo vittima
— Caso B):
1. La vittima carica il **proprio** KeyPackage (config locale) — l'attaccante non
   lo tocca.
2. La vittima genera nonce freschi e manda i commitment (pubblici comunque).
3. L'attaccante costruisce un package con dentro i commitment della vittima
   (altrimenti `IncorrectCommitment`) + i propri.
4. La vittima vede hex + y/n. Se digita `y`, firma col suo share reale e lo manda.
5. L'attaccante ottiene: **una singola share** su un messaggio a sua scelta.
   Non può aggregare (mancano t−1 share del gruppo vittima). La share singola con
   nonce freschi non leakka `s_i`. **Fondi: zero.** Ottiene solo DoS/attenzione
   della vittima + intel di social engineering.
Caso A (attaccante = insider con share nel gruppo vittima): vedi §2 — è l'unico
scenario fondi, ma non è la catena a crearlo.

### #5 + insider + blind-confirm — il confine dei fondi
**Scenario concreto** (t=2, attaccante A membro del gruppo con 1 share):
1. A crea sessione fantasma `{A, V}` su frostd, A coordinator.
2. V lancia `frost-client participant` senza `-S`; unica sessione visibile = quella
   di A → **auto-join silenzioso** (#5). Address-book check: passa (A è membro).
3. V manda commitment (Noise_K verso A — cifratura vera, irrilevante).
4. A costruisce `SigningPackage{commitments:{A,V}, message=m_evil}` dove `m_evil`
   è es. il sighash di una tx Zcash che paga A.
5. `confirm_message` mostra a V solo **hex di m_evil + y/n** (F4). V digita `y`.
6. V firma con lo share reale → A aggrega la propria share → **firma di gruppo
   valida su m_evil** → A finalizza/broadcasta → **fondi mossi**.

**Verdetto: FONDI SÌ, ma NON È la composizione a produrli — nessuna escalation di
classe.** Il primitivo "insider malizioso + vittima che conferma hex alla cieca"
è già interamente descritto da F4 (`confirm_message` hex+y/n unica difesa): un
insider-coordinator in una cerimonia *legittima* ottiene lo stesso risultato con
meccanica identica e precondizioni identiche (share insider + threshold
raggiungibile + `y` della vittima). #5 cambia solo il **trigger** (la vittima non
aveva intenzione di firmare; basta che lanci il binary mentre la sessione fantasma
è l'unica visibile) ma non rimuove né aggiunge requisiti, e l'esito è identico.
È una variante di delivery di F4, non un salto DoS→fondi. Documentata qui come
boundary, non come nuova finding.

### #6 + coordinator malevolo — zcash-sign blind signing
**Meccanica corretta** (riverificata): `zcash-sign` NON è il firmatario FROST —
`sign_pczt` mostra `SIGHASH: <hex>`, poi `prompt_for_signatures` chiede di
**incollare** share prodotte esternamente e `apply_signature` le verifica contro
`(rk_spend, sighash)`. Il PCZT arriva da **file locale** (`tx_plan`), non dalla
rete: nessuna iniezione remota possibile (#5 non compone: zcash-sign non fa
auto-join di sessioni). Lo sfruttamento è: coordinator malevolo passa alla vittima
un PCZT che dirotta i fondi ("firma il payroll") → vittima produce share col
frost-client (hex+y/n, F4) → le incolla → se la collusione raggiunge t, fondi
persi. **Confronto col modello wallet (ZIP-374 / OpenPGP):** lì il secondo device
(trusted, es. telefono) riesegue i check ZIP-374 sul PCZT *prima* di co-firmare;
qui l'unico "secondo fattore" è un umano che legge 64 hex char. Per utenti
non-tecnici in un deployment reale è un gap sfruttabile via social engineering —
ma resta condizionato a collusione threshold + inganno, e non scala con nessuno
degli altri candidati. Verdetto: gap UX reale, già candidato (Z1); nessuna
composizione lo amplifica.

### Altre coppie (scremate, nessuna trazione)
- **#3 + #1-variante** (bury coda coordinator): due modi diversi di uccidere la
  liveness, attori diversi; nessuna interazione.
- **#7 + #5:** il token thief non passa l'address-book check come coordinator
  credibile e non può completare Noise_K come V → morto.
- **#4 + #2/#3:** il DKG è peer-to-peer senza coordinator; #2/#3 non c'entrano.
- **#1 come smokescreen** per downgrade a SocketComms plaintext (F3): speculativo
  sul comportamento utente, non una catena. Scartata.

---

## 2. La domanda chiave: esiste una catena DoS → fondi?

**Risposta brutale: NO.** Dimostrazione per esaustione:

1. Il core crittografico regge contro **coordinator malevolo + relay malevolo
   combinati** (ri-derivazione in §3): binding `ρ_i=H1(i,m,L)`, challenge
   `c=H2(R,vk,m)`, share di package diversi non aggregano; l'attacco Drijvers
   richiede doppia firma sullo stesso nonce, impossibile col participant one-shot;
   il relay vede solo ciphertext che non può usare (è già il destinatario
   legittimo di share/commitment in chiaro verso il coordinator).
2. Tutte le composizioni tra i 7 candidati restano in **availability**
   (DoS/liveness/framing-mancato) o collassano per premesse false (#2).
3. L'unico scenario che tocca i fondi (insider + blind-confirm, §1 Caso A) **non
   è generato dalla composizione**: esiste già come F4 senza bisogno di #5, e #5
   gli aggiunge solo un trigger alternativo a parità di precondizioni ed esito.

**Nessun draft, nessuno stop.** Il boundary più vicino ai fondi resta F4/Z1
(blind signing) — già noto dal Round 1; la raccomandazione è hardening
(riepilogo human-readable del PCZT / binding sessione-contesto), non una nuova
finding.

---

## 3. Revisit dei lead killati (occhi nuovi, dottrina: non chiudere presto)

### 3a. Split-view/equivocation con coordinator che controlla ANCHE il relay — rifatto da zero
**KILL CONFERMATO, argomento rafforzato.** In `frost-core 2.2.0` (`src/round2.rs:125`):
`z_i = d_i + e_i·ρ_i + λ_i·s_i·c`, con `ρ_i` da `compute_binding_factor_list`
(`H1(i, m, L)`) e `c = H2(R, vk, m)`. Caso per caso:
- *Package diversi a firmatari diversi:* share legate a `(R_A,c_A)` vs `(R_B,c_B)`
  non aggregano mai a una firma valida — il check del verifier fallisce comunque.
- *Drijvers (stesso nonce, due binding):* richiede due `sign()` sullo stesso
  `SigningNonces`. Il participant è one-shot (`participant/cli.rs:84-114`:
  genera → un `get_signing_package` → un `confirm` → un `generate_signature` →
  exit; a errore il processo muore e i nonce sono `Zeroizing`-droppati). Il
  coordinator+relay non può estrarre due firme da un processo che ne fa una sola
  e poi esce; due processi = due nonce freschi indipendenti.
- *Replay share sessione 1 → sessione 2:* `R` fresco → share invalida;
  `aggregate()` verifica comunque (è per questo che #3 produce `InvalidSignature`
  invece di una firma sbagliata).
- *Il relay "vede tutto":* vede ciphertext Noise (non li apre) ed è già il
  destinatario legittimo in chiaro di commitment/share verso il coordinator —
  nessuna informazione nuova sfruttabile per forgery. Nel DKG l'echo-broadcast
  (Goldwasser-Lindell, `session.rs`) neutralizza l'equivocation del relay: solo
  DoS.
Il Round 1 non aveva esplicitato il caso coordinator+relay; l'analisi regge anche lì.

### 3b. Riuso nonce: stesso share in DUE istanze del participant — KILL CONFERMATO
Verificato: i nonce nascono in `participant()` da `thread_rng()` **per-processo**,
nessuno stato condiviso, nessun file, nessun pool. Due macchine / due processi =
due set di nonce indipendenti; lo share long-term condiviso è normale uso FROST,
non un leak. **Non esiste alcun lock e non ne serve alcuno.** Caveat onesto (già
noto): la safety è implicita nel control-flow one-shot, non difesa in profondità —
se un futuro maintainer trasforma `participant()` in daemon con pool di nonce, il
leak classico appare silenziosamente. Nota di hardening, non finding. (La
refactor "participant as library", commit `53df99c`, non introduce riuso: ogni
chiamata genera nonce freschi.)

### 3c. Tutti i "killed" con attaccante = il relay STESSO
| Lead killato | Regge con relay malevolo? |
|---|---|
| Race `challenges.remove` | Sì (atomico sotto write-lock; e al relay malevolo i race non servono) |
| Spoofing `sender` ("impossibile, server-side") | **Da ri-scope-are**: impossibile per outsider; banale a livello transport per il relay — MA l'impersonation *crittografica* come V fallisce comunque per `ss` in Noise_K (§0). Il kill originale era troppo grossolano nei due sensi |
| Equivocation/drop dal server | Sì — fuori threat model per la safety; solo liveness. Confermato |
| Challenge non legato al richiedente | Sì — by design (freshness-only) |
| Blame DKG inghiottito | Sì — propagato fino al main; il relay vede ciphertext |
| Replay cross-sessione DKG | Sì — identifier session-bound + PoK lega l'identifier |
| Commitment inventati → `IncorrectCommitment` | Sì — il relay può iniettare commitment arbitrari a livello transport, ma `sign()` li confronta coi nonce reali della vittima → fail-closed |
| Message substitution / bait-and-switch | Sì (crypto); il gap resta solo UX (F4/Z1) |
| Share distribuzione in chiaro | Sì — cifratura per-destinatario |
| Auth challenge-response | Sì — single-use atomico |

---

## 4. Note per il parent

1. **#2 va riscritto nel ledger**: non è "Noise_K non verifica l'identità" — per K
   l'identità è verificata via `ss`+`rs` pre-configurato. Il residuo reale è lo
   *handshake-replay → slot-squat* (stretto, finestra = restart coordinator) e il
   fatto che la fix proposta era una tautologia. Impatto: si sposta da "medio" a
   "basso/note".
2. La catena più vicina ai fondi (#5+insider+blind-confirm, Caso A) è una variante
   di delivery di F4, non una nuova classe — ma è il miglior candidato per un
   contributo "hardening del reference": *phantom session + auto-join silenzioso
   come trigger remoto di blind signing*.
3. Test empirico in `frost-client/tests/noise_k_impersonation.rs` (3/3 passati):
   impersonation senza privkey vittima RIGETTATA, tamper del sender RILEVATO,
   replay handshake K accettato + lockout vittima. La correzione è dimostrata,
   non asserita.
4. Nessuna catena scala a fondi/chiavi → **nessun draft, nessuno stop**, come da
   protocollo.
