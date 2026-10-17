#!/usr/bin/env python3
"""Black-box fuzzer for the frostd HTTP state machine (FROST relay server).

Phases:
  0. sanity        - login flow works, all endpoints respond
  1. malformed     - invalid JSON, wrong types, missing/extra fields, bad UTF-8,
                     huge/negative ints, huge strings, bad UUIDs, bad headers
  2. sequences     - randomized session state-machine walks, invariant checks
  3. races         - concurrent requests on the same endpoints/objects
  4. boundaries    - empty/self recipients, unknown sessions, msg size edges,
                     message_count edges, pubkey/signature shape edges
  5. memory        - bounded fan-out growth check (confirms unbounded clone)

Findings are written to results.jsonl; crashes saved under crashes/.
The server process is liveness-checked between phases; any death is recorded
with the last input sent (replayable PoC).
"""
import json, os, random, sys, threading, time, uuid, subprocess
import requests

XSIGN = os.environ.get("XSIGN", os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "target-workerC", "release", "xsign"))

def xsign_gen():
    out = subprocess.run([XSIGN, "gen"], capture_output=True, text=True, timeout=30)
    return json.loads(out.stdout)

def xsign_sign(privkey_hex, msg_hex):
    out = subprocess.run([XSIGN, "sign", privkey_hex, msg_hex],
                         capture_output=True, text=True, timeout=30)
    return out.stdout.strip()

BASE = os.environ.get("FROSTD_BASE", "http://127.0.0.1:27499")
OUTDIR = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(OUTDIR, "results.jsonl")
CRASHDIR = os.path.join(OUTDIR, "crashes")
os.makedirs(CRASHDIR, exist_ok=True)
SEED = int(os.environ.get("FUZZ_SEED", "1234"))
random.seed(SEED)

server_pid = int(os.environ.get("FROSTD_PID", "0"))

results_f = open(RESULTS, "w")
crash_inputs = []
lock = threading.Lock()

def log(**kw):
    kw["t"] = time.time()
    with lock:
        results_f.write(json.dumps(kw) + "\n")
        results_f.flush()

def rss_kb():
    try:
        with open(f"/proc/{server_pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS"):
                    return int(line.split()[1])
    except Exception:
        return -1
    return -1

def alive():
    if server_pid:
        try:
            os.kill(server_pid, 0)
            return True
        except ProcessLookupError:
            return False
    try:
        requests.post(BASE + "/challenge", timeout=3)
        return True
    except Exception:
        return False

def check_alive(phase, note=""):
    ok = alive()
    log(phase=phase, event="liveness", alive=ok, note=note, rss_kb=rss_kb())
    if not ok:
        log(phase=phase, event="SERVER_DEAD", note=note)
        print(f"!!! SERVER DEAD during {phase}: {note}", flush=True)
    return ok

# ---------------------------------------------------------------- clients

class Client:
    def __init__(self):
        kp = xsign_gen()
        self.privkey = kp["privkey"]
        self.pk = kp["pubkey"]          # hex string (x25519 montgomery pubkey)
        self.token = None

    def login(self, challenge=None, sig=None, pubkey=None):
        if challenge is None:
            ch = requests.post(BASE + "/challenge", timeout=10).json()["challenge"]
        else:
            ch = challenge
        msg = uuid.UUID(ch).bytes.hex()
        s = xsign_sign(self.privkey, msg) if sig is None else sig
        p = self.pk if pubkey is None else pubkey
        r = requests.post(BASE + "/login",
                          json={"challenge": ch, "pubkey": p, "signature": s},
                          timeout=10)
        if r.status_code == 200:
            self.token = r.json()["access_token"]
        return r

    def post(self, path, body="__json__", raw=None, headers=None, token="__self__", timeout=15):
        h = {}
        t = self.token if token == "__self__" else token
        if t:
            h["Authorization"] = "Bearer " + t
        if headers:
            h.update(headers)
        if raw is not None:
            return requests.post(BASE + path, data=raw, headers=h, timeout=timeout)
        return requests.post(BASE + path, json=body, headers=h, timeout=timeout)

def jpost(path, body, token=None, raw=None, headers=None, timeout=15):
    h = {}
    if token:
        h["Authorization"] = "Bearer " + token
    if headers:
        h.update(headers)
    if raw is not None:
        return requests.post(BASE + path, data=raw, headers=h, timeout=timeout)
    return requests.post(BASE + path, json=body, headers=h, timeout=timeout)

def summarize(resp):
    try:
        body = resp.json()
        bs = json.dumps(body)
        if len(bs) > 300:
            bs = bs[:300] + "...<%d chars>" % len(bs)
        return {"status": resp.status_code, "body": bs}
    except Exception:
        b = resp.content[:200]
        return {"status": resp.status_code, "body": repr(b)}

# ---------------------------------------------------------------- phase 0: sanity

def phase0():
    c = Client()
    r = c.login()
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    log(phase=0, event="login_ok")
    # create session with 2 participants
    c2 = Client(); c2.login()
    r = c.post("/create_new_session", {"pubkeys": [c.pk, c2.pk], "message_count": 1})
    assert r.status_code == 200, f"create failed: {r.status_code} {r.text[:200]}"
    sid = r.json()["session_id"]
    # send + receive roundtrip
    r = c.post("/send", {"session_id": sid, "recipients": [c2.pk], "msg": b"hello".hex()})
    assert r.status_code == 200, f"send failed: {r.status_code} {r.text[:200]}"
    r = c2.post("/receive", {"session_id": sid, "as_coordinator": False})
    msgs = r.json()["msgs"]
    assert len(msgs) == 1 and bytes.fromhex(msgs[0]["msg"]) == b"hello", f"roundtrip broken: {r.text[:200]}"
    # second receive drains
    r = c2.post("/receive", {"session_id": sid, "as_coordinator": False})
    assert r.json()["msgs"] == [], "receive did not drain"
    # close
    r = c.post("/close_session", {"session_id": sid})
    assert r.status_code == 200, f"close failed: {r.status_code} {r.text[:200]}"
    log(phase=0, event="sanity_ok")
    print("phase 0 sanity OK", flush=True)
    return True

# ---------------------------------------------------------------- phase 1: malformed inputs

RAW_MUTATIONS = [
    ("empty", b"", "application/json"),
    ("not-json", b"hello world", "application/json"),
    ("truncated", b'{"session_id":', "application/json"),
    ("lone-brace", b"{", "application/json"),
    ("lone-bracket", b"[", "application/json"),
    ("null-byte", b'{"a": "\x00"}', "application/json"),
    ("invalid-utf8", b'{"a": "\xff\xfe"}', "application/json"),
    ("invalid-utf8-raw", b"\xff\xfe\x00bad", "application/json"),
    ("deep-nest", b"{" * 5000, "application/json"),
    ("huge-array", b"[" + b"1," * 200000 + b"1]", "application/json"),
    ("dup-keys", b'{"session_id": "a", "session_id": "b"}', "application/json"),
    ("trailing-garbage", b'{} garbage', "application/json"),
    ("wrong-ct", b'{"a":1}', "text/plain"),
    ("no-ct", b'{"a":1}', None),
    ("huge-string", b'{"x": "' + b"A" * 2_000_000 + b'"}', "application/json"),
    ("huge-number", b'{"x": ' + b"9" * 100 + b"}", "application/json"),
    ("neg-huge", b'{"x": -' + b"9" * 100 + b"}", "application/json"),
    ("float", b'{"x": 1.5}', "application/json"),
    ("nan", b'{"x": NaN}', "application/json"),
    ("inf", b'{"x": Infinity}', "application/json"),
    ("top-array", b"[1,2,3]", "application/json"),
    ("top-string", b'"str"', "application/json"),
    ("top-null", b"null", "application/json"),
    ("top-int", b"42", "application/json"),
    ("top-bool", b"true", "application/json"),
]

FIELD_MUTATIONS = [
    ("missing-all", {}),
    ("extra-field", {"__extra__": "x"}),
    ("null-body-fields", {"session_id": None}),
    ("int-as-string", {"message_count": "1"}),
    ("string-as-int", {"msg": 12345}),
    ("null-instead-of-string", {"challenge": None}),
    ("array-instead-of-object", []),
    ("nested-arrays", {"pubkeys": [[["a"]]]}),
    ("dict-instead-of-list", {"pubkeys": {"a": "b"}}),
    ("bool-fields", {"as_coordinator": "yes"}),
    ("int-bool", {"as_coordinator": 1}),
    ("neg-message-count", {"message_count": -1}),
    ("huge-message-count", {"message_count": 10**30}),
    ("float-message-count", {"message_count": 2.5}),
    ("bad-uuid", {"session_id": "not-a-uuid"}),
    ("empty-uuid", {"session_id": ""}),
    ("uuid-no-dashes", {"session_id": "a" * 32}),
    ("uuid-too-long", {"session_id": "a" * 100}),
    ("uuid-null-bytes", {"session_id": "\x00" * 36}),
    ("long-string-field", {"session_id": "x" * 100000}),
    ("unicode-field", {"session_id": "ses\u00e9-\U0001f600"}),
]

ENDPOINT_BASES = {
    "/challenge": {},
    "/login": {"challenge": "CH", "pubkey": "PK", "signature": "SIG"},
    "/logout": {},
    "/create_new_session": {"pubkeys": ["PK"], "message_count": 1},
    "/list_sessions": {},
    "/get_session_info": {"session_id": "SID"},
    "/send": {"session_id": "SID", "recipients": ["PK2"], "msg": "MSG"},
    "/receive": {"session_id": "SID", "as_coordinator": False},
    "/close_session": {"session_id": "SID"},
}

def fill(base, c, sid, c2):
    out = {}
    for k, v in base.items():
        if v == "CH":
            out[k] = str(uuid.uuid4())
        elif v == "PK":
            out[k] = c.pk
        elif v == "PK2":
            out[k] = c2.pk
        elif v == "SIG":
            out[k] = "ab" * 64
        elif v == "SID":
            out[k] = sid
        elif v == "MSG":
            out[k] = b"hi".hex()
        else:
            out[k] = v
    return out

def phase1():
    c = Client(); c.login()
    c2 = Client(); c2.login()
    r = c.post("/create_new_session", {"pubkeys": [c.pk], "message_count": 1})
    sid = r.json()["session_id"]
    n500 = 0
    total = 0
    for path, base in ENDPOINT_BODIES():
        filled = fill(base, c, sid, c2)
        # raw mutations
        for name, raw, ct in RAW_MUTATIONS:
            total += 1
            headers = {}
            if ct is not None:
                headers["Content-Type"] = ct
            try:
                resp = c.post(path, raw=raw, headers=headers, timeout=15)
                s = summarize(resp)
            except Exception as e:
                s = {"status": "EXC", "body": repr(e)[:200]}
                log(phase=1, event="exception", path=path, mut=name, err=repr(e)[:200])
            interesting = (s["status"] == 500)
            if interesting:
                n500 += 1
            log(phase=1, event="mut", path=path, mut=name, interesting=interesting, **s)
            if not check_alive(1, f"raw mut {name} on {path}"):
                save_crash(path, raw, name)
                return False
        # field mutations
        for name, mut in FIELD_MUTATIONS:
            total += 1
            body = apply_field_mut(name, mut, filled)
            try:
                resp = c.post(path, body, timeout=15)
                s = summarize(resp)
            except Exception as e:
                s = {"status": "EXC", "body": repr(e)[:200]}
                log(phase=1, event="exception", path=path, mut=name, err=repr(e)[:200])
            interesting = (s["status"] == 500)
            if interesting:
                n500 += 1
            log(phase=1, event="mut", path=path, mut=name, interesting=interesting, **s)
            if not check_alive(1, f"field mut {name} on {path}"):
                save_crash(path, json.dumps(body).encode(), name)
                return False
    # auth header mutations
    for name, hdrs in [
        ("no-auth", {"__drop__": 1}),
        ("empty-bearer", {"Authorization": "Bearer "}),
        ("bad-scheme", {"Authorization": "Token abc"}),
        ("non-uuid-token", {"Authorization": "Bearer not-a-uuid"}),
        ("null-uuid-token", {"Authorization": "Bearer 00000000-0000-0000-0000-000000000000"}),
        ("huge-token", {"Authorization": "Bearer " + "a" * 100000}),
        ("basic-auth", {"Authorization": "Basic Zm9vOmJhcg=="}),
        ("two-auth-headers", {"Authorization": "Bearer abc, Bearer def"}),
    ]:
        total += 1
        h = dict(hdrs)
        drop = h.pop("__drop__", None)
        try:
            resp = c.post("/list_sessions", {}, headers=h, token=None if drop else "__self__", timeout=15)
            # token=None means no Authorization header at all
            s = summarize(resp)
        except Exception as e:
            s = {"status": "EXC", "body": repr(e)[:200]}
        log(phase=1, event="auth_mut", mut=name, **s)
        if not check_alive(1, f"auth mut {name}"):
            return False
    # method mutations
    for method in ["GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
        try:
            resp = requests.request(method, BASE + "/send", timeout=10)
            s = summarize(resp)
        except Exception as e:
            s = {"status": "EXC", "body": repr(e)[:200]}
        log(phase=1, event="method_mut", method=method, **s)
    log(phase=1, event="done", total=total, n500=n500, rss_kb=rss_kb())
    print(f"phase 1 done: {total} mutations, {n500} x 500", flush=True)
    return True

def apply_field_mut(name, mut, body):
    """Apply a named field mutation to a filled body dict. Returns new body."""
    b = dict(body)
    if name == "missing-all":
        return {}
    if name == "extra-field":
        b["__extra__"] = "x"
        return b
    if name == "null-body-fields":
        return {k: None for k in b}
    if name == "array-instead-of-object":
        return []
    if name == "int-as-string" and "message_count" in b:
        b["message_count"] = "1"
    elif name == "string-as-int" and "msg" in b:
        b["msg"] = 12345
    elif name == "null-instead-of-string" and "challenge" in b:
        b["challenge"] = None
    elif name == "nested-arrays" and "pubkeys" in b:
        b["pubkeys"] = [[["a"]]]
    elif name == "dict-instead-of-list" and "pubkeys" in b:
        b["pubkeys"] = {"a": "b"}
    elif name == "bool-fields" and "as_coordinator" in b:
        b["as_coordinator"] = "yes"
    elif name == "int-bool" and "as_coordinator" in b:
        b["as_coordinator"] = 1
    elif name == "neg-message-count" and "message_count" in b:
        b["message_count"] = -1
    elif name == "huge-message-count" and "message_count" in b:
        b["message_count"] = 10 ** 30
    elif name == "float-message-count" and "message_count" in b:
        b["message_count"] = 2.5
    elif name == "bad-uuid" and "session_id" in b:
        b["session_id"] = "not-a-uuid"
    elif name == "empty-uuid" and "session_id" in b:
        b["session_id"] = ""
    elif name == "uuid-no-dashes" and "session_id" in b:
        b["session_id"] = "a" * 32
    elif name == "uuid-too-long" and "session_id" in b:
        b["session_id"] = "a" * 100
    elif name == "uuid-null-bytes" and "session_id" in b:
        b["session_id"] = "\x00" * 36
    elif name == "long-string-field" and "session_id" in b:
        b["session_id"] = "x" * 100000
    elif name == "unicode-field" and "session_id" in b:
        b["session_id"] = "sesé-😀"
    return b


def ENDPOINT_BODIES():
    return list(ENDPOINT_BASES.items())


def save_crash(path, raw, name):
    fn = os.path.join(CRASHDIR, f"crash_{int(time.time())}_{name}.bin")
    meta = {"path": path, "mutation": name, "content_type": "application/json",
            "replay": f"curl -s -X POST {BASE}{path} -H 'Content-Type: application/json' --data-binary @- < {os.path.basename(fn)}"}
    with open(fn, "wb") as f:
        f.write(raw if isinstance(raw, bytes) else raw.encode())
    with open(fn + ".json", "w") as f:
        json.dump(meta, f, indent=2)
    crash_inputs.append(fn)
    log(phase="crash", event="saved", file=fn, **meta)

# ---------------------------------------------------------------- phase 2: sequences

def phase2(nops=400):
    users = [Client() for _ in range(4)]
    for u in users:
        u.login()
    sessions = {}  # sid -> dict(owner_idx, participants, closed)
    anomalies = 0
    for i in range(nops):
        op = random.choice(["create", "send", "receive", "close", "list", "info",
                            "double_close", "send_closed", "recv_nosend", "logout_reuse",
                            "challenge_replay", "cross_token", "bad_token"])
        try:
            if op == "create":
                owner = random.randrange(4)
                parts = random.sample(range(4), random.randint(0, 3))
                mc = random.choice([1, 2, 255])
                r = users[owner].post("/create_new_session",
                    {"pubkeys": [users[p].pk for p in parts], "message_count": mc})
                if r.status_code == 200:
                    sid = r.json()["session_id"]
                    sessions[sid] = {"owner": owner, "parts": parts, "closed": False,
                                     "pending": {p: 0 for p in parts}}
                    # owner may not be a participant; track coordinator separately
            elif op == "send" and sessions:
                sid, st = random.choice(list(sessions.items()))
                if st["closed"]:
                    continue
                u = random.randrange(4)
                # pick recipients: subset of participants, maybe empty (coordinator queue)
                recips = [users[p].pk for p in st["parts"] if random.random() < 0.5]
                if random.random() < 0.2:
                    recips = []
                if random.random() < 0.1 and st["parts"]:
                    recips.append(users[random.choice(st["parts"])].pk)  # dup
                msg = os.urandom(random.choice([0, 1, 16, 1000]))
                r = users[u].post("/send", {"session_id": sid, "recipients": recips, "msg": msg.hex()})
                s = summarize(r)
                if r.status_code == 200:
                    targets = recips if recips else ["__coord__"]
                    for t in targets:
                        pass
                    # only owner/participants may succeed
                    allowed = (u == st["owner"]) or (u in st["parts"] and all(
                        any(users[p].pk == x for p in st["parts"]) for x in recips))
                    if not allowed:
                        anomalies += 1
                        log(phase=2, event="ANOMALY", op=op, note="send succeeded for outsider",
                            user=u, sid=sid, **s)
                log(phase=2, event="op", op=op, user=u, sid=sid, **s)
            elif op == "receive" and sessions:
                sid, st = random.choice(list(sessions.items()))
                if st["closed"]:
                    continue
                u = random.randrange(4)
                as_c = random.random() < 0.5
                r = users[u].post("/receive", {"session_id": sid, "as_coordinator": as_c})
                s = summarize(r)
                if r.status_code == 200:
                    allowed = (u == st["owner"]) or (u in st["parts"])
                    if not allowed:
                        anomalies += 1
                        log(phase=2, event="ANOMALY", op=op, note="receive succeeded for outsider",
                            user=u, sid=sid, as_coord=as_c, **s)
                log(phase=2, event="op", op=op, user=u, sid=sid, **s)
            elif op == "close" and sessions:
                sid, st = random.choice(list(sessions.items()))
                if st["closed"]:
                    continue
                u = random.randrange(4)
                r = users[u].post("/close_session", {"session_id": sid})
                s = summarize(r)
                if r.status_code == 200:
                    if u != st["owner"]:
                        anomalies += 1
                        log(phase=2, event="ANOMALY", op=op, note="non-coordinator closed session",
                            user=u, sid=sid, **s)
                    st["closed"] = True
                log(phase=2, event="op", op=op, user=u, sid=sid, **s)
            elif op == "list":
                u = random.randrange(4)
                r = users[u].post("/list_sessions", {})
                s = summarize(r)
                log(phase=2, event="op", op=op, user=u, **s)
            elif op == "info" and sessions:
                sid, st = random.choice(list(sessions.items()))
                u = random.randrange(4)
                r = users[u].post("/get_session_info", {"session_id": sid})
                s = summarize(r)
                if r.status_code == 200:
                    allowed = (u == st["owner"]) or (u in st["parts"])
                    if not allowed:
                        anomalies += 1
                        log(phase=2, event="ANOMALY", op=op, note="info leaked to outsider",
                            user=u, sid=sid, **s)
                log(phase=2, event="op", op=op, user=u, sid=sid, **s)
            elif op == "double_close" and sessions:
                cands = [s for s in sessions.items() if not s[1]["closed"]]
                if not cands:
                    continue
                sid, st = random.choice(cands)
                u = st["owner"]
                r1 = users[u].post("/close_session", {"session_id": sid})
                r2 = users[u].post("/close_session", {"session_id": sid})
                st["closed"] = True
                ok = r1.status_code == 200 and r2.status_code == 500
                if not ok:
                    anomalies += 1
                log(phase=2, event="op", op=op, first=r1.status_code, second=r2.status_code,
                    expected="200,500", ok=ok)
            elif op == "send_closed" and sessions:
                cands = [s for s in sessions.items() if s[1]["closed"]]
                if not cands:
                    continue
                sid, st = random.choice(cands)
                r = users[st["owner"]].post("/send", {"session_id": sid, "recipients": [],
                                                     "msg": b"x".hex()})
                ok = r.status_code == 500
                if not ok:
                    anomalies += 1
                log(phase=2, event="op", op=op, status=r.status_code, expected=500, ok=ok)
            elif op == "recv_nosend" and sessions:
                cands = [s for s in sessions.items() if not s[1]["closed"]]
                if not cands:
                    continue
                sid, st = random.choice(cands)
                u = st["owner"] if random.random() < 0.5 else (st["parts"][0] if st["parts"] else st["owner"])
                r = users[u].post("/receive", {"session_id": sid, "as_coordinator": u == st["owner"]})
                log(phase=2, event="op", op=op, status=r.status_code,
                    n_msgs=len(r.json()["msgs"]) if r.status_code == 200 else -1)
            elif op == "logout_reuse":
                u = random.randrange(4)
                tok = users[u].token
                users[u].post("/logout", {})
                r = users[u].post("/list_sessions", {}, token=tok)
                ok = r.status_code == 500  # token must be dead
                if not ok:
                    anomalies += 1
                log(phase=2, event="op", op=op, status=r.status_code, expected=500, ok=ok)
                users[u].login()
            elif op == "challenge_replay":
                u = random.randrange(4)
                ch = requests.post(BASE + "/challenge", timeout=10).json()["challenge"]
                sig = xsign_sign(users[u].privkey, uuid.UUID(ch).bytes.hex())
                body = {"challenge": ch, "pubkey": users[u].pk, "signature": sig}
                r1 = jpost("/login", body)
                r2 = jpost("/login", body)
                ok = r1.status_code == 200 and r2.status_code == 500
                if not ok:
                    anomalies += 1
                log(phase=2, event="op", op=op, first=r1.status_code, second=r2.status_code,
                    expected="200,500", ok=ok)
            elif op == "cross_token":
                a, b = random.sample(range(4), 2)
                # user a performs op with user b's token => acts as b; must not act as a
                r = users[b].post("/list_sessions", {}, token=users[a].token)
                log(phase=2, event="op", op=op, status=r.status_code)
            elif op == "bad_token":
                u = random.randrange(4)
                r = users[u].post("/list_sessions", {}, token=str(uuid.uuid4()))
                ok = r.status_code == 500
                if not ok:
                    anomalies += 1
                log(phase=2, event="op", op=op, status=r.status_code, expected=500, ok=ok)
        except Exception as e:
            log(phase=2, event="exception", op=op, err=repr(e)[:300])
        if i % 50 == 0 and not check_alive(2, f"op {i}"):
            return False
    # consistency: list_sessions vs get_session_info for each live session
    for sid, st in sessions.items():
        if st["closed"]:
            continue
        for u in [st["owner"]] + st["parts"]:
            r = users[u].post("/list_sessions", {})
            if r.status_code == 200 and sid not in r.json()["session_ids"]:
                anomalies += 1
                log(phase=2, event="ANOMALY", note="live session missing from list_sessions",
                    user=u, sid=sid)
    log(phase=2, event="done", nops=nops, anomalies=anomalies, rss_kb=rss_kb())
    print(f"phase 2 done: {nops} ops, {anomalies} anomalies", flush=True)
    return True

# ---------------------------------------------------------------- phase 3: races

def race_worker(fn, iters, errs):
    for _ in range(iters):
        try:
            fn()
        except Exception as e:
            with lock:
                errs.append(repr(e)[:200])

def phase3():
    errs = []
    # R1: concurrent login with the SAME challenge -> exactly one must win
    c = Client()
    wins = []
    def try_login(ch, sig, pk):
        r = jpost("/login", {"challenge": ch, "pubkey": pk, "signature": sig})
        if r.status_code == 200:
            with lock:
                wins.append(r.json()["access_token"])
    ch = requests.post(BASE + "/challenge", timeout=10).json()["challenge"]
    sig = xsign_sign(c.privkey, uuid.UUID(ch).bytes.hex())
    pk = c.pk
    ts = [threading.Thread(target=try_login, args=(ch, sig, pk)) for _ in range(16)]
    [t.start() for t in ts]; [t.join() for t in ts]
    log(phase=3, event="race", name="challenge_reuse", wins=len(wins), expected=1,
        ok=len(wins) == 1)
    print(f"race challenge_reuse: {len(wins)} wins (expect 1)", flush=True)
    if not check_alive(3, "challenge_reuse"):
        return False

    # R2: concurrent create+close storms on shared session set
    users = [Client() for _ in range(4)]
    for u in users: u.login()
    created = []
    def mk():
        r = users[0].post("/create_new_session", {"pubkeys": [u.pk for u in users], "message_count": 1})
        if r.status_code == 200:
            with lock: created.append(r.json()["session_id"])
    ts = [threading.Thread(target=lambda: race_worker(mk, 10, errs)) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    log(phase=3, event="race", name="create_storm", created=len(created), errs=len(errs))
    print(f"race create_storm: {len(created)} created, {len(errs)} errs", flush=True)
    if not check_alive(3, "create_storm"): return False

    # R3: concurrent close of the same session
    r = users[0].post("/create_new_session", {"pubkeys": [u.pk for u in users], "message_count": 1})
    sid = r.json()["session_id"]
    closes = []
    def closer(u):
        rr = u.post("/close_session", {"session_id": sid})
        with lock: closes.append(rr.status_code)
    ts = [threading.Thread(target=closer, args=(users[i % 4],)) for i in range(16)]
    [t.start() for t in ts]; [t.join() for t in ts]
    n200 = closes.count(200)
    log(phase=3, event="race", name="close_same", ok200=n200, expected=1, codes=sorted(set(closes)))
    print(f"race close_same: {n200} x 200 (expect 1)", flush=True)
    if not check_alive(3, "close_same"): return False

    # R4: concurrent send storm to one session, then drain consistency
    r = users[0].post("/create_new_session", {"pubkeys": [u.pk for u in users], "message_count": 1})
    sid = r.json()["session_id"]
    NSEND = 200
    def sender(u, i):
        u.post("/send", {"session_id": sid, "recipients": [users[(i + 1) % 4].pk],
                         "msg": f"m{i}".encode().hex()})
    ts = []
    for i in range(NSEND):
        ts.append(threading.Thread(target=sender, args=(users[i % 4], i)))
    [t.start() for t in ts]; [t.join() for t in ts]
    total_recv = 0
    for u in users:
        rr = u.post("/receive", {"session_id": sid, "as_coordinator": False})
        if rr.status_code == 200:
            total_recv += len(rr.json()["msgs"])
    # each send -> exactly 1 recipient -> total received must equal NSEND
    log(phase=3, event="race", name="send_storm_drain", sent=NSEND, received=total_recv,
        ok=total_recv == NSEND)
    print(f"race send_storm: sent={NSEND} received={total_recv}", flush=True)
    if not check_alive(3, "send_storm"): return False
    users[0].post("/close_session", {"session_id": sid})

    # R5: concurrent logout + token use
    c2 = Client(); c2.login()
    tok = c2.token
    outcomes = []
    def use_tok():
        rr = c2.post("/list_sessions", {}, token=tok)
        with lock: outcomes.append(rr.status_code)
    def do_logout():
        c2.post("/logout", {})
    ts = [threading.Thread(target=use_tok) for _ in range(10)] + \
         [threading.Thread(target=do_logout) for _ in range(4)]
    random.shuffle(ts)
    [t.start() for t in ts]; [t.join() for t in ts]
    log(phase=3, event="race", name="logout_vs_use", codes=sorted(set(outcomes)))
    print(f"race logout_vs_use: codes={sorted(set(outcomes))}", flush=True)
    if not check_alive(3, "logout_vs_use"): return False

    # R6: receive storm on coordinator queue (empty recipients -> coordinator)
    r = users[0].post("/create_new_session", {"pubkeys": [users[1].pk], "message_count": 1})
    sid = r.json()["session_id"]
    for i in range(50):
        users[1].post("/send", {"session_id": sid, "recipients": [], "msg": f"k{i}".encode().hex()})
    got = []
    def recv_c():
        rr = users[0].post("/receive", {"session_id": sid, "as_coordinator": True})
        if rr.status_code == 200:
            with lock: got.extend(rr.json()["msgs"])
    ts = [threading.Thread(target=recv_c) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    # drain is atomic per request; total must be exactly 50, no dup, no loss
    senders = sorted(m["sender"] for m in got)
    bodies = sorted(bytes.fromhex(m["msg"]).decode() for m in got)
    log(phase=3, event="race", name="coord_drain", total=len(got), expected=50,
        dup=len(bodies) != len(set(bodies)), ok=len(got) == 50 and len(set(bodies)) == 50)
    print(f"race coord_drain: got={len(got)} unique={len(set(bodies))} (expect 50/50)", flush=True)
    if not check_alive(3, "coord_drain"): return False

    log(phase=3, event="done", errs=errs[:20], rss_kb=rss_kb())
    print("phase 3 done", flush=True)
    return True

# ---------------------------------------------------------------- phase 4: boundaries

def phase4():
    c = Client(); c.login()
    c2 = Client(); c2.login()
    outsider = Client(); outsider.login()
    r = c.post("/create_new_session", {"pubkeys": [c.pk, c2.pk], "message_count": 1})
    sid = r.json()["session_id"]

    cases = []
    def t(name, path, body, tok="__self__", raw=None, headers=None):
        cases.append((name, path, body, tok, raw, headers))

    t("recv-unknown-session", "/receive", {"session_id": str(uuid.uuid4()), "as_coordinator": False})
    t("send-unknown-session", "/send", {"session_id": str(uuid.uuid4()), "recipients": [], "msg": "00"})
    t("info-unknown-session", "/get_session_info", {"session_id": str(uuid.uuid4())})
    t("close-unknown-session", "/close_session", {"session_id": str(uuid.uuid4())})
    t("recv-malformed-uuid", "/receive", {"session_id": "zzz", "as_coordinator": False})
    t("send-empty-recipients", "/send", {"session_id": sid, "recipients": [], "msg": b"to-coord".hex()})
    t("send-self-recipient", "/send", {"session_id": sid, "recipients": [c.pk], "msg": b"self".hex()})
    t("send-dup-recipients", "/send", {"session_id": sid, "recipients": [c2.pk] * 50, "msg": b"d".hex()})
    t("send-outsider-recipient", "/send", {"session_id": sid, "recipients": [outsider.pk], "msg": b"x".hex()})
    t("send-outsider-sender", "/send", {"session_id": sid, "recipients": [c2.pk], "msg": b"x".hex()}, tok=outsider.token)
    t("recv-outsider", "/receive", {"session_id": sid, "as_coordinator": False}, tok=outsider.token)
    t("recv-as-coord-by-participant", "/receive", {"session_id": sid, "as_coordinator": True}, tok=c2.token)
    t("recv-as-coord-by-coord", "/receive", {"session_id": sid, "as_coordinator": True})
    t("info-outsider", "/get_session_info", {"session_id": sid}, tok=outsider.token)
    t("close-by-participant", "/close_session", {"session_id": sid}, tok=c2.token)
    t("msg-empty", "/send", {"session_id": sid, "recipients": [c2.pk], "msg": ""})
    t("msg-65535", "/send", {"session_id": sid, "recipients": [c2.pk], "msg": "ab" * 65535})
    t("msg-65536", "/send", {"session_id": sid, "recipients": [c2.pk], "msg": "ab" * 65536})
    t("msg-1MB", "/send", {"session_id": sid, "recipients": [c2.pk], "msg": "ab" * 500000})
    t("msg-3MB", "/send", {"session_id": sid, "recipients": [c2.pk], "msg": "ab" * 1500000})
    t("create-empty-pubkeys", "/create_new_session", {"pubkeys": [], "message_count": 1})
    t("create-dup-pubkeys", "/create_new_session", {"pubkeys": [c.pk] * 10, "message_count": 1})
    t("create-self-only", "/create_new_session", {"pubkeys": [c.pk], "message_count": 1})
    t("create-mc-0", "/create_new_session", {"pubkeys": [c.pk], "message_count": 0})
    t("create-mc-255", "/create_new_session", {"pubkeys": [c.pk], "message_count": 255})
    t("create-500-pubkeys", "/create_new_session",
      {"pubkeys": [os.urandom(32).hex() for _ in range(500)], "message_count": 1})
    t("login-empty-pubkey", "/login", {"challenge": str(uuid.uuid4()), "pubkey": "", "signature": "ab" * 64}, tok=None)
    t("login-empty-sig", "/login", {"challenge": str(uuid.uuid4()), "pubkey": c.pk, "signature": ""}, tok=None)
    t("login-short-pubkey", "/login", {"challenge": str(uuid.uuid4()), "pubkey": "ab" * 10, "signature": "ab" * 64}, tok=None)
    t("login-long-pubkey", "/login", {"challenge": str(uuid.uuid4()), "pubkey": "ab" * 5000, "signature": "ab" * 64}, tok=None)
    t("login-short-sig", "/login", {"challenge": str(uuid.uuid4()), "pubkey": c.pk, "signature": "ab" * 10}, tok=None)
    t("login-long-sig", "/login", {"challenge": str(uuid.uuid4()), "pubkey": c.pk, "signature": "ab" * 5000}, tok=None)
    t("login-bad-challenge", "/login", {"challenge": str(uuid.uuid4()), "pubkey": c.pk, "signature": "ab" * 64}, tok=None)
    t("login-garbage-challenge", "/login", {"challenge": "nope", "pubkey": c.pk, "signature": "ab" * 64}, tok=None)
    # NOTE: logout cases are last; they kill c's token. Re-login after.
    t("logout-no-token", "/logout", {}, tok=None)
    t("logout-twice", "/logout", {})

    for name, path, body, tok, raw, headers in cases:
        try:
            resp = c.post(path, body, token=tok, raw=raw, headers=headers, timeout=30)
            s = summarize(resp)
        except Exception as e:
            s = {"status": "EXC", "body": repr(e)[:200]}
            log(phase=4, event="exception", case=name, err=repr(e)[:200])
        if name == "logout-twice":
            # c's token is now dead; re-login so later cases + drain check work
            c.login()
        # flag anything unexpected: 500 is "expected" for error paths (server maps all errors to 500),
        # but a 200 on a negative case is interesting
        negative = name in ("send-outsider-recipient", "send-outsider-sender", "recv-outsider",
                            "info-outsider", "close-by-participant", "login-bad-challenge",
                            "login-garbage-challenge", "login-empty-pubkey", "login-empty-sig",
                            "login-short-pubkey", "login-long-pubkey", "login-short-sig",
                            "login-long-sig", "create-mc-0", "recv-unknown-session",
                            "send-unknown-session", "info-unknown-session", "close-unknown-session",
                            "recv-malformed-uuid", "logout-no-token", "msg-65536")
        interesting = (negative and s["status"] == 200)
        log(phase=4, event="case", case=name, negative=negative, interesting=interesting, **s)
        if interesting:
            print(f"  INTERESTING: {name} -> {s}", flush=True)
        if not check_alive(4, name):
            save_crash(path, json.dumps(body).encode() if raw is None else raw, name)
            return False

    # verify self-send actually queued, and coordinator-queue read rules
    r = c2.post("/receive", {"session_id": sid, "as_coordinator": False})
    n_c2 = len(r.json()["msgs"]) if r.status_code == 200 else -1
    r = c.post("/receive", {"session_id": sid, "as_coordinator": True})
    n_coord = len(r.json()["msgs"]) if r.status_code == 200 else -1
    r = c.post("/receive", {"session_id": sid, "as_coordinator": False})
    n_cself = len(r.json()["msgs"]) if r.status_code == 200 else -1
    log(phase=4, event="drain_check", c2=n_c2, coord=n_coord, c_self=n_cself)
    print(f"phase 4 drain check: c2={n_c2} coord={n_coord} c_self={n_cself}", flush=True)
    log(phase=4, event="done", rss_kb=rss_kb())
    print("phase 4 done", flush=True)
    return True

# ---------------------------------------------------------------- phase 5: bounded memory

def phase5():
    c = Client(); c.login()
    others = [os.urandom(32).hex() for _ in range(3000)]
    r = c.post("/create_new_session", {"pubkeys": [c.pk] + others[:100], "message_count": 1})
    sid = r.json()["session_id"]
    rss0 = rss_kb()
    # bounded fan-out: 100 recipients x 64KB = 6.4MB per send; measure growth
    big = "ab" * 65535  # 65535 bytes
    for i in range(5):
        r = c.post("/send", {"session_id": sid, "recipients": others[:100], "msg": big}, timeout=60)
        assert r.status_code == 200, f"send failed: {r.status_code}"
        time.sleep(0.3)
    rss1 = rss_kb()
    # many sessions with many pubkeys (bounded)
    for i in range(20):
        c.post("/create_new_session",
               {"pubkeys": [os.urandom(32).hex() for _ in range(200)],
                "message_count": 1}, timeout=30)
    rss2 = rss_kb()
    # token spray (bounded): 200 logins
    for i in range(200):
        cc = Client(); cc.login()
    rss3 = rss_kb()
    # challenge spray (bounded): 2000 challenges, 10s expiry
    for i in range(2000):
        requests.post(BASE + "/challenge", timeout=10)
    time.sleep(1)
    rss4 = rss_kb()
    log(phase=5, event="mem", rss0=rss0, after_fanout=rss1, after_sessions=rss2,
        after_tokens=rss3, after_challenges=rss4)
    print(f"phase 5 mem KB: start={rss0} fanout={rss1} sessions={rss2} tokens={rss3} challenges={rss4}", flush=True)
    # cleanup
    c.post("/close_session", {"session_id": sid})
    log(phase=5, event="done", rss_kb=rss_kb())
    return check_alive(5, "end")

# ---------------------------------------------------------------- main

def main():
    which = sys.argv[1:] or ["0", "1", "2", "3", "4", "5"]
    if not check_alive("init", "startup"):
        print("server not alive at start", flush=True)
        sys.exit(2)
    log(event="start", seed=SEED, rss_kb=rss_kb())
    phases = {"0": phase0, "1": phase1, "2": lambda: phase2(400), "3": phase3,
              "4": phase4, "5": phase5}
    for w in which:
        print(f"=== phase {w} ===", flush=True)
        try:
            ok = phases[w]()
        except Exception as e:
            log(phase=w, event="phase_exception", err=repr(e)[:500])
            print(f"phase {w} raised: {e!r}", flush=True)
            ok = False
        if not ok:
            print(f"phase {w} FAILED (see results)", flush=True)
            break
        if not check_alive(w, "post-phase"):
            break
    log(event="end", rss_kb=rss_kb(), crashes=len(crash_inputs))
    print(f"done. crashes saved: {crash_inputs}", flush=True)
    results_f.close()

if __name__ == "__main__":
    main()
