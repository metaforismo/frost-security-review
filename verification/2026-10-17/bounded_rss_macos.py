#!/usr/bin/env python3
"""Bounded localhost RSS slope check for frostd; at most 2,000 recipients."""

import json
import os
import subprocess
import sys
import time
import uuid

import requests


def rss_kib(pid):
    output = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)
    return int(output.strip())


def post(base, path, body=None, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = requests.post(base + path, json=body or {}, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json() if response.content else None


def sample(binary, helper, port, recipients):
    assert 1 <= recipients <= 2_000
    base = f"http://127.0.0.1:{port}"
    with open(os.devnull, "wb") as devnull:
        server = subprocess.Popen(
            [binary, "--ip", "127.0.0.1", "--port", str(port), "--no-tls-very-insecure"],
            stdout=devnull,
            stderr=devnull,
        )
        try:
            for _ in range(40):
                if server.poll() is not None:
                    raise RuntimeError(f"server exited during startup: {server.returncode}")
                try:
                    post(base, "/challenge")
                    break
                except requests.RequestException:
                    time.sleep(0.1)
            else:
                raise RuntimeError("server did not become ready")

            keypair = json.loads(subprocess.check_output([helper, "gen"], text=True))
            challenge = post(base, "/challenge")["challenge"]
            signature = subprocess.check_output(
                [helper, "sign", keypair["privkey"], uuid.UUID(challenge).bytes.hex()], text=True
            ).strip()
            token = post(base, "/login", {
                "challenge": challenge,
                "pubkey": keypair["pubkey"],
                "signature": signature,
            })["access_token"]

            fake_keys = [os.urandom(32).hex() for _ in range(recipients)]
            session = post(base, "/create_new_session", {
                "pubkeys": [keypair["pubkey"], *fake_keys],
                "message_count": 1,
            }, token)["session_id"]
            time.sleep(0.3)
            before = rss_kib(server.pid)
            post(base, "/send", {
                "session_id": session,
                "recipients": fake_keys,
                "msg": "41" * 65_535,
            }, token)
            time.sleep(0.3)
            after = rss_kib(server.pid)
            return {
                "recipients": recipients,
                "message_bytes": 65_535,
                "rss_before_kib": before,
                "rss_after_kib": after,
                "rss_delta_mib": round((after - before) / 1024, 3),
                "payload_mib": round(recipients * 65_535 / (1024 * 1024), 3),
                "server_alive": server.poll() is None,
            }
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


if __name__ == "__main__":
    frostd_binary, xsign_binary = sys.argv[1:3]
    port_base = int(os.environ.get("FROSTD_RSS_PORT_BASE", "27600"))
    for idx, n in enumerate((500, 1_000, 2_000)):
        print(json.dumps(sample(frostd_binary, xsign_binary, port_base + idx, n)), flush=True)
