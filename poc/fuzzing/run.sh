#!/usr/bin/env bash
# Run only against a local, disposable frostd instance owned by this script.
set -euo pipefail

FUZZDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BIN=${FROSTD_BIN:?Set FROSTD_BIN to a locally built frostd executable}
XSIGN=${XSIGN:-"$FUZZDIR/xsign/target/release/xsign"}
PORT=${FROSTD_PORT:-27499}
OUTDIR=${FUZZ_OUTDIR:-"$FUZZDIR/run-artifacts"}
PYTHON=${PYTHON:-python3}

if [[ ! -x "$BIN" || ! -x "$XSIGN" ]]; then
  echo "Build frostd and xsign first; set FROSTD_BIN and optionally XSIGN." >&2
  exit 1
fi
mkdir -p "$OUTDIR"

RUST_LOG=info "$BIN" --ip 127.0.0.1 --port "$PORT" --no-tls-very-insecure > "$OUTDIR/frostd-server.log" 2>&1 &
SRVPID=$!
cleanup() {
  kill "$SRVPID" 2>/dev/null || true
  wait "$SRVPID" 2>/dev/null || true
}
trap cleanup EXIT

READY=0
for _ in {1..30}; do
  if ! kill -0 "$SRVPID" 2>/dev/null; then
    echo "frostd exited during startup; see $OUTDIR/frostd-server.log" >&2
    exit 1
  fi
  if curl -fsS --max-time 2 -X POST "http://127.0.0.1:$PORT/challenge" > /dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [[ "$READY" != 1 ]]; then
  echo "frostd did not become ready; see $OUTDIR/frostd-server.log" >&2
  exit 1
fi

export XSIGN FUZZ_OUTDIR="$OUTDIR" FROSTD_PID="$SRVPID" FROSTD_BASE="http://127.0.0.1:$PORT"
if [[ $# -eq 0 ]]; then
  set -- 0 1 2 3 4
fi
"$PYTHON" "$FUZZDIR/frostd_fuzz.py" "$@"
