#!/bin/bash
# Run frostd under a memory cap and execute the fuzzer phases.
set -u
FUZZDIR=~/workspace/hunt/frost-client-audit/fuzz-frostd
BIN=${FROSTD_BIN:-~/workspace/hunt/frost-client-audit/target-workerC/release/frostd}
PORT=27499
LOG=$FUZZDIR/frostd-server.log

if [ ! -x "$BIN" ]; then
  echo "frostd binary not found at $BIN" >&2
  exit 1
fi

# kill any previous instance on this port
pkill -f "frostd.*$PORT" 2>/dev/null
sleep 1

# 4 GB virtual address space cap (RLIMIT_AS); server must stay well under it.
ulimit -v 4000000
echo "=== starting frostd on 127.0.0.1:$PORT (log: $LOG) ==="
RUST_LOG=info "$BIN" --ip 127.0.0.1 --port $PORT --no-tls-very-insecure > "$LOG" 2>&1 &
SRVPID=$!
echo "server pid: $SRVPID"
export FROSTD_PID=$SRVPID
export FROSTD_BASE="http://127.0.0.1:$PORT"

# wait for readiness
for i in $(seq 1 30); do
  if curl -s -m 2 -X POST "$FROSTD_BASE/challenge" >/dev/null 2>&1; then
    echo "server up after ${i}s"
    break
  fi
  sleep 1
  if ! kill -0 $SRVPID 2>/dev/null; then
    echo "server died during startup; log tail:" >&2
    tail -30 "$LOG" >&2
    exit 1
  fi
done

cd "$FUZZDIR"
python3 frostd_fuzz.py "$@"
FUZZ_RC=$?

echo "=== fuzzer exit: $FUZZ_RC ==="
if kill -0 $SRVPID 2>/dev/null; then
  echo "server still alive (rss: $(awk '/VmRSS/{print $2$3}' /proc/$SRVPID/status))"
else
  echo "SERVER DIED during fuzzing"
fi
echo "--- server log tail ---"
tail -20 "$LOG"
kill $SRVPID 2>/dev/null
exit $FUZZ_RC
