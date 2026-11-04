#!/bin/bash
# Build (offline) and run the F1 signing-oracle PoC, capturing the full log.
set -e
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")"
echo "pinned frost commit: $(git -C ../../frost/frost rev-parse HEAD)"
cargo build --offline --release 2>&1 | tail -2
./target/release/f1-signing-oracle-poc 2>&1 | tee run.log
