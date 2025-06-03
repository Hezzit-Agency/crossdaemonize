#!/usr/bin/env bash
set -euo pipefail

# Build examples first so the tester binary is up to date
cargo build -p crossdaemonize-tests --examples

# Run tests capturing full output
LOG_FILE="test_output.log"
: > crossdaemonize-tests/tester_debug.log
cargo test -p crossdaemonize-tests -- --nocapture 2>&1 | tee "$LOG_FILE"

echo "Test results saved to $LOG_FILE"
echo "Tester debug log: crossdaemonize-tests/tester_debug.log"
