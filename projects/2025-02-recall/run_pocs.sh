#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/contracts"

echo "[*] Running all PoCs..."
forge test --match-contract "PoCH" -v
