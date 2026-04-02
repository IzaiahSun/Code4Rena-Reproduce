#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Installing forge dependencies..."
forge install foundry-rs/forge-std --no-commit
forge install OpenZeppelin/openzeppelin-contracts --no-commit
forge install transmissions11/solmate --no-commit
forge install arcs/discord-runtime-clone --no-commit
forge install Uniswap/v3-core --no-commit
forge install Uniswap/v3-periphery --no-commit
forge install Uniswap/v4-core --no-commit
forge install vectorized/solady --no-commit

echo "[*] Environment setup complete."
