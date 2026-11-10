#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

# Create virtual environment if not present
if [ ! -d "venv" ]; then
    echo "[*] Setting up Python virtual environment..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r requirements.txt
fi

PORT="${SECRETSCOPE_PORT:-8077}"
echo "=========================================================="
echo "  SecretScope - Bug Bounty Secret & API Key Recon Tool"
echo "  Web UI: http://localhost:${PORT}"
echo "=========================================================="

./venv/bin/python run.py
