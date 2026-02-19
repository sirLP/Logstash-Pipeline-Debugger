#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$REPO_DIR"

echo "[1/4] Pulling latest changes..."
git pull

echo "[2/4] Copying .pfelk configs to /etc/pfelk/conf.d/..."
sudo cp conf.d/*.pfelk /etc/pfelk/conf.d/.

echo "[3/4] Restarting logstash..."
sudo systemctl restart logstash

echo "[4/4] Following logstash journal (Ctrl+C to stop)..."
sudo journalctl -u logstash -f
