#!/usr/bin/env bash
# Copies the nyseion-ws crates from a local checkout into `nyseion-ws/`, where Cargo.toml and the
# Dockerfile look for them. Usage: local-src.sh [CHECKOUT] (default /mnt/nvme1tb/claude-tmp/nyseion-h3).
set -euo pipefail
src=${1:-/mnt/nvme1tb/claude-tmp/nyseion-h3}
dst=$(cd "$(dirname "$0")" && pwd)/nyseion-ws
rm -rf "$dst" && mkdir -p "$dst"
rsync -a --exclude target --exclude hpack-test-case "$src/wtx" "$src/wtx-macros" "$src/README.md" "$dst/"
git -C "$src" rev-parse HEAD > "$dst/REVISION"
echo "nyseion-ws $(cat "$dst/REVISION") copied to $dst"
