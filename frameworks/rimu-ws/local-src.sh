#!/usr/bin/env bash
# Copies the rimu-ws crates from a local checkout into `rimu-ws/`, where Cargo.toml and the
# Dockerfile look for them. Usage: local-src.sh [CHECKOUT] (default /mnt/nvme1tb/claude-tmp/rimu-h3).
set -euo pipefail
src=${1:-/mnt/nvme1tb/claude-tmp/rimu-h3}
dst=$(cd "$(dirname "$0")" && pwd)/rimu-ws
rm -rf "$dst" && mkdir -p "$dst"
rsync -a --exclude target --exclude hpack-test-case "$src/wtx" "$src/wtx-macros" "$src/README.md" "$dst/"
git -C "$src" rev-parse HEAD > "$dst/REVISION"
echo "rimu-ws $(cat "$dst/REVISION") copied to $dst"
