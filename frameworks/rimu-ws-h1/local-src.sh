#!/usr/bin/env bash
# Copies the rimu-ws crates from a local checkout into `rimu-ws/`, where Cargo.toml and the
# Dockerfile look for them, and the server with its allocation tests (the checkout's arena-h1:
# `src/main.rs`, `src/arena_h1/alloc_tests.rs`). Usage: local-src.sh [CHECKOUT] (default
# /mnt/nvme1tb/claude-tmp/rimu-h1).
set -euo pipefail
src=${1:-/mnt/nvme1tb/claude-tmp/rimu-h1}
dst=$(cd "$(dirname "$0")" && pwd)/rimu-ws
rm -rf "$dst" && mkdir -p "$dst"
rsync -a --exclude target --exclude hpack-test-case "$src/wtx" "$src/wtx-macros" "$src/README.md" "$dst/"
git -C "$src" rev-parse HEAD > "$dst/REVISION"
here=$(dirname "$dst")
cp "$src/wtx-internal/src/bin/arena-h1.rs" "$here/src/main.rs"
mkdir -p "$here/src/arena_h1"
cp "$src/wtx-internal/src/bin/arena_h1/alloc_tests.rs" "$here/src/arena_h1/alloc_tests.rs"
echo "rimu-ws $(cat "$dst/REVISION") copied to $dst"
