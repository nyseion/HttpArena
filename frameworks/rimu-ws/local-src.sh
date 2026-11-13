#!/usr/bin/env bash
# Copies the rimu-ws crates from a local checkout into `rimu-ws/` (and the rimu crates it depends
# on beside it), where Cargo.toml and the Dockerfile look for them. Usage: local-src.sh [CHECKOUT] (default /mnt/nvme1tb/claude-tmp/rimu-h3).
set -euo pipefail
src=${1:-/mnt/nvme1tb/claude-tmp/rimu-h3}
dst=$(cd "$(dirname "$0")" && pwd)/rimu-ws
rm -rf "$dst" && mkdir -p "$dst"
rsync -a --exclude target --exclude hpack-test-case "$src/wtx" "$src/wtx-macros" "$src/README.md" "$dst/"
git -C "$src" rev-parse HEAD > "$dst/REVISION"
# The rimu crates rimu-ws depends on by path (`../../rimu-<name>` from rimu-ws/wtx), beside
# `rimu-ws/`: from CRATES, or the checkout's parent directory.
crates=${CRATES:-$(dirname "$src")}
for crate in rimu-json rimu-gzip rimu-http1; do
  rm -rf "$(dirname "$dst")/$crate"
  rsync -a --exclude target --exclude .git --exclude .codegraph --exclude .superpowers \
    "$crates/$crate/" "$(dirname "$dst")/$crate/"
  git -C "$crates/$crate/" rev-parse HEAD > "$(dirname "$dst")/$crate/REVISION"
done
echo "rimu-ws $(cat "$dst/REVISION") copied to $dst"
