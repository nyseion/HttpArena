#!/usr/bin/env bash
# Copies the nyseion-ws crates from a local checkout into `nyseion-ws/` (and the nyseion crates it depends
# on beside it), where Cargo.toml and the Dockerfile look for them. Usage: local-src.sh [CHECKOUT] (default /mnt/nvme1tb/claude-tmp/nyseion-h3).
set -euo pipefail
src=${1:-/mnt/nvme1tb/claude-tmp/nyseion-h3}
dst=$(cd "$(dirname "$0")" && pwd)/nyseion-ws
rm -rf "$dst" && mkdir -p "$dst"
rsync -a --exclude target --exclude hpack-test-case "$src/wtx" "$src/wtx-macros" "$src/README.md" "$dst/"
git -C "$src" rev-parse HEAD > "$dst/REVISION"
# The nyseion crates nyseion-ws depends on by path (`../../nyseion-<name>` from nyseion-ws/wtx), beside
# `nyseion-ws/`: from CRATES, or the checkout's parent directory.
crates=${CRATES:-$(dirname "$src")}
for crate in nyseion-json nyseion-gzip nyseion-http1; do
  rm -rf "$(dirname "$dst")/$crate"
  rsync -a --exclude target --exclude .git --exclude .codegraph --exclude .superpowers \
    "$crates/$crate/" "$(dirname "$dst")/$crate/"
  git -C "$crates/$crate/" rev-parse HEAD > "$(dirname "$dst")/$crate/REVISION"
done
echo "nyseion-ws $(cat "$dst/REVISION") copied to $dst"
