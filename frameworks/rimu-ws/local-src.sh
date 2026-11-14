#!/usr/bin/env bash
# Copies the rimu-ws crates from a local checkout into `rimu-ws/`, and the rimu-quic workspace
# (rimu-quic, rimu-h3) and rimu-qpack beside it, where Cargo.toml and the Dockerfile look for
# them. Usage: local-src.sh [CHECKOUT] (default /mnt/nvme1tb/claude-tmp/rimu-h3); the crates come
# from CRATES (default: the checkout's parent directory), each at the commit its checkout has.
# Copy clean checkouts: an uncommitted change is copied too, under the commit's name.
set -euo pipefail
src=${1:-/mnt/nvme1tb/claude-tmp/rimu-h3}
dst=$(cd "$(dirname "$0")" && pwd)/rimu-ws
rm -rf "$dst" && mkdir -p "$dst"
rsync -a --exclude target --exclude hpack-test-case "$src/wtx" "$src/wtx-macros" "$src/README.md" "$dst/"
git -C "$src" rev-parse HEAD > "$dst/REVISION"
# rimu-ws depends on them by path: ../../rimu-quic/rimu-{quic,h3} and ../../rimu-qpack from
# rimu-ws/wtx
crates=${CRATES:-$(dirname "$src")}
for crate in rimu-quic rimu-qpack; do
  rm -rf "$(dirname "$dst")/$crate"
  rsync -a --exclude target --exclude .git --exclude .codegraph --exclude .superpowers \
    --exclude fuzz --exclude 'bench/results' "$crates/$crate/" "$(dirname "$dst")/$crate/"
  git -C "$crates/$crate/" rev-parse HEAD > "$(dirname "$dst")/$crate/REVISION"
  echo "$crate $(cat "$(dirname "$dst")/$crate/REVISION") copied beside rimu-ws"
done
echo "rimu-ws $(cat "$dst/REVISION") copied to $dst"
