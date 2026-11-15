#!/usr/bin/env bash

# h3spec (https://github.com/kazu-yamamoto/h3spec) against rimu-h3's uring_server, in Docker,
# on UDP 127.0.0.1:$PORT. The h3spec run is rimu-ws's .scripts/h3spec.sh's: the pinned binary in a
# pinned Debian container, its sha256 checked.
#
#   scripts/h3spec.sh [--fetch] [H3SPEC_ARGS...]
#
# Pinned: h3spec v0.1.15, asset h3spec-linux-x86_64,
#   sha256 c3c5f497153f4ba81f82023791ba7f9a4bc46d4141211e614196f141c5996830
#
# Environment: H3SPEC_DIR (default /mnt/nvme1tb/claude-tmp/h3spec), WORKERS (default 4),
# TIMEOUT_MS (default 2000), and those of scripts/server.sh.
#
# Output: h3spec's own, and `h3spec: N examples, N failures` last; exit status 0 only if every case
# passed. The 0-RTT case is pending in h3spec itself: rimu-quic refuses 0-RTT.

set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=server.sh
source "$dir/server.sh"

version=v0.1.15
sha256=c3c5f497153f4ba81f82023791ba7f9a4bc46d4141211e614196f141c5996830
h3spec_dir=${H3SPEC_DIR:-/mnt/nvme1tb/claude-tmp/h3spec}
timeout_ms=${TIMEOUT_MS:-2000}
workers=${WORKERS:-4}

if [ "${1:-}" = "--fetch" ]; then
	mkdir -p "$h3spec_dir"
	curl -fsSL -o "$h3spec_dir/h3spec" "https://github.com/kazu-yamamoto/h3spec/releases/download/$version/h3spec-linux-x86_64"
	chmod 755 "$h3spec_dir/h3spec"
	shift
fi
[ -f "$h3spec_dir/h3spec" ] || { echo "no $h3spec_dir/h3spec (use --fetch)" >&2; exit 2; }
echo "$sha256  $h3spec_dir/h3spec" | sha256sum --check --quiet || { echo "h3spec: wrong sha256" >&2; exit 2; }
udp_port_busy && { echo "UDP $PORT is busy" >&2; exit 3; }

server=rq-h3spec-server-$$
client=rq-h3spec-$$
cleanup() {
	docker rm -f "$client" >/dev/null 2>&1 || true
	docker logs "$server" >"${TMPDIR:-/mnt/nvme1tb/claude-tmp}/h3spec-server.log" 2>&1 || true
	server_stop "$server"
}
trap cleanup EXIT

server_start "$server" -e WORKERS="$workers" -e PIN=0
server_wait "$server"
sleep 0.5

# -n: the certificate is self-signed and h3spec has no option for a CA
status=0
out=$(docker run --rm --name "$client" --network host --cap-drop ALL \
	--security-opt no-new-privileges --pids-limit 256 --memory 1g --read-only \
	-v "$h3spec_dir/h3spec:/h3spec:ro" "$IMAGE" \
	/h3spec -n -t "$timeout_ms" "$@" 127.0.0.1 "$PORT" 2>&1) || status=$?
echo "$out"
echo "h3spec: $(grep -E '^[0-9]+ examples?,' <<<"$out" || echo 'no summary')"
exit "$status"
