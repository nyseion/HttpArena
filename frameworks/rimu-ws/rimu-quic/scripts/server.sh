#!/usr/bin/env bash

# Helpers of the verification scripts: rimu-h3's uring_server example in a Docker container
# (io_uring needs more locked memory than a user's RLIMIT_MEMLOCK allows for several workers, and
# Docker's default seccomp profile blocks io_uring, hence the flags).
#
#   source scripts/server.sh
#   server_start NAME [docker run options...]   e.g. -e WORKERS=4 --cpuset-cpus 0-5
#   server_wait NAME                            until UDP $PORT is bound (20 s)
#   server_stats NAME                           the last `h3-stats ...` line after a SIGUSR1
#   server_stop NAME                            SIGTERM (graceful drain), then removal
#
# Environment:
#   URING_BIN   the uring_server binary (default $CARGO_TARGET_DIR/release/examples/uring_server),
#               built with `cargo build --release -p rimu-h3 --features uring --example uring_server`
#   CERTS       directory with server.crt and server.key (default ~/src/HttpArena/certs)
#   STATIC      the static files (default ~/src/HttpArena/data/static)
#   PORT        UDP port (default 8443)
#   IMAGE       the image the binary runs in (default debian:bookworm-slim, pinned)

target=${CARGO_TARGET_DIR:-/mnt/nvme1tb/claude-tmp/rimu-quic/target}
URING_BIN=${URING_BIN:-$target/release/examples/uring_server}
CERTS=${CERTS:-$HOME/src/HttpArena/certs}
STATIC=${STATIC:-$HOME/src/HttpArena/data/static}
PORT=${PORT:-8443}
IMAGE=${IMAGE:-debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171}

udp_port_busy() {
	[[ $(ss -lun "sport = :${1:-$PORT}") == *":${1:-$PORT}"* ]]
}

server_start() {
	local name=$1
	shift
	[ -x "$URING_BIN" ] || { echo "no $URING_BIN" >&2; return 2; }
	docker rm -f "$name" >/dev/null 2>&1 || true
	docker run -d --name "$name" --network host --ulimit memlock=-1:-1 \
		--ulimit nofile=1048576:1048576 --security-opt seccomp=unconfined \
		-v "$(dirname "$URING_BIN"):/b:ro" -v "$CERTS:/certs:ro" -v "$STATIC:/data/static:ro" \
		"$@" "$IMAGE" "/b/$(basename "$URING_BIN")" "[::]:$PORT" >/dev/null
}

server_wait() {
	local name=$1
	for _ in $(seq 1 80); do
		udp_port_busy && return 0
		[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ] || {
			docker logs "$name" >&2 2>&1 || true
			return 5
		}
		sleep 0.25
	done
	return 5
}

server_stats() {
	local name=$1 seen now
	seen=$(docker logs "$name" 2>/dev/null | grep -c '^h3-stats ' || true)
	docker kill -s USR1 "$name" >/dev/null 2>&1 || return 1
	for _ in $(seq 1 100); do
		now=$(docker logs "$name" 2>/dev/null | grep -c '^h3-stats ' || true)
		if [ "$now" -gt "$seen" ]; then
			docker logs "$name" 2>/dev/null | grep '^h3-stats ' | tail -1
			return 0
		fi
		sleep 0.02
	done
	return 1
}

server_stop() {
	local name=$1
	docker kill -s TERM "$name" >/dev/null 2>&1 || true
	for _ in $(seq 1 60); do
		[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ] || break
		sleep 0.25
	done
	docker rm -f "$name" >/dev/null 2>&1 || true
}
