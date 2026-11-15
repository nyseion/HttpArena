#!/usr/bin/env bash

# HTTP/3 interop and impairment matrix against rimu-h3's uring_server (in Docker, 4 workers by
# default): independent clients, direct and through udp-impair, on 127.0.0.1 and ::1. Correctness
# only. Adapted from rimu-ws's .scripts/h3-interop.sh (the user's): the same clients, client
# drivers (mounted read-only from rimu-ws), paths and scenarios; the server and its counters are
# this repository's.
#
#   scripts/h3-interop.sh [-c CLIENTS] [-p PATHS] [-f FAMILIES]
#
#   -c CLIENTS  comma list of curl, ngtcp2, quic-go (default: all three)
#   -p PATHS    comma list of direct, loss1, loss5, rebind (default: all four)
#   -f FAMILIES comma list of v4, v6 (default: both)
#
# Clients: images rimu-h3-interop-curl (curl 8.23.0 on ngtcp2 v1.26.0 / nghttp3 v1.19.0 / quictls,
# and ngtcp2's example client) and rimu-h3-interop-quic-go (quic-go v0.65.0), built by rimu-ws's
# .scripts/h3-interop.sh -b.
#
# Paths: direct; loss1 (1 % dropped, 0.5 ms each way); loss5 (5 % dropped, 5 % reordered by 1-5 ms,
# 5 % duplicated, 0.5 ms); rebind (a NAT that gives the client a new source port every REBIND
# datagrams, and from the second time on the address 127.0.0.2 on v4: the server must follow it,
# RFC 9000 section 9.3; the cell fails if no rebinding happened).
#
# Scenarios per cell (the client drivers'): GET /baseline2; every file under /static with
# accept-encoding br, gzip and identity (bytes and content-encoding checked); POST of 1 MiB to
# /echo; 1,000 sequential requests on one connection; 64 parallel connections of five requests.
#
# The server's counters (h3-stats on SIGUSR1) are read around each cell: the cell also fails if
# the server sent STREAM frames of bytes already acknowledged (frames_resent_acked). Not judged,
# unlike rimu-ws's script: handler panics (the server has no panic counter: a panic would end a
# worker, and the crash check below catches it) and logged errors (the server logs none).
#
# Environment: IMPAIR_BIN (default /mnt/nvme1tb/claude-tmp/rimu-quic/soak-target/release/udp-impair,
# built in ~/src/rimu-soak), DRIVERS (default ~/src/rimu-ws/.scripts/h3-interop), WORKERS (4),
# SEED (1), SEQ (1000), PAR (64), REBIND (200), CELL_LIMIT (240 s), and those of scripts/server.sh.

set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=server.sh
source "$dir/server.sh"

impair_bin=${IMPAIR_BIN:-/mnt/nvme1tb/claude-tmp/rimu-quic/soak-target/release/udp-impair}
drivers=${DRIVERS:-$HOME/src/rimu-ws/.scripts/h3-interop}
workers=${WORKERS:-4}
seed=${SEED:-1}
seq_n=${SEQ:-1000}
par_n=${PAR:-64}
cell_limit=${CELL_LIMIT:-240}
rebind_n=${REBIND:-200}
work=${TMPDIR:-/mnt/nvme1tb/claude-tmp}/rq-h3-interop
mkdir -p "$work"

clients=curl,ngtcp2,quic-go
paths=direct,loss1,loss5,rebind
families=v4,v6
while getopts "c:p:f:" opt; do
	case $opt in
	c) clients=$OPTARG ;;
	p) paths=$OPTARG ;;
	f) families=$OPTARG ;;
	*) exit 2 ;;
	esac
done

image_curl=rimu-h3-interop-curl
image_go=rimu-h3-interop-quic-go
for image in $image_curl $image_go; do
	docker image inspect "$image" >/dev/null 2>&1 || { echo "no image $image" >&2; exit 2; }
done
[ -x "$impair_bin" ] || { echo "no $impair_bin" >&2; exit 2; }
udp_port_busy && { echo "UDP $PORT is busy" >&2; exit 3; }

server=rq-interop-server-$$
cell_name=rq-interop-cell-$$
impair_pid=""
stop_impair() {
	if [ -n "$impair_pid" ]; then
		kill "$impair_pid" 2>/dev/null || true
		wait "$impair_pid" 2>/dev/null || true
		impair_pid=""
	fi
}
cleanup() {
	stop_impair
	docker rm -f "$cell_name" >/dev/null 2>&1 || true
	docker logs "$server" >"$work/server.log" 2>&1 || true
	server_stop "$server"
}
trap cleanup EXIT

server_start "$server" -e WORKERS="$workers" -e PIN=0
server_wait "$server"
sleep 0.5

counter() {
	grep -o " $2=[0-9]*" <<<" $1" | cut -d= -f2
}

start_path() {
	local params
	case $1 in
	direct)
		target_port=$PORT
		return
		;;
	loss1) params=(--drop 0.01 --delay-us 500) ;;
	loss5) params=(--drop 0.05 --reorder 0.05 --dup 0.05 --delay-us 500) ;;
	rebind) params=(--rebind "$rebind_n" --delay-us 500) ;;
	*) echo "unknown path $1" >&2; exit 2 ;;
	esac
	: >"$work/impair.out"
	"$impair_bin" --server-port "$PORT" --seed "$seed" "${params[@]}" >"$work/impair.out" 2>"$work/impair.err" &
	impair_pid=$!
	for _ in $(seq 1 40); do
		target_port=$(sed -n 's/^listening //p' "$work/impair.out")
		[ -n "$target_port" ] && return
		kill -0 "$impair_pid" 2>/dev/null || { cat "$work/impair.err" >&2; exit 7; }
		sleep 0.1
	done
	echo "udp-impair did not start" >&2
	exit 7
}

run_client() {
	local client=$1 addr=$2
	local mounts=(-v "$CERTS:/certs:ro" -v "$STATIC:/data/static:ro" -v "$drivers:/driver:ro")
	local env=(-e "ADDR=$addr" -e CA=/certs/server.crt -e STATIC=/data/static -e "SEQ=$seq_n" -e "PAR=$par_n")
	docker rm -f "$cell_name" >/dev/null 2>&1 || true
	case $client in
	curl)
		timeout "$cell_limit" docker run --rm --name "$cell_name" --network host "${mounts[@]}" "${env[@]}" \
			"$image_curl" bash /driver/client-curl.sh >"$work/cell.out" 2>&1
		;;
	ngtcp2)
		timeout "$cell_limit" docker run --rm --name "$cell_name" --network host "${mounts[@]}" "${env[@]}" \
			"$image_curl" bash /driver/client-ngtcp2.sh >"$work/cell.out" 2>&1
		;;
	quic-go)
		timeout "$cell_limit" docker run --rm --name "$cell_name" --network host "${mounts[@]}" \
			"$image_go" -addr "$addr" -ca /certs/server.crt -static /data/static -seq "$seq_n" -par "$par_n" \
			>"$work/cell.out" 2>&1
		;;
	*) echo "unknown client $client" >&2; exit 2 ;;
	esac
}

cells=0
failed=0
IFS=, read -ra client_list <<<"$clients"
IFS=, read -ra path_list <<<"$paths"
IFS=, read -ra family_list <<<"$families"
for client in "${client_list[@]}"; do
	for family in "${family_list[@]}"; do
		for path in "${path_list[@]}"; do
			cells=$((cells + 1))
			case $family in
			v4) host=127.0.0.1 ;;
			v6) host='[::1]' ;;
			*) echo "unknown family $family" >&2; exit 2 ;;
			esac
			start_path "$path"
			before=$(server_stats "$server") || before=""
			start=$SECONDS
			status=PASS
			run_client "$client" "$host:$target_port" || status=FAIL
			elapsed=$((SECONDS - start))
			stop_impair
			rebinds=""
			if [ "$path" = rebind ]; then
				cp "$work/impair.err" "$work/last-$client-$family-$path.impair"
				rebinds=$(grep -c '^rebind ' "$work/impair.err" || true)
				address_rebinds=$(grep -c '^rebind .* 127\.0\.0\.2:' "$work/impair.err" || true)
				if [ "$rebinds" -eq 0 ]; then
					status=FAIL
					echo "FAIL proxy: no rebinding happened" >>"$work/cell.out"
				fi
				if [ "$family" = v4 ] && [ "$address_rebinds" -eq 0 ]; then
					status=FAIL
					echo "FAIL proxy: no rebinding to 127.0.0.2 happened" >>"$work/cell.out"
				fi
				rebinds="$rebinds address_rebinds=$address_rebinds"
			fi
			if [ "$(docker inspect -f '{{.State.Running}}' "$server" 2>/dev/null)" != true ]; then
				echo "cell $client $family $path FAIL ${elapsed}s the server died"
				exit 1
			fi
			after=$(server_stats "$server") || after=""
			detail=""
			if [ -n "$before" ] && [ -n "$after" ]; then
				for name in requests datagrams_in forwarded packets_lost pto_probes frames_resent frames_resent_acked \
					udp_send_errors forward_dropped; do
					delta=$(($(counter "$after" $name) - $(counter "$before" $name)))
					detail="$detail $name=$delta"
					if [ "$name" = frames_resent_acked ] && [ "$delta" -ne 0 ]; then
						status=FAIL
						echo "FAIL server: $delta STREAM frames carried bytes that were already acknowledged" >>"$work/cell.out"
					fi
				done
			else
				status=FAIL
				echo "FAIL server: no h3-stats line" >>"$work/cell.out"
			fi
			[ -z "$rebinds" ] || detail="$detail rebinds=$rebinds"
			echo "cell $client $family $path $status ${elapsed}s$detail"
			if [ "$status" = FAIL ]; then
				failed=$((failed + 1))
				grep -v '^ok ' "$work/cell.out" | head -20 | sed 's/^/    /'
			fi
			cp "$work/cell.out" "$work/last-$client-$family-$path.out"
		done
	done
done
echo "summary: $cells cells, $failed failed"
[ "$failed" -eq 0 ]
