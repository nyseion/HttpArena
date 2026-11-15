#!/usr/bin/env bash

# A/B of HTTP/3 throughput: rimu-h3's uring_server against rimu-ws's in-tree HTTP/3 (the HttpArena
# `rimu-ws` entry, image httparena-rimu-ws), both in Docker on the same CPUs, with HttpArena's
# h2load-h3 generator (image httparena-h2load-h3) on other CPUs. The h2load invocation is
# rimu-ws's .scripts/h3-bench.sh's (HttpArena's: --alpn-list=h3, -c 64 -m 64, -D 5s; static-h3
# with its URI file and Accept-Encoding), with -t set to the generator's CPUs.
#
#   scripts/h3-ab.sh [ROUNDS]        (default 3)
#
# Each round starts each server once per profile (the order of the servers alternates between
# rounds) and runs h2load RUNS times (default 3) against it; a run's rps is 2xx responses over
# h2load's "finished in", as HttpArena counts it, and the best run of a start is its result. Every
# run records the 1-minute load average before it and the server's CPU time per 2xx response
# (from its container's cgroup). One line per run:
#   run SERVER PROFILE ROUND N rps=... cpu_us_per_req=... errors=... load1=...
# and one per start: best SERVER PROFILE ROUND rps=...
#
# Environment: SERVER_CPUS (default 0-5), LOAD_CPUS (default 6-11), RUNS (3), DURATION (5s),
# ARENA (default ~/src/HttpArena: data/, certs/, requests/), and those of scripts/server.sh
# (URING_BIN: build it with RUSTFLAGS="-C target-cpu=native", as the HttpArena entry is).

set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=server.sh
source "$dir/server.sh"

rounds=${1:-3}
server_cpus=${SERVER_CPUS:-0-5}
load_cpus=${LOAD_CPUS:-6-11}
runs=${RUNS:-3}
duration=${DURATION:-5s}
arena=${ARENA:-$HOME/src/HttpArena}
generator=httparena-h2load-h3
intree_image=httparena-rimu-ws
work=${TMPDIR:-/mnt/nvme1tb/claude-tmp}/rq-h3-ab
mkdir -p "$work"
printf '127.0.0.1 localhost\n' >"$work/hosts-v4"

count_cpus() {
	local n=0 part
	IFS=, read -ra parts <<<"$1"
	for part in "${parts[@]}"; do
		if [[ $part == *-* ]]; then n=$((n + ${part#*-} - ${part%-*} + 1)); else n=$((n + 1)); fi
	done
	echo "$n"
}
load_threads=$(count_cpus "$load_cpus")

busy() {
	[[ $(ss -lun "sport = :$PORT"; ss -ltn "sport = :$PORT") == *":$PORT"* ]]
}
busy && { echo "port $PORT is busy" >&2; exit 3; }

name=rq-ab-server-$$
gen=rq-ab-gen-$$
cleanup() {
	docker rm -f "$gen" >/dev/null 2>&1 || true
	docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start() {
	local server=$1
	case $server in
	ours)
		STATIC=$arena/data/static CERTS=$arena/certs server_start "$name" --cpuset-cpus "$server_cpus"
		;;
	intree)
		docker rm -f "$name" >/dev/null 2>&1 || true
		docker run -d --name "$name" --network host --security-opt seccomp=unconfined \
			--ulimit memlock=-1:-1 --ulimit nofile=1048576:1048576 --cpuset-cpus "$server_cpus" \
			-v "$arena/data/dataset.json:/data/dataset.json:ro" -v "$arena/data/static:/data/static:ro" \
			-v "$arena/certs:/certs:ro" "$intree_image" >/dev/null
		;;
	esac
}

cgroup_of() {
	local id c
	id=$(docker inspect -f '{{.Id}}' "$1")
	for c in "/sys/fs/cgroup/system.slice/docker-$id.scope" "/sys/fs/cgroup/docker/$id"; do
		[ -r "$c/cpu.stat" ] && { echo "$c"; return; }
	done
	return 1
}

ready() {
	local deadline=$((SECONDS + 60)) answer
	while [ "$SECONDS" -lt "$deadline" ]; do
		answer=$(timeout 10 docker run --rm --name "$gen" --network host --cpuset-cpus "$load_cpus" \
			-v "$work/hosts-v4:/etc/hosts:ro" "$generator" --alpn-list=h3 -n 1 -c 1 -t 1 \
			"https://localhost:$PORT/baseline2?a=1&b=1" 2>/dev/null || true)
		docker rm -f "$gen" >/dev/null 2>&1 || true
		[[ $answer == *" 1 2xx"* ]] && return 0
		sleep 0.5
	done
	return 1
}

one_start() {
	local server=$1 profile=$2 round=$3 args cg best=0
	case $profile in
	baseline-h3) args=("https://localhost:$PORT/baseline2?a=1&b=1") ;;
	static-h3) args=(-i /requests/static-h2-uris.txt -H "Accept-Encoding: br;q=1, gzip;q=0.8") ;;
	esac
	args=(--alpn-list=h3 "${args[@]}" -c 64 -m 64 -t "$load_threads" -D "$duration")
	start "$server"
	ready || { echo "fail $server $profile $round: no answer within 60 s"; docker logs "$name" 2>&1 | tail -5; return; }
	cg=$(cgroup_of "$name")
	for run in $(seq 1 "$runs"); do
		local out=$work/$server-$profile-$round-$run.txt load1 before after ok secs bad rps cpu
		load1=$(cut -d' ' -f1 /proc/loadavg)
		before=$(awk '/^usage_usec/ { print $2 }' "$cg/cpu.stat")
		timeout 30 docker run --rm --name "$gen" --network host --cpuset-cpus "$load_cpus" \
			-v "$work/hosts-v4:/etc/hosts:ro" --ulimit nofile=1048576:1048576 \
			-v "$arena/requests:/requests:ro" "$generator" "${args[@]}" >"$out" 2>&1 || true
		after=$(awk '/^usage_usec/ { print $2 }' "$cg/cpu.stat")
		docker rm -f "$gen" >/dev/null 2>&1 || true
		ok=$(awk '/status codes:/ { print $3 }' "$out")
		secs=$(awk '/^finished in/ { sub("s,", "", $3); print $3 }' "$out")
		bad=$(awk '/^requests:/ { f = $10 + $12 + $14 } /status codes:/ { n = $5 + $7 + $9 } END { print f + n }' "$out")
		rps=$(awk -v ok="${ok:-0}" -v s="${secs:-0}" 'BEGIN { if (s > 0) printf "%.0f", ok / s; else print 0 }')
		cpu=$(awk -v a="$before" -v b="$after" -v n="${ok:-0}" 'BEGIN { if (n > 0) printf "%.2f", (b - a) / n; else print "null" }')
		echo "run $server $profile $round $run rps=$rps cpu_us_per_req=$cpu errors=${bad:-1} load1=$load1"
		[ "$rps" -gt "$best" ] && best=$rps
		sleep 1
	done
	echo "best $server $profile $round rps=$best"
	docker rm -f "$name" >/dev/null 2>&1 || true
	for _ in $(seq 1 40); do busy || break; sleep 0.25; done
}

echo "# $(date -Is) server_cpus=$server_cpus load_cpus=$load_cpus runs=$runs duration=$duration uptime: $(uptime)"
for round in $(seq 1 "$rounds"); do
	if [ $((round % 2)) = 1 ]; then order=(intree ours); else order=(ours intree); fi
	for profile in baseline-h3 static-h3; do
		for server in "${order[@]}"; do
			echo "# uptime: $(uptime)"
			one_start "$server" "$profile" "$round"
		done
	done
done
