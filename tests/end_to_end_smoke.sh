#!/usr/bin/env bash

set -euo pipefail

server_bin="$1"
client_bin="$2"
stats_bin="$3"
config_path="$4"

port=$((30000 + RANDOM % 10000))
tmp_dir="$(mktemp -d)"
server_log="${tmp_dir}/server.log"
server_pid=""

cleanup() {
    if [[ -n "${server_pid}" ]]; then
        kill "${server_pid}" 2>/dev/null || true
        wait "${server_pid}" 2>/dev/null || true
    fi

    rm -f "/tmp/malware_scan_${port}.req.fifo" "/tmp/malware_scan_${port}.resp.fifo"
    rm -rf "${tmp_dir}"
}

trap cleanup EXIT

printf 'hello world\n' > "${tmp_dir}/clean.txt"
printf 'payload /bin/sh payload\n' > "${tmp_dir}/infected.txt"

"${server_bin}" "${config_path}" "${port}" >"${server_log}" 2>&1 &
server_pid="$!"

for _ in $(seq 1 50); do
    if [[ -p "/tmp/malware_scan_${port}.req.fifo" && -p "/tmp/malware_scan_${port}.resp.fifo" ]]; then
        break
    fi

    sleep 0.1
done

if ! kill -0 "${server_pid}" 2>/dev/null; then
    if grep -F "socket failed: Operation not permitted" "${server_log}" >/dev/null 2>&1; then
        echo "skipping end-to-end smoke: socket listeners are not allowed in this environment"
        exit 0
    fi

    echo "server exited unexpectedly"
    cat "${server_log}"
    exit 1
fi

clean_output="$("${client_bin}" "${tmp_dir}/clean.txt" "${port}")"
infected_output="$("${client_bin}" "${tmp_dir}/infected.txt" "${port}")"
stats_output="$("${stats_bin}" "${port}")"

grep -F "No threats found in file: clean.txt" <<<"${clean_output}" >/dev/null
grep -F "Threats found in file: infected.txt" <<<"${infected_output}" >/dev/null
grep -F -- "- shell_spawn: 1" <<<"${infected_output}" >/dev/null
grep -F "Scanned files: 2" <<<"${stats_output}" >/dev/null
grep -F -- "- shell_spawn: 1" <<<"${stats_output}" >/dev/null

kill "${server_pid}" 2>/dev/null || true
wait "${server_pid}" 2>/dev/null || true
server_pid=""
