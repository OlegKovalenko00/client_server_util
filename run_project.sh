#!/usr/bin/env bash

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_dir="${project_dir}/build"
config_path="${project_dir}/configs/patterns.conf.example"
port="9090"
run_demo="0"
skip_build="0"

usage() {
    cat <<EOF
Usage: ./run_project.sh [options]

Options:
  --port <port>         TCP port for scan_server. Default: 9090
  --config <path>       Path to patterns config. Default: configs/patterns.conf.example
  --build-dir <path>    Build directory. Default: ./build
  --no-build            Skip cmake configure/build
  --demo                Create demo files, run full check cycle and stop the server
  -h, --help            Show this help
EOF
}

while (($# > 0)); do
    case "$1" in
        --port)
            if (($# < 2)); then
                echo "missing value for --port" >&2
                exit 1
            fi
            port="$2"
            shift 2
            ;;
        --config)
            if (($# < 2)); then
                echo "missing value for --config" >&2
                exit 1
            fi
            config_path="$2"
            shift 2
            ;;
        --build-dir)
            if (($# < 2)); then
                echo "missing value for --build-dir" >&2
                exit 1
            fi
            build_dir="$2"
            shift 2
            ;;
        --no-build)
            skip_build="1"
            shift
            ;;
        --demo)
            run_demo="1"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

server_bin="${build_dir}/scan_server"
client_bin="${build_dir}/scan_client"
stats_bin="${build_dir}/scan_stats"
request_fifo="/tmp/malware_scan_${port}.req.fifo"
response_fifo="/tmp/malware_scan_${port}.resp.fifo"
demo_dir="${project_dir}/demo_files"
clean_file="${demo_dir}/clean.txt"
infected_file="${demo_dir}/infected.txt"
runtime_dir="$(mktemp -d "/tmp/malware_scan_runtime_${port}_XXXXXX")"
server_log="${runtime_dir}/server.log"
server_pid=""

cleanup() {
    if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
        kill "${server_pid}" 2>/dev/null || true
        wait "${server_pid}" 2>/dev/null || true
    fi

    rm -rf "${runtime_dir}"
}

trap cleanup EXIT

if [[ "${skip_build}" != "1" ]]; then
    cmake -S "${project_dir}" -B "${build_dir}"
    cmake --build "${build_dir}"
fi

for binary in "${server_bin}" "${client_bin}" "${stats_bin}"; do
    if [[ ! -x "${binary}" ]]; then
        echo "missing executable: ${binary}" >&2
        exit 1
    fi
done

if [[ ! -f "${config_path}" ]]; then
    echo "config file not found: ${config_path}" >&2
    exit 1
fi

mkdir -p "${demo_dir}"

printf 'hello world\n' > "${clean_file}"
printf 'payload /bin/sh payload\n' > "${infected_file}"

"${server_bin}" "${config_path}" "${port}" >"${server_log}" 2>&1 &
server_pid="$!"

for _ in $(seq 1 50); do
    if [[ -p "${request_fifo}" && -p "${response_fifo}" ]]; then
        break
    fi

    if ! kill -0 "${server_pid}" 2>/dev/null; then
        echo "server exited unexpectedly" >&2
        cat "${server_log}" >&2
        exit 1
    fi

    sleep 0.1
done

if [[ ! -p "${request_fifo}" || ! -p "${response_fifo}" ]]; then
    echo "server did not create fifo files in time" >&2
    cat "${server_log}" >&2
    exit 1
fi

cat <<EOF
Project is up.

Server:
  PID: ${server_pid}
  Port: ${port}
  Config: ${config_path}
  Log: ${server_log}

Demo files:
  Clean: ${clean_file}
  Infected: ${infected_file}

Useful commands:
  "${client_bin}" "${clean_file}" "${port}"
  "${client_bin}" "${infected_file}" "${port}"
  "${stats_bin}" "${port}"

EOF

if [[ "${run_demo}" == "1" ]]; then
    echo
    echo "[demo] clean file"
    "${client_bin}" "${clean_file}" "${port}"

    echo
    echo "[demo] infected file"
    "${client_bin}" "${infected_file}" "${port}"

    echo
    echo "[demo] stats"
    "${stats_bin}" "${port}"

    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
    server_pid=""

    echo
    echo "Demo cycle completed."
    echo "Demo files were left in: ${demo_dir}"
    exit 0
fi

echo "Press Ctrl+C in this terminal to stop the server."
wait "${server_pid}"
