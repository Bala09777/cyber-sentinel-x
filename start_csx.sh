#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

PYTHON="./.venv/bin/python"

[[ -x "$PYTHON" ]] || {
    echo "ERROR: Python virtual environment missing"
    exit 1
}

mkdir -p logs/csx_runtime

exec 9>logs/csx_runtime/start.lock
flock -n 9 || {
    echo "Cyber Sentinel X already running"
    exit 1
}

if pgrep -f '[b]ackend\.pcap\.live_capture|[s]cripts/notifications_worker\.py|[b]ackend\.app:create_app' >/dev/null; then
    echo "STOP: Existing CSX services detected"
    exit 1
fi

if [[ -n "$(ss -H -ltn 'sport = :8000')" ]]; then
    echo "STOP: Port 8000 already in use"
    exit 1
fi

export PYTHONUNBUFFERED=1

pids=()

cleanup() {
    trap - EXIT
    echo "Stopping Cyber Sentinel X..."
    for pid in "${pids[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    wait || true
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$PYTHON" -m flask --app backend.app:create_app run \
    --host 127.0.0.1 --port 8000 --no-reload \
    >>logs/csx_runtime/dashboard.log 2>&1 &
pids+=("$!")

"$PYTHON" -m backend.pcap.live_capture \
    >>logs/csx_runtime/capture.log 2>&1 &
pids+=("$!")

"$PYTHON" scripts/notifications_worker.py \
    >>logs/csx_runtime/notifications.log 2>&1 &
pids+=("$!")

echo "========================================"
echo " CYBER SENTINEL X - SOC PLATFORM"
echo " Dashboard: http://127.0.0.1:8000"
echo " Services: Dashboard / Capture / Alerts"
echo " Logs: logs/csx_runtime/"
echo " Press CTRL+C to stop all services"
echo "========================================"

wait -n || true
echo "A service stopped. Check runtime logs."
exit 1
