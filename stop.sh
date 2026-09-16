#!/usr/bin/env bash
# Stop whatever is listening on the app's port (5002 unless -p says otherwise).
set -uo pipefail

PORT=5002

usage() {
    cat <<USAGE
Usage: ./stop.sh [-p PORT]

  -p, --port PORT   Port to free (default: $PORT)
  -h, --help        Show this message
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--port)
            [ $# -ge 2 ] || { echo "[stop] $1 needs a port number" >&2; exit 2; }
            PORT="$2"; shift 2 ;;
        -p=*|--port=*)
            PORT="${1#*=}"; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "[stop] Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$PORT" in
    ''|*[!0-9]*) echo "[stop] Not a port number: $PORT" >&2; exit 2 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "[stop] Port $PORT is out of range — pick one between 1 and 65535." >&2
    exit 2
fi

PIDS="$(lsof -ti tcp:"$PORT" 2>/dev/null || true)"

if [ -z "$PIDS" ]; then
    echo "[stop] Nothing listening on port $PORT"
    exit 0
fi

echo "[stop] Terminating PID(s) on port $PORT: $PIDS"
# shellcheck disable=SC2086
kill $PIDS 2>/dev/null || true

for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 0.3
    REMAINING="$(lsof -ti tcp:"$PORT" 2>/dev/null || true)"
    [ -z "$REMAINING" ] && { echo "[stop] Stopped."; exit 0; }
done

echo "[stop] Still alive, sending SIGKILL"
# shellcheck disable=SC2086
kill -9 $(lsof -ti tcp:"$PORT" 2>/dev/null) 2>/dev/null || true
echo "[stop] Stopped."
