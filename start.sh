#!/usr/bin/env bash
# Bootstrap the virtualenv, install pinned deps, then run the Flask app.
# Serves on 127.0.0.1:5002 unless -H / -p say otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV="$ROOT/venv"
PORT=5002
HOST=""

usage() {
    cat <<USAGE
Usage: ./start.sh [-p PORT] [-H HOST]

  -p, --port PORT   TCP port to listen on (default: $PORT)
  -H, --host HOST   Address to bind (default: 127.0.0.1)
  -h, --help        Show this message

The port is checked before the server starts, so a port already in use is
reported with what holds it rather than as a bind failure.

The server answers only this machine unless -H says otherwise. It has no
authentication and its API returns HEC tokens in clear text, so -H 0.0.0.0
publishes those to everything on your network. It warns when you ask for it.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--port)
            [ $# -ge 2 ] || { echo "[start] $1 needs a port number" >&2; exit 2; }
            PORT="$2"; shift 2 ;;
        -p=*|--port=*)
            PORT="${1#*=}"; shift ;;
        -H|--host)
            [ $# -ge 2 ] || { echo "[start] $1 needs an address" >&2; exit 2; }
            HOST="$2"; shift 2 ;;
        -H=*|--host=*)
            HOST="${1#*=}"; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "[start] Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$PORT" in
    ''|*[!0-9]*) echo "[start] Not a port number: $PORT" >&2; exit 2 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "[start] Port $PORT is out of range — pick one between 1 and 65535." >&2
    exit 2
fi

if [ ! -d "$VENV" ]; then
    echo "[start] Creating virtualenv in $VENV"
    python3 -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "[start] Installing dependencies from requirements.txt"
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet -r "$ROOT/requirements.txt"

echo "[start] Launching app on http://${HOST:-127.0.0.1}:$PORT"
cd "$ROOT/log-generator"
if [ -n "$HOST" ]; then
    exec python3 app.py --port "$PORT" --host "$HOST"
fi
exec python3 app.py --port "$PORT"
