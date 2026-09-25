#!/bin/sh
# RemoteDev - lanceur Linux/macOS. Usage identique à remotedev.cmd.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "[remotedev] Première utilisation : création de l'environnement Python..."
  python3 -m venv "$ROOT/.venv" && "$PY" -m pip install -q -r "$ROOT/requirements.txt" || exit 1
fi
[ -f "$ROOT/config/hosts.yaml" ] || { echo "[remotedev] config/hosts.yaml manquant : copier config/hosts.example.yaml"; exit 1; }
action=${1:-ui}
[ $# -gt 0 ] && shift
case "$action" in
  ui)     exec "$PY" "$ROOT/server.py" --ui ;;
  http)   exec "$PY" "$ROOT/server.py" --http "$@" ;;
  status) exec "$PY" "$ROOT/server.py" --status ;;
  stop)   exec "$PY" "$ROOT/server.py" --stop "$@" ;;
  check)  exec "$PY" "$ROOT/server.py" --check ;;
  stdio)  exec "$PY" "$ROOT/server.py" ;;
  *) echo "Usage : remotedev.sh [ui | http [--minutes N] [--allow-dev] [--no-tunnel] | status | stop | check | stdio]"; exit 2 ;;
esac
