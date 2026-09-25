#!/bin/sh
# RemoteDev - lanceur Linux/macOS (mini PC dédié compris). Usage identique à remotedev.cmd.
#   ./remotedev.sh           tableau de bord (fenêtre si écran, mode texte sinon / via SSH)
#   ./remotedev.sh stdio     serveur MCP stdio (ex. lancé par Claude Desktop via ssh)
# Les messages vont sur stderr : en mode stdio, stdout est réservé au protocole MCP.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PY="$ROOT/.venv/bin/python"
CONFIG_DIR=${REMOTEDEV_CONFIG_DIR:-$ROOT/config}
# Le marqueur n'est écrit qu'après une installation réussie : un venv à moitié créé
# (pip interrompu, réseau coupé) est réparé au lancement suivant au lieu d'être ignoré.
if [ ! -f "$ROOT/.venv/.remotedev-ok" ]; then
  echo "[remotedev] Installation de l'environnement Python..." >&2
  { [ -x "$PY" ] || python3 -m venv "$ROOT/.venv"; } >&2 \
    && "$PY" -m pip install -q -r "$ROOT/requirements.txt" >&2 \
    && touch "$ROOT/.venv/.remotedev-ok" \
    || { echo "[remotedev] échec de l'installation (python3-venv installé ? réseau ?)" >&2; exit 1; }
fi
[ -f "$CONFIG_DIR/hosts.yaml" ] || { echo "[remotedev] $CONFIG_DIR/hosts.yaml manquant : copier config/hosts.example.yaml" >&2; exit 1; }
action=${1:-ui}
[ $# -gt 0 ] && shift
case "$action" in
  ui)     exec "$PY" "$ROOT/server.py" --ui ;;
  tui)    exec "$PY" "$ROOT/server.py" --tui ;;
  http)   exec "$PY" "$ROOT/server.py" --http "$@" ;;
  status) exec "$PY" "$ROOT/server.py" --status ;;
  stop)   exec "$PY" "$ROOT/server.py" --stop "$@" ;;
  check)  exec "$PY" "$ROOT/server.py" --check ;;
  stdio)  exec "$PY" "$ROOT/server.py" ;;
  *) echo "Usage : remotedev.sh [ui | tui | http [--minutes N] [--allow-dev] [--no-tunnel] | status | stop | check | stdio]" >&2; exit 2 ;;
esac
