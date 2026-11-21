#!/bin/sh
# Sobe o backend do Sentinel (Node, o mesmo de sempre) e abre a TUI em Python.
# Não precisa de X/Wayland - roda inteiro no terminal. Ctrl+C encerra os dois juntos.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
cd "$ROOT"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js não encontrado. Instale com:"
  echo "  sudo apt install nodejs   (Debian/Ubuntu)"
  echo "  sudo dnf install nodejs   (Fedora)"
  echo "  sudo pacman -S nodejs     (Arch)"
  exit 1
fi

PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then PY=python; fi
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "Python 3 não encontrado. Instale com: sudo apt install python3 python3-venv"
  exit 1
fi

VENV="$DIR/.venv"
if [ ! -d "$VENV" ]; then
  echo "Primeira vez: criando ambiente Python isolado em $VENV ..."
  "$PY" -m venv "$VENV" || { echo "Falhou criar o venv. Tente: sudo apt install python3-venv"; exit 1; }
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet -r "$DIR/requirements.txt"
fi

PORT="${SENTINEL_PORT:-7777}"
export SENTINEL_PORT="$PORT"

node server.js &
SERVER_PID=$!

cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# espera o backend responder antes de abrir a TUI
for i in $(seq 1 30); do
  if command -v curl >/dev/null 2>&1 && curl -s -o /dev/null "http://127.0.0.1:$PORT/api/auth/state"; then break; fi
  sleep 0.3
done

echo "Backend em http://127.0.0.1:$PORT  (também acessível de outro dispositivo se você ligar o Acesso Remoto)"
SENTINEL_URL="http://127.0.0.1:$PORT" "$VENV/bin/python" "$DIR/sentinel_tui.py"
