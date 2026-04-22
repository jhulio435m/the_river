#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

export DISPLAY="${DISPLAY:-:1}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$TMPDIR}"
mkdir -p "$XDG_RUNTIME_DIR"

if command -v am >/dev/null 2>&1; then
  am start --user 0 -n com.termux.x11/com.termux.x11.MainActivity >/dev/null 2>&1 || true
fi

if ! pgrep -f "termux-x11.*${DISPLAY}" >/dev/null 2>&1; then
  echo ">>> Iniciando companion server Termux:X11 en ${DISPLAY}..."
  nohup termux-x11 "${DISPLAY}" >/dev/null 2>&1 &
  sleep 2
else
  echo ">>> Termux:X11 ya estaba ejecutandose en ${DISPLAY}."
fi

echo "DISPLAY=${DISPLAY}"
echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR}"
