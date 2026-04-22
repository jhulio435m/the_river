#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

START_TOR=0
REBUILD=0

for arg in "$@"; do
  case "$arg" in
    --start-tor) START_TOR=1 ;;
    --rebuild) REBUILD=1 ;;
    *)
      echo "Uso: $0 [--rebuild] [--start-tor]"
      exit 1
      ;;
  esac
done

export DISPLAY="${DISPLAY:-:1}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$TMPDIR}"
export CXX="${CXX:-clang++}"
export CC="${CC:-clang}"

"${SCRIPT_DIR}/start_termux_x11.sh"

if [[ "$START_TOR" -eq 1 ]]; then
  if ! pgrep -x tor >/dev/null 2>&1; then
    echo ">>> Iniciando tor local en segundo plano..."
    mkdir -p "$HOME/.the_river/tor-data"
    nohup tor --SocksPort 9050 --DataDirectory "$HOME/.the_river/tor-data" >/dev/null 2>&1 &
    sleep 3
  else
    echo ">>> tor ya estaba en ejecucion."
  fi
else
  echo ">>> Tor no se arranca automaticamente. Usa --start-tor si quieres que este script lo levante."
fi

cd "$ROOT_DIR"
if [[ "$REBUILD" -eq 1 || ! -x "$ROOT_DIR/the_river_client" ]]; then
  echo ">>> Compilando cliente para Termux..."
  bash "$ROOT_DIR/build.sh"
fi

echo ">>> Ejecutando the_river_client en ${DISPLAY}..."
exec "$ROOT_DIR/the_river_client"
