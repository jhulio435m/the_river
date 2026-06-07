#!/usr/bin/env bash
set -euo pipefail

# Script para compilar SOLO el cliente para Windows
# Por defecto intenta usar cross-compiler de Linux (mingw-w64)
# Si estas en Windows con MSYS2, cambia CXX a g++

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo ">>> COMPILANDO CLIENTE THE RIVER (WINDOWS EXE) <<<"

# Detectar compilador de cross-compilation o local
if command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
    CXX_BIN="x86_64-w64-mingw32-g++"
    CC_BIN="x86_64-w64-mingw32-gcc"
else
    CXX_BIN="g++"
    CC_BIN="gcc"
fi

COMMON_SRC="src/common/security_utils.cpp src/common/secure_envelope.cpp src/common/tor_connection.cpp src/common/base64.cpp src/common/shared_config.cpp src/common/net_transport.cpp"
RUNTIME_SRC="src/client/platform_runtime.cpp"
CLIENT_PLATFORM_SRC="src/client/ui_win32.cpp src/client/file_picker_win32.cpp"
IMGUI_SRC="imgui_src/imgui.cpp imgui_src/imgui_draw.cpp imgui_src/imgui_tables.cpp imgui_src/imgui_widgets.cpp imgui_src/backends/imgui_impl_win32.cpp imgui_src/backends/imgui_impl_opengl3.cpp"

CLIENT_SRC="$CLIENT_PLATFORM_SRC src/client/app_ui.cpp src/client/chat_state.cpp src/client/chat_client.cpp src/client/command_processor.cpp src/client/ui_sections.cpp src/client/attachment_utils.cpp src/client/image_preview_win32.cpp $RUNTIME_SRC"

# En Windows/MinGW solemos vincular estaticamente para portabilidad
LIBS="-lglfw3 -lgdi32 -lopengl32 -limm32 -lcomdlg32 -lole32 -lssl -lcrypto -lws2_32 -lurlmon -lcrypt32 -ldwmapi -lgdiplus -lpthread"
INCLUDES="-I./include -I. -I./imgui_src -I./imgui_src/backends"

if [ ! -f sqlite3_win.o ]; then
    echo ">>> Compilando sqlite3_win.o..."
    "$CC_BIN" -O2 -c sqlite3.c -o sqlite3_win.o
fi

echo ">>> Generando ejecutable: the_river_client.exe..."
"$CXX_BIN" -std=c++17 -O3 -o the_river_client.exe $CLIENT_SRC $COMMON_SRC $IMGUI_SRC sqlite3_win.o $LIBS $INCLUDES -static

echo ">>> OK: Cliente Windows (the_river_client.exe) generado."
