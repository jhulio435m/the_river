#!/usr/bin/env bash
set -euo pipefail

# Script para compilar SOLO el cliente en Linux Desktop
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo ">>> COMPILANDO CLIENTE THE RIVER (LINUX DESKTOP) <<<"

CXX_BIN="${CXX:-g++}"
CC_BIN="${CC:-gcc}"

COMMON_SRC="src/common/security_utils.cpp src/common/secure_envelope.cpp src/common/tor_connection.cpp src/common/base64.cpp"
RUNTIME_SRC="src/client/platform_runtime.cpp"
CLIENT_PLATFORM_SRC="src/client/ui_glfw.cpp src/client/file_picker_linux.cpp"
IMGUI_SRC="imgui_src/imgui.cpp imgui_src/imgui_draw.cpp imgui_src/imgui_tables.cpp imgui_src/imgui_widgets.cpp imgui_src/backends/imgui_impl_glfw.cpp imgui_src/backends/imgui_impl_opengl3.cpp"

CLIENT_SRC="$CLIENT_PLATFORM_SRC src/client/app_ui.cpp src/client/chat_state.cpp src/client/chat_client.cpp src/client/command_processor.cpp src/client/ui_sections.cpp src/client/attachment_utils.cpp src/client/image_preview_linux.cpp $RUNTIME_SRC"

PKG_CFLAGS="$(pkg-config --cflags glfw3 2>/dev/null || true)"
GLFW_LIBS="$(pkg-config --libs glfw3 2>/dev/null || echo -lglfw)"
OPENGL_LIBS="$(pkg-config --libs gl 2>/dev/null || echo -lGL)"
OPENSSL_LIBS="$(pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)"
INCLUDES="-I./include -I. -I./imgui_src -I./imgui_src/backends ${PKG_CFLAGS}"

if [ ! -f sqlite3.o ]; then
    echo ">>> Compilando sqlite3.o..."
    "$CC_BIN" -O2 -c sqlite3.c -o sqlite3.o
fi

echo ">>> Generando binario: the_river_client..."
"$CXX_BIN" -std=c++17 -O3 -o the_river_client $CLIENT_SRC $COMMON_SRC $IMGUI_SRC sqlite3.o $GLFW_LIBS $OPENGL_LIBS -lpthread -ldl $OPENSSL_LIBS $INCLUDES

echo ">>> OK: Cliente Linux compilado."
