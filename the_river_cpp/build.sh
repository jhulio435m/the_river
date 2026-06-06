#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ">>> COMPILANDO THE RIVER SUITE (LINUX)..."

check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 no está instalado."
        exit 1
    fi
}

check_lib() {
    if ! pkg-config --exists "$1"; then
        echo "Advertencia: pkg-config no encuentra $1. Se intentarán flags por defecto."
    fi
}

check_dependency "pkg-config"
check_lib "glfw3"
check_lib "openssl"
check_lib "gl"

CC_BIN="${CC:-gcc}"
CXX_BIN="${CXX:-g++}"

check_dependency "$CC_BIN"
check_dependency "$CXX_BIN"

COMMON_SRC="src/common/security_utils.cpp src/common/secure_envelope.cpp src/common/shared_config.cpp src/common/net_transport.cpp src/common/tor_connection.cpp src/common/base64.cpp"
SERVER_SRC="src/server/user_repository.cpp src/server/chat_server.cpp server.cpp"
ADMIN_SRC="admin_console.cpp"
RUNTIME_SRC="src/client/platform_runtime.cpp"
IMGUI_SRC="imgui_src/imgui.cpp imgui_src/imgui_draw.cpp imgui_src/imgui_tables.cpp imgui_src/imgui_widgets.cpp imgui_src/backends/imgui_impl_glfw.cpp imgui_src/backends/imgui_impl_opengl3.cpp"
PKG_CFLAGS="$(pkg-config --cflags glfw3 2>/dev/null || true)"
GLFW_LIBS="$(pkg-config --libs glfw3 2>/dev/null || echo -lglfw)"
OPENGL_LIBS="$(pkg-config --libs gl 2>/dev/null || echo -lGL)"
OPENSSL_LIBS="$(pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)"
INCLUDES="-I./include -I. -I./imgui_src -I./imgui_src/backends ${PKG_CFLAGS}"

if [[ -n "${TERMUX_VERSION:-}" || "${PREFIX:-}" == *"com.termux"* ]]; then
    echo ">>> ENTORNO DETECTADO: TERMUX"
    CLIENT_PLATFORM_SRC="src/client/ui_termux.cpp src/client/file_picker_termux.cpp src/client/platform_open_termux.cpp"
else
    echo ">>> ENTORNO DETECTADO: LINUX DESKTOP"
    CLIENT_PLATFORM_SRC="src/client/ui_glfw.cpp src/client/file_picker_linux.cpp"
fi

CLIENT_SRC="$CLIENT_PLATFORM_SRC src/client/app_ui.cpp src/client/chat_state.cpp src/client/chat_client.cpp src/client/command_processor.cpp src/client/ui_sections.cpp src/client/attachment_utils.cpp src/client/image_preview_linux.cpp $RUNTIME_SRC"

echo ">>> COMPILANDO SQLITE..."
"$CC_BIN" -O2 -c sqlite3.c -o sqlite3.o

echo ">>> COMPILANDO SERVIDOR..."
"$CXX_BIN" -std=c++17 -O2 -o the_river_server $SERVER_SRC $COMMON_SRC sqlite3.o -lpthread -ldl $OPENSSL_LIBS $INCLUDES

echo ">>> COMPILANDO CONSOLA ADMIN..."
"$CXX_BIN" -std=c++17 -O2 -o the_river_admin $ADMIN_SRC $COMMON_SRC -lpthread $OPENSSL_LIBS $INCLUDES

echo ">>> COMPILANDO CLIENTE GUI..."
# Nota desktop: requiere libglfw3-dev y zenity/kdialog o compatibles.
# Nota Termux: requiere glfw, Termux:X11 y termux-api para picker/apertura nativos.
"$CXX_BIN" -std=c++17 -O2 -o the_river_client $CLIENT_SRC $COMMON_SRC $IMGUI_SRC $GLFW_LIBS $OPENGL_LIBS -lpthread -ldl $OPENSSL_LIBS $INCLUDES

echo ">>> PROCESO FINALIZADO."
