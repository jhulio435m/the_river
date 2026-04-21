#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ">>> COMPILANDO THE RIVER SUITE (LINUX)..."

COMMON_SRC="src/common/security_utils.cpp src/common/tor_connection.cpp src/common/base64.cpp src/aes.cpp"
SERVER_SRC="src/server/user_repository.cpp src/server/chat_server.cpp server.cpp"
ADMIN_SRC="admin_console.cpp"
CLIENT_SRC="src/client/ui_glfw.cpp src/client/app_ui.cpp src/client/chat_state.cpp src/client/chat_client.cpp src/client/command_processor.cpp src/client/ui_sections.cpp src/client/attachment_utils.cpp src/client/file_picker_linux.cpp src/client/image_preview_linux.cpp"
IMGUI_SRC="imgui_src/imgui.cpp imgui_src/imgui_draw.cpp imgui_src/imgui_tables.cpp imgui_src/imgui_widgets.cpp imgui_src/backends/imgui_impl_glfw.cpp imgui_src/backends/imgui_impl_opengl3.cpp"
INCLUDES="-I./include -I. -I./imgui_src -I./imgui_src/backends"

echo ">>> COMPILANDO SQLITE..."
gcc -O2 -c sqlite3.c -o sqlite3.o

echo ">>> COMPILANDO SERVIDOR..."
g++ -std=c++17 -O2 -o the_river_server $SERVER_SRC $COMMON_SRC sqlite3.o -lpthread -ldl $INCLUDES

echo ">>> COMPILANDO CONSOLA ADMIN..."
g++ -std=c++17 -O2 -o the_river_admin $ADMIN_SRC $COMMON_SRC -lpthread $INCLUDES

echo ">>> COMPILANDO CLIENTE GUI..."
# Nota: requiere libglfw3-dev y zenity o kdialog para los dialogs nativos.
g++ -std=c++17 -O2 -o the_river_client $CLIENT_SRC $COMMON_SRC $IMGUI_SRC -lglfw -lGL -lpthread -ldl $INCLUDES

echo ">>> PROCESO FINALIZADO."
