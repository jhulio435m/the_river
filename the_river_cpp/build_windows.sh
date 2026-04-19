#!/bin/bash
set -e

echo ">>> COMPILANDO BACKEND WINDOWS (MINGW)..."

COMMON_SRC="src/common/security_utils.cpp src/common/tor_connection.cpp src/aes.cpp"
SERVER_SRC="src/server/user_repository.cpp src/server/chat_server.cpp server.cpp"
ADMIN_SRC="admin_console.cpp"
CLIENT_SRC="src/client/ui_win32.cpp src/client/app_ui.cpp src/client/chat_state.cpp src/client/chat_client.cpp src/client/command_processor.cpp"
IMGUI_SRC="imgui_src/imgui.cpp imgui_src/imgui_draw.cpp imgui_src/imgui_tables.cpp imgui_src/imgui_widgets.cpp imgui_src/backends/imgui_impl_win32.cpp imgui_src/backends/imgui_impl_opengl3.cpp"

echo ">>> COMPILANDO SQLITE..."
i686-w64-mingw32-gcc -O2 -c sqlite3.c -o sqlite3_win.o

echo ">>> COMPILANDO SERVIDOR (.EXE)..."
i686-w64-mingw32-g++ -std=c++17 -O2 -o the_river_server.exe $SERVER_SRC $COMMON_SRC sqlite3_win.o -lws2_32 -static-libgcc -static-libstdc++ -I./include -I.

echo ">>> COMPILANDO CONSOLA ADMIN (.EXE)..."
i686-w64-mingw32-g++ -std=c++17 -O2 -o the_river_admin.exe $ADMIN_SRC $COMMON_SRC -lws2_32 -static-libgcc -static-libstdc++ -I./include -I.

echo ">>> COMPILANDO CLIENTE GUI (.EXE)..."
i686-w64-mingw32-g++ -std=c++17 -O2 -o the_river_client.exe $CLIENT_SRC $COMMON_SRC $IMGUI_SRC -lopengl32 -lgdi32 -limm32 -ldwmapi -lws2_32 -static-libgcc -static-libstdc++ -I./include -I. -I./imgui_src -I./imgui_src/backends

echo ">>> PROCESO FINALIZADO."
