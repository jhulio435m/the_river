#!/bin/bash
echo ">>> COMPILANDO THE RIVER SUITE (CON SQLITE3)..."

# Directorios de interés
IMGUI_DIR="imgui_src"
# Quitamos src/aes.cpp de SOURCES porque ya lo incluimos explícitamente después para evitar duplicados
SOURCES="main.cpp $IMGUI_DIR/imgui*.cpp $IMGUI_DIR/backends/imgui_impl_glfw.cpp $IMGUI_DIR/backends/imgui_impl_opengl3.cpp"
LIBS="-lGL -lglfw -lGLEW -lpthread -ldl"

# Compilar Cliente
echo ">>> COMPILANDO CLIENTE..."
g++ -O2 -o the_river_linux $SOURCES src/aes.cpp $LIBS -I$IMGUI_DIR -I$IMGUI_DIR/backends -I./include

# Compilar Servidor (Incluyendo sqlite3.c)
echo ">>> COMPILANDO SERVIDOR CON DB SEGURA..."
gcc -O2 -c sqlite3.c -o sqlite3.o
g++ -O2 -o the_river_server server.cpp src/aes.cpp sqlite3.o -lpthread -ldl -I./include -I.

# Compilar Consola Admin
echo ">>> COMPILANDO CONSOLA ADMIN..."
g++ -O2 -o the_river_admin admin_console.cpp src/aes.cpp -lpthread -I./include

echo ">>> PROCESO FINALIZADO."
