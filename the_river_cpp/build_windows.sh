#!/bin/bash
echo ">>> COMPILANDO SUITE PARA WINDOWS (USANDO MINGW)..."

# Compilar Servidor para Windows
echo ">>> COMPILANDO SERVIDOR (.EXE)..."
i686-w64-mingw32-gcc -O2 -c sqlite3.c -o sqlite3_win.o
i686-w64-mingw32-g++ -O2 -o the_river_server.exe server.cpp src/aes.cpp sqlite3_win.o -lws2_32 -static-libgcc -static-libstdc++ -I./include -I.

if [ $? -eq 0 ]; then
    echo ">>> SERVIDOR WINDOWS LISTO: the_river_server.exe"
else
    echo ">>> ERROR COMPILANDO SERVIDOR WINDOWS."
fi

# Compilar Consola Admin para Windows
echo ">>> COMPILANDO CONSOLA ADMIN (.EXE)..."
i686-w64-mingw32-g++ -O2 -o the_river_admin.exe admin_console.cpp src/aes.cpp -lws2_32 -static-libgcc -static-libstdc++ -I./include

if [ $? -eq 0 ]; then
    echo ">>> CONSOLA ADMIN WINDOWS LISTO: the_river_admin.exe"
else
    echo ">>> ERROR COMPILANDO CONSOLA ADMIN WINDOWS."
fi

echo ">>> PROCESO FINALIZADO."
