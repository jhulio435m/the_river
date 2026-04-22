#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

echo ">>> Habilitando repositorio grafico de Termux..."
pkg install -y x11-repo

echo ">>> Actualizando indices..."
pkg update -y

echo ">>> Instalando toolchain y runtime base..."
pkg install -y clang pkg-config make git glfw mesa mesa-dev libglvnd-dev dbus termux-api tor

echo ">>> Instalando companion package de Termux:X11..."
pkg install -y termux-x11-nightly

echo ">>> Preparando acceso a almacenamiento compartido..."
termux-setup-storage

echo
echo "Dependencias instaladas."
echo "Siguiente paso:"
echo "  1. Instala la app Android de Termux:X11 desde el release nightly oficial."
echo "  2. Ejecuta scripts/start_termux_x11.sh"
echo "  3. Ejecuta scripts/run_termux_client.sh --rebuild"
