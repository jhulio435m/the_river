# Guía de Instalación Ultra-Rápida (Copia y Pega)

Usa estos bloques de comandos para configurar todo de una vez, desde la descarga hasta la creación de carpetas y archivos de configuración.

---

## 🐧 Linux (Terminal)

Copia y pega este bloque completo en tu terminal. Hará todo por ti:

```bash
# 1. Crear carpeta y descargar
mkdir -p ~/TheRiverChat && cd ~/TheRiverChat
wget https://github.com/jhulio435m/the_river/releases/download/v1.0.2/the_river_client_linux.zip

# 2. Extraer y preparar permisos
unzip -o the_river_client_linux.zip
chmod +x the_river_client tor_bin/tor

# 3. Crear carpetas de datos y configuración
mkdir -p tor_data
printf "THE_RIVER_AES_KEY=4183e31d65323b633c6f2f8669bcdd850eb42dab779c6265d30816385ec14c84\nTHE_RIVER_ONION=3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion\n" > tor_data/runtime.env

# 4. Iniciar el cliente
./the_river_client
```

---

## 🪟 Windows (PowerShell)

Abre PowerShell, copia y pega este bloque completo:

```powershell
# 1. Crear carpeta de trabajo
New-Item -ItemType Directory -Force -Path "$HOME\TheRiverChat"
cd "$HOME\TheRiverChat"

# 2. Descargar el cliente
Invoke-WebRequest -Uri "https://github.com/jhulio435m/the_river/releases/download/v1.0.2/the_river_client_windows.zip" -OutFile "client.zip"

# 3. Extraer archivos
Expand-Archive -Path "client.zip" -DestinationPath "." -Force

# 4. Crear carpeta de datos y configuración
New-Item -ItemType Directory -Force -Path "tor_data"
@'
THE_RIVER_AES_KEY=4183e31d65323b633c6f2f8669bcdd850eb42dab779c6265d30816385ec14c84
THE_RIVER_ONION=3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion
'@ | Out-File -FilePath "tor_data\runtime.env" -Encoding ascii

# 5. Iniciar el cliente
.\the_river_client.exe
```

---

## 🔑 Credenciales de Acceso
Una vez que el programa abra y diga "CONECTADO" (puede tardar 60 segundos), usa estos datos:

*   **Usuario:** `jhulio`
*   **Contraseña:** `176132`

---

## 🛠️ Solución de Problemas
*   **Si no conecta:** Verifica que tu internet funcione. Tor puede tardar un poco en encontrar la ruta al servidor la primera vez.
*   **Error de librerías en Linux:** Asegúrate de tener instalados los paquetes básicos (`libglfw3`, `libssl`, `libgl1`).
