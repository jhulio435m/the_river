# Guía de Instalación Ultra-Rápida (Copia y Pega)

Usa estos bloques de comandos para configurar todo de una vez, desde la descarga hasta la creación de carpetas y archivos de configuración.

---

## 🐧 Linux (Terminal)

Copia y pega este bloque completo en tu terminal. Hará todo por ti:

```bash
# 1. Crear carpeta y descargar
mkdir -p ~/TheRiverChat && cd ~/TheRiverChat
wget -L https://github.com/jhulio435m/the_river/releases/download/v1.0.3/the_river_client_linux.zip

# 2. Extraer y preparar permisos
unzip -o the_river_client_linux.zip
chmod +x the_river_client tor_bin/tor

# 3. Crear carpetas de datos y configuración
mkdir -p tor_data
# Protocolo 2: el cliente solo necesita la direccion .onion (NO THE_RIVER_AES_KEY)
printf "THE_RIVER_ONION=<tu-direccion>.onion\n" > tor_data/runtime.env

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
Invoke-WebRequest -Uri "https://github.com/jhulio435m/the_river/releases/download/v1.0.3/the_river_client_windows.zip" -OutFile "client.zip"

# 3. Extraer archivos
Expand-Archive -Path "client.zip" -DestinationPath "." -Force

# 4. Crear carpeta de datos y configuración
New-Item -ItemType Directory -Force -Path "tor_data"
# Protocolo 2: el cliente solo necesita la direccion .onion (NO THE_RIVER_AES_KEY)
@'
THE_RIVER_ONION=<tu-direccion>.onion
'@ | Out-File -FilePath "tor_data\runtime.env" -Encoding ascii

# 5. Iniciar el cliente
.\the_river_client.exe
```

---

## 🔑 Credenciales de Acceso
Una vez que el programa abra y diga "CONECTADO" (puede tardar 60 segundos), entra con el usuario y la clave inicial que te dio el administrador del servidor (por un canal privado; nunca se publican en esta guía). En el primer acceso el cliente te pide elegir un nombre y una clave nueva de al menos 12 caracteres.

---

## 📁 Archivos locales del cliente
El cliente crea estos archivos junto al ejecutable (en la carpeta desde la que lo inicias). Haz copia de seguridad de los dos primeros:

*   `river_identity_<usuario>.key`: tu clave de identidad para los mensajes privados E2E (cifrada con tu contraseña). Si la pierdes, el cliente genera una nueva y tus contactos verán el aviso `[!] La clave de <usuario> cambio`.
*   `river_known_keys.txt`: las huellas de tus contactos fijadas la primera vez (TOFU). Sirve para detectar cambios de clave.
*   `river_client.cfg`: preferencias de la interfaz (se puede borrar sin problema).
*   `.the_river_machine_id`: el HWID de este equipo. Si lo borras, el servidor verá otra máquina.

Verifica las huellas con tus contactos por otro canal usando `/fingerprint` (la tuya) y `/fingerprint <usuario>` (la de otro).

---

## 🛠️ Solución de Problemas
*   **Si no conecta:** Verifica que tu internet funcione. Tor puede tardar un poco en encontrar la ruta al servidor la primera vez.
*   **Diagnóstico:** inicia el cliente con `THE_RIVER_CLIENT_LOG=1 ./the_river_client` para generar un log local de diagnóstico (no contiene mensajes ni claves).
*   **`Servidor incompatible (se requiere protocolo 2)` o `CLIENTE OBSOLETO`:** cliente y servidor deben ser de la misma versión (protocolo 2); descarga la última release.
*   **Error de librerías en Linux:** Asegúrate de tener instalados los paquetes básicos (`libglfw3`, `libssl`, `libgl1`).
