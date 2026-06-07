# Guía de Instalación Rápida (Solo Consola)

Sigue estos pasos para descargar, configurar y ejecutar el cliente de **The River** usando únicamente la terminal.

## 🐧 Linux (x86_64)

### 1. Descargar y Extraer
Copia y pega este bloque en tu terminal para descargar la última versión y preparar las carpetas:

```bash
# Descargar el paquete desde GitHub
wget https://github.com/jhulio435m/the_river/releases/download/v1.0.2/the_river_client_linux.zip

# Extraer y entrar a la carpeta
unzip the_river_client_linux.zip -d the_river_client
cd the_river_client

# Dar permisos de ejecución
chmod +x the_river_client tor_bin/tor
```

### 2. Configurar Conexión
Ejecuta este comando para crear el archivo de configuración con las llaves del servidor:

```bash
mkdir -p tor_data
cat <<EOF > tor_data/runtime.env
THE_RIVER_AES_KEY=4183e31d65323b633c6f2f8669bcdd850eb42dab779c6265d30816385ec14c84
THE_RIVER_ONION=3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion
EOF
```

### 3. Ejecutar
```bash
./the_river_client
```

---

## 🪟 Windows (PowerShell)

### 1. Descargar y Extraer
Abre PowerShell y ejecuta estos comandos:

```powershell
# Descargar el zip
Invoke-WebRequest -Uri "https://github.com/jhulio435m/the_river/releases/download/v1.0.2/the_river_client_windows.zip" -OutFile "client.zip"

# Extraer el contenido
Expand-Archive -Path "client.zip" -DestinationPath "TheRiver"
cd TheRiver
```

### 2. Configurar Conexión
Crea el archivo de llaves necesario:

```powershell
New-Item -ItemType Directory -Force -Path "tor_data"
@'
THE_RIVER_AES_KEY=4183e31d65323b633c6f2f8669bcdd850eb42dab779c6265d30816385ec14c84
THE_RIVER_ONION=3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion
'@ | Out-File -FilePath "tor_data\runtime.env" -Encoding ascii
```

### 3. Ejecutar
```powershell
.\the_river_client.exe
```

---

## 💡 Notas Importantes
- **Tiempo de espera:** La primera vez que abras el programa, tardará unos **60-90 segundos** en conectar a Tor. No lo cierres, espera a que la interfaz muestre el estado de conexión.
- **Login:** Usa tu usuario (`jhulio`) y contraseña para entrar.
