# Guía de Descarga - The River

Esta guía explica cómo obtener los binarios oficiales de **The River** para diferentes plataformas.

## 🚀 Obtener la última versión

Los binarios precompilados se encuentran en la sección de **Releases** de este repositorio:

👉 [**Descargar última versión aquí**](https://github.com/jhulio435m/the_river/releases/latest)

### Archivos Disponibles:

1.  **Windows (`the_river_client_windows.zip`)**:
    *   Contiene el cliente gráfico (`the_river_client.exe`) y el bundle de Tor necesario para Windows.
2.  **Linux (`the_river_client_linux.zip`)**:
    *   Contiene el cliente gráfico para Linux x86_64 y las librerías de Tor necesarias.

---

## 🛠️ Instalación por Plataforma

### Windows
1. Descarga `the_river_client_windows.zip`.
2. Descomprime el archivo en una carpeta de tu elección.
3. Sigue los pasos de la [Guía de Uso](GUIDE_USAGE.md) para configurar la dirección `.onion` (`THE_RIVER_ONION`) antes de abrir el programa. El cliente ya no necesita `THE_RIVER_AES_KEY`.

### Linux (Ubuntu, Debian, Arch, etc.)
1. Descarga `the_river_client_linux.zip`.
2. Extrae el contenido:
   ```bash
   unzip the_river_client_linux.zip -d the_river
   cd the_river
   ```
3. Otorga permisos de ejecución:
   ```bash
   chmod +x the_river_client tor_bin/tor
   ```
4. Sigue los pasos de la [Guía de Uso](GUIDE_USAGE.md) para configurar el entorno.

> **Protocolo 2:** las versiones actuales del cliente y del servidor hablan el protocolo 2 y no son compatibles con clientes antiguos (protocolo 1): el servidor los rechaza con `CLIENTE OBSOLETO`. Actualiza cliente y servidor a la vez.
>
> **Al actualizar o mover el cliente**, copia también `river_identity_<usuario>.key` y `river_known_keys.txt` de la carpeta anterior (y `river_client.cfg` si quieres conservar tus preferencias). Sin el archivo de identidad se genera una clave nueva y tus contactos verán un aviso de cambio de clave.

### Termux (Android)
Para usuarios de Android, se recomienda compilar directamente en el dispositivo usando los scripts incluidos en el repositorio:
1. Instala dependencias: `bash the_river_cpp/scripts/install_termux_dependencies.sh`
2. Compila: `bash the_river_cpp/scripts/build_client_termux.sh`
3. Ejecuta: `bash the_river_cpp/scripts/run_termux_client.sh`
