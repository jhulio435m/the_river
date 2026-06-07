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
3. Sigue los pasos de la [Guía de Uso](GUIDE_USAGE.md) para configurar las llaves de acceso antes de abrir el programa.

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

### Termux (Android)
Para usuarios de Android, se recomienda compilar directamente en el dispositivo usando los scripts incluidos en el repositorio:
1. Instala dependencias: `bash the_river_cpp/scripts/install_termux_dependencies.sh`
2. Compila: `bash the_river_cpp/scripts/build_client_termux.sh`
3. Ejecuta: `bash the_river_cpp/scripts/run_termux_client.sh`
