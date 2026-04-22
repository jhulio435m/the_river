# Plan De Compatibilidad Con Termux

## Objetivo

Integrar `the_river_cpp` en Termux de forma limpia, mantenible y funcional, sin degradar la arquitectura actual para Linux desktop y Windows.

La meta no es generar una APK nativa en esta fase. La meta es ejecutar el cliente como binario compilado para Termux y mostrar la interfaz por medio de `Termux:X11`.

## Alcance De Esta Integracion

- Soporte para ejecutar el cliente GUI en Termux usando `Termux:X11`
- Compatibilidad con entrada de texto, portapapeles y selección/copia
- Compatibilidad para adjuntar, abrir y guardar archivos
- Compatibilidad con imágenes y videos recibidos
- Flujo de conexión por Tor con mensajes claros de error
- Documentación y scripts de instalación/arranque para el usuario

## Lo Que No Es Esta Fase

- No es una APK nativa de Android
- No es una reescritura de la UI en Android SDK
- No es una bifurcación completa del cliente

## Estado Actual Del Proyecto

### Arquitectura

La arquitectura base del cliente ya es razonablemente escalable:

- `ui_win32.cpp`: bootstrap de Windows
- `ui_glfw.cpp`: bootstrap de Linux desktop
- `app_ui.cpp`: ensamblado principal de UI
- `ui_sections.cpp`: lógica de pantallas y secciones compartidas
- `chat_client.cpp`: red, autenticación, adjuntos
- `chat_state.cpp`: estado del cliente

El punto de entrada Linux no es monolítico. El mayor archivo compartido y futuro candidato a refactor es `ui_sections.cpp`.

### Bloqueos Actuales Para Termux

- El backend Linux asume escritorio clásico con GLFW + OpenGL + entorno X11 estable
- El selector de archivos Linux depende de herramientas de escritorio como `zenity`, `kdialog`, `xdg-open`, `gio`
- La búsqueda de fuentes asume rutas típicas de Linux desktop
- El arranque automático de Tor no está implementado para Linux
- La UI fue pensada principalmente para pantallas de escritorio

## Decisiones De Diseño

### 1. Termux Tendrá Backend Propio

No se mezclará toda la lógica dentro del backend Linux actual.

Se crearán componentes específicos para Termux:

- `src/client/ui_termux.cpp`
- `src/client/file_picker_termux.cpp`
- `src/client/platform_open_termux.cpp`

Y si conviene, abstracciones compartidas:

- `include/client/platform_runtime.h`
- `include/client/platform_file_picker.h`
- `include/client/platform_launcher.h`

### 2. La UI Compartida Se Mantiene

La lógica visual y funcional del chat seguirá viviendo en los módulos compartidos:

- `app_ui.cpp`
- `ui_sections.cpp`
- `chat_client.cpp`
- `chat_state.cpp`

Esto evita duplicación de lógica entre Windows, Linux desktop y Termux.

### 3. No Será APK Nativa En Esta Fase

La app se ejecutará así:

- binario compilado en Termux
- ventana mostrada con `Termux:X11`

Si en el futuro se quisiera una APK real de `the_river`, eso sería otra iniciativa técnica.

### 4. La Identidad Visual Se Conserva, El Layout Se Adapta

No se hará un rediseño visual.

Sí se hará adaptación de layout para pantallas más estrechas:

- misma identidad BBS
- misma paleta y atmósfera
- redistribución de paneles para móvil
- targets táctiles más grandes
- menos dependencia de hover y doble clic

## Requisitos Del Usuario En Termux

### Paquetes Y Apps

El usuario necesitará, como base:

- `Termux`
- `Termux:X11`
- `x11-repo`
- `termux-x11-nightly`
- librerías necesarias para GLFW/OpenGL/X11 dentro de Termux

Para experiencia completa:

- `termux-setup-storage`
- `Termux:API`
- paquete `termux-api`

Para Tor:

- `tor` en Termux, o un proxy Tor ya disponible en `127.0.0.1:9050`

## Estrategia Tecnica

## Fase 1. Refactor De Plataforma

Objetivo: separar Termux como plataforma propia.

Trabajo:

- Crear entrypoint `ui_termux.cpp`
- Crear backend de selector de archivos específico
- Crear backend de apertura de archivos específico
- Ajustar headers para seleccionar backend por plataforma

Resultado esperado:

- el código deja de tratar Termux como “Linux desktop raro”

## Fase 2. Build Y Arranque En Termux

Objetivo: compilar y abrir la ventana del cliente dentro de `Termux:X11`.

Trabajo:

- adaptar `build.sh`
- detectar entorno Termux
- usar rutas y flags adecuados para Termux
- agregar scripts de ejecución

Resultado esperado:

- el cliente abre y renderiza correctamente

## Fase 3. Entrada, Portapapeles Y Layout Compacto

Objetivo: que la app sea usable en móvil.

Trabajo:

- validar pegado/copia/selección en Termux:X11
- adaptar layout para pantallas estrechas
- aumentar tamaños interactivos cuando corresponda
- reducir dependencia de hover/doble clic

Resultado esperado:

- escribir, pegar, seleccionar y copiar funciona bien en Termux

## Fase 4. Archivos, Imágenes Y Adjuntos

Objetivo: integrar bien con el almacenamiento Android.

Trabajo:

- picker de archivo específico para Termux
- apertura con integración Android/Termux
- guardado y apertura de adjuntos
- compatibilidad de imágenes y videos

Resultado esperado:

- el usuario puede adjuntar, abrir y guardar sin depender de utilidades Linux de escritorio

## Fase 5. Tor

Objetivo: tener conectividad funcional y clara.

Trabajo inicial recomendado:

- no autolanzar Tor al principio
- validar `127.0.0.1:9050`
- mostrar mensajes claros si falta Tor

Trabajo posterior opcional:

- backend específico para arrancar/parar `tor` desde Termux

Resultado esperado:

- conexión confiable o errores diagnósticos claros

## Fase 6. Scripts Y Documentacion

Objetivo: que la instalación sea repetible para el usuario.

Trabajo:

- script de instalación de dependencias
- script de arranque de `Termux:X11`
- script de arranque del cliente
- guía de troubleshooting

Resultado esperado:

- proceso de instalación y ejecución documentado y replicable

## Estrategia De UI En Termux

### Principio

La UI no debe ser idéntica en distribución a desktop si el ancho disponible cambia mucho.

### Lo Que Se Conserva

- estilo visual BBS
- colores
- tipografía y tono general
- flujo funcional del chat

### Lo Que Se Adaptará

- panel lateral de usuarios podría pasar a panel colapsable o modal
- feed principal tendrá prioridad
- input y botones tendrán mejor área táctil
- previews y modales se dimensionarán para pantalla móvil

### Regla

Una sola UI compartida con dos disposiciones:

- `desktop`
- `compact/mobile`

No se crearán dos aplicaciones distintas.

## Riesgos Principales

- integración de picker de archivos con almacenamiento Android
- diferencias entre dispositivos y ROMs Android
- estabilidad de procesos de Termux/Tor en segundo plano
- variaciones de clipboard/comportamiento de `Termux:X11`

## Definicion De Integracion Completa

La compatibilidad con Termux se considerará completa cuando el usuario pueda:

- instalar dependencias con pasos documentados
- abrir el cliente en `Termux:X11`
- iniciar sesión
- escribir, pegar, seleccionar y copiar
- adjuntar archivos
- abrir imágenes y videos
- guardar adjuntos
- conectarse por Tor o recibir errores claros y accionables

## Recomendacion De Implementacion

Orden recomendado:

1. Refactor de plataforma
2. Build y arranque en Termux
3. Layout compacto y UX táctil
4. Archivos y adjuntos
5. Tor
6. Scripts y documentación final

## Criterio De Limpieza Arquitectonica

Para mantener el proyecto escalable:

- no saturar `ui_glfw.cpp` con ramas específicas de Termux
- no meter toda la lógica Termux dentro de `file_picker_linux.cpp`
- mantener la lógica de negocio y UI principal compartida
- encapsular diferencias de plataforma detrás de archivos o abstracciones específicas
