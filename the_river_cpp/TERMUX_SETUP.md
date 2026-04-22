# the_river_cpp En Termux

## Objetivo

Ejecutar el cliente GUI dentro de `Termux:X11`, con picker/apertura compatibles con Termux y layout compacto para pantallas estrechas.

## Requisitos

- `Termux`
- app Android `Termux:X11`
- paquete `termux-x11-nightly`
- `termux-api`
- `tor` si quieres levantar proxy local en `127.0.0.1:9050`

## Instalacion

Desde la raiz de `the_river_cpp`:

```bash
bash scripts/install_termux_dependencies.sh
```

Luego instala manualmente la app Android de `Termux:X11` desde su release nightly oficial.

## Arranque Rapido

```bash
bash scripts/run_termux_client.sh --rebuild --start-tor
```

Si prefieres manejar Tor por separado:

```bash
tor --SocksPort 9050 --DataDirectory "$HOME/.the_river/tor-data"
```

Y en otra sesion:

```bash
bash scripts/run_termux_client.sh --rebuild
```

## Flujo Esperado

1. `start_termux_x11.sh` exporta `DISPLAY=:1` y arranca el companion server.
2. `build.sh` detecta Termux y compila `ui_termux.cpp` + backends específicos.
3. `file_picker_termux.cpp` usa `termux-storage-get` para importar archivos.
4. `platform_open_termux.cpp` usa `termux-open` para abrir imágenes, videos y adjuntos.

## UX Compacta

- La lista de usuarios pasa a panel colapsable.
- Los adjuntos se abren con un solo tap/click en layout compacto.
- El header y footer se simplifican para no desperdiciar ancho.

## Tor

En Termux no se autolanza Tor desde el binario. Si el cliente no detecta proxy en `127.0.0.1:9050`, mostrará un error accionable.

## Troubleshooting

- Si el picker falla:
  confirma `termux-setup-storage` y que `termux-storage-get` exista.
- Si la ventana no aparece:
  relanza `bash scripts/start_termux_x11.sh` y verifica que la app Android `Termux:X11` esté instalada.
- Si no conecta por Tor:
  verifica que `tor` esté corriendo y escuchando en `127.0.0.1:9050`.
- Si `build.sh` no encuentra compilador:
  exporta `CC=clang` y `CXX=clang++`, o usa `bash scripts/run_termux_client.sh --rebuild`.

## Referencias

- Termux:X11 oficial: https://github.com/termux/termux-x11
- Termux packages oficial: https://github.com/termux/termux-packages
