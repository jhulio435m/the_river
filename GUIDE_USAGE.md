# Guía de Uso y Configuración - The River

Para que el cliente pueda conectarse al servidor seguro, es obligatorio configurar las llaves de encriptación y la dirección del nodo Onion.

## 🔑 1. Configuración de Llaves

Dentro de la carpeta donde extrajiste el cliente, debes crear una estructura de carpetas y un archivo de configuración:

1. Crea una carpeta llamada `tor_data`.
2. Dentro de esa carpeta, crea un archivo llamado `runtime.env`.
3. Abre el archivo con un editor de texto y pega el siguiente contenido (ajustado a tu servidor):

```env
# Llave maestra de encriptación (Debe ser la misma que el servidor)
THE_RIVER_AES_KEY=4183e31d65323b633c6f2f8669bcdd850eb42dab779c6265d30816385ec14c84

# Dirección .onion del servidor
THE_RIVER_ONION=3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion
```

---

## 🖥️ 2. Ejecución del Cliente

Una vez configurado el archivo `runtime.env`:

*   **En Windows**: Ejecuta `the_river_client.exe`.
*   **En Linux**: Ejecuta `./the_river_client`.

**Nota**: La primera conexión puede tardar hasta **2 minutos** mientras Tor establece el circuito seguro. Si la barra de estado indica "Conectando...", por favor espera.

---

## ⚡ 3. Consola de Administración (Admin)

Si eres el administrador del servidor, puedes gestionar usuarios usando la consola `the_river_admin`.

### Comandos Disponibles:
*   `/users`: Lista todos los usuarios conectados actualmente.
*   `/newuser`: Genera un nuevo usuario (ej. `user1`, `user2`) con la contraseña por defecto del servidor.
*   `/passwd <usuario> <nueva_contraseña>`: Cambia la contraseña de un usuario específico.
*   `/banhwid <hwid>`: Bloquea una máquina permanentemente.
*   `/kick <usuario>`: Desconecta a un usuario a la fuerza.

### Cómo ejecutarla en el servidor:
1. Conéctate por SSH a tu servidor.
2. Ve a la carpeta del proyecto: `cd the_river/the_river_cpp`
3. Ejecuta: `./the_river_admin`
4. Introduce tus credenciales de administrador.

---

## 🛡️ 4. Seguridad Recomendada
*   Nunca compartas el archivo `runtime.env` públicamente.
*   Cambia la contraseña de administrador después del primer inicio.
*   Usa contraseñas de al menos 12 caracteres.
