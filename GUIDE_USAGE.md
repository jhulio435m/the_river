# Guía de Uso y Configuración - The River

Para que el cliente pueda conectarse al servidor seguro, solo hace falta configurar la dirección del nodo Onion. Desde el protocolo 2 el cliente **no** usa `THE_RIVER_AES_KEY` (esa clave es solo del servidor); si alguien te la pide para conectarte, desconfía.

## 🔑 1. Configuración de la dirección Onion

Dentro de la carpeta donde extrajiste el cliente, debes crear una estructura de carpetas y un archivo de configuración:

1. Crea una carpeta llamada `tor_data`.
2. Dentro de esa carpeta, crea un archivo llamado `runtime.env`.
3. Abre el archivo con un editor de texto y pega el siguiente contenido (ajustado a tu servidor):

```env
# Dirección .onion del servidor (te la da el administrador)
THE_RIVER_ONION=<tu-direccion>.onion
```

Opcional: `THE_RIVER_CLIENT_LOG=1` (como variable de entorno) activa un log local de diagnóstico, `client_runtime.log`, que nunca contiene mensajes, credenciales ni claves.

---

## 🖥️ 2. Ejecución del Cliente

Una vez configurado el archivo `runtime.env`:

*   **En Windows**: Ejecuta `the_river_client.exe`.
*   **En Linux**: Ejecuta `./the_river_client`.

**Nota**: La primera conexión puede tardar hasta **2 minutos** mientras Tor establece el circuito seguro. Si la barra de estado indica "Conectando...", por favor espera.

En el primer acceso entras con el usuario y la clave inicial que te dio el administrador; el cliente te pide un nombre y una clave nueva (mínimo 12 caracteres). La clave nueva nunca viaja por la red: el cliente envía solo un verificador SCRAM.

### Comandos del cliente
*   `/msg <usuario> <texto>` (o `/pm`, `/w`): mensaje privado cifrado de extremo a extremo (E2E). Si el destinatario está desconectado, el servidor lo guarda cifrado y se lo entrega en su próximo inicio de sesión (máx. 7 días).
*   `/r <texto>`: responde al último mensaje privado.
*   `/fingerprint` muestra tu huella; `/fingerprint <usuario>` la de otro. Compárala con esa persona por otro canal (en persona, llamada...).
*   `/users`, `/ping`, `/clear`, `/logout`, `/help`.

Al entrar recibes el historial reciente de la sala (últimos 100 mensajes), marcado como historial y sin notificación.

### Archivos locales (haz copia de seguridad)
El cliente guarda en su carpeta de trabajo:
*   `river_identity_<usuario>.key`: tu clave de identidad E2E, cifrada con tu contraseña. **Guárdala**: si la pierdes se genera una nueva y tus contactos verán `[!] La clave de <usuario> cambio (huella ...). Verificala por otro canal.`
*   `river_known_keys.txt`: huellas de tus contactos fijadas la primera vez (TOFU). Si ves el aviso de cambio de clave de alguien sin motivo, verifica su huella antes de seguir.
*   `river_client.cfg`: preferencias de la interfaz.
*   `.the_river_machine_id`: el HWID de este equipo (si lo borras, el servidor ve otra máquina).

---

## ⚡ 3. Consola de Administración (Admin)

Si eres el administrador del servidor, puedes gestionar usuarios usando la consola `the_river_admin`.

La consola de administración habla el protocolo 2 y solo necesita `THE_RIVER_ONION`. No envía ni lee mensajes privados E2E (no tiene clave de identidad): úsala para gestión, y el cliente gráfico para conversar.

### Comandos Disponibles:
*   `/users`: Lista todos los usuarios conectados actualmente.
*   `/newuser`: Genera un nuevo usuario (ej. `user1`, `user2`) con una contraseña inicial aleatoria de un solo uso, distinta para cada cuenta. Solo se muestra en la respuesta al admin y no se vuelve a mostrar: entrégala al invitado por un canal privado (si se pierde, usa `/passwd`).
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
*   Nunca compartas el archivo `runtime.env` ni tu `river_identity_<usuario>.key` públicamente.
*   Verifica las huellas (`/fingerprint`) de tus contactos por otro canal.
*   Cambia la contraseña de administrador después del primer inicio.
*   Usa contraseñas de al menos 12 caracteres.
