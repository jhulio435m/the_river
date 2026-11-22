# The River privacy setup

The project intentionally keeps deployment secrets out of source code. Configure these variables in the local shell, service manager, or deployment secret store before starting the binaries.

Required for client and admin console (protocol v2: this is the only client setting; clients do **not** use `THE_RIVER_AES_KEY`):

```bash
export THE_RIVER_ONION="<tu-direccion>.onion"
```

Required for server bootstrap:

```bash
export THE_RIVER_AES_KEY="<clave-aleatoria-de-32+-caracteres>"   # server only, e.g. $(openssl rand -hex 32)
export THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD="replace-before-first-run"
```

`THE_RIVER_NEW_USER_PASSWORD` is no longer required. Without it (recommended) `/newuser` generates a random one-time initial password for each new account (16 characters, no look-alike characters) and shows it **only** in the reply to the admin who ran the command; it is never logged and cannot be shown again (use `/passwd <user> <key>` if it is lost). Hand each password to its invitee over a private channel. If you still set `THE_RIVER_NEW_USER_PASSWORD` (legacy mode), every new account shares that password, so any invitee could claim another pending account; the server logs a warning at startup.

Optional (server):

```bash
export THE_RIVER_ADMIN_USER="admin"
export THE_RIVER_DB="secure_river.db"
export THE_RIVER_LOG="chat_history.log"
export THE_RIVER_BIND_ADDR="127.0.0.1"
export THE_RIVER_PORT="8888"          # listen port (1-65535); point the hidden service's HiddenServicePort 80 at it
```

Optional (client / admin console):

```bash
export THE_RIVER_MACHINE_ID_FILE=".the_river_machine_id"
export THE_RIVER_TOR_PROXY_PORT="9050"   # local Tor SOCKS5 port; with a non-default port the client does not auto-start Tor
export THE_RIVER_CLIENT_LOG=1            # diagnostic client_runtime.log (no message contents, credentials or keys)
```

The client always connects to the onion service on port 80; `THE_RIVER_PORT` only changes where the server listens locally.

Client files (working directory of the client):

- `river_identity_<user>.key`: the user's X25519 identity key for end-to-end private messages and attachments, encrypted with the account password (0600). Back it up. If it is lost or cannot be decrypted, a new key is generated and published, and every peer sees `[!] La clave de <user> cambio (huella ...). Verificala por otro canal.`
- `river_known_keys.txt`: TOFU pins (`user fingerprint` per line) of peers' keys. Back it up too; without it the next key seen for each peer is trusted silently.
- `river_client.cfg`: UI preferences; safe to delete.
- `.the_river_machine_id`: the HWID reported to the server.

Verify keys out of band: `/fingerprint` prints your fingerprint, `/fingerprint <user>` a peer's.

Operational notes:

- Do not commit `CirculoServer/identidad/`; Tor must generate that hidden-service identity locally.
- Rotate the onion service if the previous `hs_ed25519_secret_key` was ever pushed or shared.
- Rotate `THE_RIVER_AES_KEY` if a build, guide or repo history ever included it (earlier guides in this repository did). Rotating it makes history sealed with the old key unreadable.
- `THE_RIVER_AES_KEY` is server-only and must be at least 32 characters long; shorter values are rejected by the server and the payload envelope. Never hand it to clients.
- Protocol v2 is not compatible with v1 clients. An existing v1 database is migrated automatically at server start (password hashes become SCRAM credentials; users keep their passwords).
- Treat `THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD` (and the per-account initial passwords from `/newuser`) as bootstrap values, not long-term user passwords; each invitee replaces theirs on first login.
- Clients generate a private `.the_river_machine_id` on first run instead of deriving identity from the hostname. Keep that file private; deleting it changes the HWID seen by the server.
- The chat history log stores a sealed audit entry with a payload SHA-256, not the message body itself.
