# The River privacy setup

The project intentionally keeps deployment secrets out of source code. Configure these variables in the local shell, service manager, or deployment secret store before starting the binaries.

Required for client and admin console:

```bash
export THE_RIVER_ONION="your-hidden-service.onion"
export THE_RIVER_AES_KEY="32+ random chars shared by server and clients"
```

Required for server bootstrap:

```bash
export THE_RIVER_AES_KEY="32+ random chars shared by server and clients"
export THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD="replace-before-first-run"
export THE_RIVER_NEW_USER_PASSWORD="single-use-initial-password"
```

Optional:

```bash
export THE_RIVER_ADMIN_USER="admin"
export THE_RIVER_DB="secure_river.db"
export THE_RIVER_LOG="chat_history.log"
export THE_RIVER_MACHINE_ID_FILE=".the_river_machine_id"
```

Operational notes:

- Do not commit `CirculoServer/identidad/`; Tor must generate that hidden-service identity locally.
- Rotate the onion service if the previous `hs_ed25519_secret_key` was ever pushed or shared.
- Rotate `THE_RIVER_AES_KEY` if a build or repo history ever included the old shared key.
- `THE_RIVER_AES_KEY` must be at least 32 characters long; shorter values are rejected by the client, server, and payload envelope.
- Treat `THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD` and `THE_RIVER_NEW_USER_PASSWORD` as bootstrap values, not long-term user passwords.
- Clients generate a private `.the_river_machine_id` on first run instead of deriving identity from the hostname. Keep that file private; deleting it changes the HWID seen by the server.
- The chat history log stores a sealed audit entry with a payload SHA-256, not the message body itself.
