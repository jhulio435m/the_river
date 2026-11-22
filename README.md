# The River

C++ chat suite with Tor transport, ImGui client, admin console, SQLite user store, and attachment support.

This repository is now scoped to the C++ implementation. The previous VB client/server artifacts and bundled Tor identity files were removed so the next repository can start clean.

Current builds speak **protocol v2** (`the_river_cpp/docs/PROTOCOL_V2.md`): SCRAM-SHA-256 login with mutual authentication, end-to-end encrypted private messages and attachments, room history and offline private messages. Protocol v2 is **not compatible with v1 clients**: the server answers them with `CLIENTE OBSOLETO` and closes the connection, so update clients, admin console and server together. An existing server database is migrated automatically on first start (v1 password hashes become SCRAM credentials; users keep their passwords).

## Layout

- `the_river_cpp/src/client/`: GUI client, chat state, attachments, and platform adapters.
- `the_river_cpp/src/server/`: chat server and user repository.
- `the_river_cpp/src/common/`: shared runtime config, Tor connection, base64, and security helpers.
- `the_river_cpp/include/`: public headers for the C++ components.
- `the_river_cpp/scripts/`: platform helper scripts.
- `the_river_cpp/PRIVACY_SETUP.md`: required private environment variables.

## Build

```bash
cd the_river_cpp
./build.sh
```

The build produces:

- `the_river_server`
- `the_river_client`
- `the_river_admin`

Generated binaries, databases, logs, and Tor runtime identity data are ignored by Git.

Tests (`ctest`) include unit, crypto and integration tests plus two end-to-end tests: `river_e2e_server_tests` (drives the real server binary over TCP) and `river_e2e_client_tests` (runs the real client through a local SOCKS5 shim against scripted fake servers and the real server). They need neither Tor nor a display:

```bash
cmake -S the_river_cpp -B build && cmake --build build -j && ctest --test-dir build --output-on-failure
```

## Privacy

Before running anything, configure the private values documented in `the_river_cpp/PRIVACY_SETUP.md`. The code no longer ships with a hardcoded onion address, shared encryption key, admin bootstrap password, or default user password.

- **Clients (GUI and admin console) only need `THE_RIVER_ONION`.** They do not use `THE_RIVER_AES_KEY`; that key is server-only (at-rest encryption of history and logs). Nobody should ask you for it to connect.
- Optional client settings: `THE_RIVER_CLIENT_LOG=1` writes a diagnostic `client_runtime.log` (never message contents or credentials); `THE_RIVER_TOR_PROXY_PORT` changes the local Tor SOCKS port (default 9050).
- The client keeps these files in its working directory: `river_identity_<user>.key` (your E2E identity key, encrypted with your password), `river_known_keys.txt` (pinned peer fingerprints), `river_client.cfg` (UI preferences) and `.the_river_machine_id` (HWID). **Back up the identity and known-keys files**: if the identity file is lost a new key is generated and your peers see a key-change warning.
- Verify peers' keys out of band with `/fingerprint` (yours) and `/fingerprint <user>`.

## Security model

- **Room messages** are readable by the server (it stores the recent history, sealed at rest with `THE_RIVER_AES_KEY`). In transit they are protected by the Tor onion circuit between client and hidden service.
- **Private messages and attachment contents** are end-to-end encrypted (X25519 + HKDF + AES-256-GCM, `RE2` envelopes). The server only relays or queues envelopes it cannot open. Attachment *offers* (file name, MIME type, size) are room broadcasts and are visible to the server and everyone in the room.
- **Metadata is visible to the server**: who is online, who sends a PM or attachment to whom, message sizes and timing, HWIDs, and the public keys and fingerprints of every user.
- **Passwords never reach the server**: login is a SCRAM proof and the first-login change sends only a verifier; the server checks its own signature to the client, so a fake server cannot complete a login. The database stores no password-equivalent.
- **HWID is client-reported** (`.the_river_machine_id` or `THE_RIVER_MACHINE_ID`) and can be spoofed; HWID binding and bans are a speed bump, not an identity guarantee.
- **Key trust is TOFU**: the first key seen for a user is pinned in `river_known_keys.txt`. A later change shows `[!] La clave de <user> cambio (huella ...)` but messages still flow. A malicious server could hand out a wrong key on first contact; only comparing `/fingerprint` over another channel rules that out.
- **No forward secrecy beyond the per-message ephemeral key on the sender side**: each envelope uses a fresh ephemeral key, but it is combined with the recipient's long-term key, so anyone who later obtains a recipient's identity key file and password can decrypt recorded envelopes sent to them.
- The admin console has no identity key: it cannot send or read E2E private messages.

## Commands

### Client (GUI)

| Command | Description |
| --- | --- |
| `/help` | List local commands. |
| `/msg <user> <text>` (`/pm`, `/w`) | Send an end-to-end encrypted private message. If the user is offline the server queues the envelope (up to 200 per user, 7 days) and delivers it at their next login. |
| `/r <text>` | Reply to the last private conversation. |
| `/fingerprint [user]` (`/fp`) | Show your key fingerprint, or `<user>`'s; compare it with them over another channel. |
| `/users` (`/who`) | List active nodes. |
| `/ping` | Measure round-trip latency to the server. |
| `/clear` | Clear the local feed. |
| `/logout` | Close the session and return to the login screen. |
| `/adminhelp` | (Admins) Ask the server for the admin command list. |

Composer shortcuts: `Up`/`Down` recall previously sent lines, `Tab` completes nicknames, and right-clicking a user in the node list offers *Private message* / *Copy name*.

After login the server replays the latest 100 room messages (marked as history, no new-message notification; no duplicates after a reconnect), then any queued private messages.

After a dropped link the client re-authenticates automatically with the credentials of the current session (kept only in memory). It does not do so after a kick, ban, `/logout` or when the same identity signs in from another connection.

### Admin (server-side)

`/newuser` (creates the next `userN` account with a random one-time initial password shown only to you; send it to the invitee privately), `/passwd <user> <key>`, `/users`, `/accounts`, `/whois <user>`, `/kick <user> [reason]`, `/banhwid <hwid> [reason]`, `/banuser <user> [reason]`, `/unbanhwid <hwid>`, `/bans`, `/resethwid <user>`, `/deluser <user>`, `/announce <text>`. `/whois` also shows the user's key fingerprint. The admin console (`the_river_admin`) speaks protocol v2 and needs only `THE_RIVER_ONION`; it has no identity key, so it cannot send or read end-to-end encrypted private messages (use the GUI client for that).
