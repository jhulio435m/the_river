# The River

C++ chat suite with Tor transport, ImGui client, admin console, SQLite user store, and attachment support.

This repository is now scoped to the C++ implementation. The previous VB client/server artifacts and bundled Tor identity files were removed so the next repository can start clean.

Current builds use a binary frame transport between client, admin console, and server. Older line-delimited clients are not protocol-compatible. Attachment payloads are streamed as encrypted binary chunks instead of base64 text messages.

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

## Privacy

Before running anything, configure the private values documented in `the_river_cpp/PRIVACY_SETUP.md`. The code no longer ships with a hardcoded onion address, shared encryption key, admin bootstrap password, or default user password.

## Commands

### Client (GUI)

| Command | Description |
| --- | --- |
| `/help` | List local commands. |
| `/msg <user> <text>` (`/pm`, `/w`) | Send an encrypted private message. |
| `/r <text>` | Reply to the last private conversation. |
| `/users` (`/who`) | List active nodes. |
| `/ping` | Measure round-trip latency to the server. |
| `/clear` | Clear the local feed. |
| `/logout` | Close the session and return to the login screen. |
| `/adminhelp` | (Admins) Ask the server for the admin command list. |

Composer shortcuts: `Up`/`Down` recall previously sent lines, `Tab` completes nicknames, and right-clicking a user in the node list offers *Private message* / *Copy name*.

After a dropped link the client re-authenticates automatically with the credentials of the current session (kept only in memory). It does not do so after a kick, ban, `/logout` or when the same identity signs in from another connection.

### Admin (server-side)

`/newuser`, `/passwd <user> <key>`, `/users`, `/accounts`, `/whois <user>`, `/kick <user> [reason]`, `/banhwid <hwid> [reason]`, `/banuser <user> [reason]`, `/unbanhwid <hwid>`, `/bans`, `/resethwid <user>`, `/deluser <user>`, `/announce <text>`. The admin console also supports `/msg <user> <text>`.
