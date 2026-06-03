# The River

C++ chat suite with Tor transport, ImGui client, admin console, SQLite user store, and attachment support.

This repository is now scoped to the C++ implementation. The previous VB client/server artifacts and bundled Tor identity files were removed so the next repository can start clean.

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
