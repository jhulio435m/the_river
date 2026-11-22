# The River — Protocol v2

Status: normative spec for the v2 rework. All components (server, GUI client,
admin console, tests) MUST follow it. v1 clients are rejected with a clear
message; there is no v1 compatibility mode (v1 login was pass-the-hash).

## 0. Goals

1. The server database never stores a password-equivalent secret (SCRAM).
2. No shared symmetric key on clients. `THE_RIVER_AES_KEY` becomes
   server-only (at-rest encryption of logs/history). Removing or banning a user
   revokes their access immediately.
3. Private messages and attachment payloads are end-to-end encrypted between
   users (server cannot read them). Room messages are protected in transit by
   the Tor onion circuit (end-to-end client<->hidden service) and are readable
   by the server by design.
4. Room history and offline private messages.
5. Explicit protocol version.

Framing is unchanged (TRV1 frames, `net_platform.h`). Text frames carry the
lines below. `b64` = standard base64 (`common/base64.h`). Fields are separated
by `:`; any field that can contain arbitrary bytes is b64.

## 1. Crypto primitives (module `common/e2e_crypto.h`, `common/scram.h`)

All built on OpenSSL 3 EVP APIs.

### 1.1 SCRAM-SHA-256 style credentials (`river::scram`)

- `SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iter, 32)`
  (identical to the v1 `pbkdf2-sha256$iter$saltHex$hashHex` digest, so v1
  hashes migrate without user action).
- `ClientKey = HMAC(SaltedPassword, "Client Key")`
- `StoredKey = SHA256(ClientKey)`
- `ServerKey = HMAC(SaltedPassword, "Server Key")`
- Stored credential string:
  `scram-sha256$<iter>$<saltHex>$<storedKeyHex>$<serverKeyHex>`
- `AuthMessage = "river-auth-v2|" + user + "|" + hwid + "|" + clientNonce + "|" + combinedNonce + "|" + saltHex + "|" + iter`
- `ClientSignature = HMAC(StoredKey, AuthMessage)`
- `ClientProof = ClientKey XOR ClientSignature` (32 bytes)
- Server verifies: `SHA256(ClientProof XOR ClientSignature) == StoredKey`
  (constant-time compare).
- `ServerSignature = HMAC(ServerKey, AuthMessage)`; the client MUST verify it
  (mutual authentication) before trusting `ACCESO CONCEDIDO`.
- Minimum iterations for new credentials: 210000 (keep existing constant if
  higher). Salt: 16 random bytes.

### 1.2 Identity keys and E2E envelopes (`river::e2e`)

- Each user has an X25519 identity keypair. Public key = 32 raw bytes.
- Fingerprint = first 16 bytes of SHA256(pubkey), hex, grouped `xxxx-xxxx-...`.
- **Envelope seal** (sender S static key, recipient R static pubkey):
  1. generate ephemeral X25519 keypair E;
  2. `dh1 = X25519(E.priv, R.pub)`, `dh2 = X25519(S.priv, R.pub)`;
  3. `key = HKDF-SHA256(ikm = dh1 || dh2, salt = E.pub, info = "river-e2e-v2|" + context + "|" + fromUser + "|" + toUser, 32)`;
  4. AES-256-GCM, random 12-byte nonce, AAD = `info`.
  5. Binary envelope: `"RE2" | version(1 byte = 1) | E.pub(32) | nonce(12) | ciphertext | tag(16)`.
- **Envelope open** mirrors it with `dh1 = X25519(R.priv, E.pub)`,
  `dh2 = X25519(R.priv, S.pub)`; fails closed on any error.
- `context` values: `"pm"` for private messages and attachment control,
  `"att:" + attachmentId` for attachment chunks.
- Local identity file (client): `river_identity_<user>.key`, in the client
  data directory (same directory used for other client files), permissions
  0600 on POSIX. Content: `"RIK1" | salt(16) | nonce(12) | AES-256-GCM(privkey(32)) | tag(16)`,
  key = PBKDF2-HMAC-SHA256(password, salt, 210000, 32). When the password
  changes, the file is re-encrypted (and renamed if the username changes).
  If the file is missing or cannot be decrypted, a new keypair is generated
  and published (peers will see a key-change warning).

## 2. Handshake and authentication

```
S: SYSTEM: UPLINK ESTABLISHED. PROTO=2
C: [AUTH_START]:2:<user>:<hwid>:<clientNonceHex32>
S: AUTH_CHALLENGE2:<combinedNonceHex>:<saltHex>:<iter>      (combined = clientNonce + 32 hex server chars)
C: [AUTH_PROOF]:<user>:<hwid>:<combinedNonceHex>:<clientProofB64>
S (success): AUTH_OK:<serverSignatureB64>
             then one of:
               SYSTEM: ACCESO CONCEDIDO.   + SESSION:<id>   (normal)
               SYSTEM: FIRST LOGIN. CHANGE REQUIRED.        (first login)
S (failure): SYSTEM: CREDENCIALES INCORRECTAS. | SYSTEM: ACCESO BLOQUEADO. | SYSTEM: HWID NO RECONOCIDO.
```

- Unknown users still receive an `AUTH_CHALLENGE2` with a deterministic fake
  salt (HMAC of username with a per-process random secret) and fixed iter, so
  user existence is not leaked; the proof then fails normally.
- Challenge TTL 60 s; lockouts per user/origin as in v1.
- Any v1 line (`[LOGIN_INIT]:`, `[LOGIN_PROOF]:`) → `SYSTEM: CLIENTE OBSOLETO. Actualiza al protocolo 2.`
- Client: if the banner lacks `PROTO=2`, show error
  "Servidor incompatible (se requiere protocolo 2)." and do not log in.

### 2.1 First-login change (password never leaves the client)

```
C: [CHANGE2]:<newUser>:<saltHex>:<iter>:<storedKeyHex>:<serverKeyHex>
S: SYSTEM: ACTUALIZADO.  SYSTEM: ACCESO CONCEDIDO.  SESSION:<id>
   or SYSTEM: ERROR ACTUALIZANDO USUARIO.
```

The client enforces `IsStrongEnoughPassword` locally; the server validates the
username, iter >= 100000, field lengths/hex.

## 3. Key directory

After `ACCESO CONCEDIDO` the client MUST publish its key:

```
C: [KEY_SET]:<pubkeyB64>
S: SYSTEM: CLAVE PUBLICA REGISTRADA.        (or ... RECHAZADA. on bad length)
C: [KEY_GET]:<user>
S: KEY:<user>:<pubkeyB64>        or   KEY:<user>:-     (unknown / no key)
```

- Server stores one current key per user (`user_keys(username PK, pubkey, updated_at)`)
  and broadcasts `KEY_CHANGED:<user>` to authenticated clients when it changes.
- Client keeps a TOFU pin file `river_known_keys.txt` (`user fingerprint` per
  line). First sight → pin. Changed key → system log warning
  `"[!] La clave de <user> cambio (huella <fp>). Verificala por otro canal."`,
  then pin the new key (messages still flow; the warning is the defence).
- Client command `/fingerprint [user]` prints own or peer fingerprint.

## 4. Messages

### 4.1 Room (server-readable, protected by Tor)

```
C: [MSG]:<textB64>
S→all: MSG:<fromUser>:<unixTs>:<textB64>
```

Server stores each room message in `room_history(id INTEGER PK, ts, from_user, body)`,
`body` sealed at rest with `river::SealPayload` (server-only key). Keep the
newest 500 rows. Payload limit 8 KiB decoded.

After login the server sends the latest 100 messages:
```
S: HISTORY_BEGIN:<count>
S: HIST:<fromUser>:<unixTs>:<textB64>     (count times, oldest first)
S: HISTORY_END
```
Client renders history entries normally (timestamp from `unixTs`), marks them
as history (no new-message notification).

### 4.2 Private messages (E2E)

```
C: [PM2]:<toUser>:<envelopeB64>
S→to: PM2:<fromUser>:<unixTs>:<envelopeB64>
```

- If the recipient is offline but exists, the server stores the envelope in
  `offline_pm(id PK, to_user, from_user, ts, envelope)` (max 200 per
  recipient, TTL 7 days) and replies `SYSTEM: Mensaje privado en cola para <user>.`
  On the recipient's next login (after history) the server delivers them as
  `PM2:` lines and deletes them.
- Unknown user → `SYSTEM: Usuario '<user>' no encontrado.`
- The client must fetch (`KEY_GET`) and cache the recipient key before
  sending; if the recipient has no key → local error
  "<user> aun no tiene clave publica.". Messages queued while waiting for a
  key reply are sent once the `KEY:` line arrives.
- Decryption failure → system log `[PM ilegible de <user>]`.
- Envelope plaintext for PMs: UTF-8 text, or attachment-control strings
  (`@attachreq|...`, `@attachmeta|...`, `@attacherr|...`) as in v1 —
  attachment control travels inside PM2 envelopes.

### 4.3 Attachments

- Offer (room broadcast, metadata server-visible):
  `C: [ATTACH2]:<id>:<kind>:<nameB64>:<mimeB64>:<size>` →
  `S→all: ATTACH2:<fromUser>:<id>:<kind>:<nameB64>:<mimeB64>:<size>`.
- Request / meta / error: PM2 envelopes as in §4.2 (no offline queueing for
  `@attach*` control: server forwards only if online; it cannot see the type,
  so the *client* sends attachment control with `[PMX]:` instead of `[PM2]:`,
  identical format, which the server never queues).
- Chunks: binary frame type 2 as in v1, but the chunk payload is an E2E
  envelope with `context = "att:" + id` (sealed per chunk, sender→requester).
  Server chunk budget per minute stays separate from offers.
- Receiver streams chunks to `<target>.part` on disk (no whole-file buffer),
  verifies size + SHA-256 at the end, then renames.

## 5. Other

- `PING`/`PONG` both directions unchanged.
- Server → client `SYSTEM:` notices from the current code stay as they are.
- Client config: only `THE_RIVER_ONION` is required. `THE_RIVER_AES_KEY` is
  required by the server only.
- Client runtime log `client_runtime.log` is written only when
  `THE_RIVER_CLIENT_LOG=1`, and never contains message contents, credentials
  or raw unhandled lines.
