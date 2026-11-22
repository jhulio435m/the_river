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

### 4.4 Client-side message integrity

Client-only rules (the server relays envelopes opaquely and is unaffected).

**RM1 plaintext.** Every PM2 *and* PMX envelope (text PMs and `@attach*`
control alike) seals

```
RM1|<msgIdHex32>|<senderUnixTs>|<payload>
```

- `msgIdHex32`: 16 random bytes, 32 lowercase hex chars, fresh per send.
- `senderUnixTs`: sender clock, decimal seconds (> 0) at sealing time.
- `payload`: the v1-style text or `@attachreq|...` / `@attachmeta|...` /
  `@attacherr|...` string; it may contain `|`.

The receiver, after opening the envelope:

1. Plaintext not matching `RM1|` + 32 lowercase hex + `|` + digits + `|` →
   rejected, system log `[PM ilegible de <user>]` (no legacy format).
2. `senderUnixTs` older than 8 days (server keeps offline PMs 7 days) or more
   than 24 h in the future → dropped
   (`SYSTEM: [!] Mensaje privado de <user> descartado (marca de tiempo fuera de rango).`).
3. A `msgId` already seen from that peer → dropped as a replay
   (`SYSTEM: [!] Mensaje privado repetido de <user> descartado (reenvio).`);
   control messages are dropped silently.
4. Otherwise the id is recorded *before* the message is shown or acted on, and
   the PM is displayed with `senderUnixTs` (authenticated) instead of the
   server `ts`.

Seen ids are kept per (local user, peer): at most 5000 ids per peer; when the
oldest is evicted its timestamp becomes the peer's *watermark* and anything
with `senderUnixTs <= watermark` is rejected, so eviction never reopens a
replay window. Persisted in `river_seen_ids.txt` (client data directory),
append-only lines `S <me> <peer> <msgId> <ts>` and `W <me> <peer> <watermark>`,
compacted on load / when it grows; entries older than 8 days are pruned.

**Key changes (supersedes the re-pin sentence of section 3).** When a fetched
key's fingerprint differs from the pinned one, the client does **not** re-pin.
It logs
`[!] La clave de <user> cambio (huella <fp>). Verificala por otro canal. Usa /trust <user> para aceptar la nueva clave.`
and marks the peer *unverified-changed*: pending and new outgoing PMs, outgoing
attachment control and uploads requested by that peer are held (bounded) with
a `SYSTEM:` line saying so; incoming PMs still open with the new key but are
shown prefixed `[clave no verificada] `; an `@attachmeta` from such a peer
fails the transfer. `/trust <user>` pins exactly the fingerprint shown in the
warning and flushes what was held (re-fetching the key first if it is no longer
cached; if it changed again the cycle repeats). Unverified state is not stored:
the pin file still holds the old fingerprint, so it is re-detected after a
restart.

**Key directory use.** Received PMs whose sender key is unknown are buffered
(256 per sender, 2000 total) until the `KEY:` reply. KEY_GET requests made
while processing incoming lines are coalesced (60 ms window or 50 names) into
`[KEY_GET]:<u1>,<u2>,...` lines of at most 50 names; requests from the user
(sending a PM, `/fingerprint`) go out at once (single name). If the server
answers a list as one name (`KEY:<a,b>:-`), the client falls back to one name
per line. After `SYSTEM: LIMITE DE CONSULTAS DE CLAVES EXCEDIDO.` unanswered
names stay pending and are asked again 61 s later.

**Attachments.** Uploads: at most 2 concurrent, one per (requester, id);
duplicates of an in-flight or queued request are ignored; up to 8 wait in a
queue; beyond that the owner answers `@attacherr|<id>|<b64("Ocupado, reintenta")>`.
Received files: cache path `attachments_cache/<hex(SHA256(owner|id))[:24]>_<sanitized name>`;
`.part` files are created exclusively (O_EXCL; a unique `<target>.<n>.part` on
collision). The GUI hands a received file to the system shell ("Open") only
when its local path has an extension matching its kind (image: png jpg jpeg
gif bmp webp; video: mp4 mkv webm mov avi m4v); otherwise only "Save As" is
offered, with a `SYSTEM:` warning.

**Reconnects.** Fatal auth errors (bad server signature, missing AUTH_OK,
`CLIENTE OBSOLETO`, banner without `PROTO=2`, unusable challenge) stay on screen
until the user submits a new login, and the next reconnect waits 30 s (a new
login ends the wait). `SYSTEM: TIEMPO DE AUTENTICACION AGOTADO.` and
`SYSTEM: LIMITE DE TRAFICO EXCEDIDO.` are shown and the client waits 5 s
before reconnecting. `PING` is only sent after a verified `AUTH_OK`.

## 5. Other

- `PING`/`PONG` both directions unchanged.
- Client link liveness: the socket receive timeout (10 s) is only a polling
  interval; an idle link is not a dead one. Once authenticated, the client sends
  its own `PING` after 45 s without any frame (the resulting `PONG` is silent)
  and closes/reconnects only after 90 s without a single frame. A `recv()`/`send()`
  interrupted by a signal (EINTR) is retried, never treated as a link failure,
  and client sockets are close-on-exec. `THE_RIVER_CLIENT_LINK_TIMEOUTS=<poll>,<keepalive>,<dead>`
  (seconds) overrides these values; it exists for `tests/e2e_client_tests.cpp`
  only.
- Server → client `SYSTEM:` notices from the current code stay as they are.
- Client config: only `THE_RIVER_ONION` is required. `THE_RIVER_AES_KEY` is
  required by the server only.
- Client runtime log `client_runtime.log` is written only when
  `THE_RIVER_CLIENT_LOG=1`, and never contains message contents, credentials
  or raw unhandled lines.

## Implementation notes (server)

Choices made where the text above leaves room; clients can rely on them.

- **v1 lines** (`[LOGIN_INIT]:`, `[LOGIN_PROOF]:`, and also the v1 first-login
  `[CHANGE]:`) and an `[AUTH_START]` whose version field is not `2` get
  `SYSTEM: CLIENTE OBSOLETO. Actualiza al protocolo 2.` and the server then
  closes the connection.
- **AUTH_START validation**: username must pass `IsValidUsername`, hwid is
  1..128 chars without control chars, `:` or `|`, clientNonce exactly 32 hex
  chars; otherwise `SYSTEM: CREDENCIALES INCORRECTAS.` (no challenge). The
  server nonce part is 32 lowercase hex chars. Only one challenge is pending
  per connection (a new `AUTH_START` replaces it) and it is single use: any
  `AUTH_PROOF` consumes it, success or not. There is no account lockout (see
  **Login failure policy** below), so an unknown user still receives a
  challenge and a valid proof is always accepted. `AUTH_START` /
  `AUTH_PROOF` are ignored once the connection is authenticated or waiting
  for `[CHANGE2]`.
- **Fake challenge**: salt = first 16 bytes (32 hex) of
  `HMAC-SHA256(secret, "river-fake-salt|" + user)`, where `secret` is 32
  random bytes generated once and persisted in the database
  (`server_settings`, key `fake_salt_secret`; this supersedes the
  "per-process random secret" of §2), so fake salts survive restarts exactly
  like real ones. iter =
  `scram::kDefaultIterations` (210000, same as every credential the server
  creates or migrates). A stored value that is not a valid `scram-sha256$`
  credential is treated like an unknown user.
- `AUTH_OK` is sent only when the proof verifies **and** the account policy
  admits the login (normal or first login). A correct proof from a banned or
  wrong HWID gets only `SYSTEM: ACCESO BLOQUEADO.` / `SYSTEM: HWID NO RECONOCIDO.`
- **Login sequence** (normal): `AUTH_OK`, `SYSTEM: ACCESO CONCEDIDO.`,
  `SESSION:<id>`, `HISTORY_BEGIN:<n>` (always sent, also with `n = 0`), `n`×`HIST:`,
  `HISTORY_END`, queued `PM2:` lines, then the room broadcast `<user> se unió`
  and `[USERS]:...`. After `[CHANGE2]` the same sequence follows
  `SYSTEM: ACTUALIZADO.` (no second `AUTH_OK`). Room `MSG:` and `PM2:` lines are
  strictly ordered with respect to this block (none is lost or duplicated);
  other broadcasts (`KEY_CHANGED`, `ATTACH2`, `[USERS]`, announcements) may
  interleave anywhere, so clients must accept any line at any time.
- **CHANGE2**: iter must be exactly `scram::kDefaultIterations` (210000;
  supersedes "iter >= 100000" in §2.1 — any other value would make the
  account's challenge distinguishable from a fake one); salt 16..64 bytes
  hex; storedKey/serverKey exactly 64 hex chars (upper case accepted, stored
  lower case). Refused for admins, for reserved names and when the new name
  is taken **in any letter case** (see **Usernames**). The renamed account
  starts with no public key and no queued PMs. Failure answer:
  `SYSTEM: ERROR ACTUALIZANDO USUARIO.` (the connection stays in first-login
  state and may retry).
- **KEY_SET**: the key must decode to exactly 32 bytes, else
  `SYSTEM: CLAVE PUBLICA RECHAZADA.` `KEY_CHANGED:<user>` is broadcast to all
  authenticated clients (sender included) whenever the stored value differs
  from the previous one, *including the first publication* (so peers waiting
  for a key learn it exists). Re-publishing the same key only answers
  `SYSTEM: CLAVE PUBLICA REGISTRADA.`
- **KEY_GET** for a name that is not a valid username answers `KEY:<name>:-`
  (silently ignored if the name contains `:`, `|` or control chars).
  **Batch form**: `[KEY_GET]:<user1>,<user2>,...` (comma-separated, no
  spaces, at most 50 names; names after the 50th are ignored, empty names are
  skipped) is answered with one `KEY:<name>:<pubkeyB64>` / `KEY:<name>:-` line
  per name, in request order (duplicates are answered each time). The single
  form `[KEY_GET]:<user>` is simply a batch of one. KEY_GET has its own
  budget of 600 names per minute and is **not** counted in the 120 lines/min
  limit; names beyond the budget are not answered and the first excess in a
  minute gets one `SYSTEM: LIMITE DE CONSULTAS DE CLAVES EXCEDIDO.` (the
  connection stays open).
- **Base64**: every b64 field is decoded strictly and relayed/stored
  re-encoded in canonical form.
- **MSG**: invalid base64 or empty text → `SYSTEM: MENSAJE RECHAZADO.`;
  > 8192 decoded bytes → `SYSTEM: MENSAJE DEMASIADO GRANDE.` Text starting
  with `/` is never broadcast or stored: admin → admin command, others →
  `SYSTEM: Comando no disponible. Usa /help para ver los comandos.` The sender
  also receives its own `MSG:` broadcast. `room_history.body` stores
  `SealPayload(textB64)`.
- **PM2 / PMX**: envelope must decode to 64..16384 bytes, recipient must pass
  `IsValidUsername`, else `SYSTEM: MENSAJE PRIVADO RECHAZADO.` Delivered as
  `PM2:<from>:<ts>:<env>` / `PMX:<from>:<ts>:<env>`. Offline recipient:
  PM2 → queued (`SYSTEM: Mensaje privado en cola para <user>.`), or, at 200
  queued for that recipient — or at 50 queued for that recipient *from this
  sender* (per-sender sub-quota, so one user cannot fill someone else's
  queue) — `SYSTEM: Cola de mensajes privados llena para <user>.`
  (the new message is refused; older ones are kept). PMX →
  `SYSTEM: Usuario '<user>' no conectado.` Unknown recipient (both) →
  `SYSTEM: Usuario '<user>' no encontrado.` Queued PMs keep their original
  `ts`, are delivered once (deleted when read at login, even if that
  connection then drops) and expire after 7 days. `offline_pm.envelope` holds
  the (already E2E encrypted) envelope b64 as is.
- **ATTACH2**: id 1..80 chars, no `:`/`|`/control chars; kind
  `image|video|file`; name non-empty ≤ 1024 bytes decoded; mime ≤ 255 bytes
  decoded (may be empty); size decimal 1..12 MiB. Invalid →
  `SYSTEM: ADJUNTO RECHAZADO.`; line > 16 KiB → `SYSTEM: ADJUNTO RECHAZADO POR TAMANO.`
  Broadcast to everyone, sender included.
- **Chunks**: envelope part must be 64..(64 KiB + 64) bytes, else
  `SYSTEM: ADJUNTO RECHAZADO.` Framing is unchanged.
- **Rate limits**: `MSG`, `PM2`, `PMX` share the 60/min message budget (admin
  commands sent as `MSG` count too); `ATTACH2` 12/min; chunks 1200/min; all
  text lines except `[KEY_GET]` (including empty lines, `PING`/`PONG` and
  frames of unknown type) 120/min; KEY_GET 600 names/min (above). Every frame
  of any type also counts toward 2400 frames/min. Exceeding the line or
  frame budget → `SYSTEM: LIMITE DE TRAFICO EXCEDIDO.` and the connection is
  closed.
- **Migration** (`PRAGMA user_version` 1 → 2): every `pbkdf2-sha256$...` row is
  converted in the `InitSchema` transaction. A row that cannot be parsed is
  left untouched (logged; that account needs `/passwd`) instead of aborting
  startup. The credential column keeps its v1 name `password_hash`.
  2 → 3: table `server_settings(key PK, value)` (fake-salt secret) and the
  unique index `idx_users_username_nocase ON users(username COLLATE NOCASE)`.
  If the database already holds names that differ only in case, they are
  logged and kept (each still logs in with its exact name) and the index is
  not created; the application-level case-insensitive check still prevents
  new variants. Existing accounts with reserved names are logged.
- `/whois <user>` appends `| huella=<fingerprint>` (or `huella=-`).
- **Usernames**: unique ignoring ASCII case (`Alice` cannot be created while
  `alice` exists). Login, PM routing, KEY_GET and admin commands still match
  the exact stored spelling. Reserved (refused for `[CHANGE2]` and never
  generated by `/newuser`), compared case-insensitively: `admin`, `system`,
  `server` and the configured `THE_RIVER_ADMIN_USER`.
- **Connection admission and deadlines**: at most 256 connections. A
  connection is *pre-auth* until it receives `AUTH_OK`; at most 64 may be
  pre-auth at once. When a new connection arrives and either cap is reached,
  the **oldest pre-auth connection is closed** (no notice) to make room, so
  pre-auth floods cannot lock out real logins; only when every slot is held
  by authenticated/first-login connections is the newcomer refused with
  `SYSTEM: SERVIDOR SATURADO. Intenta mas tarde.` Pre-auth connections must
  get `AUTH_OK` within **30 s** of connecting, and first-login connections
  must complete `[CHANGE2]` within **10 min** of `AUTH_OK`; otherwise the
  server sends `SYSTEM: TIEMPO DE AUTENTICACION AGOTADO.` and closes
  (enforced by the heartbeat thread, 1 s resolution). Before `AUTH_OK`:
  `PING` is not answered, any non-text frame (attachment chunk or unknown
  type) closes the connection, and at most 20 lines may be sent in total.
  The server PINGs first-login connections every 30 s like authenticated
  ones.
- **Login failure policy** (replaces the v1-style lockouts): a valid proof is
  **never** refused or delayed because of earlier failures (nobody can lock
  out another account, the admin included). Failed proofs (wrong proof,
  malformed/expired `AUTH_PROOF`, unknown user) are throttled instead:
  (a) each connection may fail at most 3 proofs (`CREDENCIALES INCORRECTAS`,
  `ACCESO BLOQUEADO` or `HWID NO RECONOCIDO`); the 3rd failure answer is
  followed by closing the connection; (b) after 5 failed proof verifications for
  one username (case-insensitive) within 15 min, every further failed answer
  for that username is delayed by 1 s per extra failure (max 5 s);
  (c) when more than 60 proofs fail server-wide in one minute, every failed
  answer is delayed by at least 2 s. The per-username table is bounded
  (4096 entries, least recently failed evicted first) and pruned of entries
  idle for 15 min from the heartbeat. There is no origin/hwid-keyed lock
  (the hwid is client-supplied). Banned-HWID and HWID-mismatch answers are
  unchanged.
- **/newuser**: creates the next free `userN` (skipping names taken in any
  case). If `THE_RIVER_NEW_USER_PASSWORD` is **unset** (recommended; it is no
  longer required), the account gets a random one-time initial password
  (16 chars from `A-Z a-z 2-9` without `I O l o 0 1`) and only the requesting
  admin connection receives
  `SYSTEM: NUEVO USUARIO: userN / clave inicial: <password> (de un solo uso; ...)`;
  the password is never logged, audited or shown again. If it is **set**
  (legacy), every new account shares it, the reply stays
  `SYSTEM: NUEVO USUARIO: userN / clave inicial definida por THE_RIVER_NEW_USER_PASSWORD`,
  and the server logs a warning at startup.
- Admin kicks/bans, session replacement and heartbeat reaping act on the
  connection object captured under the session lock, never on a raw
  descriptor, so a reused descriptor can never receive another
  connection's kick.
