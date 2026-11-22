#!/usr/bin/env python3
"""Tiny protocol-v2 client used to prepare demo accounts on a local server.

It speaks the real wire protocol (TRV1 frames, SCRAM-SHA-256 login,
docs/PROTOCOL_V2.md) directly to 127.0.0.1:<port> -- no Tor needed for the
admin side. Two sub-commands:

  create --port P --admin-pass X [--count 2]
      logs in as the admin and sends /newuser COUNT times; prints one line
      "userN<TAB>one-time-password" per account (the server's own reply).

  first-login --port P --user userN --password OTP --new-user bob
              --new-password ... --hwid <64 hex>
      performs the mandatory first-login change ([CHANGE2]) the way the GUI
      does (the new password never leaves this process: only SCRAM keys are
      sent). The account gets bound to --hwid, so start that user's GUI client
      with THE_RIVER_MACHINE_ID=<same hwid>.

Only for local demos/tests: never point it at a production server.
"""
import argparse
import base64
import hashlib
import hmac
import os
import socket
import struct
import sys
import time

MAGIC = 0x54525631  # "TRV1"
ITERATIONS = 210000


def send_text(sock, text):
    data = text.encode()
    sock.sendall(struct.pack(">IHI", MAGIC, 1, len(data)) + data)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("server closed the connection")
        buf += chunk
    return buf


def recv_text(sock):
    while True:
        magic, ftype, length = struct.unpack(">IHI", recv_exact(sock, 10))
        if magic != MAGIC:
            raise ConnectionError("bad frame magic")
        payload = recv_exact(sock, length) if length else b""
        if ftype == 1:
            return payload.decode("utf-8", "replace")


def recv_until(sock, pred, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock.settimeout(max(0.1, deadline - time.time()))
        line = recv_text(sock)
        if line == "PING":
            send_text(sock, "PONG")
            continue
        if pred(line):
            return line
    raise TimeoutError("timed out waiting for the server")


def hmac256(key, msg):
    return hmac.new(key, msg if isinstance(msg, bytes) else msg.encode(), hashlib.sha256).digest()


def login(port, user, password, hwid, expect):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    recv_until(s, lambda l: "UPLINK ESTABLISHED" in l and "PROTO=2" in l)
    cnonce = os.urandom(16).hex()
    send_text(s, f"[AUTH_START]:2:{user}:{hwid}:{cnonce}")
    ch = recv_until(s, lambda l: l.startswith("AUTH_CHALLENGE2:")).split(":")
    combined, salt_hex, iters = ch[1], ch[2], int(ch[3])
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), iters, 32)
    client_key = hmac256(salted, "Client Key")
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac256(salted, "Server Key")
    auth_msg = f"river-auth-v2|{user}|{hwid}|{cnonce}|{combined}|{salt_hex}|{iters}"
    proof = bytes(a ^ b for a, b in zip(client_key, hmac256(stored_key, auth_msg)))
    send_text(s, f"[AUTH_PROOF]:{user}:{hwid}:{combined}:{base64.b64encode(proof).decode()}")
    ok = recv_until(s, lambda l: l.startswith("AUTH_OK:") or "INCORRECTAS" in l or "BLOQUEADO" in l or "HWID" in l)
    if not ok.startswith("AUTH_OK:"):
        raise SystemExit(f"login failed for {user}: {ok}")
    if not hmac.compare_digest(base64.b64decode(ok[8:]), hmac256(server_key, auth_msg)):
        raise SystemExit("server signature mismatch")
    recv_until(s, lambda l: expect in l)
    return s


def cmd_create(a):
    s = login(a.port, a.admin_user, a.admin_pass, a.hwid, "ACCESO CONCEDIDO")
    for _ in range(a.count):
        send_text(s, "[MSG]:" + base64.b64encode(b"/newuser").decode())
    for _ in range(a.count):
        line = recv_until(s, lambda l: "NUEVO USUARIO: " in l)
        rest = line.split("NUEVO USUARIO: ", 1)[1]
        name = rest.split(" ", 1)[0]
        pw = rest.split("clave inicial: ", 1)[1].split(" ", 1)[0] if "clave inicial: " in rest else ""
        print(f"{name}\t{pw}")
    s.close()


def cmd_first_login(a):
    if len(a.new_password) < 12:
        raise SystemExit("new password must have at least 12 characters")
    s = login(a.port, a.user, a.password, a.hwid, "FIRST LOGIN")
    salt = os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", a.new_password.encode(), salt, ITERATIONS, 32)
    stored = hashlib.sha256(hmac256(salted, "Client Key")).hexdigest()
    server = hmac256(salted, "Server Key").hex()
    send_text(s, f"[CHANGE2]:{a.new_user}:{salt.hex()}:{ITERATIONS}:{stored}:{server}")
    line = recv_until(s, lambda l: "ACCESO CONCEDIDO" in l or "ERROR ACTUALIZANDO" in l)
    if "ERROR" in line:
        raise SystemExit(f"first-login change refused: {line}")
    print(f"{a.user} -> {a.new_user}: ok")
    s.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--port", type=int, required=True)
    c.add_argument("--admin-user", default="admin")
    c.add_argument("--admin-pass", required=True)
    c.add_argument("--count", type=int, default=2)
    c.add_argument("--hwid", default="ad" * 32)
    f = sub.add_parser("first-login")
    f.add_argument("--port", type=int, required=True)
    f.add_argument("--user", required=True)
    f.add_argument("--password", required=True)
    f.add_argument("--new-user", required=True)
    f.add_argument("--new-password", required=True)
    f.add_argument("--hwid", required=True)
    a = ap.parse_args()
    {"create": cmd_create, "first-login": cmd_first_login}[a.cmd](a)


if __name__ == "__main__":
    main()
