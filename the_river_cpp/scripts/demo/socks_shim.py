#!/usr/bin/env python3
"""Minimal SOCKS5 shim that stands in for the Tor proxy during local demos.

The River clients (GUI and admin console) always connect through a SOCKS5
proxy to THE_RIVER_ONION. For a local, Tor-less recording this shim accepts
the SOCKS5 CONNECT (any .onion host, no auth), ignores the requested host and
pipes the stream to the local the_river_server on 127.0.0.1:<target-port>.
It is the same approach used by tests/e2e_client_tests.cpp.

  socks_shim.py --listen 19050 --target 18888 [--delay 1.0]

--delay adds latency before answering CONNECT so the client's real
"NEGOCIANDO TOR" connection screen is visible for a moment (a real onion
circuit typically takes several seconds). It never alters the payload.
"""
import argparse
import socket
import struct
import sys
import threading
import time


def pipe(src, dst, label):
    reason = "eof"
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError as exc:
        reason = repr(exc)
    finally:
        sys.stderr.write(f"[shim] {time.strftime('%H:%M:%S')} {label} closed ({reason})\n")
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def handle(client, target_port, delay):
    try:
        ver, nmethods = recv_exact(client, 2)
        if ver != 5:
            client.close()
            return
        recv_exact(client, nmethods)
        client.sendall(b"\x05\x00")  # no authentication
        ver, cmd, _rsv, atyp = recv_exact(client, 4)
        if atyp == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif atyp == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode("ascii", "replace")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            client.close()
            return
        port = struct.unpack(">H", recv_exact(client, 2))[0]
        if cmd != 1:
            client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            client.close()
            return
        if delay > 0:
            time.sleep(delay)
        try:
            upstream = socket.create_connection(("127.0.0.1", target_port), timeout=5)
            upstream.settimeout(None)
        except OSError:
            client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            client.close()
            return
        sys.stderr.write(f"[shim] {time.strftime('%H:%M:%S')} CONNECT {host}:{port} -> 127.0.0.1:{target_port}\n")
        client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        threading.Thread(target=pipe, args=(client, upstream, 'client->server'), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, client, 'server->client'), daemon=True).start()
    except (OSError, ConnectionError, ValueError):
        try:
            client.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", type=int, required=True, help="port to listen on (127.0.0.1)")
    ap.add_argument("--target", type=int, required=True, help="local the_river_server port")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds to wait before answering CONNECT")
    args = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.listen))
    srv.listen(32)
    sys.stderr.write(f"[shim] SOCKS5 on 127.0.0.1:{args.listen} -> 127.0.0.1:{args.target}\n")
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client, args.target, args.delay), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
