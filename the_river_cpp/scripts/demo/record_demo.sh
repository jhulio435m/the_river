#!/usr/bin/env bash
# Records the real-screen demo clips of The River used on the project website.
#
# Everything on screen is the real software: the_river_server, the_river_admin
# and two the_river_client GUI windows (alice and bob), driven with xdotool on a
# virtual X display (Xvfb) and captured with ffmpeg x11grab. Tor is replaced by
# socks_shim.py, a local SOCKS5 proxy that pipes the client's onion CONNECT to
# the local server (same technique as tests/e2e_client_tests.cpp).
#
# Usage:
#   scripts/demo/record_demo.sh [--build] [--out DIR] [--keep-work]
#
#   --build      configure + build the three binaries into $BUILD_DIR first
#   --out DIR    where the final mp4/webm/jpg go (default: <repo>/site/media)
#   --keep-work  keep the temporary work dir (raw captures, logs, databases)
#
# Environment: BUILD_DIR (default /tmp/demo_build), DISPLAY_NUM (default :77),
#   TYPE_DELAY ms per typed character (default 75), SHIM_DELAY seconds of
#   simulated onion-circuit latency (default 2.0).
#
# Only demo credentials are used; the server AES key is random, generated per
# run and never shown. See README.md in this folder.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CPP_ROOT="$(cd "$HERE/../.." && pwd)"
REPO_ROOT="$(cd "$CPP_ROOT/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-/tmp/demo_build}"
OUT_DIR="$REPO_ROOT/site/media"
DISPLAY_NUM="${DISPLAY_NUM:-:77}"
TYPE_DELAY="${TYPE_DELAY:-75}"
SHIM_DELAY="${SHIM_DELAY:-2.0}"
DO_BUILD=0
KEEP_WORK=0

while [ $# -gt 0 ]; do
    case "$1" in
        --build) DO_BUILD=1 ;;
        --out) OUT_DIR="$2"; shift ;;
        --keep-work) KEEP_WORK=1 ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

for tool in Xvfb xdotool xclip ffmpeg python3 xterm script zenity; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool (see README.md)" >&2; exit 1; }
done

if [ "$DO_BUILD" = 1 ]; then
    cmake -S "$CPP_ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
    cmake --build "$BUILD_DIR" -j"$(nproc)" --target the_river_server the_river_client the_river_admin
fi
for bin in the_river_server the_river_client the_river_admin; do
    [ -x "$BUILD_DIR/$bin" ] || { echo "missing $BUILD_DIR/$bin (run with --build)" >&2; exit 1; }
done

WORK="$(mktemp -d /tmp/river-demo.XXXXXX)"
mkdir -p "$WORK/raw" "$OUT_DIR"
PIDS=()
REC_PID=""

kill_tree() {  # signal pid and all its descendants (children first)
    local sig="$1" pid="$2" child
    for child in $(pgrep -P "$pid" 2>/dev/null); do kill_tree "$sig" "$child"; done
    kill "-$sig" "$pid" 2>/dev/null
}
cleanup() {
    set +e
    trap - EXIT INT TERM
    [ -n "$REC_PID" ] && kill -INT "$REC_PID" 2>/dev/null && wait "$REC_PID" 2>/dev/null
    for ((i=${#PIDS[@]}-1; i>=0; i--)); do kill_tree TERM "${PIDS[$i]}"; done
    sleep 0.5
    for ((i=${#PIDS[@]}-1; i>=0; i--)); do kill_tree KILL "${PIDS[$i]}"; done
    pkill -f "zenity --file-selection" 2>/dev/null
    wait 2>/dev/null
    if [ "$KEEP_WORK" = 1 ]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT INT TERM

log() { printf '\033[1;36m[demo]\033[0m %s\n' "$*"; }
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
wait_port() { for _ in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# ------------------------------------------------------------------ demo setup
SERVER_PORT="$(free_port)"
SHIM_PORT="$(free_port)"
AES_KEY="$(python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(40)))')"
ADMIN_PASS="demo-admin-pass-2026"
BOB_PASS="bob-demo-clave-2026"
ALICE_PASS="alice-demo-clave-2026"
# Any syntactically valid v3 onion name: the shim ignores the host anyway.
ONION="riverdemoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"
ALICE_HWID="$(printf 'a1%.0s' $(seq 1 32))"
BOB_HWID="$(printf 'b0%.0s' $(seq 1 32))"

export DISPLAY="$DISPLAY_NUM"
export LIBGL_ALWAYS_SOFTWARE=1
export THE_RIVER_ONION="$ONION"
export THE_RIVER_TOR_PROXY_PORT="$SHIM_PORT"
export NO_AT_BRIDGE=1

log "work dir $WORK, server :$SERVER_PORT, shim :$SHIM_PORT, display $DISPLAY"
Xvfb "$DISPLAY" -screen 0 1920x1080x24 -nolisten tcp >"$WORK/xvfb.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do xdotool getdisplaygeometry >/dev/null 2>&1 && break; sleep 0.1; done

mkdir -p "$WORK/server" "$WORK/alice" "$WORK/bob" "$WORK/admin"
(cd "$WORK/server" && exec env -u THE_RIVER_NEW_USER_PASSWORD \
    THE_RIVER_AES_KEY="$AES_KEY" THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD="$ADMIN_PASS" \
    THE_RIVER_DB="$WORK/server/demo.db" THE_RIVER_LOG="$WORK/server/chat_history.log" \
    THE_RIVER_PORT="$SERVER_PORT" "$BUILD_DIR/the_river_server" >"$WORK/server/server.log" 2>&1) &
PIDS+=($!)
wait_port "$SERVER_PORT" || { echo "server did not start" >&2; cat "$WORK/server/server.log" >&2; exit 1; }
unset AES_KEY

python3 "$HERE/socks_shim.py" --listen "$SHIM_PORT" --target "$SERVER_PORT" --delay "$SHIM_DELAY" \
    >"$WORK/shim.log" 2>&1 &
PIDS+=($!)
wait_port "$SHIM_PORT"

# bob's account: created and first-login-changed off camera over the real protocol.
read -r BOB_INITIAL BOB_OTP < <(python3 "$HERE/create_users.py" create --port "$SERVER_PORT" \
    --admin-pass "$ADMIN_PASS" --count 1)
python3 "$HERE/create_users.py" first-login --port "$SERVER_PORT" --user "$BOB_INITIAL" \
    --password "$BOB_OTP" --new-user bob --new-password "$BOB_PASS" --hwid "$BOB_HWID"

# Demo image for the attachment clip (generated, no external content).
ffmpeg -loglevel error -y -f lavfi -i "mandelbrot=size=480x320:start_scale=2.2:end_scale=2.2:inner=period" \
    -frames:v 1 "$WORK/alice/rio.png"

# ------------------------------------------------------------------ helpers
rec_start() {  # name x y w h
    log "recording $1"
    ffmpeg -loglevel error -y -f x11grab -draw_mouse 1 -framerate 30 -video_size "$4x$5" \
        -i "$DISPLAY+$2,$3" -c:v libx264 -preset ultrafast -qp 0 -pix_fmt yuv444p "$WORK/raw/$1.mkv" \
        </dev/null >"$WORK/raw/$1.log" 2>&1 &
    REC_PID=$!
    sleep 0.6
}
rec_stop() {
    sleep "${1:-1.5}"
    kill -INT "$REC_PID" 2>/dev/null || true
    wait "$REC_PID" 2>/dev/null || true
    REC_PID=""
}
focus() { xdotool windowfocus --sync "$1" 2>/dev/null || xdotool windowfocus "$1"; sleep 0.15; }
human_type() { focus "$1"; xdotool type --delay "$TYPE_DELAY" -- "$2"; }
key() { focus "$1"; shift; xdotool key --delay 120 "$@"; }
say() { human_type "$1" "$2"; sleep 0.25; key "$1" Return; }  # type a line and submit it
click_at() { xdotool mousemove --sync "$1" "$2"; sleep 0.25; xdotool click 1; }
glide() { # glide the pointer to x y so viewers can follow it
    local x y cx cy
    eval "$(xdotool getmouselocation --shell)"; cx=$X; cy=$Y
    for i in 1 2 3 4 5 6 7 8 9 10; do
        x=$(( cx + ($1 - cx) * i / 10 )); y=$(( cy + ($2 - cy) * i / 10 ))
        xdotool mousemove "$x" "$y"; sleep 0.02
    done
}
start_client() {  # name hwid -> sets CLIENT_PID, CLIENT_WIN
    local dir="$WORK/$1"
    (cd "$dir" && HOME="$dir" THE_RIVER_MACHINE_ID="$2" exec "$BUILD_DIR/the_river_client" \
        >"$dir/client.out" 2>&1) &
    CLIENT_PID=$!
    PIDS+=("$CLIENT_PID")
    CLIENT_WIN=""
    for _ in $(seq 1 100); do
        CLIENT_WIN="$(xdotool search --all --onlyvisible --pid "$CLIENT_PID" --name 'the river' 2>/dev/null | head -1 || true)"
        [ -n "$CLIENT_WIN" ] && break
        sleep 0.1
    done
    [ -n "$CLIENT_WIN" ] || { echo "client window for $1 did not appear" >&2; exit 1; }
}
# /clear empties the feed (off camera) so every clip starts clean.
clear_feed() { say "$1" "/clear"; sleep 0.3; }

# Login panel geometry (ui_sections.cpp RenderLoginScreen / RenderCredentialChangeScreen),
# relative to the window's top-left corner; the panels are centred.
login_fields() {  # w h -> ID_X ID_Y PW_Y
    ID_X=$(( $1 / 2 )); ID_Y=$(( $2 / 2 - 150 + 41 )); PW_Y=$(( $2 / 2 - 150 + 67 ))
}

# ================================================================== clip: admin
# The admin console in a terminal creates alice's account (/newuser) and lists
# the accounts. The one-time password it prints is a throwaway demo value that
# alice consumes on camera in the next clip.
log "admin console"
LC_ALL=C.UTF-8 xterm -u8 -fa 'DejaVu Sans Mono' -fs 11 -geometry 112x28+0+0 -bg black -fg '#d8d8d8' -T the_river_admin \
    -xrm 'XTerm*cursorBlink: true' -e bash -c "cd '$WORK/admin' && HOME='$WORK/admin' \
    script -qfc '$BUILD_DIR/the_river_admin' '$WORK/admin/typescript'" &
PIDS+=($!)
ADMIN_WIN=""
for _ in $(seq 1 100); do
    ADMIN_WIN="$(xdotool search --onlyvisible --name '^the_river_admin$' 2>/dev/null | head -1 || true)"
    [ -n "$ADMIN_WIN" ] && break
    sleep 0.1
done
eval "$(xdotool getwindowgeometry --shell "$ADMIN_WIN")"
AW=$(( WIDTH / 2 * 2 )); AH=$(( HEIGHT / 2 * 2 ))
rec_start admin 0 0 "$AW" "$AH"
for _ in $(seq 1 150); do grep -q "IDENTIFICADOR DE ACCESO" "$WORK/admin/typescript" 2>/dev/null && break; sleep 0.1; done
sleep 0.6
xdotool mousemove 600 300
say "$ADMIN_WIN" "admin"
sleep 0.5
say "$ADMIN_WIN" "$ADMIN_PASS"
for _ in $(seq 1 150); do grep -q "ADMIN>" "$WORK/admin/typescript" 2>/dev/null && break; sleep 0.1; done
sleep 1.2
say "$ADMIN_WIN" "/newuser"
for _ in $(seq 1 100); do grep -q "NUEVO USUARIO" "$WORK/admin/typescript" 2>/dev/null && break; sleep 0.1; done
sleep 1.8
say "$ADMIN_WIN" "/accounts"
rec_stop 3
LINE="$(grep -a "NUEVO USUARIO" "$WORK/admin/typescript" | tail -1 | sed 's/\x1b\[[0-9;]*m//g')"
ALICE_INITIAL="$(sed -E 's/.*NUEVO USUARIO: ([A-Za-z0-9_]+) .*/\1/' <<<"$LINE")"
ALICE_OTP="$(sed -E 's/.*clave inicial: ([A-Za-z0-9]+).*/\1/' <<<"$LINE")"
[ -n "$ALICE_INITIAL" ] && [ -n "$ALICE_OTP" ] || { echo "could not read /newuser reply" >&2; exit 1; }
say "$ADMIN_WIN" "/exit"
sleep 0.5
xdotool windowunmap "$ADMIN_WIN" 2>/dev/null || true

# ================================================================== clip: login
# alice starts the client: connection screen, ES button, login with the one-time
# key, mandatory first-access change, then she is in the room.
log "login ($ALICE_INITIAL -> alice)"
rec_start login 0 0 960 620
start_client alice "$ALICE_HWID"
ALICE_WIN="$CLIENT_WIN"
xdotool windowmove "$ALICE_WIN" 0 0
xdotool mousemove 700 330
sleep 0.5
glide 925 18; sleep 0.3; xdotool click 1          # ES: switch the UI to Spanish
sleep 0.8; glide 700 400                           # move away so the tooltip closes
sleep "$SHIM_DELAY"; sleep 1.0                     # NEGOCIANDO TOR -> TOR LISTO
login_fields 960 620
glide "$ID_X" "$ID_Y"; xdotool click 1
human_type "$ALICE_WIN" "$ALICE_INITIAL"; key "$ALICE_WIN" Return; sleep 0.5
human_type "$ALICE_WIN" "$ALICE_OTP"; sleep 0.4
glide "$ID_X" $(( 620 / 2 - 150 + 106 )); sleep 0.2; xdotool click 1   # ESTABLECER ENLACE
sleep 4.5                                          # SCRAM (PBKDF2 210k) -> PRIMER ACCESO
CHG_ID_Y=$(( 620 / 2 - 180 + 81 ))   # "NUEVO ID" row of the first-access panel
glide "$ID_X" "$CHG_ID_Y"; xdotool click 1
human_type "$ALICE_WIN" "alice"; key "$ALICE_WIN" Return; sleep 0.5
human_type "$ALICE_WIN" "$ALICE_PASS"; sleep 0.4
key "$ALICE_WIN" Return
sleep 5                                            # ACTUALIZANDO -> SEGURO, key published
xdotool mousemove 700 300
say "$ALICE_WIN" "hola! primera vez en el rio"
rec_stop 2.5

# ================================================================== side by side
log "bob logs in (off camera)"
start_client bob "$BOB_HWID"
BOB_WIN="$CLIENT_WIN"
xdotool windowmove "$BOB_WIN" 960 0
sleep "$SHIM_DELAY"; sleep 1
click_at $(( 960 + 925 )) 18                       # ES
login_fields 960 620
click_at $(( 960 + ID_X )) "$ID_Y"
human_type "$BOB_WIN" "bob"; key "$BOB_WIN" Return; sleep 0.5
human_type "$BOB_WIN" "$BOB_PASS"; key "$BOB_WIN" Return
sleep 6
# Two 800x620 windows side by side (the UI adapts to the window size).
xdotool windowsize "$ALICE_WIN" 800 620 windowmove "$ALICE_WIN" 0 0
xdotool windowsize "$BOB_WIN" 800 620 windowmove "$BOB_WIN" 800 0
sleep 1
clear_feed "$ALICE_WIN"; clear_feed "$BOB_WIN"
xdotool mousemove 800 650

# ================================================================== clip: chat
log "chat"
rec_start chat 0 0 1600 620
say "$BOB_WIN" "hola alice! te leo por el tunel onion"
sleep 1.2
human_type "$ALICE_WIN" "bo"; sleep 0.4; key "$ALICE_WIN" Tab; sleep 0.6   # nickname completion
human_type "$ALICE_WIN" "fuerte y claro. quedamos a las 21:00?"; key "$ALICE_WIN" Return
sleep 1.5
say "$BOB_WIN" "mejor un poco mas tarde"
sleep 1.2
key "$ALICE_WIN" Up; sleep 0.9                     # history: recall the last line
key "$ALICE_WIN" BackSpace BackSpace BackSpace BackSpace BackSpace BackSpace; sleep 0.3
human_type "$ALICE_WIN" "22:00?"; sleep 0.4; key "$ALICE_WIN" Return
sleep 1.2
say "$BOB_WIN" "perfecto, a las 22:00"
rec_stop 2.5

# ================================================================== clip: private
clear_feed "$ALICE_WIN"; clear_feed "$BOB_WIN"
log "private"
rec_start private 0 0 1600 620
say "$ALICE_WIN" "/fingerprint bob"
sleep 1.2
say "$BOB_WIN" "/fingerprint"
sleep 1.5
say "$ALICE_WIN" "/msg bob huellas verificadas. esto solo lo leemos tu y yo"
sleep 1.8
say "$BOB_WIN" "/r confirmado: cifrado de extremo a extremo"
rec_stop 3

# ================================================================== clip: attachment
clear_feed "$ALICE_WIN"; clear_feed "$BOB_WIN"
log "attachment"
rec_start attachment 0 0 1600 620
say "$ALICE_WIN" "os paso una foto del rio"
sleep 0.8
glide $(( 800 - 10 - 48 )) $(( 620 - 42 - 42 ))   # "Adjuntar" button
sleep 0.2; xdotool click 1
PICKER=""
for _ in $(seq 1 100); do
    PICKER="$(xdotool search --onlyvisible --name 'Select attachment' 2>/dev/null | head -1 || true)"
    [ -n "$PICKER" ] && break
    sleep 0.1
done
[ -n "$PICKER" ] || { echo "file picker did not appear" >&2; exit 1; }
xdotool windowsize "$PICKER" 720 400 windowmove "$PICKER" 40 90
sleep 2
# The path is pasted into GTK's location entry: typing it lets GTK's delayed
# inline completion land in the middle of it (".../rio.pngce/").
printf '%s' "$WORK/alice/rio.png" | xclip -quiet -selection clipboard >/dev/null 2>&1 &
PIDS+=($!)
for attempt in 1 2 3; do   # GTK4 sometimes needs a moment (and a click) before it takes keys
    glide 400 300; xdotool click 1; sleep 0.4             # empty area of the file list
    key "$PICKER" ctrl+l; sleep 0.5                        # location entry
    key "$PICKER" ctrl+a BackSpace; sleep 0.2
    key "$PICKER" ctrl+v; sleep 1.2                        # paste the image path
    key "$PICKER" Return
    sleep 1.5
    xdotool search --onlyvisible --name 'Select attachment' >/dev/null 2>&1 || break
done
sleep 2.0
# bob double-clicks the attachment line (the last line of his feed), then
# "Previsualizar" in the dialog; positions are read from bob's window pixels.
snap_bob() { ffmpeg -loglevel error -y -f x11grab -video_size 800x620 -i "$DISPLAY+800,0" -frames:v 1 "$WORK/snap.png"; }
LX=""
for _ in $(seq 1 40); do   # wait until the [IMG] offer line (2nd chat line) is there
    snap_bob
    if POS="$(python3 "$HERE/locate.py" last-line "$WORK/snap.png" 2 2>/dev/null)"; then read -r LX LY <<<"$POS"; break; fi
    sleep 0.5
done
[ -n "$LX" ] || { cp "$WORK/snap.png" "${OUT_DIR}/../attachment-failure.png" 2>/dev/null; echo "attachment offer never reached bob" >&2; exit 1; }
glide $(( 800 + LX )) "$LY"; sleep 0.3
xdotool click --repeat 2 --delay 90 1
sleep 1.5
snap_bob
read -r PX PY < <(python3 "$HERE/locate.py" first-button "$WORK/snap.png")
glide $(( 800 + PX )) "$PY"; sleep 0.3; xdotool click 1    # Previsualizar
sleep 4
glide 1500 560
rec_stop 2

# ------------------------------------------------------------------ encode
encode() {  # name [trim_start_seconds]
    local name="$1" ss="${2:-0}"
    log "encoding $name"
    ffmpeg -loglevel error -y -ss "$ss" -i "$WORK/raw/$name.mkv" -an -c:v libx264 -preset slow -crf 28 \
        -tune animation -pix_fmt yuv420p -r 30 -movflags +faststart "$OUT_DIR/$name.mp4"
    ffmpeg -loglevel error -y -ss "$ss" -i "$WORK/raw/$name.mkv" -an -c:v libvpx-vp9 -b:v 0 -crf 42 \
        -row-mt 1 -deadline good -cpu-used 2 -pix_fmt yuv420p -r 30 "$OUT_DIR/$name.webm"
    ffmpeg -loglevel error -y -sseof -1.2 -i "$OUT_DIR/$name.mp4" -frames:v 1 -q:v 4 "$OUT_DIR/$name.jpg"
}
encode admin 0
encode login 0
encode chat 0
encode private 0
encode attachment 0
log "done: $(ls "$OUT_DIR" | tr '\n' ' ')"
