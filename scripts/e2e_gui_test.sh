#!/bin/bash
# End-to-end GUI test for the airgapped Encrypt-C++ app.
#
# Runs the app on a dedicated Xvfb display (clean-room: no window manager or
# clipboard-manager interference), drives it with xdotool keyboard navigation
# and verifies the full round-trip against the CLIPBOARD selection:
#   1. encrypt: type password + plaintext, press "Cifrar", copy the envelope
#   2. decrypt: relaunch, select "Descifrar", paste password + envelope, copy
#   3. the decrypted text is byte-identical to the original plaintext
#   4. clipboard auto-clears after ENCRYPT_CLIPBOARD_TIMEOUT_MS
#   5. nothing is persisted under $HOME
#
# Text entry uses the CLIPBOARD selection (xclip owns it, ImGui Ctrl+V pastes),
# which also exercises the X11 selection plumbing of the secure clipboard.
#
# Note: ImGui windows are drawn inside the GLFW window, so they are NOT
# separate X11 windows; screen transitions are verified functionally via the
# clipboard instead of xdotool window-title searches.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/build/encrypt_app"
[ -x "$APP" ] || { echo "E2E FAIL: $APP not built"; exit 1; }

XDISPLAY=:99
export ENCRYPT_CLIPBOARD_TIMEOUT_MS=3000
export HOME=/tmp/encrypt_home

PASSWORD="e2e-contrasena-2026"
PLAINTEXT="Texto secreto para la prueba E2E: airgapped 2026"

XVFB=
APP_PID=
WID=

cleanup() {
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null
  [ -n "$XVFB" ] && kill "$XVFB" 2>/dev/null
  wait "$APP_PID" 2>/dev/null
  wait "$XVFB" 2>/dev/null
}
trap cleanup EXIT

pkill -f "$ROOT/build/encrypt_app" 2>/dev/null
pkill -f "Xvfb $XDISPLAY" 2>/dev/null
sleep 0.5
rm -rf "$HOME" && mkdir -p "$HOME"

if command -v Xvfb >/dev/null 2>&1; then
  Xvfb "$XDISPLAY" -screen 0 1280x900x24 >/tmp/opencode/e2e_xvfb.log 2>&1 &
  XVFB=$!
  sleep 1.5
  export DISPLAY=$XDISPLAY
else
  echo "E2E WARN: Xvfb not found, using existing DISPLAY=${DISPLAY:-}"
fi

launch() {
  "$APP" >/tmp/opencode/e2e_app.log 2>&1 &
  APP_PID=$!
  sleep 2.5
  WID=$(xdotool search --name "Encrypt - Cifrador local" | head -1)
  if [ -z "$WID" ]; then
    echo "E2E FAIL: window not found"; exit 1
  fi
  xdotool windowactivate "$WID" 2>/dev/null
  xdotool windowfocus "$WID" 2>/dev/null
  sleep 0.5
}

stop_app() {
  kill "$APP_PID" 2>/dev/null
  wait "$APP_PID" 2>/dev/null
  APP_PID=
  sleep 0.5
}

key() { xdotool key --window "$WID" "$1"; sleep 0.25; }

setclip() { printf '%s' "$1" | xclip -selection clipboard >/dev/null 2>&1 & sleep 0.5; }

getclip() { timeout 3 xclip -selection clipboard -o 2>/dev/null; }

# ---------------------------------------------------------------------------
# Phase A: encrypt. Focus order on this screen (no pepper):
#   [radio Cifrar, radio Descifrar, pass, confirm, pepper checkbox,
#    plaintext, perfil Estándar, perfil Máxima, Cifrar, Copiar sobre]
# ---------------------------------------------------------------------------
launch

setclip "$PASSWORD"
for _ in 1 2 3; do key Tab; done          # -> password
key ctrl+v
key Tab                                   # -> confirm
key ctrl+v
setclip "$PLAINTEXT"
key Tab                                   # -> pepper checkbox
key Tab                                   # -> plaintext
key ctrl+v
for _ in 1 2 3; do key Tab; done          # -> perfil Estándar, Máxima, Cifrar
key Return
sleep 2

ENV=
for _ in 1 2 3 4 5; do
  key Tab                                 # -> Copiar sobre (or retry)
  key Return
  sleep 0.6
  ENV=$(getclip)
  if echo "$ENV" | grep -Eq '^[A-Za-z0-9_-]{100,}$'; then break; fi
done
if ! echo "$ENV" | grep -Eq '^[A-Za-z0-9_-]{100,}$'; then
  echo "E2E FAIL: envelope copy unexpected: '${ENV:0:80}'"
  exit 1
fi
echo "E2E ok: envelope copied (${#ENV} chars)"
stop_app

# ---------------------------------------------------------------------------
# Phase B: decrypt. Focus order on this screen (no pepper):
#   [radio Cifrar, radio Descifrar, pass, pepper checkbox, sobre,
#    Descifrar, Copiar texto descifrado]
# ---------------------------------------------------------------------------
launch

for _ in 1 2; do key Tab; done            # -> Descifrar radio
key Return
sleep 0.5

setclip "$PASSWORD"
key Tab                                   # -> password
key ctrl+v
key Tab                                   # -> pepper checkbox
key Tab                                   # -> sobre
setclip "$ENV"
key ctrl+v
key Tab                                   # -> Descifrar
key Return
sleep 3

DEC=
for _ in 1 2 3 4 5; do
  key Tab                                 # -> Copiar texto descifrado
  key Return
  sleep 0.6
  DEC=$(getclip)
  if [ "$DEC" = "$PLAINTEXT" ]; then break; fi
done
if [ "$DEC" != "$PLAINTEXT" ]; then
  echo "E2E FAIL: decrypted text mismatch: '${DEC:0:80}'"
  exit 1
fi
echo "E2E ok: decrypted text round-trips"
echo "  $DEC"

# ---------------------------------------------------------------------------
# Auto-clear: the last copy restarted the 3 s timer; wait past it. The app
# owns the CLIPBOARD selection until then, and must hand it back as empty.
# ---------------------------------------------------------------------------
sleep 4
AFTER=$(getclip)
if [ -n "$AFTER" ]; then
  echo "E2E FAIL: clipboard not auto-cleared: '$AFTER'"; exit 1
fi
echo "E2E ok: clipboard auto-cleared after timeout"
stop_app

# ---------------------------------------------------------------------------
# No persistence: the app must not write anything under $HOME.
# ---------------------------------------------------------------------------
NFILES=$(find "$HOME" -type f 2>/dev/null | wc -l)
echo "HOME files: $NFILES"
if [ "$NFILES" -ne 0 ]; then
  echo "E2E FAIL: app persisted files under HOME"
  find "$HOME" -type f -exec ls -l {} \;
  exit 1
fi

echo "E2E PASS: encrypt -> copy -> decrypt -> round-trip -> auto-clear -> no persistence"
exit 0
