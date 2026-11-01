#!/bin/sh
# bpb installer: download, install as a service, bring up a quick tunnel.
#
# Linux only. Windows builds ship with the panel UI and are left alone.
#
#   curl -fsSL https://raw.githubusercontent.com/ycm50/bpb-panel-cpp/warp-built-in/install.sh | sh
#   sh install.sh --port 8080
#
# The first run registers an ad-hoc Cloudflare tunnel so the panel is reachable
# from anywhere without opening a firewall port; the script prints its domain.
set -eu

REPO="ycm50/bpb-panel-cpp"
TAG="${BPB_TAG:-latest}"
LOCAL_BIN=""
# 发布产物是按协议分开的：bpb-linux-<arch>-<协议>。默认装 VLESS。
PROTOCOL="${BPB_PROTOCOL:-vless}"
PORT=8080
DATA_DIR=""
PREFIX="/usr/local/bin"
# Service name follows the data directory, so a second install with a different
# --data does not hijack the unit of an existing one. The default stays "bpb".
SERVICE="bpb"
NO_TUNNEL=0
UNINSTALL=0

log()  { printf "\033[1;34m==>\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m warn\033[0m %s\n" "$*" >&2; }
die()  { printf "\033[1;31merror\033[0m %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
bpb installer

  --port N        panel port (the tunnel relays to it too)   [default 8080]
  --data DIR      data directory                            [default /root/.bpbdata]
  --tag TAG       release tag to install                    [default latest]
  --local PATH    install this binary instead of downloading it
  --protocol NAME inbound protocol the binary was built with [default vless]
  --no-tunnel     do not enable the built-in quick tunnel
  --uninstall     stop and remove the service
  -h, --help      this text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --port)      PORT="${2:?--port needs a value}"; shift 2 ;;
    --data)      DATA_DIR="${2:?--data needs a value}"; shift 2 ;;
    --tag)       TAG="${2:?--tag needs a value}"; shift 2 ;;
    --local)     LOCAL_BIN="${2:?--local needs a path}"; shift 2 ;;
    --protocol)  PROTOCOL="${2:?--protocol needs a value}"; shift 2 ;;
    --no-tunnel) NO_TUNNEL=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
done

case "$PORT" in
  ""|*[!0-9]*) die "--port must be a number" ;;
esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port out of range"

have() { command -v "$1" >/dev/null 2>&1; }

[ -z "$DATA_DIR" ] && DATA_DIR="/root/.bpbdata"

# A non-default data directory is a separate instance: give it its own unit and
# binary so a second install (or a test run) cannot hijack a live one --
# otherwise `--data /root/.bpbtest --port 9099` rewrites bpb.service and the
# real panel stops answering on its own port.
if [ "$DATA_DIR" != "/root/.bpbdata" ]; then
  # Reduce the path to a unit-safe slug without relying on tr's locale
  # behaviour (a non-C locale left "--" runs and broke the unit name).
  slug="$(printf "%s" "$DATA_DIR" | sed 's#^/##; s#/#-#g; s#[^A-Za-z0-9._-]#-#g; s#--*#-#g; s#^[-.][-.]*##; s#[-.]*$##')"
  SERVICE="bpb-$slug"
  PREFIX="/usr/local/lib/$SERVICE"
fi

if [ "$UNINSTALL" = 1 ]; then
  [ "$(id -u)" = 0 ] || die "run as root"
  if have systemctl && [ -f "/etc/systemd/system/$SERVICE.service" ]; then
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE.service"
    systemctl daemon-reload || true
  fi
  rm -f "$PREFIX/bpb"
  rmdir "$PREFIX" 2>/dev/null || true
  log "uninstalled $SERVICE (data directory kept)"
  exit 0
fi

[ "$(id -u)" = 0 ] || die "run as root (it installs a systemd service)"

# --- architecture -----------------------------------------------------------
# The release ships one static musl binary per architecture.
arch=""
case "$(uname -m)" in
  x86_64|amd64)   arch=amd64 ;;
  aarch64|arm64)  arch=arm64 ;;
  armv7l|armv7|armhf) arch=armv7 ;;
  i386|i486|i586|i686|x86) arch=386 ;;
  riscv64)        arch=riscv64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
[ "$(uname -s)" = "Linux" ] || die "this installer is Linux-only"
log "architecture: $arch"

# --- download ---------------------------------------------------------------
# 按协议分开命名的产物优先；老 release（改名之前）只有 bpb-linux-<arch>，
# 所以找不到新名字时退回旧名字，而不是直接失败。
asset="bpb-linux-$arch-$PROTOCOL"
legacy_asset="bpb-linux-$arch"
if [ "$TAG" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$TAG"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch() {
  if have curl; then curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1"
  elif have wget; then wget -q -T 20 -O "$2" "$1"
  else die "need curl or wget"
  fi
}

if [ -n "$LOCAL_BIN" ]; then
  [ -f "$LOCAL_BIN" ] || die "--local: no such file: $LOCAL_BIN"
  log "installing local binary $LOCAL_BIN"
  cp "$LOCAL_BIN" "$tmp/bpb"
else
log "downloading $asset ($TAG)"
if ! fetch "$base/$asset" "$tmp/bpb"; then
  if fetch "$base/$legacy_asset" "$tmp/bpb" 2>/dev/null; then
    warn "$asset not found in this release; using $legacy_asset (no per-protocol binaries)"
    asset="$legacy_asset"
  else
  cat >&2 <<EOF

download failed: $base/$asset

That URL 404s while the release has not been built. This repository publishes
binaries from a MANUAL workflow, so a tag on its own is not enough:

  GitHub -> Actions -> build -> Run workflow   (enter the tag number)

The tag is created only after every architecture succeeds. Once it exists:

  sh install.sh --tag <tag>

To install a binary you already have:

  install -m0755 ./bpb /usr/local/bin/bpb
  sh install.sh --no-tunnel --port 8080
EOF
  exit 1
  fi
fi
fi

# Verify against SHA256SUMS when the release carries it.
if [ -z "$LOCAL_BIN" ] && fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" 2>/dev/null; then
  want="$(awk -v a="$asset" '$2==a {print $1}' "$tmp/SHA256SUMS")"
  if [ -n "$want" ]; then
    if have sha256sum; then got="$(sha256sum "$tmp/bpb" | awk '{print $1}')"
    elif have shasum; then got="$(shasum -a 256 "$tmp/bpb" | awk '{print $1}')"
    else got="" ; fi
    if [ -n "$got" ] && [ "$got" != "$want" ]; then
      die "checksum mismatch for $asset"
    fi
    [ -n "$got" ] && log "checksum ok"
  fi
else
  warn "SHA256SUMS unavailable, skipping checksum"
fi

install -d "$PREFIX"
install -m 0755 "$tmp/bpb" "$PREFIX/bpb"
log "installed $PREFIX/bpb"

# The warp-rust branch keeps its WARP outbound in a second binary that bpb looks
# for next to itself; the warp-built-in branch has it in-process and the release
# simply carries no such asset. Fetch it when present, warn when not -- a missing
# sidecar only costs the WARP outbound, the panel and VLESS keep working.
if [ -z "$LOCAL_BIN" ] && fetch "$base/warp-rust-linux-$arch" "$tmp/warp-rust" 2>/dev/null; then
  install -m 0755 "$tmp/warp-rust" "$PREFIX/warp-rust"
  log "installed $PREFIX/warp-rust (external WARP outbound)"
else
  log "release has no warp-rust sidecar: WARP runs in-process (warp-built-in)"
fi

# --- data directory ---------------------------------------------------------
mkdir -p "$DATA_DIR"

# Seed cfTunnel.enabled with an EMPTY token: that is the documented way to ask
# for an ad-hoc quick tunnel, and the domain it allocates becomes mainDomain so
# generated subscriptions point at a reachable host.
#
# originPort MUST match --port. It defaults to 8080 in the binary, so a panel
# on any other port would register a working tunnel that relays to nothing.
if [ ! -f "$DATA_DIR/settings.json" ]; then
  enabled=false
  [ "$NO_TUNNEL" = 0 ] && enabled=true
  cat > "$DATA_DIR/settings.json" <<JSON
{"proxySettings":{"cfTunnel":{"enabled":$enabled,"token":"","originHost":"127.0.0.1","originPort":$PORT}},"telegramBot":{},"warpAccounts":[],"pwd":"","secretKey":""}
JSON
  log "wrote $DATA_DIR/settings.json (tunnel=$enabled, origin 127.0.0.1:$PORT)"
else
  # Existing install: keep every other setting, only repoint the origin.
  if have python3; then
    python3 - "$DATA_DIR/settings.json" "$PORT" "$NO_TUNNEL" <<'PY' && log "updated origin port in existing settings.json"
import json, sys
path, port, no_tunnel = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"
try:
    with open(path) as f: d = json.load(f)
except Exception:
    sys.exit(1)
ps = d.setdefault("proxySettings", {})
ct = ps.setdefault("cfTunnel", {})
ct["originHost"] = "127.0.0.1"
ct["originPort"] = port
if no_tunnel:
    ct["enabled"] = False
with open(path, "w") as f: json.dump(d, f, indent=2)
PY
  else
    warn "python3 missing: set cfTunnel.originPort=$PORT in $DATA_DIR/settings.json yourself"
  fi
fi

# --- service ----------------------------------------------------------------
unit="/etc/systemd/system/$SERVICE.service"
if have systemctl; then
  cat > "$unit" <<UNIT
[Unit]
Description=bpb panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DATA_DIR
ExecStart=$PREFIX/bpb --host 0.0.0.0 --port $PORT --data $DATA_DIR
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE"
  log "service $SERVICE started"
else
  warn "systemd not found; starting in the background with nohup"
  pkill -f "$PREFIX/bpb --port $PORT" 2>/dev/null || true
  ( cd "$DATA_DIR" && setsid nohup "$PREFIX/bpb" --host 0.0.0.0 --port "$PORT" --data "$DATA_DIR" \
      > "$DATA_DIR/bpb.log" 2>&1 < /dev/null & )
fi

# --- wait for it to answer --------------------------------------------------
SP=""; DOMAIN=""
tries=0
while [ "$tries" -lt 40 ]; do
  sleep 1
  tries=$((tries + 1))
  # The redirect from / gives the secure path without needing the JSON API.
  loc="$(curl -s -o /dev/null -w "%{redirect_url}" "http://127.0.0.1:$PORT/" 2>/dev/null || true)"
  if [ -n "$loc" ]; then
    SP="$(printf "%s" "$loc" | sed -n "s#.*/\([^/]*\)/panel.*#\1#p")"
    break
  fi
done
[ -n "$SP" ] || die "panel did not answer on port $PORT; check: journalctl -u $SERVICE -n 50"

# The tunnel registers in the background; poll for the hostname it allocates.
if [ "$NO_TUNNEL" = 0 ]; then
  tries=0
  while [ "$tries" -lt 45 ]; do
    sleep 2
    tries=$((tries + 1))
    js="$(curl -s "http://127.0.0.1:$PORT/$SP/panel/tunnel-status" 2>/dev/null || true)"
    DOMAIN="$(printf "%s" "$js" | sed -n 's/.*"hostname":"\([^"]*\)".*/\1/p')"
    [ -n "$DOMAIN" ] && break
  done
fi

echo
log "done"
printf "\n"
printf "  面板（本机）: http://127.0.0.1:%s/%s/panel\n" "$PORT" "$SP"
if [ -n "$DOMAIN" ]; then
  printf "  面板（公网）: https://%s/%s/panel\n" "$DOMAIN" "$SP"
  printf "  隧道域名    : %s\n" "$DOMAIN"
  printf "\n  临时隧道随时可能被回收；需要固定域名就换成命名隧道的 token：\n"
  printf "  /%s/panel → Cloudflare 隧道 → 隧道 Token\n" "$SP"
else
  [ "$NO_TUNNEL" = 1 ] && warn "tunnel disabled (--no-tunnel)" || warn "tunnel domain not assigned yet; check journalctl -u $SERVICE"
fi
printf "\n  数据目录: %s\n" "$DATA_DIR"
printf "  日志    : journalctl -u %s -f\n" "$SERVICE"
printf "  卸载    : sh install.sh --uninstall\n\n"
