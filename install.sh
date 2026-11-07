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
# 发布产物是按协议分开的：bpb-linux-<arch>-<协议>，另外还有一个全协议产物
# bpb-linux-<arch>-all。默认装 vless（与 README 一致，二进制小、启动快）。
#
# 代价要写明白：分协议二进制会让面板上的 gRPC/XHTTP 开关变成空操作 —— 订阅侧
# inbound::has() 直接把它过滤掉，这是最容易被误判为"功能没做"的坑。所以默认
# 不是 all 时脚本必须警告（见下面 "installed the ...-only binary"），要用那些
# 传输就显式 --protocol all。
PROTOCOL="${BPB_PROTOCOL:-vless}"
PORT=8080
DATA_DIR=""
PREFIX="/usr/local/bin"
# Service name follows the data directory, so a second install with a different
# --data does not hijack the unit of an existing one. The default stays "bpb".
SERVICE="bpb"
NO_TUNNEL=0
UNINSTALL=0
# Empty means "generate one". A quick tunnel makes the panel reachable from the
# whole internet, so shipping a passwordless panel behind a public hostname is
# the one default this installer must not have.
PANEL_PASSWORD=""
# Memory ceiling in MiB for the service. Empty = ask the binary
# (bpb --mem-default), so the unit and the process share one source of truth.
MEM_MAX_MB=""

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
  --protocol NAME inbound protocol the binary was built with [default vless;
                  use "all" for the binary that carries every transport]
  --passwd PW     panel credential to set on install. Omit it and a random
                  one is generated and printed once (the tunnel is public)
  --mem-max N     memory ceiling in MiB for the service (systemd MemoryMax) and
                  for the relay budget. Default: whatever the binary reports
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
    --passwd)    PANEL_PASSWORD="${2:?--passwd needs a value}"; shift 2 ;;
    --mem-max)   MEM_MAX_MB="${2:?--mem-max needs a value}"; shift 2 ;;
    --no-tunnel) NO_TUNNEL=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
done

case "$PORT" in
  ""|*[!0-9]*) die "--port must be a number" ;;
esac
# Strip leading zeros TEXTUALLY, not with $((PORT)).
#
# '08080' passes the digit check and was written into settings.json verbatim,
# where a leading zero is not valid JSON: nlohmann rejects the whole file,
# load() fails, the process exits, Restart=always loops it, and the readiness
# probe below reports "panel did not answer" for a much simpler reason.
#
# Do not reach for $((PORT)) here: dash (i.e. /bin/sh on Debian and Ubuntu)
# treats a leading zero as octal and aborts with "Illegal number: 08080"
# because 8 is not an octal digit -- the script would die with an arithmetic
# error instead of a usable message.
PORT="$(printf '%s' "$PORT" | sed 's/^0*//')"
[ -z "$PORT" ] && PORT=0
# Length check first: '[ 99999999999999999999 -ge 1 ]' is itself an error in
# dash ("Illegal number"), which leaked a raw shell message to the operator.
if [ "${#PORT}" -gt 5 ]; then die "--port out of range"; fi
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port out of range"

# --mem-max is validated here, with the other arguments, and not where the unit
# is written: a bad value must fail before the script has replaced a working
# binary or touched settings.json, not after.
#
# It is checked by hand rather than left to systemd because a directive like
# MemoryMax=64G (or a typo such as 64MB) is accepted silently and means
# something else, which would remove the backstop the flag exists to set.
if [ -n "$MEM_MAX_MB" ]; then
  case "$MEM_MAX_MB" in
    *[!0-9]*) die "--mem-max must be a whole number of MiB (got '$MEM_MAX_MB')" ;;
  esac
  if [ "$MEM_MAX_MB" -lt 24 ] || [ "$MEM_MAX_MB" -gt 65536 ]; then
    die "--mem-max out of range (24..65536 MiB)"
  fi
fi

have() { command -v "$1" >/dev/null 2>&1; }

[ -z "$DATA_DIR" ] && DATA_DIR="/root/.bpbdata"

# Collapse '//', drop the trailing slash, and resolve '.' / '..' textually. The
# comparison below decides "same instance as the default" purely by string, so
# '/root/.bpbdata/' used to miss it and install a SECOND copy next to the live
# one -- same data directory, different unit and prefix -- while the real
# bpb.service kept serving the old binary. '--uninstall --data /root/.bpbdata'
# then found nothing, because the install had been registered under a slug.
norm_path() {
  _p="$1"
  case "$_p" in
    /*) : ;;
    *)  _p="$(pwd)/$_p" ;;
  esac
  while :; do
    _q="$(printf '%s' "$_p" | sed -e 's#//*#/#g' -e 's#/\./#/#g' -e 's#/\.$##')"
    # 'a/../b' -> 'b'; repeat because one pass can expose another
    _q="$(printf '%s' "$_q" | sed -e 's#/[^/][^/]*/\.\./#/#g')"
    [ "$_q" = "$_p" ] && break
    _p="$_q"
  done
  # Trailing slash (except for '/')
  [ "$_p" != "/" ] && _p="$(printf '%s' "$_p" | sed 's#/*$##')"
  printf '%s' "$_p"
}
DATA_DIR="$(norm_path "$DATA_DIR")"

# A data directory with whitespace cannot be expressed in a systemd unit without
# quoting every directive that names it (WorkingDirectory, ReadWritePaths,
# ExecStart), and getting one of them wrong fails at *namespace* setup with
#     Failed to set up mount namespacing: /root/.bpb: No such file or directory
# -- a message that points at a path which does exist. Refuse it up front
# instead of writing a unit that cannot start.
case "$DATA_DIR" in
  *[[:space:]]*|*'"'*|*"'"*)
    die "--data must not contain whitespace, single or double quotes: '$DATA_DIR'" ;;
esac

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
  # The unit and the install prefix both derive from --data, so uninstalling
  # without repeating it targets "bpb" and silently leaves the custom install
  # (and its running service) in place. Clean that up instead of reporting a
  # success that did not happen.
  [ "$DATA_DIR" = "/root/.bpbdata" ] && DATA_DIR=""
  # $unit is only assigned further down (the service section), so build it here.
  unit="/etc/systemd/system/$SERVICE.service"
  found=0
  if have systemctl && [ -f "$unit" ]; then
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "$unit"
    systemctl daemon-reload || true
    found=1
  fi
  # A nohup install (no systemd) leaves a detached process behind that keeps
  # holding the port; removing the binary while it runs hides that, and a later
  # reinstall then hits "listen failed". Kill it by its actual argv.
  if have pkill; then
    pkill -f "$PREFIX/bpb .*--port [0-9]+( |$)" 2>/dev/null || true
  fi
  if [ -f "$PREFIX/bpb" ]; then
    rm -f "$PREFIX/bpb" "$PREFIX/bpb.prev"
    found=1
  fi
  rmdir "$PREFIX" 2>/dev/null || true
  if [ "$found" = 0 ]; then
    warn "nothing installed as '$SERVICE' (looked for $unit and $PREFIX/bpb)"
    if [ -z "$DATA_DIR" ]; then
      warn "for a custom install, repeat its --data: sh install.sh --uninstall --data DIR"
    fi
    exit 1
  fi
  # A leftover drop-in (e.g. the TasksMax override) keeps applying to a later
  # reinstall of the same unit name, so remove it with the unit.
  rm -rf "/etc/systemd/system/$SERVICE.service.d" 2>/dev/null || true
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
  # --max-time is the total budget, not just the connect phase: with
  # --connect-timeout alone a half-open connection (GitHub behind a filtered
  # egress, a proxy that accepts and then stalls) hung the installer for the
  # whole retry budget with no output. 60 s is generous for a ~7 MB binary.
  if have curl; then curl -fsSL --retry 3 --connect-timeout 20 --max-time 60 -o "$2" "$1"
  elif have wget; then wget -q -T 60 -O "$2" "$1"
  else die "need curl or wget"
  fi
}

if [ -n "$LOCAL_BIN" ]; then
  [ -f "$LOCAL_BIN" ] && [ -r "$LOCAL_BIN" ] || die "--local: not a readable file: $LOCAL_BIN"
  # Refuse the obvious footgun: a Windows build shares the name but cannot run
  # here, and the failure would surface later as a vague systemd restart loop.
  if head -c 2 "$LOCAL_BIN" 2>/dev/null | grep -q 'MZ'; then
    die "--local: $LOCAL_BIN is a Windows executable (MZ header), this installer is Linux-only"
  fi
  # An MZ header only rules out Windows. The release also ships arm64, armv7,
  # 386 and riscv64 builds under the same name, and a wrong-architecture binary
  # installs cleanly, then dies with "Exec format error" in a systemd restart
  # loop that says nothing about the real cause. Compare ELF e_machine instead.
  elf_arch() {
    # $1 file -> prints amd64|arm64|386|armv7|riscv64, or nothing if not ELF.
    # tr -d '[:space:]' instead of a backslash escape: od pads its output with
    # spaces and a newline, and a literal \n inside single quotes is not
    # portable across every shell this script runs under.
    [ "$(od -An -tx1 -N4 "$1" 2>/dev/null | tr -d '[:space:]')" = "7f454c46" ] || return 0
    _m="$(od -An -tx1 -j18 -N2 "$1" 2>/dev/null | tr -d '[:space:]')"
    # e_machine, as the two bytes appear in the file (all published targets are
    # little-endian).
    case "$_m" in
      3e00) printf 'amd64' ;;
      b700) printf 'arm64' ;;
      0300) printf '386' ;;
      2800) printf 'armv7' ;;
      f300) printf 'riscv64' ;;
    esac
  }
  local_arch="$(elf_arch "$LOCAL_BIN")"
  if [ -n "$local_arch" ] && [ "$local_arch" != "$arch" ]; then
    die "--local: $LOCAL_BIN is a $local_arch binary, this machine is $arch"
  fi
  log "installing local binary $LOCAL_BIN"
  cp "$LOCAL_BIN" "$tmp/bpb" || die "--local: cannot copy $LOCAL_BIN"
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
# Keep the previous binary. systemd has Restart=always, so a bad build that
# loads settings but cannot serve loops forever with no way back except a manual
# re-download -- and the operator usually notices after the old file is gone.
if [ -f "$PREFIX/bpb" ]; then
  cp -p "$PREFIX/bpb" "$PREFIX/bpb.prev" 2>/dev/null || warn "could not save $PREFIX/bpb.prev"
fi
install -m 0755 "$tmp/bpb" "$PREFIX/bpb"
log "installed $PREFIX/bpb (previous binary kept as bpb.prev)"

# Say which inbounds the binary really carries. A trimmed binary is not an
# error, but it silently turns the panel switches for XHTTP/gRPC into no-ops,
# so the user should see it here rather than discover it in a subscription.
# This is the DEFAULT path now (vless), so it must not read like a failure:
# it says what is missing and the one command that changes it.
if [ "$PROTOCOL" != "all" ]; then
  log "this build carries the $PROTOCOL inbound only; the panel's gRPC/XHTTP"
  log "switches will not produce working subscriptions."
  log "need them? re-run with: sh install.sh --protocol all"
fi
# Two independent reasons the two transport switches may be unusable, and users
# hit them in this order: a trimmed binary does not carry them, and even a
# binary that does cannot serve them through the tunnel. Say both here so the
# panel's refusal (update-settings stores them off) is not a surprise.
if [ "$NO_TUNNEL" = 0 ]; then
  log "note: the tunnel is on, so the panel's XHTTP/gRPC switches will stay off."
  log "      Cloudflare's edge does not forward a response without Content-Length,"
  log "      so those two transports only work with the tunnel disabled (direct)."
fi

# WARP terminates in this process (in-tree WireGuard + lwIP), so there is no
# sidecar to fetch. An install left over from the retired external-sidecar
# layout may still carry one: bpb only loads it when the binary is next to
# itself, so a stale copy is dead weight that silently keeps a second WARP
# implementation around. Remove it and say so rather than leaving it behind.
if [ -f "$PREFIX/warp-rust" ]; then
  rm -f "$PREFIX/warp-rust"
  log "removed leftover $PREFIX/warp-rust (WARP is in-process now)"
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
  #
  # --no-tunnel must actually turn the tunnel OFF. The first version only wrote
  # cfTunnel.enabled=false under python3 and, when python3 was absent, printed
  # "set originPort yourself" and left the tunnel enabled -- so `--no-tunnel`
  # silently kept a quick tunnel running and kept republishing its hostname.
  #
  if grep -q '"cfTunnel"' "$DATA_DIR/settings.json" 2>/dev/null; then
    cp -p "$DATA_DIR/settings.json" "$DATA_DIR/settings.json.bpb-bak" 2>/dev/null || true
    if have python3; then
      # Python does the whole edit, not just the boolean: it can also fix a
      # field whose TYPE is wrong, which sed cannot. A hand-edited
      #     "originPort": "8080"
      # is perfectly valid JSON, so a validity check passes -- but the binary
      # reads the field with nlohmann value<int>(), which throws
      # type_error.302 on a string, and start_from_store() has no try/catch
      # around it: the process aborts at startup, systemd restarts it, it
      # aborts again. Rewriting the value as an int removes the whole class.
      if ! python3 - "$DATA_DIR/settings.json" "$PORT" "$NO_TUNNEL" <<'PY'
import json, sys
path, port, no_tunnel = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"
with open(path) as f:
    d = json.load(f)
if not isinstance(d.get("proxySettings"), dict):
    d["proxySettings"] = {}
ps = d["proxySettings"]
if not isinstance(ps.get("cfTunnel"), dict):
    ps["cfTunnel"] = {}
ct = ps["cfTunnel"]
ct["enabled"] = not no_tunnel
ct["originHost"] = "127.0.0.1"
ct["originPort"] = port          # int, never a string
with open(path, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY
      then
        cp -p "$DATA_DIR/settings.json.bpb-bak" "$DATA_DIR/settings.json" 2>/dev/null || true
        die "$DATA_DIR/settings.json could not be rewritten (not valid JSON?). The previous version was restored; fix the file and re-run."
      fi
      log "updated origin to 127.0.0.1:$PORT in existing settings.json"
    else
      # No python3. The file only needs two scalars replaced, and sed can do
      # that -- but it cannot change a value's type, and it cannot tell whether
      # what it produced is still valid JSON. So: rewrite, then verify the port
      # really came out as a bare integer, and refuse to hand the binary a file
      # it will die on.
      # Rule order matters: the float rule has to run before the plain-integer
      # one, or '8080.0' becomes '9093.0' and then '9093.00'. The quoted rule
      # only matches a fully quoted bare number, so ' 8080' (quoted, padded)
      # is NOT silently half-rewritten -- it falls to the plain rule, produces
      # broken JSON, and the verification below refuses it.
      sed -i.bpb-bak -e "s#\"originHost\"[[:space:]]*:[[:space:]]*\"[^\"]*\"#\"originHost\":\"127.0.0.1\"#" \
                       -e "s#\"originPort\"[[:space:]]*:[[:space:]]*\"[0-9][0-9]*\"#\"originPort\":$PORT#" \
                       -e "s#\"originPort\"[[:space:]]*:[[:space:]]*[0-9][0-9]*\.[0-9][0-9]*#\"originPort\":$PORT#" \
                       -e "s#\"originPort\"[[:space:]]*:[[:space:]]*[0-9][0-9]*#\"originPort\":$PORT#" \
          "$DATA_DIR/settings.json"
      # The value must now be a bare integer and the object must still close:
      # anything else means sed produced a file the binary would abort on.
      if grep -q "\"originPort\"[[:space:]]*:[[:space:]]*$PORT[[:space:]]*[,}]" "$DATA_DIR/settings.json" 2>/dev/null; then
        log "updated origin to 127.0.0.1:$PORT in existing settings.json"
      else
        cp -p "$DATA_DIR/settings.json.bpb-bak" "$DATA_DIR/settings.json" 2>/dev/null || true
        die "could not rewrite cfTunnel.originPort in $DATA_DIR/settings.json without python3 (the value is not a plain number?). The previous file was restored. Install python3, or edit the file by hand so it reads: \"originPort\": $PORT"
      fi
    fi
  else
    # No cfTunnel block at all: the sed rules have nothing to anchor on, and
    # leaving the file alone means the binary falls back to its compiled-in
    # originPort 8080 -- a tunnel that registers fine and relays to a port
    # nobody listens on. With python3 the block can simply be created; without
    # it, refuse rather than write a config that cannot work.
    if have python3; then
      python3 - "$DATA_DIR/settings.json" "$PORT" "$NO_TUNNEL" <<'PY'
import json, sys
path, port, no_tunnel = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"
with open(path) as f:
    d = json.load(f)
if not isinstance(d.get("proxySettings"), dict):
    d["proxySettings"] = {}
ps = d["proxySettings"]
if not isinstance(ps.get("cfTunnel"), dict):
    ps["cfTunnel"] = {}
ct = ps["cfTunnel"]
ct["enabled"] = not no_tunnel
ct["originHost"] = "127.0.0.1"
ct["originPort"] = port
with open(path, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY
      log "created cfTunnel block (origin 127.0.0.1:$PORT) in existing settings.json"
    else
      warn "$DATA_DIR/settings.json has no cfTunnel block and python3 is missing."
      warn "The tunnel would relay to the compiled-in default port 8080, not $PORT."
      warn "Fix by hand: add \"cfTunnel\":{\"enabled\":true,\"token\":\"\",\"originHost\":\"127.0.0.1\",\"originPort\":$PORT}"
      warn "inside proxySettings, or install python3 and re-run."
    fi
  fi
  # The switch is driven in BOTH directions -- the python3 branch above already
  # wrote cfTunnel.enabled. Only writing it for --no-tunnel meant "re-run the
  # installer to (re)enable the tunnel" did nothing: the file kept enabled=false
  # from an earlier --no-tunnel run, so the process never started a tunnel and
  # the script printed "domain not assigned yet" forever.
  #
  # Without python3 there is no safe way to flip exactly one boolean: a bare
  # s#enabled...#false# would rewrite every "enabled" in the file (wgOutbound,
  # enableXHTTP, ...). Say so instead of guessing.
  # (case 4 above -- no cfTunnel and no python3 -- has already said it cannot
  # write the block at all; do not repeat it with a vaguer message.)
  if ! have python3 && grep -q '"cfTunnel"' "$DATA_DIR/settings.json" 2>/dev/null; then
    if [ "$NO_TUNNEL" = 1 ]; then
      warn "cfTunnel.enabled was left as it was (no python3 to flip one boolean);"
      warn "turn the tunnel off in the panel: /<sp>/panel -> Cloudflare 隧道 -> 禁用"
    else
      warn "cfTunnel.enabled was left as it was (no python3); make sure it is true in"
      warn "$DATA_DIR/settings.json (panel -> Cloudflare 隧道 -> 启用)"
    fi
  fi
fi

# --- memory ceiling ----------------------------------------------------------
# Resolved BEFORE the unit is written, because the unit needs the number and the
# process will be started with the same one.
#
# The default is whatever the binary reports (bpb --mem-default). That is the
# whole point of the flag: the cgroup limit and the relay budget used to be two
# unrelated constants, and on a 100 MB container a burst of downloads reached
# exactly the 40 MB cgroup ceiling and systemd answered with
#     A process of this unit has been killed by the OOM killer.
# i.e. every live session dropped at once. Now install.sh asks the binary, the
# process clamps its relay pool to half of the same number, and an over-capacity
# connection is refused instead of the process being killed.
resolve_mem_max() {
  if [ -n "$MEM_MAX_MB" ]; then
    return 0   # already validated with the other arguments, before any change
  fi
  # Ask the binary. A binary too old to know the flag prints its help instead;
  # fall back to a value that is safe on a small box rather than guessing wildly.
  MEM_MAX_MB="$("$PREFIX/bpb" --mem-default 2>/dev/null | head -1 | tr -cd '0-9')"
  case "$MEM_MAX_MB" in
    ""|*[!0-9]*)
      MEM_MAX_MB=64
      warn "could not read --mem-default from the binary; assuming ${MEM_MAX_MB}M"
      ;;
  esac
}

resolve_mem_max
# MemoryHigh is 85% of MemoryMax: reclaim starts while there is still room to
# make progress, so the newest session is throttled rather than every session
# being dropped when the hard limit is reached.
MEM_MAX="${MEM_MAX_MB}M"
mem_high_mb=$((MEM_MAX_MB * 85 / 100))
# Never publish a MemoryHigh below the floor the binary itself accepts, or
# systemd would reclaim constantly on a hand-picked small --mem-max.
if [ "$mem_high_mb" -lt 24 ]; then mem_high_mb=24; fi
MEM_HIGH="${mem_high_mb}M"
log "memory ceiling: MemoryMax=$MEM_MAX MemoryHigh=$MEM_HIGH"

# --- panel credential --------------------------------------------------------
# A quick tunnel publishes the panel to the whole internet under a random
# hostname, and the hostname is the only secret. Shipping that with an empty
# <data>/passwd means Store::has_pwd() is false, so no route asks for a login at
# all: anyone who reads the URL from a proxy log owns the subscriptions, the
# WARP pool and the settings. So an install either takes --passwd or gets one
# generated here, printed once.
#
# Idempotent on purpose: a re-run over an install that already has a credential
# must not replace it with a fresh password the operator never gets to see.
PANEL_PASSWORD_GENERATED=0
ensure_password() {
  if [ -f "$DATA_DIR/passwd" ]; then
    log "panel credential already set ($DATA_DIR/passwd); left untouched"
    return 0
  fi
  _pw="$PANEL_PASSWORD"
  _generated=0
  if [ -z "$_pw" ]; then
    # 24 hex chars from the kernel, no dependency on openssl/base64 being present.
    if [ -r /proc/sys/kernel/random/uuid ]; then
      _pw="$(tr -d '-' < /proc/sys/kernel/random/uuid | cut -c1-24)"
    elif [ -r /dev/urandom ]; then
      _pw="$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')"
    elif have sha256sum; then
      _pw="$(date +%s%N | sha256sum | cut -c1-24)"
    else
      # Last resort: still unique per install, just not cryptographic.
      _pw="$(date +%s)-$$"
    fi
    _generated=1
  fi
  # The binary owns the format (salted SHA-256 in <data>/passwd, mode 0600) and
  # also rotates the JWT key so previously issued cookies die with the old one.
  if "$PREFIX/bpb" --passwd "$_pw" --data "$DATA_DIR" >/dev/null 2>&1; then
    if [ "$_generated" = 1 ]; then
      PANEL_PASSWORD="$_pw"
      PANEL_PASSWORD_GENERATED=1
    else
      log "panel credential set from --passwd"
    fi
  else
    PANEL_PASSWORD=""
    warn "could not set a panel credential; the panel will accept anyone who"
    warn "knows its URL. Fix with: $PREFIX/bpb --passwd <pw> --data $DATA_DIR"
  fi
}

# Set the credential BEFORE the service is (re)started: the first panel request
# after the unit comes up must already demand a login. Doing it afterwards left
# a window where a freshly published tunnel hostname answered without one.
ensure_password

# --- service ----------------------------------------------------------------
unit="/etc/systemd/system/$SERVICE.service"
# 'systemctl exists' is not 'systemd runs this container'. On a plain container
# (or a WSL rootfs) /usr/bin/systemctl is present while it cannot talk to PID 1,
# so the unit was written, 'systemctl restart' failed, and the script exited on
# a bare non-zero status with the panel never started. Detect it and fall through
# to the nohup path instead.
#
# The test is two-part on purpose:
#   * /run/systemd/system is the canonical "systemd is PID 1" marker -- systemd
#     creates it only when it boots as init, and a plain container has the
#     systemctl binary without it;
#   * 'systemctl is-system-running' must then produce SOME state. It exits
#     non-zero for "degraded" (one unrelated failed unit -- common on a VPS) and
#     for "starting", so its exit status alone is the wrong signal and using it
#     by itself silently skipped systemd on healthy boxes. What matters here is
#     that systemctl can reach PID 1 at all, i.e. that it printed a state.
systemd_state=""
if have systemctl; then
  systemd_state="$(systemctl is-system-running 2>/dev/null || true)"
fi
if [ -d /run/systemd/system ] && [ -n "$systemd_state" ]; then
  cat > "$unit" <<UNIT
[Unit]
Description=bpb panel
After=network-online.target
Wants=network-online.target
# A unit that cannot even load its settings.json (hand-edited JSON, wrong
# permissions) restarts forever otherwise. 12 starts in 60 s then systemd gives
# up and reports "start request repeated too quickly", which surfaces the real
# failure instead of an endless journal loop. These two live in [Unit] since
# systemd 230; in [Service] they are ignored.
StartLimitIntervalSec=60
StartLimitBurst=12

[Service]
Type=simple
WorkingDirectory=$DATA_DIR
# Every proxied session runs on its own threads, and glibc keeps the stacks of
# exited threads in a cache (40 MB by default). A minute of load then leaves
# several MB resident with nothing using them. 1 MB still caches ~8 relay
# stacks; measured 100 short sessions -> 8.3 MB RSS instead of 10.7 MB.
Environment=GLIBC_TUNABLES=glibc.pthread.stack_cache_size=1048576
# One malloc arena per thread is what turned a burst of sessions into a
# multi-arena heap that glibc only trims on its own schedule. Two arenas keep
# contention low on a single-core box without letting the retained free space
# scale with the number of relay threads.
Environment=MALLOC_ARENA_MAX=2
# Return a freed top-of-heap page range to the kernel as soon as it is large
# enough to matter; the default (128 KiB) already does this, but a smaller
# threshold makes the peak decay faster after a burst instead of waiting for
# the next large free.
Environment=MALLOC_TRIM_THRESHOLD_=65536
# Memory ceiling. The value comes from --mem-max, or from the binary itself
# (bpb --mem-default) so the unit and the process can never disagree: the same
# number also drives the relay-buffer budget, which refuses extra sessions
# instead of letting the kernel OOM-kill the whole process.
#
# MemoryHigh sits below MemoryMax on purpose: reclaim starts while there is
# still room to make progress, so the newest session is throttled rather than
# every session being dropped by the OOM killer at once.
MemoryHigh=$MEM_HIGH
MemoryMax=$MEM_MAX
# Sandboxing. Everything below is safe for this daemon specifically, which is a
# single static binary that reads and writes one directory and nothing else:
#   * it never exec()s anything (no shells, no helper binaries), so PID/whoami
#     views and NoNewPrivileges cost nothing;
#   * NoNewPrivileges also neuters a setuid helper if one ever ships;
#   * it needs CAP_NET_BIND_SERVICE only when --port < 1024;
#   * AF_UNIX socketpair and AF_INET/AF_INET6 sockets are all it creates, so the
#     address families are spelled out instead of left open;
#   * the data directory is the only writable path.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
# --mem-max carries the same ceiling into the process, which clamps its relay
# buffer pool to half of it. Without it the budget would be sized from settings
# alone and could reserve more than the cgroup above allows.
ExecStart=$PREFIX/bpb --host 0.0.0.0 --port $PORT --data $DATA_DIR --mem-max $MEM_MAX_MB
Restart=always
RestartSec=5
LimitNOFILE=65535
# Every proxied session runs two relay threads (one per direction), so the thread
# budget is the real concurrency limit -- not file descriptors. systemd defaults
# TasksMax to 15% of the container's pids.max; inside an LXC with pids.max=128
# that is 19 tasks, i.e. roughly ten concurrent proxy sessions, after which
# pthread_create fails with EAGAIN, the relay thread never starts, and the client
# times out. "TasksMax=infinity" defers to the container's own limit.
TasksMax=infinity

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE"
  log "service $SERVICE started"
else
  warn "systemd not usable here; starting in the background with nohup"
  # The pattern has to match the argv ExecStart actually uses:
  #   bpb --host 0.0.0.0 --port N --data DIR
  # The old one, "$PREFIX/bpb --port N", required --port to come immediately
  # after the binary path, so it never matched: the previous instance kept the
  # port, the new one exited with "listen failed", and the readiness probe below
  # happily talked to the OLD process and reported a successful upgrade.
  # ( |$) keeps --port 9099 from matching --port 90990.
  pkill -f "$PREFIX/bpb .*--port $PORT( |$)" 2>/dev/null || true
  sleep 1
  ( cd "$DATA_DIR" && GLIBC_TUNABLES=glibc.pthread.stack_cache_size=1048576 \
      setsid nohup "$PREFIX/bpb" --host 0.0.0.0 --port "$PORT" --data "$DATA_DIR" --mem-max "$MEM_MAX_MB" \
      > "$DATA_DIR/bpb.log" 2>&1 < /dev/null & )
fi

# --- wait for it to answer --------------------------------------------------
SP=""; DOMAIN=""

# curl is required from here on: the readiness and hostname probes below use
# `-w %{redirect_url}`, which wget cannot do. fetch() above deliberately
# accepts wget, so say this out loud instead of looping for 40 s and then
# blaming the panel.
if ! have curl; then
  die "curl is required for the readiness probe (wget cannot report a redirect); install curl and re-run"
fi
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
#
# `X-BPB-CLI: 1` is mandatory here, not a shortcut: /panel/tunnel-status is
# behind the panel credential, so on any install that already has a password
# (i.e. every re-run and every upgrade) an unauthenticated read answers 401 and
# the hostname comes back empty. The script then told the operator "domain not
# assigned yet; check journalctl" while the tunnel was perfectly connected.
# A local process is the operator and gets full access (see README).
if [ "$NO_TUNNEL" = 0 ]; then
  tries=0
  while [ "$tries" -lt 45 ]; do
    sleep 2
    tries=$((tries + 1))
    js="$(curl -s -H 'X-BPB-CLI: 1' "http://127.0.0.1:$PORT/$SP/panel/tunnel-status" 2>/dev/null || true)"
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
if [ "$PANEL_PASSWORD_GENERATED" = 1 ] && [ -n "$PANEL_PASSWORD" ]; then
  printf "  面板密码    : %s\n" "$PANEL_PASSWORD"
  printf "                （只在这里显示一次；改密码用 %s --passwd <新密码>）\n" "$PREFIX/bpb"
elif [ -f "$DATA_DIR/passwd" ]; then
  printf "  面板密码    : 已设置（%s，本脚本不读取明文）\n" "$DATA_DIR/passwd"
else
  printf "  面板密码    : \033[1;31m未设置——任何拿到地址的人都能进面板\033[0m\n"
  printf "                先跑：%s --passwd <密码> --data %s\n" "$PREFIX/bpb" "$DATA_DIR"
fi
printf "\n  数据目录: %s\n" "$DATA_DIR"
printf "  内存上限: %s (MemoryHigh %s)\n" "$MEM_MAX" "$MEM_HIGH"
printf "  日志    : journalctl -u %s -f\n" "$SERVICE"
# A custom instance is uninstalled by repeating its --data; printing the bare
# command there aims the operator at bpb.service, and the script then refuses
# with "nothing installed as 'bpb'". Spell out the command that will work.
if [ "$DATA_DIR" = "/root/.bpbdata" ]; then
  printf "  卸载    : sh install.sh --uninstall\n"
else
  printf "  卸载    : sh install.sh --uninstall --data %s\n" "$DATA_DIR"
fi
printf "  回滚    : %s/bpb.prev（上一版二进制）\n\n" "$PREFIX"
