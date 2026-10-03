#!/usr/bin/env bash
#
# NetBlock Fortress - one-command installer ("micro + macro" ad shield, v19)
#
#   curl -fsSL https://raw.githubusercontent.com/AfzalAshraf/NetBlock-Fortress/main/install.sh | sudo bash
#
# Optional knobs (env vars, all safe to omit):
#   ADQUIT_MODE=strict|balanced|family|nuclear   protection profile   (default strict)
#   ADQUIT_HOME=/opt/adquit                      install directory    (root install)
#   ADQUIT_USER=1                                no-root install into ~/.adquit
#   ADQUIT_PASSWORD=...                          dashboard password   (default: random, printed once)
#   ADQUIT_WEB_PORT=8080                         dashboard port
#   ADQUIT_DNS_PORT=53                            DNS port
#   ADQUIT_UPSTREAM=1.1.1.1                       upstream resolver
#   ADQUIT_SKIP_LISTS=1                          do not download blocklists now
#   ADQUIT_NO_CLI=1                              do not link /usr/local/bin/adquit
#   ADQUIT_REPO / ADQUIT_REF                     fork + branch to install from
#
set -o pipefail

REPO="${ADQUIT_REPO:-AfzalAshraf/NetBlock-Fortress}"
REF="${ADQUIT_REF:-main}"
RAW="https://raw.githubusercontent.com/$REPO/$REF"
TARBALL="https://codeload.github.com/$REPO/tar.gz/refs/heads/$REF"
SERVICE="adquit"
INSTALLER_VERSION="19.3"          # this script
MIN_APP_VERSION="${ADQUIT_MIN_APP:-19.0}"   # refuse to install an older engine beside a newer CLI
HOME_DIR="${ADQUIT_HOME:-/opt/adquit}"
PROFILE="${ADQUIT_MODE:-strict}"
WEB_PORT="${ADQUIT_WEB_PORT:-8080}"
DNS_PORT="${ADQUIT_DNS_PORT:-53}"
UPSTREAM="${ADQUIT_UPSTREAM:-1.1.1.1}"
SKIP_LISTS="${ADQUIT_SKIP_LISTS:-0}"
NO_CLI="${ADQUIT_NO_CLI:-0}"

C=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; B=$'\033[1m'; D=$'\033[2m'; N=$'\033[0m' 
[ -t 1 ] || { C=""; Y=""; R=""; B=""; D=""; N=""; }
step() { printf "${B}${C}[%s/8]${N} %s\n" "$1" "$2"; }
note() { printf "        %s\n" "$1"; }
warn() { printf "        ${Y}!${N} %s\n" "$1"; }
fail() { printf "${B}${R}error:${N} %s\n" "$1" >&2; exit 1; }

OS="$(uname -s)"
IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1
HAS_SYSTEMD=""
[ -d /run/systemd/system ] && HAS_SYSTEMD=1

if [ "$IS_ROOT" = "0" ] && [ "${ADQUIT_USER:-0}" != "1" ]; then
    if command -v sudo >/dev/null 2>&1; then
        echo "re-running with sudo (or export ADQUIT_USER=1 for a no-root install)"
        exec sudo env ADQUIT_MODE="$PROFILE" ADQUIT_HOME="$HOME_DIR" ADQUIT_USER="${ADQUIT_USER:-}" \
            ADQUIT_PASSWORD="${ADQUIT_PASSWORD:-}" ADQUIT_WEB_PORT="$WEB_PORT" ADQUIT_DNS_PORT="$DNS_PORT" \
            ADQUIT_UPSTREAM="$UPSTREAM" ADQUIT_SKIP_LISTS="$SKIP_LISTS" ADQUIT_NO_CLI="$NO_CLI" \
            ADQUIT_REPO="$REPO" ADQUIT_REF="$REF" bash "$0"
    fi
    warn "no root and no sudo - installing into ~/.adquit (user mode)"
    ADQUIT_USER=1
fi
if [ "${ADQUIT_USER:-0}" = "1" ] || [ "$OS" = "Darwin" ]; then
    HOME_DIR="${ADQUIT_HOME:-$HOME/.adquit}"
    DNS_PORT="${ADQUIT_DNS_PORT:-5353}"
    [ "$IS_ROOT" = "0" ] && HAS_SYSTEMD=""
fi
STATE="$HOME_DIR/data"

echo
printf "${B}  ==============================================================${N}\n"
printf "${B}   NETBLOCK FORTRESS ${C}v19.0 \"Omni-Shield\"${N}${B}  -  micro & macro ad shield${N}\n"
printf "${B}   DNS sinkhole + creative collapse + threat intel, driven by 'adquit'${N}\n"
printf "${B}  ==============================================================${N}\n\n"

# ---------------------------------------------------------------------------
step 1 "Dependencies"
PKG=""
if command -v apt-get >/dev/null 2>&1; then PKG=apt-get
elif command -v dnf >/dev/null 2>&1; then PKG=dnf
elif command -v yum >/dev/null 2>&1; then PKG=yum
elif command -v apk >/dev/null 2>&1; then PKG=apk
elif command -v brew >/dev/null 2>&1; then PKG=brew
fi
PYBIN="$(command -v python3 || command -v python)"
if [ -z "$PYBIN" ]; then
    [ -z "$PKG" ] && fail "python3 missing and no supported package manager found - install python3 first"
    case "$PKG" in
        apt-get) apt-get update -qq && apt-get install -y -qq python3 python3-venv python3-pip curl ca-certificates ;;
        dnf)     dnf install -y -q python3 python3-pip curl ca-certificates ;;
        yum)     yum install -y -q python3 python3-pip curl ca-certificates ;;
        apk)     apk add --no-cache python3 py3-pip curl ca-certificates ;;
        brew)    brew install python3 curl ;;
    esac
    PYBIN="$(command -v python3 || command -v python)"
    [ -n "$PYBIN" ] || fail "python3 is still missing"
fi
note "python: $("$PYBIN" -V 2>&1)"
command -v curl >/dev/null 2>&1 || fail "curl is required to download the fortress"

# ---------------------------------------------------------------------------
step 2 "Install location"
if [ "$IS_ROOT" = "1" ] && [ -d /opt/netblock ] && [ ! -e /opt/adquit ]; then
    note "migrating an existing v18 install: linking /opt/adquit -> /opt/netblock"
    ln -sfn /opt/netblock /opt/adquit
    HOME_DIR=/opt/netblock; STATE="$HOME_DIR/data"
fi
mkdir -p "$HOME_DIR/bin" "$STATE/lists" "$STATE/meta" || fail "cannot create $HOME_DIR"
note "$HOME_DIR (data in $STATE)"

# ---------------------------------------------------------------------------
step 3 "Fetching NetBlock Fortress"
SRC=""
for d in "$(dirname "$(readlink -f "$0" 2>/dev/null || echo .)")/.." "$(dirname "$(readlink -f "$0" 2>/dev/null || echo .)")" "$PWD"; do
    [ -f "$d/app.py" ] && [ -f "$d/bin/adquit" ] && SRC="$d" && break
done
if [ -n "$SRC" ]; then
    note "using the local checkout: $SRC"
    install -m 0755 "$SRC/app.py" "$HOME_DIR/app.py"
    install -D -m 0755 "$SRC/bin/adquit" "$HOME_DIR/bin/adquit"
    [ -f "$SRC/requirements.txt" ] && install -m 0644 "$SRC/requirements.txt" "$HOME_DIR/requirements.txt"
else
    tmp="$(mktemp -d)"
    note "downloading https://github.com/$REPO ($REF)"
    if curl -fsSL --max-time 180 "$TARBALL" -o "$tmp/src.tar.gz" 2>/dev/null && tar -xzf "$tmp/src.tar.gz" -C "$tmp" 2>/dev/null; then
        root="$(find "$tmp" -maxdepth 1 -mindepth 1 -type d | head -n1)"
    fi
    if [ -n "${root:-}" ] && [ -f "$root/app.py" ]; then
        install -m 0755 "$root/app.py" "$HOME_DIR/app.py"
        [ -f "$root/bin/adquit" ] && install -D -m 0755 "$root/bin/adquit" "$HOME_DIR/bin/adquit"
        [ -f "$root/requirements.txt" ] && install -m 0644 "$root/requirements.txt" "$HOME_DIR/requirements.txt"
    else
        curl -fsSL --max-time 120 "$RAW/app.py" -o "$HOME_DIR/app.py" || fail "download failed ($RAW/app.py)"
        curl -fsSL --max-time 60 "$RAW/bin/adquit" -o "$HOME_DIR/bin/adquit" || warn "adquit CLI not fetched"
        chmod 0755 "$HOME_DIR/bin/adquit" 2>/dev/null || true
    fi
    rm -rf "$tmp"
fi
[ -s "$HOME_DIR/app.py" ] || fail "app.py is missing after install"

# Guard the one failure that installs silently: a ref whose app.py is older than
# this installer (e.g. main before a v19 merge, or a fork that drifted), or a
# fetched file that is not Python at all.
APP_VER="$("$PYBIN" -c 'import re, sys
try:
    src = open(sys.argv[1], errors="replace").read()
except Exception:
    print("nostamp"); sys.exit()
m = re.search(r"^VERSION[ \t]*=[ \t]*[^0-9]*([0-9][0-9.]*)", src, re.M)
print(m.group(1) if m else "nostamp")' "$HOME_DIR/app.py" 2>/dev/null)"
case "$APP_VER" in
    ""|nostamp)
        fail "the app.py fetched from $REPO/$REF is not a v$MIN_APP_VERSION fortress source (no version stamp - it is likely an older branch). Merge the newer work into $REF, install from a checkout (./install.sh), or pass ADQUIT_REF=<branch>" ;;
esac
lowest="$(printf '%s\n%s\n' "$APP_VER" "$MIN_APP_VERSION" | sort -t. -k1,1n -k2,2n | head -n1)"
if [ "$lowest" != "$MIN_APP_VERSION" ]; then
    fail "refusing to install app.py v$APP_VER from $REPO/$REF - this installer (v$INSTALLER_VERSION) needs >= v$MIN_APP_VERSION. That branch is behind: merge it into $REF, or re-run with ADQUIT_REF=<branch>"
fi
note "app.py v$APP_VER from $REPO/$REF"
# remember the channel, so `adquit update` stays on the ref this box came from
printf '%s\n' "$REF" > "$HOME_DIR/.channel" 2>/dev/null || true

# ---------------------------------------------------------------------------
step 4 "Python environment"
if [ ! -x "$HOME_DIR/venv/bin/python" ]; then
    "$PYBIN" -m venv "$HOME_DIR/venv" >/dev/null 2>&1 || note "venv unavailable, using system python"
fi
VPY="$HOME_DIR/venv/bin/python"
[ -x "$VPY" ] || VPY="$PYBIN"
if ! "$VPY" -c "import flask, requests, dnslib" >/dev/null 2>&1; then
    "$VPY" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
    "$VPY" -m pip install --quiet flask requests dnslib >/dev/null 2>&1 \
        || "$VPY" -m pip install --quiet --break-system-packages flask requests dnslib >/dev/null 2>&1 \
        || "$VPY" -m pip install --quiet --user flask requests dnslib >/dev/null 2>&1 \
        || fail "could not install flask/requests/dnslib - try: $VPY -m pip install flask requests dnslib"
fi
note "flask + requests + dnslib ready ($VPY)"

# ---------------------------------------------------------------------------
step 5 "DNS port"
RESOLVED_TOUCHED=0
if [ -n "$HAS_SYSTEMD" ] && [ "$DNS_PORT" = "53" ]; then
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if ss -ulpn 2>/dev/null | grep -q ':53 '; then
            note "systemd-resolved owns udp/53 - disabling its stub listener"
            conf=/etc/systemd/resolved.conf.d/99-adquit.conf
            mkdir -p "$(dirname "$conf")"
            printf '[Resolve]\nDNS=127.0.0.1\nDNSStubListener=no\n' > "$conf"
            systemctl restart systemd-resolved 2>/dev/null && RESOLVED_TOUCHED=1
        fi
    fi
    for other in dnsmasq pdns unbound pihole-FTL; do
        if systemctl is-active --quiet "$other" 2>/dev/null; then
            warn "$other is active and may already own udp/53 - stop it if the fortress cannot bind"
        fi
    done
fi
if ss -ulpn 2>/dev/null | grep -q ":$DNS_PORT " && [ "$RESOLVED_TOUCHED" = "0" ]; then
    who="$(ss -ulpn 2>/dev/null | grep ":$DNS_PORT " | head -n1 | sed 's/.*users://')"
    warn "udp/$DNS_PORT already in use $who"
fi

# ---------------------------------------------------------------------------
step 6 "Service"
if [ -n "$HAS_SYSTEMD" ] && [ "$IS_ROOT" = "1" ]; then
    cat > "/etc/systemd/system/$SERVICE.service" <<UNIT
[Unit]
Description=NetBlock Fortress - network-wide micro & macro ad shield
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=ADQUIT_HOME=$HOME_DIR
Environment=ADQUIT_NO_PIP=1
Environment=ADQUIT_WEB_PORT=$WEB_PORT
Environment=ADQUIT_DNS_PORT=$DNS_PORT
ExecStart=$VPY $HOME_DIR/app.py --serve
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    if [ -f /etc/systemd/system/netblock.service ]; then
        note "removing the legacy 'netblock' unit"
        systemctl stop netblock >/dev/null 2>&1 || true
        systemctl disable netblock >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/netblock.service
        systemctl daemon-reload
    fi
    cat > /etc/logrotate.d/adquit <<LOG 2>/dev/null || true
$STATE/adquit.log $STATE/queries.jsonl $STATE/gravity.log {
    size 10M
    rotate 2
    compress
    missingok
    notifempty
    copytruncate
}
LOG
    note "systemd unit '$SERVICE' installed + enabled"
    START_CMD="systemctl start $SERVICE"
elif [ "$OS" = "Darwin" ]; then
    PLIST="$HOME/Library/LaunchAgents/com.adquit.fortress.plist"
    mkdir -p "$(dirname "$PLIST")"
    cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.adquit.fortress</string>
  <key>ProgramArguments</key><array>
    <string>$VPY</string><string>$HOME_DIR/app.py</string><string>--serve</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <string>ADQUIT_HOME</string><string>$HOME_DIR</string>
    <string>ADQUIT_DNS_PORT</string><string>$DNS_PORT</string>
    <string>ADQUIT_WEB_PORT</string><string>$WEB_PORT</string>
    <string>ADQUIT_NO_PIP</string><string>1</string>
  </dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$HOME_DIR/adquit.out</string>
  <key>StandardErrorPath</key><string>$HOME_DIR/adquit.out</string>
</dict></plist>
PLIST
    launchctl unload "$PLIST" >/dev/null 2>&1 || true
    launchctl load -w "$PLIST" >/dev/null 2>&1 || true
    note "launchd agent installed (dns on :$DNS_PORT - macOS needs sudo for :53)"
    START_CMD="launchctl load -w $PLIST"
else
    nohup env ADQUIT_HOME="$HOME_DIR" ADQUIT_DNS_PORT="$DNS_PORT" ADQUIT_WEB_PORT="$WEB_PORT" \
        "$VPY" "$HOME_DIR/app.py" --serve >> "$HOME_DIR/adquit.out" 2>&1 &
    echo $! > "$HOME_DIR/adquit.pid"
    note "no systemd here - started in the background (pid $(cat "$HOME_DIR/adquit.pid"))"
    START_CMD="already started"
fi

# ---------------------------------------------------------------------------
step 7 "Firewall & CLI"
FW_STATE="none"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    FW_STATE="ufw"
    ufw allow "$DNS_PORT"/udp >/dev/null 2>&1 || true
    ufw allow "$WEB_PORT"/tcp >/dev/null 2>&1 || true
    note "ufw: opened $DNS_PORT/udp and $WEB_PORT/tcp"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    FW_STATE="firewalld"
    firewall-cmd --permanent --add-port="$DNS_PORT"/udp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port="$WEB_PORT"/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    note "firewalld: opened $DNS_PORT/udp and $WEB_PORT/tcp"
else
    note "no active host firewall - nothing to open (a cloud box still needs its security group)"
fi
if [ "$NO_CLI" != "1" ]; then
    CLI_TARGET="/usr/local/bin/adquit"
    if [ "$IS_ROOT" = "0" ]; then
        mkdir -p "$HOME/.local/bin"
        CLI_TARGET="$HOME/.local/bin/adquit"
    fi
    # rename rather than truncate: `adquit watch` or `adquit status` can be running out of this
    # very file while the installer updates it, and a truncated script under a live bash dies
    # with a syntax error in code that is fine on disk
    CLI_TMP="$CLI_TARGET.adquit-new"
    install -m 0755 "$HOME_DIR/bin/adquit" "$CLI_TMP" 2>/dev/null \
        || cp "$HOME_DIR/bin/adquit" "$CLI_TMP" 2>/dev/null
    chmod 0755 "$CLI_TMP" 2>/dev/null || true
    mv -f "$CLI_TMP" "$CLI_TARGET" 2>/dev/null || warn "could not link $CLI_TARGET"
    note "adquit command: $CLI_TARGET"
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) [ "$IS_ROOT" = "0" ] && warn "add to PATH:  export PATH=\$HOME/.local/bin:\$PATH" ;;
    esac
    mkdir -p "$HOME_DIR/completions" 2>/dev/null || true
    cat > "$HOME_DIR/completions/adquit.bash" 2>/dev/null <<'CMP' || true
# bash completion for adquit - enable with:
#   source ~/.adquit/completions/adquit.bash      (or /opt/adquit/... for a root install)
_adquit_completions() {
    local cmds
    cmds="start stop restart status logs watch run install update upgrade gravity mode"
    cmds="$cmds block allow unblock blocklist test doctor verify-lists stats json top rules"
    cmds="$cmds passwd protect uninstall help version"
    COMPREPLY=( $(compgen -W "$cmds" -- "${COMP_WORDS[COMP_CWORD]}") )
}
complete -F _adquit_completions adquit
CMP
    cat > "$HOME_DIR/completions/_adquit" 2>/dev/null <<'CMP' || true
#compdef adquit
_adquit() { _arguments '*:command:(start stop restart status logs watch run install update gravity mode block allow unblock blocklist test doctor verify-lists stats json top rules passwd protect uninstall help version)' ; }
_adquit "$@"
CMP
fi

# ---------------------------------------------------------------------------
step 8 "Fortress configuration"
PW="${ADQUIT_PASSWORD:-}"
if [ -z "$PW" ]; then
    PW="$("$VPY" -c "import secrets,string;print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(16)))" 2>/dev/null || echo change-me-please)"
    RANDOM_PW=1
fi
"$VPY" "$HOME_DIR/app.py" --set-auth "admin" "$PW" >/dev/null 2>&1 || true
"$VPY" "$HOME_DIR/app.py" --set web_port "$WEB_PORT" >/dev/null 2>&1 || true
"$VPY" "$HOME_DIR/app.py" --set dns_port "$DNS_PORT" >/dev/null 2>&1 || true
"$VPY" "$HOME_DIR/app.py" --set dns_upstream "$UPSTREAM" >/dev/null 2>&1 || true
"$VPY" "$HOME_DIR/app.py" --mode "$PROFILE" >/dev/null 2>&1 || true
note "profile: $PROFILE | dns :$DNS_PORT | dashboard :$WEB_PORT"

if [ "$SKIP_LISTS" != "1" ]; then
    note "downloading blocklists in the background (a few hundred MB, ~2-5 min)"
    nohup env ADQUIT_HOME="$HOME_DIR" "$VPY" "$HOME_DIR/app.py" --update-lists \
        >> "$STATE/gravity.log" 2>&1 &
    disown 2>/dev/null || true
    "$VPY" "$HOME_DIR/app.py" --rebuild >/dev/null 2>&1 || true
else
    "$VPY" "$HOME_DIR/app.py" --rebuild >/dev/null 2>&1 || note "run 'adquit gravity' later to pull feeds"
fi

[ "$START_CMD" = "already started" ] || { $START_CMD >/dev/null 2>&1 || true; }
sleep 2
if curl -fsS --max-time 5 "http://127.0.0.1:$WEB_PORT/api/health" >/dev/null 2>&1; then
    note "dashboard is answering on :$WEB_PORT"
else
    warn "dashboard not answering yet - here is what the service said:"
    if [ -s "$HOME_DIR/adquit.out" ]; then
        tail -n 12 "$HOME_DIR/adquit.out" 2>/dev/null | sed 's/^/        /'
    fi
    if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        journalctl -u "$SERVICE" -n 12 --no-pager 2>/dev/null | sed 's/^/        /'
    fi
    note "the first gravity pull can take a few minutes; adquit status shows progress"
    note "reachability checks:  adquit lan      (and: sudo adquit lan open)"
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$IP" ] || IP="$(ipconfig getifaddr en0 2>/dev/null)"
[ -n "$IP" ] || IP="127.0.0.1"

echo
printf "${B}  ==============================================================${N}\n"
printf "${C}${B}   FORTRESS IS UP - every ad, pixel and beacon on your LAN dies here${N}\n"
printf "${B}  ==============================================================${N}\n"
printf "   dashboard     ${B}http://%s:%s${N}\n" "$IP" "$WEB_PORT"
printf "   login         ${B}admin${N} / ${B}%s${N}%s\n" "$PW" "${RANDOM_PW:+   (generated once - store it now)}"
printf "   dns server    ${B}%s:%s${N}\n" "$IP" "$DNS_PORT"
printf "   rules         see 'adquit stats' after the first gravity pull\n"
LAN_HOST="$(hostname 2>/dev/null || echo host)"
case "$LAN_HOST" in *.local) : ;; *) LAN_HOST="$LAN_HOST.local";; esac
printf "   from any device on this network: http://%s:$WEB_PORT\n" "$LAN_HOST"
if [ "$FW_STATE" = "none" ]; then
    printf "   %snot reachable from your laptop?%s open it with:  sudo adquit lan open\n" "$Y" "$N"
    printf "   %s(your provider security group / router ACL can block $WEB_PORT too)%s\n" "$D" "$N"
fi
printf "\n   %ssubscribe browsers to the same rules:%s  %s   (uBlock Origin: Dashboard -> Import -> Add filter list)\n" "$D" "$N" "http://$IP:$WEB_PORT/adquit.txt"
printf "\n"
printf "   ${D}protect the whole network : set your router DNS to %s${N}\n" "$IP"
printf "   ${D}protect just this machine : sudo adquit protect${N}\n"
printf "   ${D}manage everything         : adquit  /  adquit help${N}\n\n"
