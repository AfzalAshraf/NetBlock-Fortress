#!/usr/bin/env bash
#
# NetBlock Fortress - clean removal.
#
#   sudo bash uninstall.sh              remove everything (rules, feeds, config)
#   sudo bash uninstall.sh --keep-data  keep /opt/adquit/data (feeds + rules)
#
# Restores systemd-resolved / NetworkManager changes made by install.sh.
set -o pipefail
SERVICE="adquit"
KEEP=0
[ "${1:-}" = "--keep-data" ] && KEEP=1
R="\033[31m"; C="\033[32m"; B="\033[1m"; N="\033[0m"
[ -t 1 ] || { C=""; R=""; B=""; N=""; }
say() { printf "  ${B}>${N} %s\n" "$1"; }

if [ "$(id -u)" != "0" ] && command -v sudo >/dev/null 2>&1; then
    exec sudo env ADQUIT_HOME="${ADQUIT_HOME:-}" bash "$0" "$@"
fi

# find the fortress home: $ADQUIT_HOME wins, then the system install, then this
# user's, then the invoking user's (sudo replaces $HOME with /root).
REAL_HOME="$(getent passwd "${SUDO_USER:-}" 2>/dev/null | cut -d: -f6)"
HOME_DIR=""
for base in "${ADQUIT_HOME:-}" /opt/adquit "$HOME/.adquit" "/home/${SUDO_USER:-}/.adquit" "$REAL_HOME/.adquit"; do
    [ -n "$base" ] && [ -f "$base/app.py" ] && HOME_DIR="$base" && break
done
[ -n "$HOME_DIR" ] || HOME_DIR=/opt/adquit

printf "\n${B}Uninstalling NetBlock Fortress${N}  (home: %s)\n\n" "$HOME_DIR"

if command -v systemctl >/dev/null 2>&1 && [ -f "/etc/systemd/system/$SERVICE.service" ]; then
    say "stopping + disabling the systemd service"
    systemctl stop "$SERVICE" 2>/dev/null || true
    systemctl disable "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE.service" /etc/logrotate.d/adquit
    systemctl daemon-reload
fi
if [ -f "/etc/systemd/system/netblock.service" ]; then
    say "removing the legacy netblock service"
    systemctl stop netblock 2>/dev/null || true
    systemctl disable netblock 2>/dev/null || true
    rm -f /etc/systemd/system/netblock.service
    systemctl daemon-reload
fi
if [ -f "$HOME_DIR/adquit.pid" ]; then
    say "killing the background runner"
    kill "$(cat "$HOME_DIR/adquit.pid")" 2>/dev/null || true
    rm -f "$HOME_DIR/adquit.pid"
fi
pkill -f "$HOME_DIR/app.py --serve" 2>/dev/null || true
pkill -f "$HOME_DIR/app.py$" 2>/dev/null || true

if command -v launchctl >/dev/null 2>&1; then
    PLIST="$HOME/Library/LaunchAgents/com.adquit.fortress.plist"
    [ -f "$PLIST" ] && { say "removing the launchd agent"; launchctl unload "$PLIST" 2>/dev/null || true; rm -f "$PLIST"; }
fi

say "restoring resolver settings"
if [ -f /etc/systemd/resolved.conf.d/99-adquit.conf ]; then
    rm -f /etc/systemd/resolved.conf.d/99-adquit.conf
    systemctl restart systemd-resolved 2>/dev/null || true
    sed -i '/DNSStubListener=no/d' /etc/systemd/resolved.conf 2>/dev/null || true
fi
if [ -f /etc/resolv.conf.adquit.bak ]; then
    cp -f /etc/resolv.conf.adquit.bak /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf.adquit.bak
fi
if command -v nmcli >/dev/null 2>&1; then
    con="$(nmcli -t -f NAME c show --active 2>/dev/null | head -n1)"
    if [ -n "$con" ]; then
        nmcli connection modify "$con" ipv4.dns "" ipv4.ignore-auto-dns no >/dev/null 2>&1 || true
    fi
fi

if [ "$KEEP" = "1" ]; then
    say "removing binaries, keeping $HOME_DIR/data"
    rm -f "$HOME_DIR/app.py" "$HOME_DIR/bin/adquit"
else
    say "removing $HOME_DIR"
    rm -rf "$HOME_DIR"
fi
rm -f /usr/local/bin/adquit "$HOME/.local/bin/adquit"

printf "\n  ${C}done${N}. Blocklists, service and command are gone.\n"
printf "  If your router still points at this machine for DNS, set it back now\n"
printf "  (auto/DHCP is fine) or devices will stop resolving.\n\n"
