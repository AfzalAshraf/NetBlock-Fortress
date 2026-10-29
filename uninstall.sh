#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="netblock"
INSTALL_DIR="/opt/netblock"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run this uninstaller as root (for example: sudo bash uninstall.sh)." >&2
    exit 1
fi

if [[ "${1:-}" != "--yes" ]]; then
    echo "This removes the NetBlock service and all data in ${INSTALL_DIR}, including configuration, custom rules, feeds, and query logs."
    if ! read -r -p "Continue? [y/N] " answer; then
        echo "No confirmation received; cancelled."
        exit 1
    fi
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
fi

REMOVE_SERVICE_USER=0
if [[ -f "${INSTALL_DIR}/.netblock-created-user" ]]; then
    REMOVE_SERVICE_USER=1
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
fi
rm -f "$SERVICE_FILE"
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    echo "Removed ${INSTALL_DIR} and its data."
fi

if [[ "$REMOVE_SERVICE_USER" -eq 1 ]] && id netblock >/dev/null 2>&1; then
    userdel netblock
    echo "Removed the system user created by the NetBlock installer."
fi

echo
echo "NetBlock Fortress has been uninstalled."
echo "Review any UFW rules added during installation with: sudo ufw status numbered"
echo "If your router points to this server for DNS, restore its previous DNS configuration."
