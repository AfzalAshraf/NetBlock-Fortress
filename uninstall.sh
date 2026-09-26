#!/usr/bin/env bash
set -e

SERVICE_NAME="netblock"
INSTALL_DIR="/opt/netblock"

echo "🗑️  Uninstalling NetBlock Fortress..."

# Stop and disable service
if systemctl list-unit-files | grep -q "${SERVICE_NAME}.service"; then
    echo "  Stopping service..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    echo "  Service removed."
fi

# Remove installation directory
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo "  Removed $INSTALL_DIR"
fi

echo ""
echo "✅ NetBlock Fortress has been uninstalled."
echo "   Blocklists and config have been removed."
echo ""
echo "   If you set your router DNS to this server,"
echo "   remember to restore your original DNS settings!"
