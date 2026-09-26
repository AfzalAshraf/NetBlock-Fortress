
---

### `install.sh`

```bash
#!/usr/bin/env bash
set -e

echo "=============================================="
echo "  🛡️  NetBlock Fortress - Installer v18.0"
echo "=============================================="

INSTALL_DIR="/opt/netblock"
SERVICE_NAME="netblock"

# Detect package manager
if command -v apt-get &>/dev/null; then
    PKG="apt-get"
elif command -v dnf &>/dev/null; then
    PKG="dnf"
elif command -v yum &>/dev/null; then
    PKG="yum"
else
    PKG="unknown"
fi

# Install system dependencies
echo "[1/7] Installing system dependencies..."
if [ "$PKG" = "apt-get" ]; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv curl git
elif [ "$PKG" = "dnf" ] || [ "$PKG" = "yum" ]; then
    $PKG install -y python3 python3-pip curl git
else
    echo "Please install python3, python3-pip, python3-venv, curl manually."
    exit 1
fi

# Disable systemd-resolved if it's occupying port 53
echo "[2/7] Checking DNS port (53)..."
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo "  Disabling systemd-resolved DNSStubListener..."
    sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 2>/dev/null || true
    sed -i 's/DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 2>/dev/null || true
    systemctl restart systemd-resolved 2>/dev/null || true
fi

# Check if port 53 is already occupied
if ss -tulnp | grep -q ':53 ' 2>/dev/null; then
    PIDS=$(ss -tulnp | grep ':53 ' | grep -oP 'pid=\K\d+' | sort -u)
    for pid in $PIDS; do
        CMD=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        if [ "$CMD" != "netblock" ] && [ "$CMD" != "python3" ]; then
            echo "  WARNING: Port 53 occupied by '$CMD' (PID $pid)"
            echo "  NetBlock needs port 53 for DNS. You may need to stop '$CMD'."
        fi
    done
fi

# Create install directory
echo "[3/7] Setting up installation directory..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Copy app.py
if [ -f "./app.py" ]; then
    echo "  Using local app.py"
elif [ -f "$OLDPWD/app.py" ]; then
    cp "$OLDPWD/app.py" "$INSTALL_DIR/app.py"
else
    echo "  Downloading app.py from GitHub..."
    curl -fsSL "https://raw.githubusercontent.com/YOUR_USERNAME/netblock-fortress/main/app.py" -o "$INSTALL_DIR/app.py"
fi

# Create Python virtual environment
echo "[4/7] Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"

# Install Python packages
echo "[5/7] Installing Python packages..."
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet flask requests dnslib

# Install systemd service
echo "[6/7] Installing systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << SERVICEEOF
[Unit]
Description=NetBlock Fortress - Network Ad Blocker & Threat Protection
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/app.py
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# Open firewall ports if ufw is active
echo "[7/7] Checking firewall..."
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow 53/udp 2>/dev/null || true
    ufw allow 8080/tcp 2>/dev/null || true
    echo "  Firewall rules added (53/udp, 8080/tcp)"
fi

# Detect server IP
SERVER_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "YOUR_SERVER_IP")

echo ""
echo "=============================================="
echo "  ✅ NetBlock Fortress installed successfully!"
echo "=============================================="
echo ""
echo "  Dashboard:    http://${SERVER_IP}:8080"
echo "  DNS Server:   ${SERVER_IP}:53"
echo "  Login:        admin / admin123  (CHANGE THIS!)"
echo ""
echo "  Next steps:"
echo "  1. Open http://${SERVER_IP}:8080 in your browser"
echo "  2. Log in with admin / admin123"
echo "  3. Go to Settings and change your password"
echo "  4. Set your router DNS to ${SERVER_IP}"
echo ""
echo "  Manage: sudo systemctl ${SERVICE_NAME} {start|stop|restart|status}"
echo "  Logs:   sudo journalctl -u ${SERVICE_NAME} -f"
echo "  Uninstall: sudo bash uninstall.sh"
echo "=============================================="
