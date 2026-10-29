#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/netblock"
SERVICE_NAME="netblock"
REPO_RAW="https://raw.githubusercontent.com/AfzalAshraf/NetBlock-Fortress/main"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run this installer as root (for example: sudo bash install.sh)." >&2
    exit 1
fi

echo "=============================================="
echo "  NetBlock Fortress v19.0 installer"
echo "=============================================="

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv curl ca-certificates iproute2
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip curl ca-certificates iproute
elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip curl ca-certificates iproute
else
    echo "Install Python 3, pip, venv, curl, and iproute manually, then rerun." >&2
    exit 1
fi

# Use the checkout when run from the repository; curl | sudo bash falls back to GitHub.
SOURCE_DIR=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
for candidate in "$PWD" "$SCRIPT_DIR" "${NETBLOCK_SOURCE_DIR:-}"; do
    if [[ -n "$candidate" && -f "$candidate/app.py" && -f "$candidate/adblock_rules.py" && -f "$candidate/requirements.txt" ]]; then
        SOURCE_DIR="$candidate"
        break
    fi
done

mkdir -p "$INSTALL_DIR"
if [[ -n "$SOURCE_DIR" ]]; then
    cp "$SOURCE_DIR/app.py" "$INSTALL_DIR/app.py"
    cp "$SOURCE_DIR/adblock_rules.py" "$INSTALL_DIR/adblock_rules.py"
    cp "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"
else
    echo "Downloading NetBlock Fortress v19.0 source..."
    curl -fsSL "$REPO_RAW/app.py" -o "$INSTALL_DIR/app.py"
    curl -fsSL "$REPO_RAW/adblock_rules.py" -o "$INSTALL_DIR/adblock_rules.py"
    curl -fsSL "$REPO_RAW/requirements.txt" -o "$INSTALL_DIR/requirements.txt"
fi

PYTHON_OK="$(python3 -c 'import sys; print(int(sys.version_info >= (3, 8)))')"
if [[ "$PYTHON_OK" != "1" ]]; then
    echo "Python 3.8 or newer is required." >&2
    exit 1
fi

python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet --requirement "$INSTALL_DIR/requirements.txt"

if ! getent passwd netblock >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin netblock
    touch "$INSTALL_DIR/.netblock-created-user"
    chmod 0600 "$INSTALL_DIR/.netblock-created-user"
fi
mkdir -p "$INSTALL_DIR/data/lists"
chown -R root:root "$INSTALL_DIR"
chown -R netblock:netblock "$INSTALL_DIR/data"
chmod 0755 "$INSTALL_DIR"
chmod 0700 "$INSTALL_DIR/data" "$INSTALL_DIR/data/lists"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" << SERVICEEOF
[Unit]
Description=NetBlock Fortress DNS Filtering Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=netblock
Group=netblock
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR}/data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# Avoid installing an internet-facing open DNS resolver/dashboard on VPS hosts.
# Permit only common private LAN ranges when UFW is already enabled; adapt for
# non-RFC1918 enterprise LANs or IPv6 networks as needed.
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        ufw allow from "$cidr" to any port 53 proto udp >/dev/null
        ufw allow from "$cidr" to any port 53 proto tcp >/dev/null
        ufw allow from "$cidr" to any port 8080 proto tcp >/dev/null
    done
    ufw allow from fc00::/7 to any port 53 proto udp >/dev/null 2>&1 || true
    ufw allow from fc00::/7 to any port 53 proto tcp >/dev/null 2>&1 || true
    ufw allow from fc00::/7 to any port 8080 proto tcp >/dev/null 2>&1 || true
    echo "UFW rules added for private LAN ranges only."
fi

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
SERVER_IP="${SERVER_IP:-YOUR_SERVER_IP}"
echo
echo "NetBlock Fortress v19.0 installed."
echo "Dashboard: http://${SERVER_IP}:8080"
echo "DNS:       ${SERVER_IP}:53 (UDP and TCP)"
echo "Login:     admin / admin123 — change the password immediately."
echo "Service:   systemctl status ${SERVICE_NAME}"
echo "Logs:      journalctl -u ${SERVICE_NAME} -f"
echo
echo "If port 53 is occupied (for example by systemd-resolved), review the README before changing resolver settings."
echo "DNS-level filtering cannot remove same-host ads or prevent clients from bypassing DNS with DoH/VPNs."
