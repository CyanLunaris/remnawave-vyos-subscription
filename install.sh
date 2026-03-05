#!/bin/bash
# Install remnaproxy-sync on VyOS
set -euo pipefail

INSTALL_LIB="/usr/local/lib/remnaproxy"
CONFIG_DIR="/etc/remnaproxy"
SING_BOX_DIR="/etc/sing-box"

echo "=== Remnaproxy Sync Installer ==="

# 1. Create directories
mkdir -p "$INSTALL_LIB" "$CONFIG_DIR" "$SING_BOX_DIR" /var/log/remnaproxy

# 2. Copy Python source
cp -r src/ "$INSTALL_LIB/"
cp src/sync.py "$INSTALL_LIB/sync.py"
cp src/heartbeat.py "$INSTALL_LIB/heartbeat.py"
touch "$INSTALL_LIB/__init__.py"
touch "$INSTALL_LIB/src/__init__.py"

# 3. Install config if not present
if [ ! -f "$CONFIG_DIR/config.env" ]; then
    cp config.env.example "$CONFIG_DIR/config.env"
    chmod 600 "$CONFIG_DIR/config.env"
    echo ""
    echo ">>> IMPORTANT: Edit $CONFIG_DIR/config.env and set SUBSCRIPTION_URL <<<"
    echo ""
fi

# 4. Install systemd units
cp systemd/sing-box.service /etc/systemd/system/
cp systemd/remnaproxy-sync.service /etc/systemd/system/
cp systemd/remnaproxy-sync.timer /etc/systemd/system/
cp systemd/remnaproxy-heartbeat.service /etc/systemd/system/
cp systemd/remnaproxy-heartbeat.timer /etc/systemd/system/

systemctl daemon-reload

# 5. Run first sync (downloads sing-box + geo files)
echo "Running initial sync (this may take a minute — downloading sing-box)..."
python3 "$INSTALL_LIB/sync.py" --config "$CONFIG_DIR/config.env"

# 6. Set up TUN interface
TUN_IF=$(grep TUN_INTERFACE "$CONFIG_DIR/config.env" | cut -d= -f2 | tr -d ' ' || echo "tun0")
TUN_ADDR=$(grep TUN_ADDRESS "$CONFIG_DIR/config.env" | cut -d= -f2 | tr -d ' ' || echo "172.19.0.1/30")

if ! ip link show "$TUN_IF" &>/dev/null; then
    ip tuntap add mode tun "$TUN_IF" || true
    ip addr add "$TUN_ADDR" dev "$TUN_IF" || true
    ip link set "$TUN_IF" up || true
fi

# 7. Enable and start services
systemctl enable --now sing-box.service
systemctl enable --now remnaproxy-sync.timer
systemctl enable --now remnaproxy-heartbeat.timer

echo ""
echo "=== Installation complete ==="
echo "Status:"
systemctl is-active sing-box.service remnaproxy-sync.timer remnaproxy-heartbeat.timer
echo ""
echo "Logs:"
echo "  journalctl -u sing-box -f"
echo "  tail -f /var/log/remnaproxy/sync.log"
echo "  tail -f /var/log/remnaproxy/heartbeat.log"
echo ""
echo "Manual sync:      python3 $INSTALL_LIB/sync.py"
echo "Manual heartbeat: python3 $INSTALL_LIB/heartbeat.py"
