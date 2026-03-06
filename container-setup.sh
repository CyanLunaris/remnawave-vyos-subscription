#!/bin/bash
# container-setup.sh — install remnaproxy-tui wrapper on VyOS.
#
# Usage:
#   sudo bash container-setup.sh [CONTAINER_NAME]
#
# Installs /config/scripts/remnaproxy-tui (persists across VyOS upgrades)
# and symlinks it to /usr/local/bin/remnaproxy-tui for convenience.

set -euo pipefail

CONTAINER="${1:-remnaproxy}"
SCRIPT_DIR="/config/scripts"
SCRIPT_PATH="$SCRIPT_DIR/remnaproxy-tui"
BIN_LINK="/usr/local/bin/remnaproxy-tui"

# Verify podman is available (VyOS uses podman, not docker)
if ! command -v podman &>/dev/null; then
    echo "ERROR: podman not found. Is this a VyOS system?" >&2
    exit 1
fi

# Check service exists (VyOS manages containers via systemd)
if ! systemctl is-active --quiet "vyos-container-$CONTAINER" 2>/dev/null; then
    echo "WARNING: vyos-container-$CONTAINER is not running — installing anyway."
    echo "  Make sure the container is running before using remnaproxy-tui."
fi

mkdir -p "$SCRIPT_DIR"

cat > "$SCRIPT_PATH" <<EOF
#!/bin/bash
# remnaproxy TUI — launches inside the running container
CONTAINER="${CONTAINER}"
SERVICE="vyos-container-\$CONTAINER"

if ! systemctl is-active --quiet "\$SERVICE" 2>/dev/null; then
    echo "ERROR: \$SERVICE is not running." >&2
    echo "  Start it with: sudo systemctl start \$SERVICE" >&2
    exit 1
fi

# VyOS uses non-default podman storage — find container ID via service cid file
CID_FILE="/run/\$SERVICE.cid"
if [ -f "\$CID_FILE" ]; then
    exec podman --root /usr/lib/live/mount/persistence/container/storage \
        exec -it "\$(cat \$CID_FILE)" python3 /app/src/tui.py "\$@"
else
    exec podman --root /usr/lib/live/mount/persistence/container/storage \
        exec -it "\$CONTAINER" python3 /app/src/tui.py "\$@"
fi
EOF

chmod +x "$SCRIPT_PATH"

# Symlink into /usr/local/bin for PATH access
ln -sf "$SCRIPT_PATH" "$BIN_LINK"

echo "Installed:  $SCRIPT_PATH"
echo "Symlinked:  $BIN_LINK -> $SCRIPT_PATH"
echo ""
echo "Run: remnaproxy-tui"
echo "  or: $SCRIPT_PATH"
