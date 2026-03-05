#!/bin/bash
# container-setup.sh — install remnaproxy-tui wrapper on the VyOS host.
#
# Usage:
#   sudo bash container-setup.sh [CONTAINER_NAME]
#
# Installs /usr/local/bin/remnaproxy-tui so you can launch the TUI with:
#   remnaproxy-tui

set -euo pipefail

CONTAINER="${1:-remnaproxy}"
INSTALL_PATH="/usr/local/bin/remnaproxy-tui"

cat > "$INSTALL_PATH" <<EOF
#!/bin/bash
exec docker exec -it ${CONTAINER} python3 /app/src/tui.py "\$@"
EOF

chmod +x "$INSTALL_PATH"
echo "Installed: $INSTALL_PATH"
echo "Run: remnaproxy-tui"
