#!/usr/bin/env bash
set -euo pipefail

# ——————————————————————————————————————————————————————————————————
# CONFIG
# ——————————————————————————————————————————————————————————————————

NAME="spotify-tokener"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_ENV="production"

# Detect the real user who invoked sudo (or fallback)
INSTALLER_USER="${SUDO_USER:-${USER}}"
USER_HOME="$(eval echo "~${INSTALLER_USER}")"
BUN_INSTALL_DIR="$USER_HOME/.bun/bin"

SERVICE_FILE="/etc/systemd/system/$NAME.service"

# ——————————————————————————————————————————————————————————————————
# HELPERS
# ——————————————————————————————————————————————————————————————————

info()  { echo -e "🔧  $*"; }
error() { echo -e "❌  $*" >&2; exit 1; }

# ——————————————————————————————————————————————————————————————————
# 0) REQUIRE sudo
# ——————————————————————————————————————————————————————————————————

if [ "$EUID" -ne 0 ]; then
  error "Please run with sudo: sudo bash ./setup.sh"
fi

info "Setting up $NAME…"
info "Base directory: $DIR/src/app.ts"

# ——————————————————————————————————————————————————————————————————
# 1) INSTALL BUN (if needed)
# ——————————————————————————————————————————————————————————————————

if ! command -v bun &>/dev/null; then
  info "Bun not found. Installing Bun for user '$INSTALLER_USER'…"
  su -l "$INSTALLER_USER" -c 'curl -fsSL https://bun.sh/install | bash'
fi

# Export the user’s bun into root’s PATH
if [ -d "$BUN_INSTALL_DIR" ]; then
  export PATH="$BUN_INSTALL_DIR:$PATH"
fi

# Double‑check
if ! command -v bun &>/dev/null; then
  error "Bun still not found after installation. Aborting."
fi

info "Found Bun: $(bun -v)"

# Symlink into /usr/local/bin for global access
if [ ! -L /usr/local/bin/bun ]; then
  info "Creating symlink /usr/local/bin/bun → $BUN_INSTALL_DIR/bun"
  ln -sf "$BUN_INSTALL_DIR/bun" /usr/local/bin/bun
fi

# ——————————————————————————————————————————————————————————————————
# 2) INSTALL PROJECT DEPENDENCIES
# ——————————————————————————————————————————————————————————————————

info "Installing dependencies with Bun…"
su -l "$INSTALLER_USER" -c "cd $DIR && bun install --production && npx playwright install && npx playwright install-deps"

# ——————————————————————————————————————————————————————————————————
# 3) CREATE systemd SERVICE
# ——————————————————————————————————————————————————————————————————

info "🧾 Creating systemd service..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=$NAME Service
After=network.target

[Service]
Type=simple
# Use the symlinked bun so root and others can start it
ExecStart=$BUN_INSTALL_DIR/bun --env-file=$DIR/.env $DIR/src/app.ts
WorkingDirectory=$DIR
Restart=always
RestartSec=5
User=$INSTALLER_USER
Environment=NODE_ENV=$NODE_ENV

[Install]
WantedBy=multi-user.target
EOF

# ——————————————————————————————————————————————————————————————————
# 4) RELOAD & START SERVICE
# ——————————————————————————————————————————————————————————————————

info "🔄 Reloading systemd daemon..."
systemctl daemon-reload

info "✅ Enabling and starting $NAME service..."
systemctl enable "$NAME"
systemctl start  "$NAME"

info "✅ All done! Use the following to manage the $NAME service:"
echo "  • systemctl status $NAME"
echo "  • journalctl -u $NAME -f"
echo "  • systemctl stop $NAME"
echo "  • systemctl restart $NAME"