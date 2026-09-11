#!/usr/bin/env bash
#
# TT-2030: installs the already-built Connector binary as a systemd service, with
# CAP_NET_ADMIN granted via AmbientCapabilities so it can create its TUN device
# without ever running the whole process as root. Mirrors the same pattern
# Agent's own systemd unit already uses in production for its one required
# capability (CAP_NET_BIND_SERVICE) - see secure-connect-backend-agent's
# agent.service.d/bind-port.conf.
#
# Run this from the repo root, after `cargo build --release` has already
# produced target/release/secure_connect_connector (i.e. right after the
# install command Portal gives you, before starting the daemon).
set -euo pipefail

BINARY_PATH="$(pwd)/target/release/secure_connect_connector"
SERVICE_NAME="secure-connect-connector"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_DIR="/etc/skipr/connector"
ENV_FILE="${ENV_DIR}/connector.env"
RUN_AS_USER="${SUDO_USER:-$(whoami)}"

if [ ! -x "$BINARY_PATH" ]; then
  echo "error: $BINARY_PATH not found or not executable - run 'cargo build --release' first." >&2
  exit 1
fi

sudo mkdir -p "$ENV_DIR"
sudo install -d -o "$RUN_AS_USER" -m 750 /var/skipr/connector/audit /var/skipr/connector/.keys
if [ ! -f "$ENV_FILE" ]; then
  sudo tee "$ENV_FILE" > /dev/null <<'EOF'
# Filled in by the admin - see the README's "Running the Connector daemon" table
# for what each of these means. CONNECTOR_IDENTITY_KEY_PATH must match exactly
# what --generate-identity used, or the daemon generates a second, unregistered
# identity (it will warn loudly if this happens).
#
# Leave a line commented out to use its documented default. systemd parses an
# uncommented `VAR=` as VAR being *set* to an empty string, not unset - which
# defeats both the defaults below and the required-variable check, so don't
# just erase the value, uncomment the line and fill it in.
#CONNECTOR_ID=
#AGENT_BASE_URL=
#AGENT_IP_ADDRESS=
#REGISTRY_BASE_URL=
# CONNECTOR_IDENTITY_KEY_PATH must be an ABSOLUTE path - systemd does not expand
# $HOME or ~ in this file, and the unit's working directory is /, so a value
# copied verbatim from the README's `export` line will NOT resolve.
#CONNECTOR_IDENTITY_KEY_PATH=

# Log level for the daemon. Without this only ERROR-level lines reach the
# journal, including the fresh-identity warning above.
RUST_LOG=info
EOF
  sudo chmod 600 "$ENV_FILE"
  echo "Created $ENV_FILE - fill in its values before starting the service."
fi

sudo tee "$UNIT_PATH" > /dev/null <<EOF
[Unit]
Description=Skipr Private Gateway Connector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_AS_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${BINARY_PATH}
Restart=always
RestartSec=5

# The one capability this daemon actually needs (creating its TUN device) -
# granted directly to the process, never by running it as root.
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

echo ""
echo "Installed. Next steps:"
echo "  1. sudo nano $ENV_FILE   # uncomment and fill in CONNECTOR_ID and the rest"
echo "  2. sudo systemctl enable --now $SERVICE_NAME"
echo "  3. journalctl -u $SERVICE_NAME -f   # watch it start"
