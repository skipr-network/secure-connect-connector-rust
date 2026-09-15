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

DEFAULT_IDENTITY_KEY_PATH="/var/skipr/connector/.keys/identity.key"

sudo mkdir -p "$ENV_DIR"
sudo install -d -o "$RUN_AS_USER" -m 750 /var/skipr/connector/audit /var/skipr/connector/.keys
if [ ! -f "$ENV_FILE" ]; then
  sudo tee "$ENV_FILE" > /dev/null <<'EOF'
# Filled in by the admin - see the README's "Running the Connector daemon" table
# for what each of these means. This install script already generates the
# Connector's identity for you at CONNECTOR_IDENTITY_KEY_PATH's default (or
# whatever you set it to below, if you re-run this script after changing it) -
# leave it commented out unless you deliberately want a non-default location.
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

# Generate the identity against the exact path the daemon will load - not a separate,
# admin-run `--generate-identity` step against whatever path their shell happens to have
# exported. Now that .keys/ above is writable by RUN_AS_USER, leaving
# CONNECTOR_IDENTITY_KEY_PATH unset would otherwise let the daemon silently generate its own,
# unregistered identity at first start instead of failing - generating it here first means the
# right file already exists by the time that happens, for both the default path and a custom
# one the admin already uncommented in $ENV_FILE. Safe to re-run: load_or_generate loads an
# existing key file rather than overwriting it.
CONFIGURED_IDENTITY_KEY_PATH="$(grep -E '^CONNECTOR_IDENTITY_KEY_PATH=' "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
# systemd's EnvironmentFile parser strips a matching pair of leading/trailing quotes
# (CONNECTOR_IDENTITY_KEY_PATH="/path" or ='/path') before the daemon ever sees the value - grep
# + cut above doesn't, so an admin who quotes the value (a natural thing to do) would otherwise
# get a path here that still has the quote characters in it, generating the identity at a path
# the daemon itself never actually resolves to.
CONFIGURED_IDENTITY_KEY_PATH="$(printf '%s' "$CONFIGURED_IDENTITY_KEY_PATH" | sed -E 's/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/')"
IDENTITY_KEY_PATH="${CONFIGURED_IDENTITY_KEY_PATH:-$DEFAULT_IDENTITY_KEY_PATH}"
sudo install -d -o "$RUN_AS_USER" -m 750 "$(dirname "$IDENTITY_KEY_PATH")"
IDENTITY_PUBLIC_KEY="$(sudo -u "$RUN_AS_USER" env CONNECTOR_IDENTITY_KEY_PATH="$IDENTITY_KEY_PATH" "$BINARY_PATH" --generate-identity)"
echo "Connector identity ready at $IDENTITY_KEY_PATH"
echo "Public key (register this in Portal's Deploy Connector screen if you haven't already):"
echo "  $IDENTITY_PUBLIC_KEY"

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
