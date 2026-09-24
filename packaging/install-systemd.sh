#!/usr/bin/env bash
#
# TT-2030: installs the already-built Connector binary as a systemd service, with
# CAP_NET_ADMIN granted via AmbientCapabilities so it can create its TUN device
# without ever running the whole process as root. Mirrors the same pattern
# Agent's own systemd unit already uses in production for its one required
# capability (CAP_NET_BIND_SERVICE) - see secure-connect-backend-agent's
# agent.service.d/bind-port.conf.
#
# Run this after `cargo build --release` has already produced
# target/release/secure_connect_connector - Portal's install command does both in one go. The repo
# root is found from this script's own location, so it doesn't matter what directory you invoke it
# from.
#
# TT-2210: the install command is the only thing an admin runs on this host. Portal fills in the
# environment's constants, so the service starts straight away and heartbeats with nothing but its
# own public key - pasting that key into Portal is the only step left:
#   AGENTS_JSON_URL          the environment's agents.json list the Connector picks a live Agent from
#   REGISTRY_BASE_URL        the environment's Registry, used to verify that Agent's signature
#   CONNECTOR_CA_BUNDLE_URL  optional - a PEM to trust for an Agent without a publicly-issued
#                            certificate, downloaded next to connector.env
# Values passed here are written into connector.env; leaving one unset keeps whatever the file
# already has, so a plain re-run after a rebuild changes nothing.
#
# Usage:
#   sudo AGENTS_JSON_URL=... REGISTRY_BASE_URL=... packaging/install-systemd.sh
#                                               install (or update) and start the service
#   packaging/install-systemd.sh --uninstall   stop, disable, and remove the service and binary
#                                               (connector.env is left in place)
set -euo pipefail

SERVICE_NAME="secure-connect-connector"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_DIR="/etc/skipr/connector"
ENV_FILE="${ENV_DIR}/connector.env"
INSTALLED_BINARY_PATH="/usr/local/bin/secure_connect_connector"

if [ "${1:-}" = "--uninstall" ]; then
  sudo systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  sudo rm -f "$UNIT_PATH" "$INSTALLED_BINARY_PATH"
  sudo systemctl daemon-reload
  echo "Uninstalled $SERVICE_NAME - $ENV_FILE was left in place."
  exit 0
fi

# Derived from where this script itself lives, not the caller's working directory - "run this
# from the repo root" was previously an unenforced convention, so a caller anywhere else silently
# got a $(pwd)-relative path that happened to look plausible right up until it didn't exist.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILT_BINARY_PATH="${REPO_ROOT}/target/release/secure_connect_connector"

# SUDO_USER is only set when this script is invoked *through* sudo - in a root shell (`sudo -i`,
# cloud-init, a Dockerfile, Ansible's `become`, a CI runner) it's unset and `whoami` returns
# `root`, which would silently generate a unit with `User=root` and quietly defeat the entire
# point of this script (CAP_NET_ADMIN without running as root) with nothing in the output saying
# so. Refuse outright instead - CONNECTOR_USER lets an admin who really is in one of those
# environments say explicitly who the service should run as.
RUN_AS_USER="${CONNECTOR_USER:-${SUDO_USER:-$(whoami)}}"
if [ "$RUN_AS_USER" = "root" ]; then
  echo "error: refusing to install a unit that runs as root - the point of this script is" >&2
  echo "       CAP_NET_ADMIN without root. Re-run as 'sudo ./packaging/install-systemd.sh'" >&2
  echo "       from your normal user, or set CONNECTOR_USER=<name>." >&2
  exit 1
fi

if [ ! -x "$BUILT_BINARY_PATH" ]; then
  # TT-2030 follow-up: the Portal install command chains `cargo build --release && ...` with no
  # C toolchain guaranteed on a fresh box - several dependencies (including BoringTun) need `cc`
  # for their build scripts, so a bare rustup install fails here with a linker error long before
  # this script ever runs. Recover instead of just erroring a second time: install the toolchain
  # if it's missing, then build here so a plain re-run of this script alone is enough to finish
  # what the first attempt couldn't.
  if ! command -v cc >/dev/null 2>&1; then
    echo "cc not found - installing build-essential (required to compile this crate's dependencies)..."
    sudo apt-get update -qq
    sudo apt-get install -y build-essential
  fi
  # Build as RUN_AS_USER, not as whoever this script process is (root, when invoked via
  # `sudo ./packaging/install-systemd.sh` as the error above tells people to do) - cargo lives in
  # RUN_AS_USER's own $HOME/.cargo/bin from their rustup install, never on root's PATH, so running
  # this as root would just trade "cc not found" for an equally silent "cargo: command not found".
  echo "Building the Connector (target/release/secure_connect_connector not found)..."
  sudo -u "$RUN_AS_USER" bash -lc "source \"\$HOME/.cargo/env\" 2>/dev/null || true; cd '$REPO_ROOT' && cargo build --release"
  if [ ! -x "$BUILT_BINARY_PATH" ]; then
    echo "error: build finished but $BUILT_BINARY_PATH still missing/not executable." >&2
    exit 1
  fi
fi

DEFAULT_IDENTITY_KEY_PATH="/var/skipr/connector/.keys/identity.key"

sudo mkdir -p "$ENV_DIR"
sudo install -d -o "$RUN_AS_USER" -m 750 /var/skipr/connector/audit /var/skipr/connector/.keys
if [ ! -f "$ENV_FILE" ]; then
  sudo tee "$ENV_FILE" > /dev/null <<'EOF'
# Written by install-systemd.sh - see the README's "Running the Connector daemon"
# table for what each of these means. AGENTS_JSON_URL and REGISTRY_BASE_URL come
# from the install command Portal gives you; the identity is generated for you at
# CONNECTOR_IDENTITY_KEY_PATH's default (or whatever you set it to below, if you
# re-run this script after changing it).
#
# Leave a line commented out to use its documented default. systemd parses an
# uncommented `VAR=` as VAR being *set* to an empty string, not unset - which
# defeats both the defaults below and the required-variable check, so don't
# just erase the value, uncomment the line and fill it in.
#AGENTS_JSON_URL=
#REGISTRY_BASE_URL=
# CONNECTOR_IDENTITY_KEY_PATH must be an ABSOLUTE path - systemd does not expand
# $HOME or ~ in this file, and the unit's working directory is /, so a value
# copied verbatim from the README's `export` line will NOT resolve.
#CONNECTOR_IDENTITY_KEY_PATH=

# Optional - each of these already has the documented default shown below and only needs
# uncommenting if you want something other than that.
#CONNECTOR_AUDIT_LOG_PATH=/var/skipr/connector/audit/audit.log
# TT-2144: the flow-admission/release channel is Connector-initiated (the Connector polls out to
# each paired Node's Gatekeeper) - no inbound port is opened for it, so there is nothing to open in
# this host's own firewall for it. Only needs setting if a Gatekeeper deployment ever changes its
# HTTP port away from the default below.
#CONNECTOR_GATEKEEPER_HTTP_PORT=4000
#CONNECTOR_TUN_NETMASK=255.255.255.0
#HEARTBEAT_INTERVAL_SECONDS=60

# Log level for the daemon. Without this only ERROR-level lines reach the
# journal, including the fresh-identity warning above.
RUST_LOG=info
EOF
  sudo chmod 600 "$ENV_FILE"
  echo "Created $ENV_FILE"
fi

# Sets KEY=VALUE in $ENV_FILE, replacing the first existing line for KEY (commented or not) or
# appending one if there is none - always canonical and unquoted, so this script and systemd's own
# EnvironmentFile parser never have to agree on how to read quoting or whitespace back. awk rather
# than sed so VALUE is written out literally, with no backslash/ampersand/delimiter escaping to get
# right (URLs are full of characters sed treats specially). Passed through the environment rather
# than `awk -v`, which interprets backslash escapes in the value and would silently drop them.
set_env_value() {
  sudo env SET_ENV_KEY="$1" SET_ENV_VAL="$2" awk '
    BEGIN { done = 0; key = ENVIRON["SET_ENV_KEY"]; val = ENVIRON["SET_ENV_VAL"] }
    $0 ~ ("^[[:space:]]*#?[[:space:]]*" key "=") {
      if (!done) { print key "=" val; done = 1; next }
    }
    { print }
    END { if (!done) print key "=" val }
  ' "$ENV_FILE" | sudo tee "${ENV_FILE}.new" > /dev/null
  sudo chmod 600 "${ENV_FILE}.new"
  sudo mv "${ENV_FILE}.new" "$ENV_FILE"
}

# KEY's current value in $ENV_FILE - empty if it is unset or only commented out.
env_value() {
  sudo grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true
}

# TT-2210: the environment's constants, as Portal's install command passes them. Only written when
# actually given, so re-running this script bare after a rebuild keeps what connector.env has.
if [ -n "${AGENTS_JSON_URL:-}" ]; then
  set_env_value AGENTS_JSON_URL "$AGENTS_JSON_URL"
fi
if [ -n "${REGISTRY_BASE_URL:-}" ]; then
  set_env_value REGISTRY_BASE_URL "$REGISTRY_BASE_URL"
fi
if [ -n "${CONNECTOR_CA_BUNDLE_URL:-}" ]; then
  CA_BUNDLE_PATH="${ENV_DIR}/ca-bundle.pem"
  echo "Downloading the CA bundle to trust from $CONNECTOR_CA_BUNDLE_URL..."
  curl -fsS "$CONNECTOR_CA_BUNDLE_URL" | sudo tee "$CA_BUNDLE_PATH" > /dev/null
  sudo chmod 644 "$CA_BUNDLE_PATH"
  set_env_value CONNECTOR_CA_BUNDLE_PATH "$CA_BUNDLE_PATH"
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
# systemd's EnvironmentFile parser strips surrounding whitespace, then a matching pair of
# leading/trailing quotes (CONNECTOR_IDENTITY_KEY_PATH="/path" or ='/path') before the daemon
# ever sees the value - grep + cut above doesn't, so an admin who quotes the value (a natural
# thing to do) or leaves a stray trailing space would otherwise get a path here that still has
# the quote characters (or the space) in it, generating the identity at a path the daemon itself
# never actually resolves to. Trim first, then unquote - trimming first also correctly handles a
# quoted value with trailing whitespace, which would otherwise break the quote-stripping pattern
# and leave the quotes in place too.
CONFIGURED_IDENTITY_KEY_PATH="$(printf '%s' "$CONFIGURED_IDENTITY_KEY_PATH" |
  sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/')"
IDENTITY_KEY_PATH="${CONFIGURED_IDENTITY_KEY_PATH:-$DEFAULT_IDENTITY_KEY_PATH}"
sudo install -d -o "$RUN_AS_USER" -m 750 "$(dirname "$IDENTITY_KEY_PATH")"
IDENTITY_PUBLIC_KEY="$(sudo -u "$RUN_AS_USER" env CONNECTOR_IDENTITY_KEY_PATH="$IDENTITY_KEY_PATH" "$BUILT_BINARY_PATH" --generate-identity)"

# Write the exact path just used back into $ENV_FILE, canonical and unquoted, replacing whatever
# commented/quoted/spaced form the admin had (or adding the line if it was never there). This is
# deliberate, not cosmetic: it stops this script and systemd's own parser from ever having to
# agree on how to re-derive the same value from the admin's original text a second time - each
# quoting/whitespace variant systemd accepts is one more way the two parsers could disagree, and
# every prior fix here was another variant found the hard way. After this, $ENV_FILE always holds
# the one plain, unambiguous string both readers already agree on byte-for-byte.
set_env_value CONNECTOR_IDENTITY_KEY_PATH "$IDENTITY_KEY_PATH"

echo "Connector identity ready at $IDENTITY_KEY_PATH"
echo "Public key (register this in Portal's Deploy Connector screen if you haven't already):"
echo "  $IDENTITY_PUBLIC_KEY"

# Without this, the Connector receives and admits a flow correctly but the reply never makes it
# back: an admitted packet is forwarded toward the real backend with its tunnel-internal source
# address left unrewritten (e.g. 10.66.66.x), which isn't routable from the backend's side, so the
# backend (or the cloud network fabric in front of it) has nowhere to send its response - the
# client just sees the connection hang and eventually time out or abort, with nothing wrong in any
# admission/entitlement/Security-Group log to explain why. Confirmed live via a packet capture on
# a Connector that was missing exactly this - packets left its outbound interface unmodified and
# no reply ever came back, on a box otherwise identical (same binary, same policy) to one that had
# this configured and worked.
#
# Two separate things, and both matter: forwarding must be turned on at all (ip_forward), and the
# forwarded packet's source must be rewritten to an address the backend can actually reply to
# (MASQUERADE). Neither was ever part of this script - previously a manual, undocumented step run
# by hand on working boxes and silently missing on every other one.
echo "Configuring IP forwarding and NAT for the Connector's outbound interface..."

# Persisted the same way the rest of this box's Skipr-specific sysctl settings are (a dedicated
# file under /etc/sysctl.d/), not just `sysctl -w` - that alone only affects the running kernel and
# silently reverts on the next reboot, which is exactly the kind of gap this script exists to close.
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-skipr-connector.conf > /dev/null
sudo sysctl -p /etc/sysctl.d/99-skipr-connector.conf > /dev/null

# The interface name is instance/AMI-specific (ens5, eth0, enX1, ...) - never hardcode it. Derived
# from the box's own default route rather than assumed, so this works unmodified on whatever
# interface this particular instance actually uses.
NAT_INTERFACE="$(ip route show default | awk '{print $5; exit}')"
if [ -z "$NAT_INTERFACE" ]; then
  echo "warning: could not determine the default outbound interface (no default route yet?) -" >&2
  echo "         skipping NAT setup. Re-run this script once the box has one, or add the rule" >&2
  echo "         yourself: sudo iptables -t nat -A POSTROUTING -o <interface> -j MASQUERADE" >&2
else
  # Checked before added (`-C` ... `|| ... -A`), not appended unconditionally - this script is
  # documented as safe to re-run (after a rebuild, a config change), and an unconditional -A would
  # silently stack up a duplicate MASQUERADE rule on every re-run instead of staying a no-op.
  if ! sudo iptables -t nat -C POSTROUTING -o "$NAT_INTERFACE" -j MASQUERADE 2>/dev/null; then
    sudo iptables -t nat -A POSTROUTING -o "$NAT_INTERFACE" -j MASQUERADE
  fi
  echo "NAT configured on interface $NAT_INTERFACE"
fi

# Copied out of the checkout rather than exec'd from target/release directly: a permanent service
# shouldn't depend on the build tree still existing at that exact path - `cargo clean`, moving the
# repo, or a `git worktree` prune would otherwise leave a unit that fails at next boot with a
# confusing 203/EXEC. The trade-off is deliberate: a rebuild now requires re-running this script
# rather than silently changing what the running service execs on its next restart, which is the
# one an admin can actually reason about from `systemctl status`.
sudo install -m 755 "$BUILT_BINARY_PATH" "$INSTALLED_BINARY_PATH"

sudo tee "$UNIT_PATH" > /dev/null <<EOF
[Unit]
Description=Skipr Private Gateway Connector
After=network-online.target
Wants=network-online.target
# [Unit], not [Service] - a unit-wide rate limit governing how often systemd will (re)start this
# unit at all, not a property of the service process itself, so systemd only recognizes it here
# (silently ignored in [Service] - no error, it just never takes effect). Paired with
# Restart=on-failure below: a genuine runtime crash still gets retried, but a config typo or other
# immediate, permanent failure trips this limit and leaves the unit in \`failed\` after a minute
# instead of grinding on forever - 5-in-25s from Restart/RestartSec alone never reaches systemd's
# default 5-in-10s limit, so without this it would just crash-loop indefinitely with the useful
# first error scrolled out of the journal.
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=${RUN_AS_USER}
EnvironmentFile=${ENV_FILE}
# The NAT rule this install added is only ever in the running kernel's netfilter table - unlike
# the ip_forward sysctl (persisted via /etc/sysctl.d/99-skipr-connector.conf), a bare \`iptables -A\`
# has no on-disk form of its own to survive a reboot, and this box may not have iptables-persistent
# (or an equivalent) installed at all. Reapplying it here ties it to the one thing that already
# reliably runs on every boot - this unit starting - instead of a second, separate persistence
# mechanism. The \`+\` prefix runs this one command as root regardless of User= above (the
# CAP_NET_ADMIN this service itself gets isn't sufficient for iptables' own netfilter access); the
# check-then-add is the same idempotent pattern the install script uses, since ExecStartPre runs on
# every restart, not just the first.
#
# Deliberately not an awk one-liner here (unlike the plain NAT_INTERFACE line above, where that's
# fine): inside this doubly-quoted /bin/sh -c wrapper, an awk script written in double quotes has
# /bin/sh itself expand its field-number variable as ITS OWN (empty) positional parameter before
# awk ever sees the script text - silently turning "print field five" into "print the whole line",
# which prints the entire "ip route show default" output instead of just the interface name. That
# then fails the iptables call (name too long) with no failure visible anywhere but this
# ExecStartPre's own stderr. set-- positional-parameter extraction below has no such nested-dollar-
# in-double-quotes ambiguity. Verified live: an awk version here produced a real
# "interface name ... must be shorter than 16 characters" iptables error on a test box; this
# version doesn't.
ExecStartPre=+/bin/sh -c 'set -- \$(ip route show default); IFACE=\$5; [ -n "\$IFACE" ] && { iptables -t nat -C POSTROUTING -o "\$IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "\$IFACE" -j MASQUERADE; } || true'
ExecStart=${INSTALLED_BINARY_PATH}
Restart=on-failure
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

# TT-2210: started here, not left for a second admin step - the Connector heartbeats with just its
# public key and is told "not registered" until the admin pastes that key into Portal, then picks
# up its policy on the very next heartbeat, with no restart. restart rather than start so a re-run
# after a rebuild or config change also takes effect immediately.
if [ -n "$(env_value AGENTS_JSON_URL)" ] && [ -n "$(env_value REGISTRY_BASE_URL)" ]; then
  sudo systemctl enable --quiet "$SERVICE_NAME"
  sudo systemctl restart "$SERVICE_NAME"
  echo ""
  echo "Installed and running."
  echo ""
  echo "Last step: paste this public key into Portal's Deploy Connector screen:"
  echo "  $IDENTITY_PUBLIC_KEY"
  echo "The Connector activates on its next heartbeat - nothing else to run here."
  echo "  journalctl -u $SERVICE_NAME -f   # to watch it"
else
  echo "" >&2
  echo "warning: AGENTS_JSON_URL and/or REGISTRY_BASE_URL are missing from $ENV_FILE, so the" >&2
  echo "         service was NOT (re)started. Re-run the install command from Portal's Deploy" >&2
  echo "         Connector screen, from the same directory - it passes both - or set them in" >&2
  echo "         that file and run: sudo systemctl enable --now $SERVICE_NAME" >&2
  # An install from before TT-2210 (CONNECTOR_ID/AGENT_BASE_URL in connector.env) may still be
  # running: its old process keeps going, but the binary just copied into place refuses to start
  # without AGENTS_JSON_URL - so the next restart or reboot would take it down. Say so now, not then.
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "warning: $SERVICE_NAME is still running the PREVIOUS binary. The new one needs these" >&2
    echo "         values and will fail on its next restart or reboot until they are set." >&2
  fi
fi
echo ""
echo "To uninstall: packaging/install-systemd.sh --uninstall"
