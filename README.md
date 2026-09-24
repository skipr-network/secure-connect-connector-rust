# secure-connect-connector-rust

The Private Gateway Connector runtime (TT-1732). Installed by an Enterprise
Admin inside their own network, next to an internal service (CRM, ERP, file
server). Heartbeats to Agent, verifies the signed policy package it gets back,
connects to VPN nodes over WireGuard, and makes the final allow/deny decision
for private-service traffic.

Spec: [Private Gateway, Endpoint Node Fleet & Client Discovery](https://github.com/skipr-network/doc_private/blob/main/03-architecture/specs/private_gateway_node_architecture_final.md)
(§B.3, §B.4, §B.7, §B.9, §B.10).

## Status

Implementation lands in feature PRs. Identity + verified heartbeat client
against Agent, WireGuard tunneling, and flow admission/release are in place;
see individual ticket history for what's landed.

## Installing on a fresh machine

A C toolchain is required before `cargo build` - several dependencies
(including BoringTun) need `cc` for their build scripts, and it's not present
by default on a minimal Ubuntu box. Install it *before* building, not after:
`install-systemd.sh` can recover a missing toolchain on a re-run (see below),
but the first `cargo build` here has no such fallback and fails outright with
`error: linker `cc` not found` if this step is skipped.

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
sudo apt-get update && sudo apt-get install -y build-essential
git clone https://github.com/skipr-network/secure-connect-connector-rust
cd secure-connect-connector-rust
cargo build --release
sudo AGENTS_JSON_URL=<your environment's agents.json> REGISTRY_BASE_URL=<your environment's Registry> ./packaging/install-systemd.sh
```

Portal's Deploy Connector screen shows this same command with both URLs already
filled in for its environment - use that one. It builds and installs the
Connector, starts it, and prints its public key. Paste that key into the same
Portal screen and you're done: the running Connector picks up its registration
on its next heartbeat (about a minute), with nothing else to run or configure
on this machine (TT-2210). Any copy of this command shown elsewhere should match
this - if it doesn't include the `apt-get install build-essential` line, it will
fail on a fresh box the same way.

## Usage

### Generating the Connector's identity (no config needed)

`install-systemd.sh` generates the identity for you. To print a public key
without installing anything, use the standalone identity mode:

```sh
secure_connect_connector --generate-identity
```

This generates (or loads, if one already exists) the Connector's X25519
identity keypair, prints only the public key to stdout, and exits. No
`AGENTS_JSON_URL`/`REGISTRY_BASE_URL` required, no network calls made. The
resolved key file path is reported on stderr (not stdout, so stdout stays
scriptable - copy just what's printed there into Portal).

The public key is the Connector's only identity - there is no separate
connector ID to configure. Run the daemon (see below) with
`CONNECTOR_IDENTITY_KEY_PATH` unchanged, so it loads the same identity rather
than generating a new, unregistered one.

`secure_connect_connector --help` prints a one-line usage summary.

### Running the Connector daemon

Requires these environment variables:

| Variable                       | Required | Default                                    |
| ------------------------------- | -------- | ------------------------------------------- |
| `AGENTS_JSON_URL`                | yes      | -                                             |
| `REGISTRY_BASE_URL`              | yes      | -                                             |
| `CONNECTOR_IDENTITY_KEY_PATH`    | no       | `/var/skipr/connector/.keys/identity.key`     |
| `CONNECTOR_AUDIT_LOG_PATH`       | no       | `/var/skipr/connector/audit/audit.log`        |
| `CONNECTOR_GATEKEEPER_HTTP_PORT` | no       | `4000`                                        |
| `CONNECTOR_TUN_NETMASK`          | no       | `255.255.255.0`                               |
| `HEARTBEAT_INTERVAL_SECONDS`     | no       | `60`                                          |
| `CONNECTOR_CA_BUNDLE_PATH`       | no       | unset                                         |

**`AGENTS_JSON_URL`** - the environment's public `agents.json` list (e.g.
`https://skipr-shared-test.s3.us-west-2.amazonaws.com/agents.json`), never one Agent's
address. Every heartbeat re-reads it and goes through an Agent listed as `operational`, staying
on the one that last answered while it is still listed, and failing over to the next one in the
same cycle if it stops answering - so an Agent rotating away needs no action here (TT-2210).
Until an admin has pasted this Connector's public key into Portal, every heartbeat is answered
"not registered", logged at `info` with the key to paste; the first heartbeat after that paste
activates the Connector without a restart.

**`CONNECTOR_CA_BUNDLE_PATH`** - a PEM bundle (one or more certificates) of extra root CAs to
trust for the Agent/Registry connections, for an Agent running behind a private/internal CA. Not
usually needed: if the CA is already installed in the box's own OS trust store (the standard
on-prem procedure), the Connector trusts it automatically with no configuration at all. Set this
only when that isn't the case. An unreadable file or invalid PEM fails the daemon at startup
rather than silently falling back to the default trust.

**Behavior change (TT-2027):** trusting the box's own OS trust store at all is new as of this
release - earlier versions only trusted the bundled Mozilla root set and had no way to pick up a
CA installed locally on the box, `CONNECTOR_CA_BUNDLE_PATH` or otherwise. Every daemon startup now
also logs an `info`/`warn` line reporting how many root certificates the OS trust store has (and
any errors reading it), purely for visibility - not consulted for any trust decision, and not an
exact count of what the running HTTP client ends up trusting (a certificate that fails to parse as
a valid trust anchor is silently skipped by the client itself, the same way a native store's own
occasional ancient or malformed entry always has been).

**`CONNECTOR_IDENTITY_KEY_PATH` must match the path `--generate-identity` actually used** when
running the raw binary by hand - it is not persisted anywhere by itself (the systemd install below
handles this for you, writing the path it used into `connector.env`). Starting the daemon with a
different value generates a second, unregistered identity - the daemon will log a loud warning if
this happens, but the fix is to export the same path explicitly first:

```sh
export CONNECTOR_IDENTITY_KEY_PATH=$HOME/.skipr/connector-identity.key
```

```sh
secure_connect_connector
```

### Running it as a systemd service (recommended)

Running the raw binary directly requires either root or manually granting it
`CAP_NET_ADMIN` (`sudo setcap cap_net_admin+ep target/release/secure_connect_connector`)
every single time it's rebuilt, since that capability is a property of the binary
file and gets wiped out on every new build - easy to forget, and a real admin has
no reason to know it's needed at all (creating the Connector's TUN device is a
privileged kernel operation, `Operation not permitted` otherwise).

The systemd install script grants that one capability declaratively, once, so it
survives every rebuild and restart without ever running the daemon as root. It
also generates the Connector's identity itself, directly at the path the
service will actually load it from - printing the public key for you to
register in Portal, the same way the standalone `--generate-identity` mode
above does, but without the separate manual step or the risk of the daemon
loading from a different path than whatever shell generated the key:

```sh
sudo AGENTS_JSON_URL=... REGISTRY_BASE_URL=... ./packaging/install-systemd.sh
```

It writes both values into `/etc/skipr/connector/connector.env`, starts the
service, and prints the public key to paste into Portal's Deploy Connector
screen - that paste is the last step. `CONNECTOR_CA_BUNDLE_URL=<url>` can be
passed the same way to download a CA bundle to trust (see
`CONNECTOR_CA_BUNDLE_PATH` above). Leave `CONNECTOR_IDENTITY_KEY_PATH` in that
file alone unless you deliberately want a non-default location (it is read by
systemd, not a shell: use an absolute path only, since `$HOME` and `~` are not
expanded there, and re-run `install-systemd.sh` afterwards so the identity gets
generated at the new path). To watch it:

```sh
journalctl -u secure-connect-connector -f
```

Re-running `install-systemd.sh` after a rebuild or an env-file change picks up the new binary/config and restarts the service; values not passed on a re-run keep whatever `connector.env` already has.

**Upgrading a Connector installed before TT-2210** (its `connector.env` has `CONNECTOR_ID` /
`AGENT_BASE_URL` / `AGENT_IP_ADDRESS`): the new binary no longer reads those and needs
`AGENTS_JSON_URL` instead, so pass both values when re-running the script, e.g. re-run Portal's
install command, or `sudo AGENTS_JSON_URL=... REGISTRY_BASE_URL=... ./packaging/install-systemd.sh`.
Its identity key, and so its registration in Portal, carry over unchanged. Re-running without them
warns that the still-running old process will not survive its next restart. The old lines can be
deleted from `connector.env`; they are ignored. To remove it entirely (`connector.env` is left in place):

```sh
./packaging/install-systemd.sh --uninstall
```

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
