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

## Usage

### Generating the Connector's identity (first run, no config needed)

Portal only issues a `CONNECTOR_ID` after an Enterprise Admin submits the
Connector's public key on the Deploy Connector screen - so the very first run
can't go through the normal startup path yet. Use the standalone identity mode
instead:

```sh
secure_connect_connector --generate-identity
```

This generates (or loads, if one already exists) the Connector's X25519
identity keypair, prints only the public key to stdout, and exits. No
`CONNECTOR_ID`/`AGENT_BASE_URL`/`AGENT_IP_ADDRESS`/`REGISTRY_BASE_URL` required,
no network calls made. The resolved key file path is reported on stderr (not
stdout, so stdout stays scriptable - copy just what's printed there into
Portal).

Copy the printed public key into Portal's Deploy Connector screen, get back a
real `connector_id`, then run the Connector normally (see below) with the
`CONNECTOR_IDENTITY_KEY_PATH` unchanged, so it loads the same identity rather
than generating a new, unregistered one.

`secure_connect_connector --help` prints a one-line usage summary.

### Running the Connector daemon

Requires these environment variables:

| Variable                       | Required | Default                                    |
| ------------------------------- | -------- | ------------------------------------------- |
| `CONNECTOR_ID`                  | yes      | -                                             |
| `AGENT_BASE_URL`                 | yes      | -                                             |
| `AGENT_IP_ADDRESS`               | yes      | -                                             |
| `REGISTRY_BASE_URL`              | yes      | -                                             |
| `CONNECTOR_IDENTITY_KEY_PATH`    | no       | `/var/skipr/connector/.keys/identity.key`     |
| `CONNECTOR_AUDIT_LOG_PATH`       | no       | `/var/skipr/connector/audit/audit.log`        |
| `CONNECTOR_CONTROL_PLANE_PORT`   | no       | `8443`                                        |
| `CONNECTOR_TUN_NETMASK`          | no       | `255.255.255.0`                               |
| `HEARTBEAT_INTERVAL_SECONDS`     | no       | `60`                                          |

```sh
secure_connect_connector
```

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
