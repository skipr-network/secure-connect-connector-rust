# secure-connect-connector-rust

The Private Gateway Connector runtime (TT-1732). Installed by an Enterprise
Admin inside their own network, next to an internal service (CRM, ERP, file
server). Heartbeats to Agent, verifies the signed policy package it gets back,
connects to VPN nodes over WireGuard, and makes the final allow/deny decision
for private-service traffic.

Spec: [Private Gateway, Endpoint Node Fleet & Client Discovery](https://github.com/skipr-network/doc_private/blob/main/03-architecture/specs/private_gateway_node_architecture_final.md)
(§B.3, §B.4, §B.7, §B.9, §B.10).

## Status

First slice only: Connector identity (Ed25519 key pair, generated and
persisted on first start) and a verified heartbeat client against Agent's
`POST /api/connectors/{connectorId}/heartbeat`. Policy application, node
tunnels (BoringTun), and traffic enforcement are later slices.

## Configuration

Set via environment variables:

| Variable | Required | Default |
| --- | --- | --- |
| `CONNECTOR_ID` | yes | - |
| `AGENT_BASE_URL` | yes | - |
| `AGENT_IP_ADDRESS` | yes | - |
| `REGISTRY_BASE_URL` | yes | - |
| `CONNECTOR_IDENTITY_KEY_PATH` | no | `/var/skipr/connector/.keys/identity.key` |
| `HEARTBEAT_INTERVAL_SECONDS` | no | `60` |

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
