# secure-connect-connector-rust

The Private Gateway Connector runtime (TT-1732). Installed by an Enterprise
Admin inside their own network, next to an internal service (CRM, ERP, file
server). Heartbeats to Agent, verifies the signed policy package it gets back,
connects to VPN nodes over WireGuard, and makes the final allow/deny decision
for private-service traffic.

Spec: [Private Gateway, Endpoint Node Fleet & Client Discovery](https://github.com/skipr-network/doc_private/blob/main/03-architecture/specs/private_gateway_node_architecture_final.md)
(§B.3, §B.4, §B.7, §B.9, §B.10).

## Status

Repo scaffold only. Implementation lands in feature PRs, first slice being
Connector identity + verified heartbeat client against Agent.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
