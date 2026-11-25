//! Thin wrapper around a real TUN network interface - the last piece needed
//! to actually forward IP traffic through a node's WireGuard tunnel (spec
//! §B.8, "Connector forwards allowed traffic only to configured internal
//! endpoints"), rather than only establishing the tunnel session
//! (`tunnel.rs`).
//!
//! Needs `CAP_NET_ADMIN` and `/dev/net/tun` - not available in a normal
//! `cargo test` environment, so nothing in this file is unit-tested and it's
//! kept as small as possible for exactly that reason (same treatment as
//! `main`'s other untestable socket-binding code). Proven for real, outside
//! this crate, before writing this: two separate Docker containers, each
//! with a real TUN device and a real `boringtun::noise::Tunn`, exchanged
//! genuine ICMP traffic end to end through actual WireGuard encryption
//! between two separate network namespaces (TT-1732 session notes,
//! 2026-08-27) - this file wires that proven mechanism into the Connector
//! itself, it doesn't re-invent it.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::AbstractDevice;

pub struct TunReader {
    inner: tun::DeviceReader,
}

pub struct TunWriter {
    inner: tun::DeviceWriter,
}

/// Creates and brings up a TUN interface at `address`/`netmask`, returning
/// separately-ownable read/write halves so each can live in its own async
/// task without needing a shared lock - only one task ever reads, only one
/// ever writes. `gatekeeper_wg0_address` (`Config::gatekeeper_wg0_address`,
/// TT-2144 review PR #21 - previously a hardcoded constant here) is what
/// `add_gatekeeper_return_route` below installs a kernel route for, derived
/// as that address's own /24 rather than a second, separately hardcoded
/// subnet - one value to get right, not two.
pub fn create(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
    gatekeeper_wg0_address: Ipv4Addr,
) -> Result<(TunReader, TunWriter)> {
    let mut config = tun::Configuration::default();
    config.address(address).netmask(netmask).mtu(mtu).up();
    let device = tun::create_as_async(&config).context("failed to create TUN device")?;
    add_gatekeeper_return_route(&device, gatekeeper_wg0_address);
    let (writer, reader) = device.split().context("failed to split TUN device")?;
    Ok((TunReader { inner: reader }, TunWriter { inner: writer }))
}

/// `gatekeeper_wg0_address`'s own /24, e.g. `10.66.66.1` -> `10.66.66.0/24` - what
/// `add_gatekeeper_return_route` installs a kernel route for. A plain string format
/// (not an actual subnet/CIDR type) since the only consumer is `ip route replace`'s
/// own argument list, which just wants text.
fn subnet_slash_24(address: Ipv4Addr) -> String {
    let [a, b, c, _] = address.octets();
    format!("{a}.{b}.{c}.0/24")
}

/// Adds the kernel route a locally-terminating reply (e.g. the flow-admission
/// HTTP server's own response to Gatekeeper) needs to route back through this
/// TUN device instead of leaking out the real network interface (TT-1734 gap
/// #6, `run_tun_send_loop`'s reply path). Tied to this interface's own
/// lifecycle, not a one-time install step: a hand-rolled TUN setup like this
/// one has no `wg-quick`-equivalent to add it automatically, and unlike a
/// persistent interface, this one - and any route pinned to it - is destroyed
/// and recreated fresh on every single process restart, so this has to run
/// here, every time, not just once at install time.
///
/// Best-effort and non-fatal: confirmed live (TT-1734 session notes,
/// 2026-09-17) that this route silently disappearing is exactly what breaks
/// Gatekeeper's flow-admission replies, but a Connector that can't run `ip`
/// at all should still come up rather than refuse to start over one missing
/// return path - it'll just repeat the same "replies leak to the internet"
/// failure until whoever's running it notices and fixes the environment.
fn add_gatekeeper_return_route(device: &tun::AsyncDevice, gatekeeper_wg0_address: Ipv4Addr) {
    let interface_name = match device.tun_name() {
        Ok(name) => name,
        Err(error) => {
            tracing::error!(%error, "could not determine the TUN interface's own name - cannot add the Gatekeeper return route");
            return;
        }
    };
    let subnet = subnet_slash_24(gatekeeper_wg0_address);
    match Command::new("ip")
        .args(["route", "replace", &subnet, "dev", &interface_name])
        .status()
    {
        Ok(status) if status.success() => {
            tracing::info!(interface = %interface_name, %subnet, "added the Gatekeeper return route");
        }
        Ok(status) => {
            tracing::error!(interface = %interface_name, %subnet, exit_code = ?status.code(), "ip route replace exited non-zero - Gatekeeper's flow-admission replies will not route back correctly");
        }
        Err(error) => {
            tracing::error!(%error, interface = %interface_name, %subnet, "failed to run ip route replace - Gatekeeper's flow-admission replies will not route back correctly");
        }
    }
}

impl TunReader {
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner
            .read(buf)
            .await
            .context("failed to read from TUN device")
    }
}

impl TunWriter {
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.inner
            .write_all(packet)
            .await
            .context("failed to write to TUN device")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_slash_24_zeroes_the_last_octet() {
        assert_eq!(
            subnet_slash_24(Ipv4Addr::new(10, 66, 66, 1)),
            "10.66.66.0/24"
        );
    }

    #[test]
    fn subnet_slash_24_works_for_a_configured_non_default_address() {
        assert_eq!(
            subnet_slash_24(Ipv4Addr::new(10, 66, 66, 9)),
            "10.66.66.0/24"
        );
    }
}
