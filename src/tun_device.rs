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

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct TunReader {
    inner: tun::DeviceReader,
}

pub struct TunWriter {
    inner: tun::DeviceWriter,
}

/// Creates and brings up a TUN interface at `address`/`netmask`, returning
/// separately-ownable read/write halves so each can live in its own async
/// task without needing a shared lock - only one task ever reads, only one
/// ever writes.
pub fn create(address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> Result<(TunReader, TunWriter)> {
    let mut config = tun::Configuration::default();
    config.address(address).netmask(netmask).mtu(mtu).up();
    let device = tun::create_as_async(&config).context("failed to create TUN device")?;
    let (writer, reader) = device.split().context("failed to split TUN device")?;
    Ok((TunReader { inner: reader }, TunWriter { inner: writer }))
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
