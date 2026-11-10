// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! msgr2 over RDMA, SEND baseline (0469-rdma-transport). One RC QP per connection carries the msgr2 byte stream as a
//! sequence of SEND_WITH_IMM work requests: each SEND holds up to one receive slot of stream bytes, its immediate
//! returns receive credits ([`credit`]). Per core: one CQ, one SRQ, one registered receive arena and one registered
//! send arena; no locks, no allocation on the data path.
//!
//! Sans-IO parts (credits, the handover endpoint record, send-ring accounting) build everywhere; the verbs data path
//! needs feature `verbs` on Linux.
#![deny(clippy::print_stderr, clippy::print_stdout)]
#![cfg_attr(test, allow(clippy::print_stderr, clippy::print_stdout))]
pub mod budget;
#[cfg(feature = "memory-windows")]
mod completion;
pub mod control;
pub mod credit;
#[cfg(all(feature = "fault-inject", feature = "verbs", target_os = "linux"))]
pub mod fault;
pub mod fence;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod grant;
pub mod hold;
pub mod host_memory;
pub mod memory;
pub mod placement;
#[cfg(any(test, all(feature = "verbs", target_os = "linux")))]
pub(crate) mod provider;
pub mod qpn;
pub mod ring;
pub mod source_pull;
pub mod status;
#[cfg(all(test, feature = "memory-windows"))]
mod test_alloc;
pub mod tx;
pub mod upgrade;

#[cfg(all(feature = "verbs", target_os = "linux"))]
pub mod verbs;

/// Receive slot size: one RoCE MTU worth of pages is too small for msgr2 frames, 64 KiB keeps the per-SEND cost low
/// for large frames while a small frame wastes the rest of one slot only.
pub const DEFAULT_SLOT: u32 = 64 * 1024;

/// Smallest receive slot a core is built with (a smaller peer record is not ours: every SEND would shrink to it).
pub const MIN_SLOT: u32 = 4096;

/// Window (credits of [`DEFAULT_SLOT`]) that carries one stream at line rate with margin: perf rdma-spike-20261019 section
/// 8 (line rate from window 8 at 64 KiB slots; 16 = 2x margin = 1 MiB in flight). The minimum memory budget
/// ([`budget::min_bytes`]) is sized for it.
pub const LINE_RATE_WINDOW: u32 = 16;

/// Largest receive window one session may hold when the budget allows it ([`budget::size`]: at most a
/// [`budget::MIN_CONNECTIONS`]th of a core's receive slots). Measured: perf rdma-spike-20261019 section 14 (64 vs 16 with
/// the client receive helpers: 4 MiB reads +15 %, writes +8 % at a third of the p99, credit stalls / 3; the receiver's
/// copy time adds to the round trip, so the window covers more than the wire's bandwidth-delay product).
pub const DEFAULT_MAX_WINDOW: u32 = 64;

/// Explicit QP READ offer. Values are bounded by the device and provider
/// attribute widths; the initiator is also bounded by local SQ depth. Zero
/// disables that direction. An offer grants
/// no memory access or object-protocol capability. Both zero is invalid on wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOffer {
    pub initiator: u8,
    pub responder: u8,
}

/// What a detached QP still holds of its core until the control thread confirmed its destroy (`verbs::Core::detach`): the
/// send slots of its outstanding WRs and the receive credits its peer may still use (a SEND of that peer can land in the
/// shared SRQ until the QP is gone). Given back with `verbs::Core::reclaim` after the destroy; lost for good when the
/// destroy failed (the HCA may still use both).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Release {
    pub slots: Vec<u32>,
    pub credits: u32,
}

/// What one side tells the other during the handover (0469-rdma-transport): QP number, initial PSN, RoCEv2 GID, the
/// receive window it granted and its receive slot size (= largest SEND it accepts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub qpn: u32,
    pub psn: u32,
    pub gid: [u8; 16],
    pub window: u32,
    pub slot: u32,
    /// Active MTU of the sender's RoCE port in bytes (1024, 2048 or 4096); 0 = not advertised (a record of an older
    /// version, whose ports are always 4096). The QP path MTU is the smaller of both sides ([`path_mtu`]).
    pub mtu: u32,
    /// Optional, explicit READ setup offer. Legacy/default peers omit it;
    /// negotiated READ depths must then remain zero in both directions.
    pub reads: Option<ReadOffer>,
}

/// Smallest accepted RoCE path MTU (netdev MTU 1500 gives 1024). 4096 stays the recommendation (0470-rdma-ops).
pub const MIN_PATH_MTU: u32 = 1024;

/// QP path MTU of a connection: the smaller of the local active MTU and the peer's advertised one. A peer that advertised
/// nothing (`peer == 0`, older version) is 4096; `None` when that leaves a pair that cannot agree (local below 4096).
pub fn path_mtu(local: u32, peer: u32) -> Option<u32> {
    match peer {
        0 if local >= 4096 => Some(4096),
        0 => None,
        p => Some(local.min(p)),
    }
}

impl Endpoint {
    /// Shortest record accepted (older versions: no MTU field).
    pub const MIN_LEN: usize = 32;
    pub const LEN: usize = 36;
    /// Base endpoint plus the exact version-1 READ capability extension.
    pub const READ_LEN: usize = 44;

    /// Base endpoint stays byte-identical for default peers. Explicit READ QPs
    /// append one eight-byte versioned capability record. Control path only.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![
            0u8;
            if self.reads.is_some() {
                Self::READ_LEN
            } else {
                Self::LEN
            }
        ];
        b[0..4].copy_from_slice(&self.qpn.to_le_bytes());
        b[4..8].copy_from_slice(&self.psn.to_le_bytes());
        b[8..24].copy_from_slice(&self.gid);
        b[24..28].copy_from_slice(&self.window.to_le_bytes());
        b[28..32].copy_from_slice(&self.slot.to_le_bytes());
        b[32..36].copy_from_slice(&self.mtu.to_le_bytes());
        if let Some(reads) = self.reads {
            b[36] = 1; // extension version
            b[38] = reads.initiator;
            b[39] = reads.responder;
        }
        b
    }

    /// Rejects a record that cannot run a connection (QPN/PSN out of 24-bit range, window outside MIN_WINDOW..=MAX_PEER_WINDOW, slot < MIN_SLOT).
    pub fn decode(b: &[u8]) -> Option<Endpoint> {
        if !matches!(b.len(), Self::MIN_LEN | Self::LEN | Self::READ_LEN) {
            return None;
        }
        let head: &[u8; Self::MIN_LEN] = b.get(..Self::MIN_LEN)?.try_into().ok()?;
        let u = |i: usize| le::u32_at(head, i);
        let mtu = match b.get(Self::MIN_LEN..Self::LEN) {
            Some(m) => u32::from_le_bytes(m.try_into().ok()?),
            None => 0,
        };
        let reads = if b.len() == Self::READ_LEN {
            if b[36] != 1 || b[37] != 0 || b[40..44] != [0; 4] || b[38..40] == [0; 2] {
                return None;
            }
            Some(ReadOffer {
                initiator: b[38],
                responder: b[39],
            })
        } else {
            None
        };
        let e = Endpoint {
            qpn: u(0),
            psn: u(4),
            gid: head[8..24].try_into().ok()?,
            window: u(24),
            slot: u(28),
            mtu,
            reads,
        };
        (e.qpn < 1 << 24
            && e.psn < 1 << 24
            && (e.mtu == 0 || (MIN_PATH_MTU..=4096).contains(&e.mtu) && e.mtu.is_power_of_two())
            && (credit::MIN_WINDOW..=credit::MAX_PEER_WINDOW).contains(&e.window)
            && e.slot >= MIN_SLOT)
            .then_some(e)
    }
}

/// Little-endian fields of an already length-checked wire record.
pub(crate) mod le {
    pub(crate) fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }
    pub(crate) fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }
    pub(crate) fn u64_at(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }
}

/// RoCEv2 GID of an IP: IPv4-mapped for IPv4, the address itself for IPv6.
pub fn gid_of(ip: std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(v) => v.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v) => v.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_offer_exact_wire_legacy_and_malformed_records() {
        let base = Endpoint {
            qpn: 1,
            psn: 2,
            gid: [3; 16],
            window: 16,
            slot: DEFAULT_SLOT,
            mtu: 4096,
            reads: None,
        };
        let legacy = base.encode();
        assert_eq!(legacy.len(), Endpoint::LEN);
        for reads in [
            ReadOffer {
                initiator: 1,
                responder: 8,
            },
            ReadOffer {
                initiator: 0,
                responder: 255,
            },
            ReadOffer {
                initiator: 255,
                responder: 0,
            },
        ] {
            let endpoint = Endpoint {
                reads: Some(reads),
                ..base
            };
            let wire = endpoint.encode();
            assert_eq!(&wire[..36], legacy.as_slice());
            assert_eq!(
                &wire[36..],
                &[1, 0, reads.initiator, reads.responder, 0, 0, 0, 0]
            );
            assert_eq!(Endpoint::decode(&wire), Some(endpoint));
            assert_eq!(Endpoint::decode(&wire[..36]), Some(base));
            for length in 0..wire.len() {
                if length == 32 || length == 36 {
                    continue;
                }
                assert!(
                    Endpoint::decode(&wire[..length]).is_none(),
                    "length {length}"
                );
            }
            for offset in [36, 37, 40, 41, 42, 43] {
                let mut bad = wire.clone();
                bad[offset] = 255;
                assert!(Endpoint::decode(&bad).is_none(), "offset {offset}");
            }
            let mut bad = wire.clone();
            bad.extend_from_slice(&[0]);
            assert!(Endpoint::decode(&bad).is_none());
            let mut bad = wire;
            bad[38..40].fill(0);
            assert!(Endpoint::decode(&bad).is_none());
        }
    }

    #[test]
    fn endpoint_roundtrip_and_validation() {
        let e = Endpoint {
            qpn: 0x12_3456,
            psn: 7,
            gid: gid_of("172.28.0.47".parse().unwrap()),
            window: 64,
            slot: DEFAULT_SLOT,
            mtu: 4096,
            reads: None,
        };
        let b = e.encode();
        assert_eq!(
            &b[8..24],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 172, 28, 0, 47]
        );
        assert_eq!(Endpoint::decode(&b), Some(e));
        assert_eq!(Endpoint::decode(&b[..Endpoint::MIN_LEN - 1]), None);
        let mut bad = e;
        bad.qpn = 1 << 24;
        assert_eq!(Endpoint::decode(&bad.encode()), None);
        bad = e;
        bad.window = 1;
        assert_eq!(Endpoint::decode(&bad.encode()), None);
        bad = e;
        bad.window = credit::MAX_PEER_WINDOW + 1;
        assert_eq!(Endpoint::decode(&bad.encode()), None);
        bad = e;
        bad.slot = MIN_SLOT - 1;
        assert_eq!(Endpoint::decode(&bad.encode()), None);
    }

    #[test]
    fn endpoint_mtu_field_is_optional_and_validated() {
        let e = Endpoint {
            qpn: 5,
            psn: 7,
            gid: [1; 16],
            window: 64,
            slot: DEFAULT_SLOT,
            mtu: 1024,
            reads: None,
        };
        let b = e.encode();
        // an older record (32 bytes) decodes with mtu 0 = not advertised
        let old = Endpoint::decode(&b[..Endpoint::MIN_LEN]).unwrap();
        assert_eq!(old, Endpoint { mtu: 0, ..e });
        // and an older decoder reads a new record: first 32 bytes are unchanged
        assert_eq!(&b[..32], &old.encode()[..32]);
        for bad in [1, 512, 1536, 3000, 8192, 4097] {
            assert_eq!(
                Endpoint::decode(&Endpoint { mtu: bad, ..e }.encode()),
                None,
                "{bad}"
            );
        }
        for ok in [1024, 2048, 4096] {
            assert!(Endpoint::decode(&Endpoint { mtu: ok, ..e }.encode()).is_some());
        }
    }

    #[test]
    fn path_mtu_is_the_smaller_side_and_old_peers_are_4096() {
        assert_eq!(path_mtu(4096, 4096), Some(4096));
        assert_eq!(path_mtu(4096, 1024), Some(1024));
        assert_eq!(path_mtu(1024, 4096), Some(1024));
        assert_eq!(path_mtu(2048, 1024), Some(1024));
        assert_eq!(path_mtu(4096, 0), Some(4096));
        assert_eq!(path_mtu(2048, 0), None);
        assert_eq!(path_mtu(1024, 0), None);
    }
}
