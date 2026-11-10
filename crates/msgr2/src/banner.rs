// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::{BannerError, Revision};

/// MSGR2 feature: v2.1 frame layout.
pub const FEATURE_REVISION_1: u64 = 1;
/// MSGR2 feature: on-wire compression.
pub const FEATURE_COMPRESSION: u64 = 2;
/// croit-flashstore-osd extension: the connection may move to an RDMA RC QP after auth (spec 18). High bit: upstream allocates
/// from the low end. Never required.
pub const FEATURE_RDMA: u64 = 1 << 62;
/// croit-flashstore-osd extension: single-read RDMA payload placement after an accepted upgrade. Never required.
pub const FEATURE_PLACEMENT: u64 = 1 << 61;
/// Optional croit-flashstore-osd object source-pull capability, distinct from placement v1.
pub const FEATURE_SOURCE_PULL: u64 = 1 << 60;

const PREFIX: &[u8; 8] = b"ceph v2\n";
const MSGR1: &[u8; 9] = b"ceph v027";

/// msgr2 banner (spec 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Banner {
    /// Features we support.
    pub supported: u64,
    /// Features the peer must support.
    pub required: u64,
}

impl Banner {
    /// croit-flashstore-osd banner: REVISION_1, no COMPRESSION, nothing required.
    pub fn ours() -> Banner {
        Banner {
            supported: FEATURE_REVISION_1,
            required: 0,
        }
    }

    /// Append the 26-byte banner.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(PREFIX);
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(&self.supported.to_le_bytes());
        out.extend_from_slice(&self.required.to_le_bytes());
    }

    /// Incremental parse. `Ok(None)` = need more bytes; `Ok(Some((banner, consumed)))`.
    /// Extra payload beyond 16 bytes is skipped.
    pub fn parse(buf: &[u8]) -> Result<Option<(Banner, usize)>, BannerError> {
        let n = buf.len().min(MSGR1.len());
        if n == MSGR1.len() && buf[..n] == MSGR1[..] {
            return Err(BannerError::Msgr1);
        }
        let m = n.min(PREFIX.len());
        if buf[..m] != PREFIX[..m] {
            return Err(BannerError::BadPrefix);
        }
        if buf.len() < 10 {
            return Ok(None);
        }
        let plen = denc::le::rd_u16(buf, 8);
        if plen < 16 {
            return Err(BannerError::BadPayloadLen(plen));
        }
        let total = 10 + plen as usize;
        if buf.len() < total {
            return Ok(None);
        }
        let rd = |o: usize| denc::le::rd_u64(buf, o);
        Ok(Some((
            Banner {
                supported: rd(10),
                required: rd(18),
            },
            total,
        )))
    }

    /// Frame revision implied by the PEER's banner.
    pub fn revision(&self) -> Revision {
        if self.supported & FEATURE_REVISION_1 != 0 {
            Revision::V21
        } else {
            Revision::V20
        }
    }

    /// Check compatibility of our banner with the peer's (spec 2 rules).
    pub fn check(&self, peer: &Banner) -> Result<(), BannerError> {
        if self.required & peer.supported != self.required
            || peer.required & self.supported != peer.required
        {
            return Err(BannerError::FeatureMismatch);
        }
        Ok(())
    }

    /// True if COMPRESSION negotiation is needed (peer advertised it).
    pub fn compression(&self) -> bool {
        self.supported & FEATURE_COMPRESSION != 0
    }

    /// True if the peer offers the RDMA upgrade (spec 18).
    pub fn rdma(&self) -> bool {
        self.supported & FEATURE_RDMA != 0
    }

    /// True if the peer offers the object source-pull extension.
    pub fn source_pull(&self) -> bool {
        self.supported & FEATURE_SOURCE_PULL != 0
    }

    /// True if the peer offers the RDMA placement extension.
    pub fn placement(&self) -> bool {
        self.supported & FEATURE_PLACEMENT != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_parse() {
        let mut v = Vec::new();
        Banner {
            supported: 3,
            required: 0,
        }
        .encode(&mut v);
        assert_eq!(v.len(), 26);
        assert_eq!(&v[..10], b"ceph v2\n\x10\x00");
        for cut in 0..26 {
            assert_eq!(Banner::parse(&v[..cut]), Ok(None), "cut {cut}");
        }
        let (b, n) = Banner::parse(&v).unwrap().unwrap();
        assert_eq!((b.supported, b.required, n), (3, 0, 26));
        assert_eq!(b.revision(), Revision::V21);
        assert_eq!(
            Banner {
                supported: 2,
                required: 0
            }
            .revision(),
            Revision::V20
        );
    }

    #[test]
    fn extra_payload_skipped() {
        let mut v = Vec::new();
        v.extend_from_slice(b"ceph v2\n");
        v.extend_from_slice(&20u16.to_le_bytes());
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend_from_slice(&[9, 9, 9, 9, 7]);
        assert_eq!(Banner::parse(&v).unwrap().unwrap().1, 30);
    }

    #[test]
    fn bad() {
        assert_eq!(Banner::parse(b"ceph v027 xxxxxx"), Err(BannerError::Msgr1));
        assert_eq!(Banner::parse(b"cep"), Ok(None));
        assert_eq!(Banner::parse(b"xeph"), Err(BannerError::BadPrefix));
        assert_eq!(
            Banner::parse(b"ceph v3\n\x10\x00"),
            Err(BannerError::BadPrefix)
        );
        let mut v = b"ceph v2\n".to_vec();
        v.extend_from_slice(&15u16.to_le_bytes());
        assert_eq!(Banner::parse(&v), Err(BannerError::BadPayloadLen(15)));
        let a = Banner {
            supported: 1,
            required: 0,
        };
        assert!(
            a.check(&Banner {
                supported: 3,
                required: 0
            })
            .is_ok()
        );
        assert!(
            a.check(&Banner {
                supported: 3,
                required: 4
            })
            .is_err()
        );
        assert!(
            Banner {
                supported: 1,
                required: 2
            }
            .check(&a)
            .is_err()
        );
    }
}
