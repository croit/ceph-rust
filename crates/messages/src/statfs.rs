// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Cluster statistics wire profile, RC179.
use crate::msg::{end, front_segments, get_psm, put_psm};
use crate::{Message, Segments, meta};
use denc::types::Uuid;
use denc::{Decode, Decoder, Encode, Error, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct ClusterStatistics {
    pub kb: u64,
    pub kb_used: u64,
    pub kb_avail: u64,
    pub num_objects: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MStatfs {
    pub version: u64,
    pub fsid: Uuid,
    pub data_pool: Option<i64>,
}
fn segments(middle: &[u8], data: &[u8]) -> Result<()> {
    if !middle.is_empty() || !data.is_empty() {
        return Err(Error::BadValue("statfs extra segment"));
    }
    Ok(())
}
impl Message for MStatfs {
    meta!(13,2,1,oldest 1);
    fn encode(&self, features: u64) -> Result<Segments> {
        front_segments(features, |e| {
            put_psm(e, self.version)?;
            self.fsid.encode(e)?;
            e.u8(u8::from(self.data_pool.is_some()))?;
            if let Some(pool) = self.data_pool {
                e.i64(pool)?;
            }
            Ok(())
        })
    }
    fn decode(version: u16, front: &[u8], middle: &[u8], data: &[u8]) -> Result<Self> {
        Self::check_version(version)?;
        if version > 2 {
            return Err(Error::BadValue("statfs request version"));
        }
        segments(middle, data)?;
        let mut d = Decoder::new(front);
        let pg_version = get_psm(&mut d)?;
        let fsid = Uuid::decode(&mut d)?;
        let data_pool = if version == 1 {
            None
        } else {
            match d.u8()? {
                0 => None,
                1 => Some(d.i64()?),
                tag => return Err(Error::BadMarker(tag)),
            }
        };
        end(&d)?;
        Ok(Self {
            version: pg_version,
            fsid,
            data_pool,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MStatfsReply {
    pub fsid: Uuid,
    pub version: u64,
    pub statistics: ClusterStatistics,
}
impl Message for MStatfsReply {
    meta!(14,1,0,oldest 1);
    fn encode(&self, features: u64) -> Result<Segments> {
        front_segments(features, |e| {
            self.fsid.encode(e)?;
            e.u64(self.version)?;
            e.u64(self.statistics.kb)?;
            e.u64(self.statistics.kb_used)?;
            e.u64(self.statistics.kb_avail)?;
            e.u64(self.statistics.num_objects)
        })
    }
    fn decode(version: u16, front: &[u8], middle: &[u8], data: &[u8]) -> Result<Self> {
        Self::check_version(version)?;
        if version != 1 {
            return Err(Error::BadValue("statfs reply version"));
        }
        segments(middle, data)?;
        let mut d = Decoder::new(front);
        let reply = Self {
            fsid: Uuid::decode(&mut d)?,
            version: d.u64()?,
            statistics: ClusterStatistics {
                kb: d.u64()?,
                kb_used: d.u64()?,
                kb_avail: d.u64()?,
                num_objects: d.u64()?,
            },
        };
        end(&d)?;
        Ok(reply)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_request_optional_pool_and_legacy_front() {
        let request = MStatfs {
            version: 9,
            fsid: Uuid([7; 16]),
            data_pool: None,
        };
        let mut expected = vec![9, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0];
        expected.extend([7; 16]);
        expected.push(0);
        assert_eq!(request.encode(0).unwrap().front, expected);
        assert_eq!(MStatfs::decode(2, &expected, &[], &[]).unwrap(), request);
        assert_eq!(
            MStatfs::decode(1, &expected[..34], &[], &[]).unwrap(),
            request
        );
        let header = crate::Header2::new(19, 13, 2, 1);
        assert_eq!(
            crate::decode_with_header(&header, &expected, &[], &[]).unwrap(),
            request.clone().into()
        );
        let mut too_new = header;
        too_new.compat_version = 3;
        assert!(crate::decode_with_header(&too_new, &expected, &[], &[]).is_err());
        expected[34] = 1;
        expected.extend((-7i64).to_le_bytes());
        assert_eq!(
            MStatfs::decode(2, &expected, &[], &[]).unwrap().data_pool,
            Some(-7)
        );
        expected[34] = 2;
        assert!(MStatfs::decode(2, &expected, &[], &[]).is_err());
    }
    #[test]
    fn frozen_reply_framing_and_dispatch() {
        let mut front = vec![7; 16];
        for value in [9u64, 1024, 123, 901, u64::MAX] {
            front.extend(value.to_le_bytes());
        }
        let reply = MStatfsReply {
            fsid: Uuid([7; 16]),
            version: 9,
            statistics: ClusterStatistics {
                kb: 1024,
                kb_used: 123,
                kb_avail: 901,
                num_objects: u64::MAX,
            },
        };
        assert_eq!(reply.encode(0).unwrap().front, front);
        assert_eq!(
            crate::decode_any(14, 1, &front, &[], &[]).unwrap(),
            reply.clone().into()
        );
        let header = crate::Header2::new(19, 14, 1, 0);
        assert_eq!(
            crate::decode_with_header(&header, &front, &[], &[]).unwrap(),
            reply.clone().into()
        );
        let mut too_new = header;
        too_new.compat_version = 2;
        assert!(crate::decode_with_header(&too_new, &front, &[], &[]).is_err());
        for n in 0..front.len() {
            assert!(MStatfsReply::decode(1, &front[..n], &[], &[]).is_err());
        }
        assert!(MStatfsReply::decode(1, &front, &[0], &[]).is_err());
        assert!(MStatfsReply::decode(1, &front, &[], &[0]).is_err());
        front.push(0);
        assert!(MStatfsReply::decode(1, &front, &[], &[]).is_err());
    }
}
