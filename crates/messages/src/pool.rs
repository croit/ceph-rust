// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Typed pool-operation wire profile (snapshots and administration, RC169).
use crate::msg::{end, front_segments, get_psm, put_psm};
use crate::{Message, Segments, meta};
use denc::types::Uuid;
use denc::{Decode, Decoder, Encode, Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PoolOperation {
    CreatePool = 0x01,
    DeletePool = 0x02,
    CreateNamedSnap = 0x11,
    RemoveNamedSnap = 0x12,
    AllocateSelfManagedSnap = 0x21,
    RemoveSelfManagedSnap = 0x22,
}
impl TryFrom<u32> for PoolOperation {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self> {
        match value {
            0x01 => Ok(Self::CreatePool),
            0x02 => Ok(Self::DeletePool),
            0x11 => Ok(Self::CreateNamedSnap),
            0x12 => Ok(Self::RemoveNamedSnap),
            0x21 => Ok(Self::AllocateSelfManagedSnap),
            0x22 => Ok(Self::RemoveSelfManagedSnap),
            _ => Err(Error::BadValue("unsupported pool operation")),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MPoolOp {
    pub version: u64,
    pub fsid: Uuid,
    pub pool: u32,
    pub operation: PoolOperation,
    pub snapid: u64,
    pub name: Vec<u8>,
    pub crush_rule: i16,
}
impl MPoolOp {
    /// Version4 front: Paxos18 + fsid16 + pool/op8 + auid/snap16 +
    /// string prefix4 + pad1 + rule2, followed by the counted name bytes.
    pub fn front_len(name_bytes: usize) -> Result<usize> {
        let total = name_bytes.checked_add(65).ok_or(Error::TooLong)?;
        u32::try_from(total).map_err(|_| Error::TooLong)?;
        Ok(total)
    }
}
fn pinned_segments(version: u16, expected: u16, middle: &[u8], data: &[u8]) -> Result<()> {
    if version != expected {
        return Err(Error::BadValue("snapshot pool message version"));
    }
    if !middle.is_empty() || !data.is_empty() {
        return Err(Error::BadValue("snapshot pool message extra segment"));
    }
    Ok(())
}
impl Message for MPoolOp {
    meta!(49,4,2,oldest 4);
    fn encode(&self, features: u64) -> Result<Segments> {
        Self::front_len(self.name.len())?;
        front_segments(features, |e| {
            put_psm(e, self.version)?;
            self.fsid.encode(e)?;
            e.u32(self.pool)?;
            e.u32(self.operation as u32)?;
            e.u64(0)?;
            e.u64(self.snapid)?;
            e.bytes(&self.name)?;
            e.u8(0)?;
            e.i16(self.crush_rule)
        })
    }
    fn decode(version: u16, front: &[u8], middle: &[u8], data: &[u8]) -> Result<Self> {
        Self::check_version(version)?;
        pinned_segments(version, 4, middle, data)?;
        let mut d = Decoder::new(front);
        let version = get_psm(&mut d)?;
        let fsid = Uuid::decode(&mut d)?;
        let pool = d.u32()?;
        let operation = PoolOperation::try_from(d.u32()?)?;
        d.skip(8)?;
        let snapid = d.u64()?;
        let name = d.bytes()?.to_vec();
        d.skip(1)?;
        let crush_rule = d.i16()?;
        end(&d)?;
        Ok(Self {
            version,
            fsid,
            pool,
            operation,
            snapid,
            name,
            crush_rule,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MPoolOpReply {
    pub version: u64,
    pub fsid: Uuid,
    pub result: i32,
    pub epoch: u32,
    pub response_data: Vec<u8>,
}
impl Message for MPoolOpReply {
    meta!(48,1,1,oldest 1);
    fn encode(&self, features: u64) -> Result<Segments> {
        front_segments(features, |e| {
            put_psm(e, self.version)?;
            self.fsid.encode(e)?;
            e.i32(self.result)?;
            e.u32(self.epoch)?;
            e.u8(u8::from(!self.response_data.is_empty()))?;
            if !self.response_data.is_empty() {
                e.bytes(&self.response_data)?;
            }
            Ok(())
        })
    }
    fn decode(version: u16, front: &[u8], middle: &[u8], data: &[u8]) -> Result<Self> {
        Self::check_version(version)?;
        pinned_segments(version, 1, middle, data)?;
        let mut d = Decoder::new(front);
        let version = get_psm(&mut d)?;
        let fsid = Uuid::decode(&mut d)?;
        let result = d.i32()?;
        let epoch = d.u32()?;
        let response_data = match d.u8()? {
            0 => Vec::new(),
            1 => d.bytes()?.to_vec(),
            tag => return Err(Error::BadMarker(tag)),
        };
        end(&d)?;
        Ok(Self {
            version,
            fsid,
            result,
            epoch,
            response_data,
        })
    }
}

#[cfg(test)]
mod front_tests {
    use super::*;
    #[test]
    fn pool_front_checks_whole_counted_name_and_matches_actual_binary_encoding() {
        let max = u32::MAX as usize;
        assert_eq!(MPoolOp::front_len(max - 65), Ok(max));
        assert_eq!(MPoolOp::front_len(max - 64), Err(Error::TooLong));
        assert_eq!(MPoolOp::front_len(usize::MAX), Err(Error::TooLong));
        for name in [vec![], vec![255, b'p'], vec![b'n'; 1024 * 1024 + 1]] {
            let message = MPoolOp {
                version: 3,
                fsid: Uuid([0; 16]),
                pool: 0,
                operation: PoolOperation::CreatePool,
                snapid: 0,
                name,
                crush_rule: -1,
            };
            let encoded = message.encode(0).unwrap();
            assert_eq!(
                encoded.front.len(),
                MPoolOp::front_len(message.name.len()).unwrap()
            );
            assert!(encoded.middle.is_empty() && encoded.data.is_empty());
            assert_eq!(
                MPoolOp::decode(4, &encoded.front, &[], &[]).unwrap(),
                message
            );
        }
    }
}
