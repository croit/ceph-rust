// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;
use denc::{Decode, Decoder, Encode, Encoder};

/// Global bitwise interval, inclusive start and exclusive end; no snapshot guarantee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListRange {
    pub(super) start: Hobject,
    pub(super) end: Hobject,
}
impl ListRange {
    pub fn new(start: Hobject, end: Hobject) -> Self {
        Self { start, end }
    }
    pub fn full() -> Self {
        Self::new(Hobject::MIN(), Hobject::MAX())
    }
    pub fn from_hash(pool: i64, hash: u32) -> Self {
        Self::new(
            Hobject::new(b"", denc::types::SnapId(opwire::NOSNAP), hash, pool, b""),
            Hobject::MAX(),
        )
    }
    pub fn start(&self) -> &Hobject {
        &self.start
    }
    pub fn end(&self) -> &Hobject {
        &self.end
    }
    /// Select one disjoint hash-space slice; this does not schedule work or balance object counts.
    /// Constant work in `parts`; byte comparisons/copies scale with supplied endpoint names.
    /// Variable endpoint copies are capped independently of later scan query/state limits.
    pub fn slice(
        &self,
        pool: i64,
        index: u64,
        parts: u64,
        max_endpoint_bytes: u64,
    ) -> Result<Self, ListScanError> {
        self.slice_policy(pool, index, parts, Some(max_endpoint_bytes))
    }
    /// Public librados slicing has no independent endpoint-copy budget.
    pub fn slice_compatible(
        &self,
        pool: i64,
        index: u64,
        parts: u64,
    ) -> Result<Self, ListScanError> {
        self.slice_policy(pool, index, parts, None)
    }
    fn slice_policy(
        &self,
        pool: i64,
        index: u64,
        parts: u64,
        max_endpoint_bytes: Option<u64>,
    ) -> Result<Self, ListScanError> {
        use std::borrow::Cow;
        if pool < 0 || pool > u32::MAX as i64 || parts == 0 || index >= parts {
            return Err(ListScanError::Range);
        }
        self.validate(pool)?;
        let coordinate = |h: &Hobject| {
            if h.max {
                1u64 << 32
            } else {
                h.hash.reverse_bits() as u64
            }
        };
        let lower = coordinate(&self.start);
        let upper = coordinate(&self.end);
        let width = upper.checked_sub(lower).ok_or(ListScanError::Range)?;
        let cut = |part: u64| -> Cow<'_, Hobject> {
            if part == 0 {
                return Cow::Borrowed(&self.start);
            }
            if part == parts {
                return Cow::Borrowed(&self.end);
            }
            let offset = ((width as u128) * (part as u128) / (parts as u128)) as u64;
            if offset == 0 {
                return Cow::Borrowed(&self.start);
            }
            let position = lower + offset;
            let candidate = if position >= 1u64 << 32 {
                Hobject::MAX()
            } else {
                Hobject::new(
                    b"",
                    denc::types::SnapId(opwire::NOSNAP),
                    (position as u32).reverse_bits(),
                    pool,
                    b"",
                )
            };
            if candidate <= self.start {
                Cow::Borrowed(&self.start)
            } else if candidate >= self.end {
                Cow::Borrowed(&self.end)
            } else {
                Cow::Owned(candidate)
            }
        };
        let start = cut(index);
        let end = cut(index + 1);
        let lengths = [
            start.key.len(),
            start.oid.len(),
            start.nspace.len(),
            end.key.len(),
            end.oid.len(),
            end.nspace.len(),
        ];
        if lengths
            .iter()
            .try_fold(0u64, |n, &v| n.checked_add(v as u64))
            .is_none_or(|n| max_endpoint_bytes.is_some_and(|maximum| n > maximum))
        {
            return Err(ListScanError::StateBudget);
        }
        let result = Self::new(start.into_owned(), end.into_owned());
        if cursor_charge(&result.start)
            .and_then(|n| n.checked_add(cursor_charge(&result.end)?))
            .is_none_or(|n| max_endpoint_bytes.is_some_and(|maximum| n > maximum))
        {
            return Err(ListScanError::StateBudget);
        }
        Ok(result)
    }
    pub(super) fn validate(&self, pool: i64) -> Result<(), ListScanError> {
        for h in [&self.start, &self.end] {
            if h.max {
                if h != &Hobject::MAX() {
                    return Err(ListScanError::Range);
                }
            } else if h != &Hobject::MIN() && h.pool != pool {
                return Err(ListScanError::Range);
            }
            let lens = [h.key.len(), h.oid.len(), h.nspace.len()];
            if lens.iter().any(|&n| n > u32::MAX as usize)
                || lens
                    .iter()
                    .try_fold(39u64, |n, &v| n.checked_add(v as u64))
                    .is_none_or(|n| n > u32::MAX as u64)
            {
                return Err(ListScanError::Range);
            }
        }
        if self.start > self.end {
            return Err(ListScanError::Range);
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct RejectedListRange {
    pub reason: ListScanError,
    pub query: ListQuery,
    pub range: ListRange,
}
#[derive(Debug)]
pub struct RejectedListScan {
    pub reason: ListScanError,
    pub scan: ListScan,
}
#[derive(Debug)]
pub struct RejectedListResume {
    pub reason: ListScanError,
    pub checkpoint: ListCheckpoint,
}
/// Validated progress, not a live operation. Resuming requires an explicit new scan budget.
/// CRC protects against accidental corruption; protect storage against malicious edits.
#[derive(Debug)]
pub struct ListCheckpoint {
    fsid: Uuid,
    epoch: u32,
    hash: u8,
    query: ListQuery,
    range: ListRange,
}
impl ListCheckpoint {
    pub fn pool(&self) -> i64 {
        self.query.pool
    }
    pub fn query(&self) -> &ListQuery {
        &self.query
    }
    pub fn range(&self) -> &ListRange {
        &self.range
    }
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    fn encoded_len(&self) -> Option<usize> {
        let mut size = 121usize; // magic + identity/profile/tags + two39B hobjects + CRC
        if let ListNamespace::Exact(n) = &self.query.namespace {
            size = size.checked_add(4)?.checked_add(n.len())?;
        }
        if let Some(filter) = &self.query.filter {
            let (a, b) = match filter {
                crate::ListFilter::Plain { raw_xattr, value } => (raw_xattr, value),
                crate::ListFilter::Class { name, parameters } => (name, parameters),
            };
            size = size
                .checked_add(8)?
                .checked_add(a.len())?
                .checked_add(b.len())?;
        }
        for h in [&self.range.start, &self.range.end] {
            size = size
                .checked_add(h.key.len())?
                .checked_add(h.oid.len())?
                .checked_add(h.nspace.len())?;
        }
        Some(size)
    }
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, ListScanError> {
        let size = self
            .encoded_len()
            .filter(|&n| n <= max_bytes)
            .ok_or(ListScanError::StateBudget)?;
        let mut e = Encoder::with_capacity(size);
        let write = (|| -> denc::Result<()> {
            e.raw(b"RADOSLC1")?;
            self.fsid.encode(&mut e)?;
            e.u32(self.epoch)?;
            e.i64(self.query.pool)?;
            e.u8(self.hash)?;
            match &self.query.namespace {
                ListNamespace::All => e.u8(0)?,
                ListNamespace::Exact(n) => {
                    e.u8(1)?;
                    e.bytes(n)?;
                }
            }
            match &self.query.filter {
                None => e.u8(0)?,
                Some(crate::ListFilter::Plain { raw_xattr, value }) => {
                    e.u8(1)?;
                    e.bytes(raw_xattr)?;
                    e.bytes(value)?;
                }
                Some(crate::ListFilter::Class { name, parameters }) => {
                    e.u8(2)?;
                    e.bytes(name)?;
                    e.bytes(parameters)?;
                }
            }
            self.range.start.encode(&mut e)?;
            self.range.end.encode(&mut e)?;
            Ok(())
        })();
        write.map_err(|_| ListScanError::Protocol)?;
        let mut bytes = e.into_vec();
        let checksum = crc::crc32c(0, &bytes);
        bytes.extend_from_slice(&checksum.to_le_bytes());
        debug_assert_eq!(bytes.len(), size);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self, ListScanError> {
        if bytes.len() > max_bytes {
            return Err(ListScanError::StateBudget);
        }
        let payload = bytes.len().checked_sub(4).ok_or(ListScanError::Protocol)?;
        let checksum = u32::from_le_bytes(
            bytes[payload..]
                .try_into()
                .map_err(|_| ListScanError::Protocol)?,
        );
        if crc::crc32c(0, &bytes[..payload]) != checksum {
            return Err(ListScanError::Protocol);
        }
        let mut d = Decoder::new(&bytes[..payload]);
        let parse = (|| -> denc::Result<Self> {
            if d.take(8)? != b"RADOSLC1" {
                return Err(denc::Error::BadValue("checkpoint magic"));
            }
            let fsid = Uuid::decode(&mut d)?;
            let epoch = d.u32()?;
            let pool = d.i64()?;
            let hash = d.u8()?;
            let namespace = match d.u8()? {
                0 => ListNamespace::All,
                1 => ListNamespace::Exact(d.bytes()?.to_vec()),
                _ => return Err(denc::Error::BadValue("checkpoint namespace")),
            };
            let filter = match d.u8()? {
                0 => None,
                1 => Some(crate::ListFilter::Plain {
                    raw_xattr: d.bytes()?.to_vec(),
                    value: d.bytes()?.to_vec(),
                }),
                2 => Some(crate::ListFilter::Class {
                    name: d.bytes()?.to_vec(),
                    parameters: d.bytes()?.to_vec(),
                }),
                _ => return Err(denc::Error::BadValue("checkpoint filter")),
            };
            let range = ListRange::new(Hobject::decode(&mut d)?, Hobject::decode(&mut d)?);
            Ok(Self {
                fsid,
                epoch,
                hash,
                query: ListQuery {
                    pool,
                    namespace,
                    filter,
                },
                range,
            })
        })();
        let checkpoint = parse.map_err(|_| ListScanError::Protocol)?;
        if !d.is_empty()
            || checkpoint.fsid == Uuid::default()
            || checkpoint.epoch == 0
            || checkpoint.query.pool < 0
            || checkpoint.query.pool > u32::MAX as i64
            || !matches!(checkpoint.hash, STR_HASH_LINUX | STR_HASH_RJENKINS)
            || matches!(&checkpoint.query.namespace,ListNamespace::Exact(n) if n.as_slice()==crate::listing::ALL_NAMESPACES)
            || checkpoint
                .query
                .filter
                .as_ref()
                .is_some_and(|f| f.validate().is_err())
            || checkpoint.range.validate(checkpoint.pool()).is_err()
        {
            return Err(ListScanError::Protocol);
        }
        Ok(checkpoint)
    }
}
impl ListScan {
    /// Consume the owner only when no request can still deliver a completion.
    /// Captures last validated progress even after a failure; does not erase that prior outcome.
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn into_checkpoint(self) -> Result<ListCheckpoint, RejectedListScan> {
        if self.pending.is_some() {
            return Err(RejectedListScan {
                reason: ListScanError::Busy,
                scan: self,
            });
        }
        Ok(ListCheckpoint {
            fsid: self.layout.fsid,
            epoch: self.layout.epoch,
            hash: self.layout.hash,
            query: self.query,
            range: ListRange::new(self.position, self.end),
        })
    }
    /// Explicit NEW logical scan with caller-supplied time/resource limits, never an active retry.
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn resume(
        layout: ListLayout,
        checkpoint: ListCheckpoint,
        limits: ListLimits,
        deadline: u64,
        now: u64,
    ) -> Result<Self, RejectedListResume> {
        let reason = if layout.fsid != checkpoint.fsid
            || layout.pool != checkpoint.pool()
            || layout.hash != checkpoint.hash
        {
            Some(ListScanError::Identity)
        } else if layout.epoch < checkpoint.epoch {
            Some(ListScanError::Layout)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(RejectedListResume { reason, checkpoint });
        }
        let ListCheckpoint {
            fsid,
            epoch,
            hash,
            query,
            range,
        } = checkpoint;
        Self::new_range(layout, query, range, limits, deadline, now).map_err(|e| {
            RejectedListResume {
                reason: e.reason,
                checkpoint: ListCheckpoint {
                    fsid,
                    epoch,
                    hash,
                    query: e.query,
                    range: e.range,
                },
            }
        })
    }
}
