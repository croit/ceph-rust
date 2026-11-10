// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::{AdmissionError, DriverError, ListFilter, Target};
use bytes::Bytes;
use denc::{
    Decode, Decoder,
    types::{Hobject, SnapId},
};
use opwire::{OsdOp, op};

/// Routing mode for one client-originated primary PG operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PgOpRoute {
    /// Input is an object hash; current pool layout maps it to the acting PG.
    Hash(u32),
    /// Input names an already-resolved PG seed.
    Pgid(u32),
}

/// Bounded one-op PG read, retaining its routing identity through retries.
#[derive(Debug, PartialEq, Eq)]
pub struct PgOpRequest {
    pub(crate) target: Target,
    route: PgOpRoute,
    operation: OsdOp,
    output: u32,
}
impl PgOpRequest {
    pub fn by_hash(
        pool: i64,
        namespace: Vec<u8>,
        hash: u32,
        operation: OsdOp,
        output: u32,
    ) -> Self {
        Self::new(pool, namespace, PgOpRoute::Hash(hash), operation, output)
    }
    pub fn by_pgid(pool: i64, namespace: Vec<u8>, pg: u32, operation: OsdOp, output: u32) -> Self {
        Self::new(pool, namespace, PgOpRoute::Pgid(pg), operation, output)
    }
    fn new(pool: i64, namespace: Vec<u8>, route: PgOpRoute, operation: OsdOp, output: u32) -> Self {
        Self {
            target: Target {
                pool,
                object: Vec::new(),
                namespace,
                locator: Vec::new(),
            },
            route,
            operation,
            output,
        }
    }
    pub fn pool(&self) -> i64 {
        self.target.pool
    }
    pub fn route(&self) -> PgOpRoute {
        self.route
    }
    pub fn operation(&self) -> &OsdOp {
        &self.operation
    }
    pub fn max_output_bytes(&self) -> u32 {
        self.output
    }
    pub(crate) fn charge(&self) -> Option<u64> {
        u64::from(self.output)
            .checked_mul(2)?
            .checked_add(self.operation.indata.len() as u64)
    }
    pub(crate) fn validate(&self, compatible: bool) -> Result<(), AdmissionError> {
        if self.target.pool < 0
            || self.output == 0
            || (!compatible && self.output > i32::MAX as u32)
            || self.operation.op & op::TYPE_MASK != op::TYPE_PG
            || self.operation.op & op::MODE_RD == 0
            || self.operation.indata.len() > u32::MAX as usize
        {
            return Err(AdmissionError::InvalidOperation);
        }
        Ok(())
    }
    pub(crate) fn wire_op(&self) -> OsdOp {
        self.operation.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListNamespace {
    Exact(Vec<u8>),
    All,
}
/// The namespace byte `[1]` selects all namespaces; every other value is one exact byte namespace (spec 167).
pub(crate) const ALL_NAMESPACES: &[u8] = &[1];
#[derive(Debug, PartialEq, Eq)]
pub struct PgListRequest {
    pub(crate) target: Target,
    pub(crate) pg: u32,
    pub(crate) pg_num: u32,
    pub(crate) cursor: Hobject,
    count: u32,
    output: u32,
    all: bool,
    filter: Option<ListFilter>,
}
impl PgListRequest {
    pub fn new(
        pool: i64,
        namespace: ListNamespace,
        pg: u32,
        pg_num: u32,
        cursor: Hobject,
        count: u32,
        max_output_bytes: u32,
    ) -> Self {
        let (namespace, all) = match namespace {
            ListNamespace::Exact(n) => (n, false),
            ListNamespace::All => (ALL_NAMESPACES.to_vec(), true),
        };
        Self {
            target: Target {
                pool,
                object: vec![],
                namespace,
                locator: vec![],
            },
            pg,
            pg_num,
            cursor,
            count,
            output: max_output_bytes,
            all,
            filter: None,
        }
    }
    pub fn with_filter(mut self, filter: ListFilter) -> Self {
        self.filter = Some(filter);
        self
    }
    pub fn filter(&self) -> Option<&ListFilter> {
        self.filter.as_ref()
    }
    pub(crate) fn code(&self) -> u16 {
        if self.filter.is_some() {
            opwire::op::PGNLS_FILTER
        } else {
            opwire::op::PGNLS
        }
    }
    pub fn pool(&self) -> i64 {
        self.target.pool
    }
    pub fn pg(&self) -> u32 {
        self.pg
    }
    pub fn pg_num(&self) -> u32 {
        self.pg_num
    }
    pub fn cursor(&self) -> &Hobject {
        &self.cursor
    }
    pub fn max_entries(&self) -> u32 {
        self.count
    }
    pub fn max_output_bytes(&self) -> u32 {
        self.output
    }
    pub(crate) fn charge(&self) -> Option<u64> {
        (self.output as u64)
            .checked_mul(2)?
            .checked_add(self.cursor.key.capacity() as u64)?
            .checked_add(self.cursor.oid.capacity() as u64)?
            .checked_add(self.cursor.nspace.capacity() as u64)?
            .checked_add(match &self.filter {
                Some(f) => f.request_charge()?,
                None => 0,
            })
    }
    pub(crate) fn validate(&self) -> Result<(), AdmissionError> {
        if let Some(f) = &self.filter {
            f.validate()?;
            if f.payload_len(&self.cursor)
                .is_none_or(|n| n > u32::MAX as u64)
            {
                return Err(AdmissionError::InvalidOperation);
            }
        }
        if [
            self.cursor.key.len(),
            self.cursor.oid.len(),
            self.cursor.nspace.len(),
        ]
        .iter()
        .any(|&n| n > u32::MAX as usize)
            || self.pg_num == 0
            || self.pg >= self.pg_num
            || self.count == 0
            || self.output == 0
            || (!self.all && self.target.namespace.as_slice() == ALL_NAMESPACES)
            || self.cursor.max
        {
            return Err(AdmissionError::InvalidOperation);
        }
        if self.cursor != Hobject::MIN()
            && (self.cursor.pool != self.target.pool
                || self.cursor < pg_start(self.target.pool, self.pg)
                || self.cursor >= pg_end(self.target.pool, self.pg, self.pg_num))
        {
            return Err(AdmissionError::InvalidOperation);
        }
        Ok(())
    }
    pub(crate) fn wire_op(&self) -> opwire::OsdOp {
        match &self.filter {
            Some(f) => f.wire_op(self.count, &self.cursor),
            None => opwire::OsdOp::pgnls(self.count as u64, &self.cursor),
        }
    }
}
#[derive(Debug)]
pub struct RejectedPgList {
    pub reason: AdmissionError,
    pub request: PgListRequest,
}

fn pg_start(pool: i64, pg: u32) -> Hobject {
    Hobject::new(b"", SnapId(0), pg, pool, b"")
}
fn pg_end(pool: i64, pg: u32, n: u32) -> Hobject {
    let bits = 32 - (n - 1).leading_zeros();
    let width = if bits == 0 {
        0
    } else {
        let half = 1u32 << (bits - 1);
        if ((pg & (half - 1)) as u64) + (half as u64) < (n as u64) {
            bits
        } else {
            bits - 1
        }
    };
    let upper = pg.reverse_bits() as u64 + (1u64 << (32 - width));
    if upper >= 1u64 << 32 {
        Hobject::MAX()
    } else {
        Hobject::new(
            b"",
            SnapId(opwire::NOSNAP),
            (upper as u32).reverse_bits(),
            pool,
            b"",
        )
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct PgListPage {
    pub pool: i64,
    pub pg: u32,
    pub pg_num: u32,
    pub map_epoch: u32,
    next: Hobject,
    entries: Bytes,
    count: u32,
    finished: bool,
    wire_len: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListedObject<'a> {
    pub namespace: &'a [u8],
    pub object: &'a [u8],
    pub locator: &'a [u8],
}
#[derive(Debug)]
pub struct PgListEntries<'a> {
    decoder: Decoder<'a>,
    left: u32,
}
impl<'a> Iterator for PgListEntries<'a> {
    type Item = ListedObject<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        Some(ListedObject {
            namespace: self.decoder.bytes().expect("validated entry"),
            object: self.decoder.bytes().expect("validated entry"),
            locator: self.decoder.bytes().expect("validated entry"),
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left as usize, Some(self.left as usize))
    }
}
impl ExactSizeIterator for PgListEntries<'_> {}
impl PgListPage {
    pub(crate) fn wire_len(&self) -> usize {
        self.wire_len
    }
    pub(crate) fn clip(&mut self, keep: usize, next: Hobject) {
        debug_assert!(keep <= self.count as usize && next <= self.next);
        let mut decoder = Decoder::new(&self.entries);
        for _ in 0..keep {
            for _ in 0..3 {
                decoder.bytes().expect("validated entry");
            }
        }
        self.entries = self.entries.slice(..decoder.position());
        self.count = keep as u32;
        self.finished &= next == self.next;
        self.next = next;
    }
    pub fn next_cursor(&self) -> &Hobject {
        &self.next
    }
    pub fn pg_finished(&self) -> bool {
        self.finished
    }
    pub fn pool_finished(&self) -> bool {
        self.next.max
    }
    pub fn len(&self) -> usize {
        self.count as usize
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn entries(&self) -> PgListEntries<'_> {
        PgListEntries {
            decoder: Decoder::new(&self.entries),
            left: self.count,
        }
    }
    pub(crate) fn decode(
        request: &PgListRequest,
        result: i32,
        epoch: u32,
        data: Bytes,
    ) -> Result<Self, DriverError> {
        let mut d = Decoder::new(&data);
        let parsed = d
            .versioned_min(1, 1, |d, version| {
                if version != 1 {
                    return Err(denc::Error::BadValue("PGNLS version"));
                }
                let next = Hobject::decode(d)?;
                let count = d.u32()?;
                if count > request.count || count as usize > d.remaining() / 12 {
                    return Err(denc::Error::BadValue("PGNLS count"));
                }
                let begin = d.position();
                for _ in 0..count {
                    let namespace = d.bytes()?;
                    if !request.all && namespace != request.target.namespace {
                        return Err(denc::Error::BadValue("PGNLS namespace"));
                    }
                    let _ = d.bytes()?;
                    let _ = d.bytes()?;
                }
                if !d.is_empty() {
                    return Err(denc::Error::BadValue("PGNLS trailing bytes"));
                }
                Ok((next, count, begin, d.position()))
            })
            .map_err(|_| DriverError::InvalidReply)?;
        let (next, count, begin, end) = parsed;
        let upper = pg_end(request.target.pool, request.pg, request.pg_num);
        if !d.is_empty()
            || !(0..=1).contains(&result)
            || next <= request.cursor
            || next > upper
            || next < pg_start(request.target.pool, request.pg)
            || (!next.max && next.pool != request.target.pool)
            || (result == 1 && next != upper)
        {
            return Err(DriverError::InvalidReply);
        }
        let finished = result == 1 || next == upper;
        Ok(Self {
            pool: request.target.pool,
            pg: request.pg,
            pg_num: request.pg_num,
            map_epoch: epoch,
            next,
            entries: data.slice(begin..end),
            count,
            finished,
            wire_len: data.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bitwise_pg_ranges_include_non_power_of_two_layouts() {
        for (n, pg, end) in [
            (1, 0, None),
            (2, 0, Some(1)),
            (2, 1, None),
            (3, 0, Some(2)),
            (3, 2, Some(1)),
            (3, 1, None),
            (5, 0, Some(4)),
            (5, 4, Some(2)),
            (5, 2, Some(1)),
            (5, 1, Some(3)),
            (5, 3, None),
            (u32::MAX, 0, Some(0x8000_0000)),
            (u32::MAX, u32::MAX - 1, Some(1)),
            (u32::MAX, 0x7fff_ffff, None),
            (0x8000_0000, 0, Some(0x4000_0000)),
            (0x8000_0001, 0, Some(0x8000_0000)),
        ] {
            let boundary = pg_end(7, pg, n);
            assert_eq!(
                if boundary.max {
                    None
                } else {
                    Some(boundary.hash)
                },
                end,
                "n={n} pg={pg}"
            );
        }
    }
    #[test]
    fn no_untrusted_entry_count_can_allocate_a_result_vector() {
        let request = PgListRequest::new(7, ListNamespace::All, 0, 1, Hobject::MIN(), 2, 1024);
        let mut wire = vec![1, 1];
        let cursor = Hobject::MAX().encode_to_vec().unwrap();
        use denc::Encode;
        wire.extend_from_slice(&((cursor.len() + 4) as u32).to_le_bytes());
        wire.extend_from_slice(&cursor);
        wire.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            PgListPage::decode(&request, 1, 9, wire.into()),
            Err(DriverError::InvalidReply)
        );
    }
}

#[cfg(test)]
mod literal_tests {
    use super::*;
    #[test]
    fn independent_literal_page_preserves_zero_copy_binary_entry_fields() {
        let text = "01 01 3b000000 04 03 21000000 00000000 00000000 0000000000000000 00000000 01 00000000 0000000000000080 01000000 02000000 00ff 01000000 41 01000000 42";
        let wire: Vec<u8> =
            text.split_whitespace()
                .flat_map(|word| {
                    word.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
                        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
                    })
                })
                .collect();
        let data = Bytes::from(wire);
        let ptr = data.as_ptr() as usize;
        let size = data.len();
        let request = PgListRequest::new(7, ListNamespace::All, 0, 1, Hobject::MIN(), 2, 1024);
        let page = PgListPage::decode(&request, 1, 9, data).unwrap();
        let entry = page.entries().next().unwrap();
        assert_eq!(entry.namespace, [0, 255]);
        assert_eq!(entry.object, b"A");
        assert_eq!(entry.locator, b"B");
        assert!(page.pool_finished());
        assert!((ptr..ptr + size).contains(&(entry.object.as_ptr() as usize)));
    }
}
