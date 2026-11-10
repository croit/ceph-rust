// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Borrowed view of an encoded `map<string,bufferlist>` with strictly ascending keys (a sorted key/value run).
//!
//! Encoding: u32 count, then per entry u32-length key and u32-length value. A sorted batch keeps this one buffer from
//! the wire to the store (no per-key decode or allocation; doc/perf/omap-perkey-20261021.md).

use crate::dec::Decoder;
use crate::error::{Error, Result};

/// Validated entries (the encoding after its u32 count) of `n` entries with strictly ascending keys.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct SortedKv<'a> {
    ents: &'a [u8],
    n: u32,
}

/// Outcome of [`SortedKv::parse`] for a well-formed map encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvShape<'a> {
    /// Strictly ascending keys: usable as is.
    Sorted(SortedKv<'a>),
    /// Well-formed but not strictly ascending (unsorted or repeated keys): decode with the map rule.
    Unsorted,
}

impl<'a> SortedKv<'a> {
    /// Validate `enc` as exactly one map encoding, count included (trailing bytes are an error, like a full decode).
    pub fn parse(enc: &'a [u8]) -> Result<KvShape<'a>> {
        let mut d = Decoder::new(enc);
        let n = d.count()?;
        Self::check(n, d.peek_rest())
    }

    /// Validate `ents` as exactly `n` entries (the bytes after the count).
    pub fn check(n: usize, ents: &'a [u8]) -> Result<KvShape<'a>> {
        let mut d = Decoder::new(ents);
        let mut prev: Option<&[u8]> = None;
        let mut sorted = true;
        for _ in 0..n {
            let k = d.bytes()?;
            d.bytes()?;
            sorted &= prev.is_none_or(|p| p < k);
            prev = Some(k);
        }
        if d.remaining() != 0 {
            return Err(Error::TrailingBytes(d.remaining()));
        }
        if !sorted {
            return Ok(KvShape::Unsorted);
        }
        let n = u32::try_from(n).map_err(|_| Error::TooLong)?;
        Ok(KvShape::Sorted(SortedKv { ents, n }))
    }

    /// A view of entry bytes that an earlier [`SortedKv::parse`] / [`SortedKv::check`] accepted with `n` entries (the
    /// owner kept the bytes; checked in debug builds). Wrong bytes make iteration panic, never read out of bounds.
    pub fn trusted(n: usize, ents: &'a [u8]) -> SortedKv<'a> {
        debug_assert!(matches!(SortedKv::check(n, ents), Ok(KvShape::Sorted(_))));
        SortedKv { ents, n: n as u32 }
    }

    /// The map encoding of `pairs`, which must be in strictly ascending key order (debug-checked), appended to `out`.
    pub fn encode_into<'b>(
        out: &mut Vec<u8>,
        n: usize,
        pairs: impl IntoIterator<Item = (&'b [u8], &'b [u8])>,
    ) {
        out.extend_from_slice(&(n as u32).to_le_bytes());
        #[cfg(debug_assertions)]
        let mut prev: Option<&[u8]> = None;
        let mut cnt = 0;
        for (k, v) in pairs {
            #[cfg(debug_assertions)]
            {
                debug_assert!(prev.is_none_or(|p| p < k), "keys not strictly ascending");
                prev = Some(k);
            }
            out.extend_from_slice(&(k.len() as u32).to_le_bytes());
            out.extend_from_slice(k);
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            out.extend_from_slice(v);
            cnt += 1;
        }
        debug_assert_eq!(cnt, n);
    }

    pub fn len(&self) -> usize {
        self.n as usize
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The entry bytes (the map encoding without its u32 count).
    pub fn entries(&self) -> &'a [u8] {
        self.ents
    }

    /// Entries in ascending key order.
    pub fn iter(&self) -> SortedKvIter<'a> {
        SortedKvIter {
            b: self.ents,
            left: self.n,
        }
    }
}

impl core::fmt::Debug for SortedKv<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Iterator over the entries of a [`SortedKv`].
#[derive(Debug, Clone)]
pub struct SortedKvIter<'a> {
    b: &'a [u8],
    left: u32,
}

impl<'a> Iterator for SortedKvIter<'a> {
    type Item = (&'a [u8], &'a [u8]);
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        // validated by `parse`: every length is in bounds
        let take = |b: &mut &'a [u8]| {
            let (l, rest) = b.split_at(4);
            let n = u32::from_le_bytes([l[0], l[1], l[2], l[3]]) as usize;
            let (x, rest) = rest.split_at(n);
            *b = rest;
            x
        };
        let k = take(&mut self.b);
        let v = take(&mut self.b);
        Some((k, v))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left as usize, Some(self.left as usize))
    }
}

impl ExactSizeIterator for SortedKvIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(p: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut v = (p.len() as u32).to_le_bytes().to_vec();
        for (k, x) in p {
            v.extend_from_slice(&(k.len() as u32).to_le_bytes());
            v.extend_from_slice(k);
            v.extend_from_slice(&(x.len() as u32).to_le_bytes());
            v.extend_from_slice(x);
        }
        v
    }

    #[test]
    fn parse_shapes() {
        let s = enc(&[(b"a", b"1"), (b"b", b""), (&[0xff, 0], b"3")]);
        let KvShape::Sorted(r) = SortedKv::parse(&s).unwrap() else {
            panic!("sorted")
        };
        assert_eq!(r.len(), 3);
        assert_eq!(r.entries().as_ptr(), s[4..].as_ptr());
        let got: Vec<_> = r.iter().collect();
        assert_eq!(got[2], (&[0xff, 0][..], &b"3"[..]));
        let mut re = Vec::new();
        SortedKv::encode_into(&mut re, 3, r.iter());
        assert_eq!(re, s);
        assert_eq!(
            SortedKv::parse(&enc(&[(b"b", b"1"), (b"a", b"2")])).unwrap(),
            KvShape::Unsorted
        );
        assert_eq!(
            SortedKv::parse(&enc(&[(b"a", b"1"), (b"a", b"2")])).unwrap(),
            KvShape::Unsorted
        );
        let e = enc(&[]);
        let KvShape::Sorted(r) = SortedKv::parse(&e).unwrap() else {
            panic!("empty")
        };
        assert!(r.is_empty() && r.iter().next().is_none());
        assert!(SortedKv::parse(&s[..s.len() - 1]).is_err());
        let mut t = s.clone();
        t.push(0);
        assert!(SortedKv::parse(&t).is_err());
        assert!(SortedKv::parse(&[]).is_err());
    }
}
