// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Encoder and the `Encode` trait.

use crate::buf::BufMut;
use crate::error::{Error, Result};
use crate::features;

/// Writes Ceph wire encoding into a [`BufMut`]. Carries the connection feature mask.
#[derive(Debug)]
pub struct Encoder<B: BufMut = Vec<u8>> {
    buf: B,
    features: u64,
    /// Shared runs spliced in by [`Encoder::splice`]: `(offset in buf, run)`, ascending; the encoded value is `buf` with
    /// each run inserted at its offset. Empty unless a caller splices (then it must take them, [`Encoder::into_rope`]).
    zc: Vec<(usize, bytes::Bytes)>,
    /// Total length of `zc`.
    zc_len: usize,
}

impl Encoder<Vec<u8>> {
    pub fn new() -> Self {
        Encoder::from_buf(Vec::new())
    }
    pub fn with_capacity(n: usize) -> Self {
        Encoder::from_buf(Vec::with_capacity(n))
    }
    pub fn into_vec(self) -> Vec<u8> {
        debug_assert!(self.zc.is_empty(), "spliced runs dropped: use into_rope");
        self.buf
    }
    /// The inline bytes and the spliced runs (`(offset in inline, run)`, ascending).
    pub fn into_rope(self) -> (Vec<u8>, Vec<(usize, bytes::Bytes)>) {
        (self.buf, self.zc)
    }
}

/// Encode with `f` into a per-thread scratch buffer and return the bytes at their exact size: one allocation however
/// large the value, instead of a fresh buffer growing 8, 16, 32, .. bytes (one allocation + copy per step). Nested use (an
/// `f` that encodes another value this way) gets a fresh scratch.
///
/// A spliced run ([`Encoder::splice`]) cannot be returned flat: that is an error, use [`encode_exact_rope`].
pub fn encode_exact(
    features: u64,
    f: impl FnOnce(&mut Encoder<Vec<u8>>) -> Result<()>,
) -> Result<Vec<u8>> {
    thread_local! {
        static SCRATCH: std::cell::Cell<Vec<u8>> = const { std::cell::Cell::new(Vec::new()) };
    }
    const KEEP: usize = 1 << 20;
    let mut buf = SCRATCH.try_with(std::cell::Cell::take).unwrap_or_default();
    buf.clear();
    let mut e = Encoder::from_buf(buf).with_features(features);
    let mut r = f(&mut e);
    if r.is_ok() && !e.zc.is_empty() {
        r = Err(Error::BadValue("spliced run in a flat encode"));
    }
    // a failed flat encode drops its runs with the error; the scratch is reused either way
    e.zc.clear();
    e.zc_len = 0;
    let buf = e.into_vec();
    let out = r.map(|()| buf.to_vec());
    if buf.capacity() <= KEEP {
        let _ = SCRATCH.try_with(|c| c.set(buf));
    }
    out
}

/// [`encode_exact`] for a value that may splice shared runs ([`Encoder::splice`]): `(inline, runs)`, see
/// [`Encoder::into_rope`].
#[expect(clippy::type_complexity)]
pub fn encode_exact_rope(
    features: u64,
    f: impl FnOnce(&mut Encoder<Vec<u8>>) -> Result<()>,
) -> Result<(Vec<u8>, Vec<(usize, bytes::Bytes)>)> {
    let mut zc = Vec::new();
    let inline = encode_exact(features, |e| {
        f(e)?;
        zc = core::mem::take(&mut e.zc);
        e.zc_len = 0;
        Ok(())
    })?;
    Ok((inline, zc))
}

impl Default for Encoder<Vec<u8>> {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! put_int {
    ($($name:ident $t:ty),*) => {$(
        #[inline]
        pub fn $name(&mut self, v: $t) -> Result<()> { self.buf.put_slice(&v.to_le_bytes()) }
    )*};
}

impl<B: BufMut> Encoder<B> {
    pub fn from_buf(buf: B) -> Self {
        Encoder {
            buf,
            features: features::ALL,
            zc: Vec::new(),
            zc_len: 0,
        }
    }
    pub fn features(&self) -> u64 {
        self.features
    }
    pub fn set_features(&mut self, f: u64) {
        self.features = f;
    }
    pub fn with_features(mut self, f: u64) -> Self {
        self.features = f;
        self
    }
    pub fn into_inner(self) -> B {
        debug_assert!(self.zc.is_empty(), "spliced runs dropped");
        self.buf
    }
    pub fn buf(&self) -> &B {
        &self.buf
    }
    /// Mutable access to the underlying buffer (write payloads in place, then `patch` the length).
    pub fn buf_mut(&mut self) -> &mut B {
        &mut self.buf
    }
    /// Bytes written so far into the buffer (spliced runs not counted).
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    /// Insert `run` here by reference (no copy): it is part of the value (envelope lengths count it) but stays out of the
    /// buffer; take both with [`Encoder::into_rope`] / [`encode_exact_rope`].
    pub fn splice(&mut self, run: bytes::Bytes) {
        self.splice_at(self.buf.len(), run);
    }
    /// [`Encoder::splice`] at buffer offset `at` (bytes written in place through [`Encoder::buf_mut`]); offsets must not
    /// decrease and an envelope open around `at` must still be open (its length counts the run when it closes).
    pub fn splice_at(&mut self, at: usize, run: bytes::Bytes) {
        debug_assert!(at <= self.buf.len() && self.zc.last().is_none_or(|(p, _)| *p <= at));
        if run.is_empty() {
            return;
        }
        self.zc_len += run.len();
        self.zc.push((at, run));
    }
    /// Raw bytes of a rope (`inline` with `zc` runs at their offsets, see [`Encoder::into_rope`]), runs spliced.
    pub fn raw_rope(&mut self, inline: &[u8], zc: &[(usize, bytes::Bytes)]) -> Result<()> {
        let mut pos = 0;
        for (at, run) in zc {
            if *at < pos || *at > inline.len() {
                return Err(Error::BadValue("rope offset"));
            }
            self.buf.put_slice(&inline[pos..*at])?;
            self.splice(run.clone());
            pos = *at;
        }
        self.buf.put_slice(&inline[pos..])
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    /// Raw bytes, no prefix.
    #[inline]
    pub fn raw(&mut self, s: &[u8]) -> Result<()> {
        self.buf.put_slice(s)
    }
    put_int!(u8 u8, i8 i8, u16 u16, i16 i16, u32 u32, i32 i32, u64 u64, i64 i64);
    #[inline]
    pub fn bool(&mut self, v: bool) -> Result<()> {
        self.u8(v as u8)
    }
    pub fn f32(&mut self, v: f32) -> Result<()> {
        self.u32(v.to_bits())
    }
    pub fn f64(&mut self, v: f64) -> Result<()> {
        self.u64(v.to_bits())
    }
    /// u32 length / count prefix.
    #[inline]
    pub fn count(&mut self, n: usize) -> Result<()> {
        self.u32(u32::try_from(n).map_err(|_| Error::TooLong)?)
    }
    /// u32 length + bytes (string / bufferlist).
    #[inline]
    pub fn bytes(&mut self, s: &[u8]) -> Result<()> {
        self.count(s.len())?;
        self.buf.put_slice(s)
    }
    /// Versioned envelope: `struct_v`, `struct_compat`, back-patched u32 body length.
    pub fn versioned<R>(
        &mut self,
        v: u8,
        compat: u8,
        f: impl FnOnce(&mut Self) -> Result<R>,
    ) -> Result<R> {
        self.u8(v)?;
        self.u8(compat)?;
        let (at, zc0) = (self.buf.len(), self.zc_len);
        self.u32(0)?;
        let r = f(self)?;
        let len = u32::try_from(self.buf.len() - at - 4 + (self.zc_len - zc0))
            .map_err(|_| Error::TooLong)?;
        self.buf.patch(at, &len.to_le_bytes());
        Ok(r)
    }
    /// LEB128 varint (denc varint family, spec 3).
    pub fn varint(&mut self, mut v: u64) -> Result<()> {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                return self.u8(b);
            }
            self.u8(b | 0x80)?;
        }
    }
    /// Signed varint: (|v| << 1) | sign. `i64::MIN` has no encoding (its magnitude needs all 64 bits).
    pub fn varint_signed(&mut self, v: i64) -> Result<()> {
        let m = v.unsigned_abs();
        if m >= 1 << 63 {
            return Err(Error::BadValue("varint_signed out of range"));
        }
        self.varint((m << 1) | (v < 0) as u64)
    }
    /// varint_lowz: strips up to 12 trailing zero bits in nibble steps. Values with more than 62 significant bits after
    /// stripping have no encoding (the packed form shifts them left by 2).
    pub fn varint_lowz(&mut self, v: u64) -> Result<()> {
        let n = if v == 0 {
            0
        } else {
            (v.trailing_zeros() / 4).min(3) as u64
        };
        let m = v >> (4 * n);
        if m >= 1 << 62 {
            return Err(Error::BadValue("varint_lowz out of range"));
        }
        self.varint((m << 2) | n)
    }
    /// Signed varint_lowz; same range limit as [`varint_lowz`](Self::varint_lowz), one bit lower.
    pub fn varint_lowz_signed(&mut self, v: i64) -> Result<()> {
        let m = v.unsigned_abs();
        let n = if m == 0 {
            0
        } else {
            (m.trailing_zeros() / 4).min(3) as u64
        };
        let m = m >> (4 * n);
        if m >= 1 << 61 {
            return Err(Error::BadValue("varint_lowz_signed out of range"));
        }
        self.varint((m << 3) | (n << 1) | (v < 0) as u64)
    }
}

/// Types with a Ceph wire encoding. Features are taken from the encoder.
pub trait Encode {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()>;

    /// Encode with an explicit feature mask (restored afterwards).
    fn encode_with_features<B: BufMut>(&self, e: &mut Encoder<B>, features: u64) -> Result<()> {
        let old = e.features();
        e.set_features(features);
        let r = self.encode(e);
        e.set_features(old);
        r
    }

    /// One exact allocation (see [`encode_exact`]).
    fn encode_to_vec(&self) -> Result<Vec<u8>> {
        encode_exact(features::ALL, |e| self.encode(e))
    }

    fn encode_to_vec_with_features(&self, features: u64) -> Result<Vec<u8>> {
        encode_exact(features, |e| self.encode(e))
    }

    /// Hook: encode a slice of elements without count (fast path for bytes).
    fn encode_elems<B: BufMut>(items: &[Self], e: &mut Encoder<B>) -> Result<()>
    where
        Self: Sized,
    {
        items.iter().try_for_each(|i| i.encode(e))
    }
}

impl<T: Encode + ?Sized> Encode for &T {
    #[inline]
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        (**self).encode(e)
    }
}

#[cfg(test)]
mod scratch_tests {
    use super::*;

    /// An `encode` that itself calls `encode_to_vec` (the scratch buffer is busy: fallback path).
    struct Nested(Vec<u32>);
    impl Encode for Nested {
        fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
            let inner = self.0.encode_to_vec()?;
            e.u32(inner.len() as u32)?;
            e.raw(&inner)
        }
    }

    #[test]
    fn encode_to_vec_is_exact_nested_and_repeatable() {
        let v: Vec<u32> = (0..300).collect();
        let plain = {
            let mut e = Encoder::with_capacity(8);
            v.encode(&mut e).unwrap();
            e.into_vec()
        };
        for _ in 0..3 {
            assert_eq!(v.encode_to_vec().unwrap(), plain);
        }
        let n = Nested(v).encode_to_vec().unwrap();
        assert_eq!(&n[4..], &plain[..]);
        assert_eq!(
            u32::from_le_bytes(n[..4].try_into().unwrap()) as usize,
            plain.len()
        );
        // a small value after a big one is exact, not padded
        assert_eq!(7u8.encode_to_vec().unwrap(), vec![7]);
    }
}

#[cfg(test)]
mod rope_tests {
    use super::*;

    fn flat(inline: &[u8], zc: &[(usize, bytes::Bytes)]) -> Vec<u8> {
        let (mut v, mut pos) = (Vec::new(), 0);
        for (at, r) in zc {
            v.extend_from_slice(&inline[pos..*at]);
            v.extend_from_slice(r);
            pos = *at;
        }
        v.extend_from_slice(&inline[pos..]);
        v
    }

    /// Spliced runs count in (nested) envelope lengths; flattening the rope = encoding the bytes inline.
    #[test]
    fn spliced_equals_inline() {
        let (a, b) = (
            bytes::Bytes::from(vec![7u8; 5000]),
            bytes::Bytes::from(vec![9u8; 3]),
        );
        let enc = |zc: bool| {
            encode_exact_rope(features::ALL, |e| {
                e.u8(1)?;
                e.versioned(3, 1, |e| {
                    e.count(a.len())?;
                    if zc {
                        e.splice(a.clone())
                    } else {
                        e.raw(&a)?
                    }
                    e.versioned(2, 2, |e| {
                        e.u16(5)?;
                        if zc {
                            e.splice(b.clone())
                        } else {
                            e.raw(&b)?
                        }
                        e.splice(bytes::Bytes::new());
                        e.u32(6)
                    })
                })?;
                e.u8(2)
            })
            .unwrap()
        };
        let (plain, none) = enc(false);
        assert!(none.is_empty());
        let (inline, zc) = enc(true);
        assert_eq!(zc.len(), 2);
        assert_eq!(inline.len() + 5003, plain.len());
        assert_eq!(flat(&inline, &zc), plain);
        // re-spliced into another encoder (raw_rope) the runs stay shared and the outer envelope counts them
        let (inline2, zc2) = encode_exact_rope(features::ALL, |e| {
            e.versioned(1, 1, |e| e.raw_rope(&inline, &zc))
        })
        .unwrap();
        assert_eq!(zc2.len(), 2);
        assert_eq!(&flat(&inline2, &zc2)[6..], &plain[..]);
        assert_eq!(
            u32::from_le_bytes(inline2[2..6].try_into().unwrap()) as usize,
            plain.len()
        );
    }

    /// A flat encode cannot return spliced runs: it fails loudly instead of returning bytes that lack them.
    #[test]
    fn flat_encode_rejects_spliced_runs() {
        struct Splices;
        impl Encode for Splices {
            fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
                e.u8(1)?;
                e.splice(bytes::Bytes::from_static(b"data"));
                e.u8(2)
            }
        }
        assert_eq!(
            Splices.encode_to_vec(),
            Err(Error::BadValue("spliced run in a flat encode"))
        );
        let (inline, zc) = encode_exact_rope(features::ALL, |e| Splices.encode(e)).unwrap();
        assert_eq!(flat(&inline, &zc), vec![1, b'd', b'a', b't', b'a', 2]);
    }

    /// A rope that is not ascending or runs past the inline bytes is an error, never a panic.
    #[test]
    fn raw_rope_rejects_bad_offsets() {
        let run = || bytes::Bytes::from_static(b"x");
        let mut e = Encoder::new();
        assert!(matches!(
            e.raw_rope(b"abcd", &[(3, run()), (1, run())]),
            Err(Error::BadValue("rope offset"))
        ));
        let mut e = Encoder::new();
        assert!(matches!(
            e.raw_rope(b"abcd", &[(5, run())]),
            Err(Error::BadValue("rope offset"))
        ));
        let mut e = Encoder::new();
        e.raw_rope(b"abcd", &[(4, run())]).unwrap();
        assert_eq!(e.into_rope().1.len(), 1);
    }
}
