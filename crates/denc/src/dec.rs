// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Decoder and the `Decode` trait.

use crate::error::{Error, Result};

/// Cursor over a borrowed buffer. All reads are bounds-checked against `end`,
/// which a versioned envelope narrows to the struct end.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    end: usize,
}

macro_rules! get_int {
    ($($name:ident $t:ty),*) => {$(
        #[inline]
        pub fn $name(&mut self) -> Result<$t> {
            Ok(<$t>::from_le_bytes(self.array()?))
        }
    )*};
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Decoder {
            buf,
            pos: 0,
            end: buf.len(),
        }
    }
    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }
    /// Bytes left in the current bound.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.end - self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
    /// Unconsumed bytes in the current bound (not consumed).
    pub fn peek_rest(&self) -> &'a [u8] {
        &self.buf[self.pos..self.end]
    }
    /// Borrow next `n` bytes.
    #[inline]
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(Error::Eof {
                needed: n,
                remaining: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }
    #[inline]
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }
    get_int!(u8 u8, i8 i8, u16 u16, i16 i16, u32 u32, i32 i32, u64 u64, i64 i64);
    #[inline]
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }
    pub fn f32(&mut self) -> Result<f32> {
        Ok(f32::from_bits(self.u32()?))
    }
    pub fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.u64()?))
    }
    /// u32 length prefix, validated against remaining bytes (each unit >= 1 byte).
    #[inline]
    pub fn count(&mut self) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > self.remaining() {
            return Err(Error::BadLength {
                len: n as u64,
                remaining: self.remaining(),
            });
        }
        Ok(n)
    }
    /// u32 length + borrowed bytes.
    #[inline]
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.count()?;
        self.take(n)
    }
    /// Borrow the next versioned envelope (`v`, `compat`, `len`, body) as raw bytes without
    /// interpreting it.
    pub fn envelope_raw(&mut self) -> Result<&'a [u8]> {
        let rest = self.peek_rest();
        if rest.len() < 6 {
            return Err(Error::Eof {
                needed: 6,
                remaining: rest.len(),
            });
        }
        let len = crate::le::rd_u32(rest, 2) as usize;
        self.take(6usize.checked_add(len).ok_or(Error::TooLong)?)
    }
    /// Borrow `u32 n` + n versioned envelopes as raw bytes (including the count).
    pub fn envelope_vec_raw(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        let n = self.count()?;
        for _ in 0..n {
            self.envelope_raw()?;
        }
        Ok(&self.buf[start..self.pos])
    }
    /// Versioned envelope. `max_compat` = highest struct_compat we understand;
    /// the closure receives struct_v and is bounded to the struct body; unread
    /// trailing bytes are skipped.
    pub fn versioned<R>(
        &mut self,
        max_compat: u8,
        f: impl FnOnce(&mut Self, u8) -> Result<R>,
    ) -> Result<R> {
        self.versioned_min(0, max_compat, f)
    }
    /// Like [`versioned`](Self::versioned) but rejects `struct_v < oldest`.
    pub fn versioned_min<R>(
        &mut self,
        oldest: u8,
        max_compat: u8,
        f: impl FnOnce(&mut Self, u8) -> Result<R>,
    ) -> Result<R> {
        let v = self.u8()?;
        let compat = self.u8()?;
        let len = self.u32()? as usize;
        if compat > max_compat {
            return Err(Error::CompatTooNew {
                compat,
                supported: max_compat,
            });
        }
        if v < oldest {
            return Err(Error::VersionTooOld { version: v, oldest });
        }
        if len > self.remaining() {
            return Err(Error::BadLength {
                len: len as u64,
                remaining: self.remaining(),
            });
        }
        let struct_end = self.pos + len;
        let old_end = self.end;
        self.end = struct_end;
        let r = f(self, v);
        self.end = old_end;
        let r = r?;
        self.pos = struct_end;
        Ok(r)
    }
    /// LEB128 varint, max 10 bytes; rejects overflow.
    pub fn varint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let b = self.u8()?;
            let bits = (b & 0x7f) as u64;
            if i == 9 && bits > 1 {
                return Err(Error::BadValue("varint overflow"));
            }
            v |= bits << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Error::BadValue("varint too long"))
    }
    pub fn varint_signed(&mut self) -> Result<i64> {
        let p = self.varint()?;
        let m = (p >> 1) as i64;
        Ok(if p & 1 != 0 { m.wrapping_neg() } else { m })
    }
    pub fn varint_lowz(&mut self) -> Result<u64> {
        let p = self.varint()?;
        let n = p & 3;
        (p >> 2)
            .checked_mul(1 << (4 * n))
            .ok_or(Error::BadValue("varint_lowz overflow"))
    }
    pub fn varint_lowz_signed(&mut self) -> Result<i64> {
        let p = self.varint()?;
        let n = (p >> 1) & 3;
        let m = ((p >> 3) as i128) << (4 * n);
        i64::try_from(if p & 1 != 0 { -m } else { m })
            .map_err(|_| Error::BadValue("varint_lowz_signed overflow"))
    }
}

/// Types decodable from the Ceph wire encoding; may borrow from the input.
pub trait Decode<'a>: Sized {
    fn decode(d: &mut Decoder<'a>) -> Result<Self>;

    /// Hook: decode `n` elements (fast path for bytes).
    fn decode_elems(d: &mut Decoder<'a>, n: usize) -> Result<Vec<Self>> {
        let mut v = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            v.push(Self::decode(d)?);
        }
        Ok(v)
    }
}

/// Decode a whole buffer; trailing bytes are an error.
pub fn from_slice<'a, T: Decode<'a>>(buf: &'a [u8]) -> Result<T> {
    let mut d = Decoder::new(buf);
    let v = T::decode(&mut d)?;
    if d.remaining() != 0 {
        return Err(Error::TrailingBytes(d.remaining()));
    }
    Ok(v)
}
