// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Encode/Decode for primitives and std containers (spec encoding.md 1, 2).

use crate::buf::BufMut;
use crate::dec::{Decode, Decoder};
use crate::enc::{Encode, Encoder};
use crate::error::{Error, Result};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

macro_rules! int_impl {
    ($($t:ty => $enc:ident, $dec:ident);*) => {$(
        impl Encode for $t {
            #[inline]
            fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> { e.$enc(*self) }
        }
        impl<'a> Decode<'a> for $t {
            #[inline]
            fn decode(d: &mut Decoder<'a>) -> Result<Self> { d.$dec() }
        }
    )*};
}
int_impl!(i8 => i8, i8; u16 => u16, u16; i16 => i16, i16; u32 => u32, u32; i32 => i32, i32;
    u64 => u64, u64; i64 => i64, i64; bool => bool, bool; f32 => f32, f32; f64 => f64, f64);

impl Encode for u8 {
    #[inline]
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u8(*self)
    }
    fn encode_elems<B: BufMut>(items: &[Self], e: &mut Encoder<B>) -> Result<()> {
        e.raw(items)
    }
}
impl<'a> Decode<'a> for u8 {
    #[inline]
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.u8()
    }
    fn decode_elems(d: &mut Decoder<'a>, n: usize) -> Result<Vec<Self>> {
        Ok(d.take(n)?.to_vec())
    }
}

impl<T: Encode> Encode for [T] {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.count(self.len())?;
        T::encode_elems(self, e)
    }
}
impl<T: Encode> Encode for Vec<T> {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        self.as_slice().encode(e)
    }
}
impl<'a, T: Decode<'a>> Decode<'a> for Vec<T> {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        let n = d.count()?;
        T::decode_elems(d, n)
    }
}
/// Same wire form as `Vec` (count + elements).
impl<T: Encode> Encode for VecDeque<T> {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.count(self.len())?;
        let (a, b) = self.as_slices();
        T::encode_elems(a, e)?;
        T::encode_elems(b, e)
    }
}
impl<'a, T: Decode<'a>> Decode<'a> for VecDeque<T> {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Vec::decode(d).map(VecDeque::from)
    }
}
/// Fixed array: elements only, no count.
impl<T: Encode, const N: usize> Encode for [T; N] {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        T::encode_elems(self, e)
    }
}
impl<'a, const N: usize> Decode<'a> for [u8; N] {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.array()
    }
}

impl Encode for str {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.bytes(self.as_bytes())
    }
}
impl Encode for String {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.bytes(self.as_bytes())
    }
}
impl<'a> Decode<'a> for String {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        core::str::from_utf8(d.bytes()?)
            .map(str::to_owned)
            .map_err(|_| Error::Utf8)
    }
}
/// Borrowed bytes (string/bufferlist wire form).
impl<'a> Decode<'a> for &'a [u8] {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.bytes()
    }
}
/// Borrowed UTF-8 string.
impl<'a> Decode<'a> for &'a str {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        core::str::from_utf8(d.bytes()?).map_err(|_| Error::Utf8)
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        match self {
            None => e.u8(0),
            Some(v) => {
                e.u8(1)?;
                v.encode(e)
            }
        }
    }
}
impl<'a, T: Decode<'a>> Decode<'a> for Option<T> {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        if d.u8()? == 0 {
            Ok(None)
        } else {
            T::decode(d).map(Some)
        }
    }
}

impl<K: Encode, V: Encode> Encode for BTreeMap<K, V> {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.count(self.len())?;
        for (k, v) in self {
            k.encode(e)?;
            v.encode(e)?;
        }
        Ok(())
    }
}
/// Duplicate keys: last wins.
impl<'a, K: Decode<'a> + Ord, V: Decode<'a>> Decode<'a> for BTreeMap<K, V> {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        let n = d.count()?;
        // Bulk build: std sorts (a no-op on sorted input) and keeps the last of equal keys.
        let mut items = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let k = K::decode(d)?;
            let v = V::decode(d)?;
            items.push((k, v));
        }
        Ok(items.into_iter().collect())
    }
}
impl<K: Encode> Encode for BTreeSet<K> {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.count(self.len())?;
        self.iter().try_for_each(|k| k.encode(e))
    }
}
impl<'a, K: Decode<'a> + Ord> Decode<'a> for BTreeSet<K> {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        let n = d.count()?;
        let items = K::decode_elems(d, n)?;
        Ok(items.into_iter().collect())
    }
}

macro_rules! tuple_impl {
    ($($n:ident),+) => {
        impl<$($n: Encode),+> Encode for ($($n,)+) {
            #[expect(non_snake_case)]
            fn encode<BB: BufMut>(&self, e: &mut Encoder<BB>) -> Result<()> {
                let ($($n,)+) = self;
                $($n.encode(e)?;)+
                Ok(())
            }
        }
        impl<'a, $($n: Decode<'a>),+> Decode<'a> for ($($n,)+) {
            fn decode(d: &mut Decoder<'a>) -> Result<Self> {
                Ok(($($n::decode(d)?,)+))
            }
        }
    };
}
tuple_impl!(A, B);
tuple_impl!(A, B, C);
tuple_impl!(A, B, C, D);
