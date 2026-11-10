// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Shared wire helpers for the RGW-family classes: legacy-compat envelope decode, packed values,
//! and the `env_struct!` macro for plain enveloped structs.

use denc::{BufMut, Decoder, Encoder, Error};

/// Decode of a struct that older encoders wrote WITHOUT an envelope
/// (`DECODE_START_LEGACY_COMPAT_LEN(v, compatv, lenv)`): `struct_v` always; a compat byte iff
/// `struct_v >= compatv`; a u32 length (body bound) iff `struct_v >= lenv`. Below `lenv` the body
/// runs unbounded on the caller's decoder. `max_compat` = highest struct_compat we understand.
pub fn legacy<'a, R>(
    d: &mut Decoder<'a>,
    max_compat: u8,
    compatv: u8,
    lenv: u8,
    f: impl FnOnce(&mut Decoder<'a>, u8) -> denc::Result<R>,
) -> denc::Result<R> {
    let v = d.u8()?;
    if v >= compatv {
        let compat = d.u8()?;
        if compat > max_compat {
            return Err(Error::CompatTooNew {
                compat,
                supported: max_compat,
            });
        }
    }
    if v >= lenv {
        let len = d.u32()? as usize;
        let body = d.take(len)?;
        f(&mut Decoder::new(body), v)
    } else {
        f(d, v)
    }
}

/// `encode_packed_val` (cls_rgw_types.h), bug-compatible: `v == 0x10000` is written with a 2-byte
/// payload and truncates to 0.
pub fn enc_packed<B: BufMut>(e: &mut Encoder<B>, v: u64) -> denc::Result<()> {
    if v < 0x80 {
        e.u8(v as u8)
    } else if v < 0x100 {
        e.u8(0x81)?;
        e.u8(v as u8)
    } else if v <= 0x10000 {
        e.u8(0x82)?;
        e.u16(v as u16)
    } else if v <= 0x100_0000 {
        e.u8(0x84)?;
        e.u32(v as u32)
    } else {
        e.u8(0x88)?;
        e.u64(v)
    }
}

pub fn dec_packed(d: &mut Decoder<'_>) -> denc::Result<u64> {
    let c = d.u8()?;
    if c < 0x80 {
        return Ok(c as u64);
    }
    match c & 0x7f {
        1 => Ok(d.u8()? as u64),
        2 => Ok(d.u16()? as u64),
        4 => Ok(d.u32()? as u64),
        8 => d.u64(),
        _ => Err(Error::BadValue("packed value")),
    }
}

/// Plain enveloped struct `ENCODE_START(v, c)` with fields in declaration order; decode accepts
/// compat <= v. For version-gated structs write the impls by hand.
#[macro_export]
macro_rules! env_struct {
    ($(#[$m:meta])* $name:ident ($v:literal, $c:literal) { $($(#[$fm:meta])* $f:ident : $t:ty),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name { $($(#[$fm])* pub $f: $t),* }
        impl denc::Encode for $name {
            fn encode<B: denc::BufMut>(&self, e: &mut denc::Encoder<B>) -> denc::Result<()> {
                e.versioned($v, $c, |e| { let _ = &e; $(denc::Encode::encode(&self.$f, e)?;)* Ok(()) })
            }
        }
        impl<'a> denc::Decode<'a> for $name {
            fn decode(d: &mut denc::Decoder<'a>) -> denc::Result<Self> {
                d.versioned($v, |d, _| { let _ = &d; Ok($name { $($f: <$t as denc::Decode>::decode(d)?),* }) })
            }
        }
    };
}
