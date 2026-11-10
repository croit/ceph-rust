// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The [`Message`] trait and shared helpers.

use denc::{BufMut, Decoder, Encoder, Error, Result};

/// The three payload segments of a MESSAGE frame (segment 1..3).
#[derive(Clone, Default)]
pub struct Segments {
    pub front: Vec<u8>,
    /// Shared runs spliced into `front` (encode side only, zero-copy multi-MiB payloads, msgr2 `Message::front_zc`):
    /// `(offset in front, run)`, ascending; the logical front is `front` with each run inserted at its offset. Received
    /// segments have them only as one whole large front (`decode_with_header_owned`). Readers use [`Segments::front_bytes`].
    pub front_zc: Vec<(usize, bytes::Bytes)>,
    /// Known crcs of the `front_zc` runs (msgr2 `Message::front_hints`): a CRC-mode frame joins them instead of a pass.
    pub front_hints: crc::CrcHints,
    pub middle: Vec<u8>,
    pub data: bytes::Bytes,
}

/// Equality is wire content: `front_hints` is send-side metadata (known crcs of runs already in `front_zc`), not part of
/// the frame, so it is excluded.
impl PartialEq for Segments {
    fn eq(&self, o: &Self) -> bool {
        let Segments {
            front,
            front_zc,
            front_hints: _,
            middle,
            data,
        } = self;
        *front == o.front && *front_zc == o.front_zc && *middle == o.middle && *data == o.data
    }
}
impl Eq for Segments {}

/// No payload bytes: a `Debug` line must never leak a ticket, keyring blob or multi-MiB front into a log or a panic.
impl std::fmt::Debug for Segments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Segments {{ front: {} B, front_zc: {} run(s), middle: {} B, data: {} B }}",
            self.front.len(),
            self.front_zc.len(),
            self.middle.len(),
            self.data.len()
        )
    }
}

impl Segments {
    pub fn front(front: Vec<u8>) -> Self {
        Segments {
            front,
            ..Default::default()
        }
    }

    /// Front + data segment, no middle (command-style payloads with an input/output blob).
    pub fn with_data(front: Vec<u8>, data: Vec<u8>) -> Self {
        Segments {
            front,
            data: data.into(),
            ..Default::default()
        }
    }

    /// Logical front length (spliced runs included).
    pub fn front_len(&self) -> usize {
        self.front.len() + self.front_zc.iter().map(|(_, r)| r.len()).sum::<usize>()
    }

    /// The whole logical front as one shared buffer (a received large front, `decode_with_header_owned`).
    pub fn front_shared(&self) -> Option<&bytes::Bytes> {
        match self.front_zc.as_slice() {
            [(0, r)] if self.front.is_empty() => Some(r),
            _ => None,
        }
    }

    /// The logical front as one buffer (copies only when runs are spliced into inline bytes). Errors when `front_zc`
    /// breaks its invariant (ascending offsets that stay inside `front`, the rule [`denc::Encoder::raw_rope`] applies);
    /// never slices unchecked.
    pub fn front_bytes(&self) -> Result<std::borrow::Cow<'_, [u8]>> {
        if self.front_zc.is_empty() {
            return Ok(std::borrow::Cow::Borrowed(&self.front));
        }
        if let Some(r) = self.front_shared() {
            return Ok(std::borrow::Cow::Borrowed(r));
        }
        let mut v = Vec::with_capacity(self.front_len());
        let mut pos = 0;
        for (at, r) in &self.front_zc {
            if *at < pos || *at > self.front.len() {
                return Err(Error::BadValue("front rope offset"));
            }
            v.extend_from_slice(&self.front[pos..*at]);
            v.extend_from_slice(r);
            pos = *at;
        }
        v.extend_from_slice(&self.front[pos..]);
        Ok(std::borrow::Cow::Owned(v))
    }
}

/// A message payload. `COMPAT_VERSION` is the value placed on the wire in `header2.compat_version`
/// (a sender that leaves 0 gets `compat = version`, so spec "hc=0" is listed as 1 here).
pub trait Message: Sized {
    const MSG_TYPE: u16;
    const HEAD_VERSION: u16;
    const COMPAT_VERSION: u16;
    /// Oldest header version this decoder accepts (0 = any).
    const OLDEST_VERSION: u16 = 0;

    /// Encode the payload for a connection with feature mask `features`.
    fn encode(&self, features: u64) -> Result<Segments>;

    /// Decode from the header `version` and the received segments. Trailing bytes in the front
    /// segment (fields of newer versions) are ignored.
    fn decode(version: u16, front: &[u8], middle: &[u8], data: &[u8]) -> Result<Self>;

    /// Reject header versions below [`Self::OLDEST_VERSION`] (call first in `decode`).
    fn check_version(version: u16) -> Result<()> {
        if version < Self::OLDEST_VERSION {
            return Err(Error::VersionTooOld {
                version: version as u8,
                oldest: Self::OLDEST_VERSION as u8,
            });
        }
        Ok(())
    }
}

/// Encode a front segment with a closure (one exact allocation, [`denc::encode_exact`]).
pub fn front_with(
    features: u64,
    f: impl FnOnce(&mut Encoder<Vec<u8>>) -> Result<()>,
) -> Result<Vec<u8>> {
    denc::encode_exact(features, f)
}

/// [`front_with`] wrapped as a front-only [`Segments`].
pub fn front_segments(
    features: u64,
    f: impl FnOnce(&mut Encoder<Vec<u8>>) -> Result<()>,
) -> Result<Segments> {
    front_with(features, f).map(Segments::front)
}

/// PaxosServiceMessage prefix: `version`, deprecated session_mon (-1), deprecated tid (0).
pub(crate) fn put_psm<B: BufMut>(e: &mut Encoder<B>, version: u64) -> Result<()> {
    e.u64(version)?;
    e.i16(-1)?;
    e.u64(0)
}

pub(crate) fn get_psm(d: &mut Decoder<'_>) -> Result<u64> {
    let v = d.u64()?;
    d.skip(2 + 8)?;
    Ok(v)
}

/// Reject bytes left in a decoder that must have consumed its input exactly.
pub(crate) fn end(d: &Decoder<'_>) -> Result<()> {
    if d.is_empty() {
        Ok(())
    } else {
        Err(Error::TrailingBytes(d.remaining()))
    }
}

/// Declare the `MSG_TYPE` / `HEAD_VERSION` / `COMPAT_VERSION` consts (and with `oldest N` the
/// `OLDEST_VERSION`) inside an `impl Message for ..` block.
#[macro_export]
macro_rules! meta {
    ($t:expr, $v:expr, $c:expr) => {
        const MSG_TYPE: u16 = $t;
        const HEAD_VERSION: u16 = $v;
        const COMPAT_VERSION: u16 = $c;
    };
    ($t:expr, $v:expr, $c:expr, oldest $o:expr) => {
        $crate::meta!($t, $v, $c);
        const OLDEST_VERSION: u16 = $o;
    };
}

/// Define an enum over message types with `From` impls, `msg_type()`, `encode()` (header tuple
/// `(type, head_version, compat_version, segments)`) and `decode_known()` (`None` = type id not
/// in the enum). With a trailing `unknown Name` an extra
/// `Name { ty, version, compat, segments }` variant carries unsupported types through unchanged,
/// including the received header compat version.
#[macro_export]
macro_rules! message_enum {
    (
        $(#[$m:meta])* $vis:vis enum $name:ident {
            $($var:ident => $t:ty),* $(,)?
        } $(unknown $unk:ident)?
    ) => {
        $(#[$m])*
        $vis enum $name {
            $($var($t),)*
            $(
                /// Unsupported type id: log + drop, never reset the connection.
                $unk { ty: u16, version: u16, compat: u16, segments: $crate::Segments },
            )?
        }

        $(impl From<$t> for $name { fn from(m: $t) -> Self { $name::$var(m) } })*

        impl $name {
            /// `(type id, head version)` of every variant, for the receiver compat check.
            pub const HEAD_BY_TYPE: &[(u16, u16)] = &[
                $( (<$t as $crate::Message>::MSG_TYPE, <$t as $crate::Message>::HEAD_VERSION), )*
            ];

            /// Header type id.
            pub fn msg_type(&self) -> u16 {
                match self {
                    $($name::$var(_) => <$t as $crate::Message>::MSG_TYPE,)*
                    $($name::$unk { ty, .. } => *ty,)?
                }
            }
            /// `(type, head_version, compat_version, segments)` ready for a msgr2 header.
            pub fn encode(&self, features: u64) -> $crate::Result<(u16, u16, u16, $crate::Segments)> {
                match self {
                    $($name::$var(m) => Ok((
                        <$t as $crate::Message>::MSG_TYPE,
                        <$t as $crate::Message>::HEAD_VERSION,
                        <$t as $crate::Message>::COMPAT_VERSION,
                        <$t as $crate::Message>::encode(m, features)?,
                    )),)*
                    $($name::$unk { ty, version, compat, segments } => {
                        Ok((*ty, *version, *compat, segments.clone()))
                    })?
                }
            }
            /// Decode by header type id and version; `None` if the type is not in this enum.
            pub fn decode_known(
                ty: u16,
                version: u16,
                front: &[u8],
                middle: &[u8],
                data: &[u8],
            ) -> Option<$crate::Result<Self>> {
                match ty {
                    $(x if x == <$t as $crate::Message>::MSG_TYPE => Some(
                        <$t as $crate::Message>::decode(version, front, middle, data).map($name::$var),
                    ),)*
                    _ => None,
                }
            }
        }
    };
}
