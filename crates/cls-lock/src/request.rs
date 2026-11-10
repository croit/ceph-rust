// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Input payloads of the seven cls `lock` methods (spec 9.3).
//!
//! Encoding is little endian; a `str` field is a u32 byte length plus the
//! bytes; an envelope is `u8 version 1, u8 compat 1, u32 body length`. All
//! lengths are checked before any payload is allocated.

use denc::types::EntityName;

/// The class name of every method.
pub const CLASS: &[u8] = b"lock";

/// A field, a body or a whole payload does not fit its u32 length prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong;

/// The seven cls `lock` methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Lock,
    Unlock,
    Break,
    GetInfo,
    ListLocks,
    AssertLocked,
    SetCookie,
}

impl Method {
    /// The class method name on the wire.
    pub const fn name(self) -> &'static [u8] {
        match self {
            Self::Lock => b"lock",
            Self::Unlock => b"unlock",
            Self::Break => b"break_lock",
            Self::GetInfo => b"get_info",
            Self::ListLocks => b"list_locks",
            Self::AssertLocked => b"assert_locked",
            Self::SetCookie => b"set_cookie",
        }
    }
}

/// One method's input, borrowed until it is encoded. `kind` and `flags` are
/// passed verbatim (stock sends the caller's value; the class validates it).
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    Lock {
        name: &'a [u8],
        kind: u8,
        cookie: &'a [u8],
        tag: &'a [u8],
        description: &'a [u8],
        duration_sec: u32,
        duration_nsec: u32,
        flags: u8,
    },
    Unlock {
        name: &'a [u8],
        cookie: &'a [u8],
    },
    Break {
        name: &'a [u8],
        locker: EntityName,
        cookie: &'a [u8],
    },
    GetInfo {
        name: &'a [u8],
    },
    List,
    Assert {
        name: &'a [u8],
        kind: u8,
        cookie: &'a [u8],
        tag: &'a [u8],
    },
    SetCookie {
        name: &'a [u8],
        kind: u8,
        cookie: &'a [u8],
        tag: &'a [u8],
        new_cookie: &'a [u8],
    },
}

/// Check one envelope body: its u32 length field and the 6-byte header plus
/// body must fit an allocation. Returns the encoded payload length.
pub fn check_envelope_body(body_len: usize) -> Result<usize, TooLong> {
    u32::try_from(body_len).map_err(|_| TooLong)?;
    let total = body_len.checked_add(6).ok_or(TooLong)?;
    if total > isize::MAX as usize {
        return Err(TooLong);
    }
    Ok(total)
}

/// The envelope body length of `fixed` non-field bytes plus `str` fields of
/// the given lengths, checked before any allocation.
pub fn body_len(
    fixed: usize,
    field_lengths: impl IntoIterator<Item = usize>,
) -> Result<usize, TooLong> {
    let mut body = fixed;
    for length in field_lengths {
        if length > u32::MAX as usize {
            return Err(TooLong);
        }
        body = body
            .checked_add(4)
            .and_then(|body| body.checked_add(length))
            .ok_or(TooLong)?;
    }
    Ok(body)
}

impl Request<'_> {
    /// The class method this request calls.
    pub fn method(&self) -> Method {
        match self {
            Self::Lock { .. } => Method::Lock,
            Self::Unlock { .. } => Method::Unlock,
            Self::Break { .. } => Method::Break,
            Self::GetInfo { .. } => Method::GetInfo,
            Self::List => Method::ListLocks,
            Self::Assert { .. } => Method::AssertLocked,
            Self::SetCookie { .. } => Method::SetCookie,
        }
    }

    /// The encoded payload length (0 for `list_locks`), checked before any
    /// allocation.
    pub fn payload_len(&self) -> Result<usize, TooLong> {
        let body = match *self {
            Self::Lock {
                name,
                cookie,
                tag,
                description,
                ..
            } => body_len(
                1 + 4 + 4 + 1,
                [name.len(), cookie.len(), tag.len(), description.len()],
            )?,
            Self::Unlock { name, cookie } => body_len(0, [name.len(), cookie.len()])?,
            // The entity name is a u8 type plus an i64 number.
            Self::Break { name, cookie, .. } => body_len(9, [name.len(), cookie.len()])?,
            Self::GetInfo { name } => body_len(0, [name.len()])?,
            Self::List => return Ok(0),
            Self::Assert {
                name, cookie, tag, ..
            } => body_len(1, [name.len(), cookie.len(), tag.len()])?,
            Self::SetCookie {
                name,
                cookie,
                tag,
                new_cookie,
                ..
            } => body_len(1, [name.len(), cookie.len(), tag.len(), new_cookie.len()])?,
        };
        check_envelope_body(body)
    }

    /// Encode the payload. The lengths were checked by [`Self::payload_len`]
    /// before the payload is allocated.
    pub fn encode(&self) -> Result<Vec<u8>, TooLong> {
        let total = self.payload_len()?;
        if total == 0 {
            return Ok(Vec::new());
        }
        let body = total - 6;
        let mut out = Vec::with_capacity(total);
        out.push(1);
        out.push(1);
        out.extend_from_slice(&(body as u32).to_le_bytes());
        match *self {
            Self::Lock {
                name,
                kind,
                cookie,
                tag,
                description,
                duration_sec,
                duration_nsec,
                flags,
            } => {
                field(&mut out, name);
                out.push(kind);
                field(&mut out, cookie);
                field(&mut out, tag);
                field(&mut out, description);
                out.extend_from_slice(&duration_sec.to_le_bytes());
                out.extend_from_slice(&duration_nsec.to_le_bytes());
                out.push(flags);
            }
            Self::Unlock { name, cookie } => {
                field(&mut out, name);
                field(&mut out, cookie);
            }
            Self::Break {
                name,
                locker,
                cookie,
            } => {
                field(&mut out, name);
                out.push(locker.ty);
                out.extend_from_slice(&locker.num.to_le_bytes());
                field(&mut out, cookie);
            }
            Self::GetInfo { name } => field(&mut out, name),
            Self::List => unreachable!("list_locks has no payload"),
            Self::Assert {
                name,
                kind,
                cookie,
                tag,
            } => {
                field(&mut out, name);
                out.push(kind);
                field(&mut out, cookie);
                field(&mut out, tag);
            }
            Self::SetCookie {
                name,
                kind,
                cookie,
                tag,
                new_cookie,
            } => {
                field(&mut out, name);
                out.push(kind);
                field(&mut out, cookie);
                field(&mut out, tag);
                field(&mut out, new_cookie);
            }
        }
        debug_assert_eq!(out.len(), total);
        Ok(out)
    }
}

/// Append one `str` field; the caller checked the length.
fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_payload_matches_the_pinned_vector_for_every_kind_and_flag() {
        for kind in [1u8, 2, 3] {
            for flags in [0u8, 1, 2] {
                let request = Request::Lock {
                    name: b"n",
                    kind,
                    cookie: b"c",
                    tag: &[0xff, 0],
                    description: b"d",
                    duration_sec: 2,
                    duration_nsec: 3,
                    flags,
                };
                let payload = request.encode().unwrap();
                assert_eq!(request.method(), Method::Lock);
                assert_eq!(request.method().name(), b"lock");
                assert_eq!(payload.len(), 37);
                let mut literal = b"\x01\x01\x1f\0\0\0\x01\0\0\0n".to_vec();
                literal.push(kind);
                literal.extend_from_slice(
                    b"\x01\0\0\0c\x02\0\0\0\xff\0\x01\0\0\0d\x02\0\0\0\x03\0\0\0",
                );
                literal.push(flags);
                assert_eq!(payload, literal);
                assert_eq!(request.payload_len(), Ok(payload.len()));
            }
        }
    }

    #[test]
    fn remaining_methods_match_their_pinned_vectors() {
        let rows: Vec<(Request<'_>, &[u8], &[u8])> = vec![
            (
                Request::Unlock {
                    name: b"n",
                    cookie: b"c",
                },
                b"unlock",
                b"\x01\x01\x0a\0\0\0\x01\0\0\0n\x01\0\0\0c",
            ),
            (
                Request::Break {
                    name: b"n",
                    locker: EntityName::client(-2),
                    cookie: b"c",
                },
                b"break_lock",
                b"\x01\x01\x13\0\0\0\x01\0\0\0n\x08\xfe\xff\xff\xff\xff\xff\xff\xff\x01\0\0\0c",
            ),
            (
                Request::GetInfo { name: &[0xff, 0] },
                b"get_info",
                b"\x01\x01\x06\0\0\0\x02\0\0\0\xff\0",
            ),
            (Request::List, b"list_locks", b""),
            (
                Request::Assert {
                    name: b"n",
                    kind: 2,
                    cookie: b"c",
                    tag: b"t",
                },
                b"assert_locked",
                b"\x01\x01\x10\0\0\0\x01\0\0\0n\x02\x01\0\0\0c\x01\0\0\0t",
            ),
            (
                Request::SetCookie {
                    name: b"n",
                    kind: 2,
                    cookie: b"c",
                    tag: b"t",
                    new_cookie: b"x",
                },
                b"set_cookie",
                b"\x01\x01\x15\0\0\0\x01\0\0\0n\x02\x01\0\0\0c\x01\0\0\0t\x01\0\0\0x",
            ),
        ];
        for (request, method, payload) in rows {
            assert_eq!(request.method().name(), method);
            assert_eq!(request.encode().unwrap(), payload);
            assert_eq!(request.payload_len(), Ok(payload.len()));
        }
    }

    #[test]
    fn striper_payload_vectors_stay_83_80_and_62_bytes() {
        const COOKIE: &[u8] = b"12345678-9abc-4def-8123-456789abcdef";
        let shared = Request::Lock {
            name: b"striper.lock",
            kind: 2,
            cookie: COOKIE,
            tag: b"Tag",
            description: b"",
            duration_sec: 0,
            duration_nsec: 0,
            flags: 0,
        }
        .encode()
        .unwrap();
        assert_eq!(shared.len(), 83);
        let exclusive = Request::Lock {
            name: b"striper.lock",
            kind: 1,
            cookie: COOKIE,
            tag: b"",
            description: b"",
            duration_sec: 0,
            duration_nsec: 0,
            flags: 0,
        }
        .encode()
        .unwrap();
        assert_eq!(exclusive.len(), 80);
        let unlock = Request::Unlock {
            name: b"striper.lock",
            cookie: COOKIE,
        }
        .encode()
        .unwrap();
        assert_eq!(unlock.len(), 62);
    }

    #[test]
    fn widths_are_checked_before_any_payload_allocation() {
        // A field that fits u32 can still overflow its envelope.
        let max_body = (u32::MAX as usize).min(isize::MAX as usize - 6);
        let fixed = 5;
        let room = max_body - fixed - 4;
        assert_eq!(body_len(fixed, [room]), Ok(max_body));
        assert_eq!(body_len(fixed, [room + 1]), Ok(max_body + 1));
        assert_eq!(
            check_envelope_body(body_len(fixed, [room + 1]).unwrap()),
            Err(TooLong)
        );
        assert_eq!(check_envelope_body(max_body), Ok(max_body + 6));
        assert_eq!(check_envelope_body(max_body + 1), Err(TooLong));
        assert_eq!(check_envelope_body(usize::MAX), Err(TooLong));
        assert_eq!(
            check_envelope_body(body_len(0, [u32::MAX as usize]).unwrap()),
            Err(TooLong)
        );
        assert_eq!(body_len(0, [u32::MAX as usize + 1]), Err(TooLong));
    }

    #[test]
    fn every_method_names_its_class_and_method() {
        assert_eq!(CLASS, b"lock");
        assert_eq!(Method::ListLocks.name(), b"list_locks");
        assert_eq!(Method::AssertLocked.name(), b"assert_locked");
        assert_eq!(Method::SetCookie.name(), b"set_cookie");
    }
}
