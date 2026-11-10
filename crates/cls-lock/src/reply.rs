// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Reply payloads of cls `lock` (spec 9.3).
//!
//! `get_info` returns the holders in a map, `list_locks` a list of names. The
//! decoders follow the reference acceptance rules: a newer envelope version is
//! accepted, bytes left inside an envelope are skipped, bytes after the reply
//! are ignored, a repeated locker key keeps the later value, and unsorted keys
//! are accepted. Each decoder reports the bytes of the reply it consumed.

use std::collections::BTreeMap;

use bytes::Bytes;
use denc::{
    Decode, Decoder,
    types::{EntityAddr, EntityName, UTime},
};

/// Why a reply was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The reply announces more records than the caller accepts.
    EntryLimit,
    /// Short buffer, incompatible envelope or a length beyond the buffer.
    Malformed(denc::Error),
}

/// One `get_info` holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locker {
    pub locker: EntityName,
    pub cookie: Bytes,
    pub expiration: UTime,
    pub address: EntityAddr,
    pub description: Bytes,
}

/// A decoded `get_info` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    /// Holders in `std::map` key order: entity type, entity number, cookie. A
    /// repeated key keeps the later reply value (spec 9.3).
    pub lockers: Vec<Locker>,
    /// The stored type byte, unchecked (stock stores it as is).
    pub kind: u8,
    pub tag: Bytes,
    /// The bytes of the outer envelope; later bytes of the buffer are ignored.
    pub consumed: usize,
}

/// A decoded `list_locks` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Names {
    /// Names in reply order; duplicates stay (stock appends to a list).
    pub names: Vec<Bytes>,
    /// The bytes of the outer envelope; later bytes of the buffer are ignored.
    pub consumed: usize,
}

/// One versioned envelope with the reference compatibility rules: version 1 is
/// the oldest accepted, compat above 1 is malformed, a newer version is
/// accepted and unread body bytes are skipped.
fn envelope<T>(
    d: &mut Decoder<'_>,
    f: impl FnOnce(&mut Decoder<'_>) -> denc::Result<T>,
) -> denc::Result<T> {
    d.versioned_min(1, 1, |d, _version| f(d))
}

/// Decode one holder: an identity envelope (name, cookie) and an info envelope
/// (expiration, address, description).
fn locker(d: &mut Decoder<'_>, data: &Bytes) -> denc::Result<Locker> {
    let (locker, cookie_start, cookie_len) = envelope(d, |d| {
        let locker = EntityName::decode(d)?;
        let cookie = d.bytes()?;
        Ok((locker, d.position() - cookie.len(), cookie.len()))
    })?;
    let (expiration, address, description_start, description_len) = envelope(d, |d| {
        let expiration = UTime::decode(d)?;
        let address = EntityAddr::decode(d)?;
        let description = d.bytes()?;
        Ok((
            expiration,
            address,
            d.position() - description.len(),
            description.len(),
        ))
    })?;
    Ok(Locker {
        locker,
        cookie: data.slice(cookie_start..cookie_start + cookie_len),
        expiration,
        address,
        description: data.slice(description_start..description_start + description_len),
    })
}

/// Decode a `get_info` reply.
pub fn decode_info(data: &Bytes, max_entries: u32) -> Result<Info, DecodeError> {
    let mut d = Decoder::new(data);
    let mut over_limit = false;
    let decoded = envelope(&mut d, |d| {
        let count = d.u32()?;
        if count > max_entries {
            over_limit = true;
            return Err(denc::Error::BadValue("cls lock entry limit"));
        }
        let mut lockers = Vec::new();
        for _ in 0..count {
            lockers.push(locker(d, data)?);
        }
        let kind = d.u8()?;
        let tag = d.bytes()?;
        let tag_start = d.position() - tag.len();
        Ok((lockers, kind, data.slice(tag_start..tag_start + tag.len())))
    });
    if over_limit {
        return Err(DecodeError::EntryLimit);
    }
    let (lockers, kind, tag) = decoded.map_err(DecodeError::Malformed)?;
    // `std::map`: a repeated key keeps the later value, entries are in key
    // order (O(n log n); the record count is bounded only by the reply size).
    let mut unique = BTreeMap::new();
    for locker in lockers {
        unique.insert((locker.locker, locker.cookie.clone()), locker);
    }
    Ok(Info {
        lockers: unique.into_values().collect(),
        kind,
        tag,
        consumed: d.position(),
    })
}

/// Decode a `list_locks` reply.
pub fn decode_names(data: &Bytes, max_entries: u32) -> Result<Names, DecodeError> {
    let mut d = Decoder::new(data);
    let mut over_limit = false;
    let decoded = envelope(&mut d, |d| {
        let count = d.u32()?;
        if count > max_entries {
            over_limit = true;
            return Err(denc::Error::BadValue("cls lock entry limit"));
        }
        let mut names = Vec::new();
        for _ in 0..count {
            let name = d.bytes()?;
            let start = d.position() - name.len();
            names.push(data.slice(start..start + name.len()));
        }
        Ok(names)
    });
    if over_limit {
        return Err(DecodeError::EntryLimit);
    }
    Ok(Names {
        names: decoded.map_err(DecodeError::Malformed)?,
        consumed: d.position(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }

    fn envelope_bytes(body: &[u8]) -> Vec<u8> {
        let mut out = vec![1, 1];
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    fn record(
        entity: EntityName,
        cookie: &[u8],
        expiration: (u32, u32),
        address: &[u8],
        description: &[u8],
    ) -> Vec<u8> {
        let mut identity = vec![entity.ty];
        identity.extend_from_slice(&entity.num.to_le_bytes());
        field(&mut identity, cookie);
        let mut info = Vec::new();
        info.extend_from_slice(&expiration.0.to_le_bytes());
        info.extend_from_slice(&expiration.1.to_le_bytes());
        info.extend_from_slice(address);
        field(&mut info, description);
        let mut out = envelope_bytes(&identity);
        out.extend_from_slice(&envelope_bytes(&info));
        out
    }

    fn info_bytes(records: &[Vec<u8>], kind: u8, tag: &[u8]) -> Vec<u8> {
        let mut body = (records.len() as u32).to_le_bytes().to_vec();
        for record in records {
            body.extend_from_slice(record);
        }
        body.push(kind);
        field(&mut body, tag);
        envelope_bytes(&body)
    }

    fn names_bytes(names: &[&[u8]]) -> Vec<u8> {
        let mut body = (names.len() as u32).to_le_bytes().to_vec();
        for name in names {
            field(&mut body, name);
        }
        envelope_bytes(&body)
    }

    /// Legacy IPv4 address: zero u32 type slot, nonce, 128-byte sockaddr.
    fn legacy_addr(nonce: u32, ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut out = vec![0, 0, 0, 0];
        out.extend_from_slice(&nonce.to_le_bytes());
        let mut sockaddr = [0u8; 128];
        sockaddr[..2].copy_from_slice(&2u16.to_be_bytes());
        sockaddr[2..4].copy_from_slice(&port.to_be_bytes());
        sockaddr[4..8].copy_from_slice(&ip);
        out.extend_from_slice(&sockaddr);
        out
    }

    /// msgr2 address: marker 1, `env(1,1){type, nonce, u32 elen, family, data}`.
    fn msgr2_addr(ty: u32, nonce: u32, ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&ty.to_le_bytes());
        body.extend_from_slice(&nonce.to_le_bytes());
        body.extend_from_slice(&16u32.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&port.to_be_bytes());
        body.extend_from_slice(&ip);
        body.extend_from_slice(&[0u8; 8]);
        let mut out = vec![1];
        out.extend_from_slice(&envelope_bytes(&body));
        out
    }

    #[test]
    fn info_v1_decodes_every_field_and_reports_the_consumed_length() {
        let data = Bytes::from(info_bytes(
            &[record(
                EntityName::client(7),
                &[0xff, 0],
                (3, 4),
                &legacy_addr(9, [127, 0, 0, 1], 1234),
                &[0xfe, 0],
            )],
            9,
            &[0x80, 0],
        ));
        let info = decode_info(&data, 4).unwrap();
        assert_eq!(info.consumed, data.len());
        assert_eq!(info.kind, 9);
        assert_eq!(&info.tag[..], &[0x80, 0]);
        assert_eq!(info.lockers.len(), 1);
        let locker = &info.lockers[0];
        assert_eq!(locker.locker, EntityName::client(7));
        assert_eq!(&locker.cookie[..], &[0xff, 0]);
        assert_eq!(locker.expiration, UTime::new(3, 4));
        assert_eq!(
            locker.address,
            EntityAddr::v4(EntityAddr::TYPE_LEGACY, 9, [127, 0, 0, 1], 1234)
        );
        assert_eq!(&locker.description[..], &[0xfe, 0]);
        // The views share the reply's allocation.
        assert_eq!(locker.cookie.as_ptr(), unsafe { data.as_ptr().add(29) });
    }

    #[test]
    fn names_v1_keep_reply_order_and_report_the_consumed_length() {
        let data = Bytes::from(names_bytes(&[b"\0\xff", b"\xff\0"]));
        let names = decode_names(&data, 4).unwrap();
        assert_eq!(names.consumed, data.len());
        assert_eq!(names.names.len(), 2);
        assert_eq!(&names.names[0][..], b"\0\xff");
        assert_eq!(&names.names[1][..], b"\xff\0");
        assert_eq!(names.names[0].as_ptr(), unsafe { data.as_ptr().add(14) });
    }

    #[test]
    fn newer_version_and_envelope_slack_are_accepted() {
        let mut info = info_bytes(
            &[record(
                EntityName::client(1),
                b"c",
                (1, 2),
                &legacy_addr(0, [1, 2, 3, 4], 5),
                b"",
            )],
            2,
            b"t",
        );
        // Version 2 and two unread bytes inside the outer envelope.
        info[0] = 2;
        info.extend_from_slice(&[0xaa, 0xbb]);
        let body = (info.len() - 6) as u32;
        info[2..6].copy_from_slice(&body.to_le_bytes());
        let data = Bytes::from(info);
        let decoded = decode_info(&data, 4).unwrap();
        assert_eq!(decoded.consumed, data.len());
        assert_eq!(decoded.lockers.len(), 1);
        assert_eq!(&decoded.tag[..], b"t");

        let mut names = names_bytes(&[b"a"]);
        names[0] = 2;
        let data = Bytes::from(names);
        assert_eq!(decode_names(&data, 4).unwrap().names.len(), 1);
    }

    #[test]
    fn compat_2_is_rejected() {
        let info = info_bytes(
            &[record(
                EntityName::client(1),
                b"c",
                (1, 2),
                &legacy_addr(0, [1, 2, 3, 4], 5),
                b"",
            )],
            1,
            b"",
        );
        let names = names_bytes(&[b"a"]);
        for (is_info, mut data) in [(true, info), (false, names)] {
            data[1] = 2;
            let data = Bytes::from(data);
            let result = if is_info {
                decode_info(&data, 4).map(|_| ())
            } else {
                decode_names(&data, 4).map(|_| ())
            };
            assert!(matches!(result, Err(DecodeError::Malformed(_))));
        }
    }

    #[test]
    fn repeated_locker_key_keeps_the_later_value() {
        let data = Bytes::from(info_bytes(
            &[
                record(
                    EntityName::client(1),
                    b"c",
                    (1, 2),
                    &legacy_addr(0, [1, 2, 3, 4], 5),
                    b"first",
                ),
                record(
                    EntityName::client(1),
                    b"c",
                    (7, 8),
                    &legacy_addr(1, [5, 6, 7, 8], 9),
                    b"later",
                ),
            ],
            1,
            b"",
        ));
        let info = decode_info(&data, 4).unwrap();
        assert_eq!(info.lockers.len(), 1);
        assert_eq!(&info.lockers[0].description[..], b"later");
        assert_eq!(info.lockers[0].expiration, UTime::new(7, 8));
    }

    #[test]
    fn unsorted_keys_are_accepted_and_returned_in_key_order() {
        let data = Bytes::from(info_bytes(
            &[
                record(
                    EntityName::client(9),
                    b"z",
                    (1, 2),
                    &legacy_addr(0, [1, 2, 3, 4], 5),
                    b"",
                ),
                record(
                    EntityName::client(3),
                    b"a",
                    (1, 2),
                    &legacy_addr(0, [1, 2, 3, 4], 5),
                    b"",
                ),
                record(
                    EntityName::client(3),
                    b"b",
                    (1, 2),
                    &legacy_addr(0, [1, 2, 3, 4], 5),
                    b"",
                ),
            ],
            1,
            b"",
        ));
        let info = decode_info(&data, 4).unwrap();
        let keys: Vec<_> = info
            .lockers
            .iter()
            .map(|locker| (locker.locker, &locker.cookie[..]))
            .collect();
        assert_eq!(
            keys,
            [
                (EntityName::client(3), b"a".as_slice()),
                (EntityName::client(3), b"b".as_slice()),
                (EntityName::client(9), b"z".as_slice()),
            ]
        );

        // list_locks keeps the reply order and duplicates (a std::list).
        let data = Bytes::from(names_bytes(&[b"z", b"a", b"z"]));
        let names = decode_names(&data, 4).unwrap();
        let got: Vec<&[u8]> = names.names.iter().map(|name| &name[..]).collect();
        assert_eq!(got, [b"z".as_slice(), b"a", b"z"]);
    }

    #[test]
    fn legacy_and_msgr2_addresses_decode() {
        for (address, expected) in [
            (
                legacy_addr(9, [127, 0, 0, 1], 1234),
                EntityAddr::v4(EntityAddr::TYPE_LEGACY, 9, [127, 0, 0, 1], 1234),
            ),
            (
                msgr2_addr(EntityAddr::TYPE_MSGR2, 7, [10, 0, 0, 1], 3300),
                EntityAddr::v4(EntityAddr::TYPE_MSGR2, 7, [10, 0, 0, 1], 3300),
            ),
        ] {
            let data = Bytes::from(info_bytes(
                &[record(EntityName::client(1), b"c", (0, 0), &address, b"")],
                1,
                b"",
            ));
            let info = decode_info(&data, 4).unwrap();
            assert_eq!(info.lockers[0].address, expected);
        }
    }

    #[test]
    fn every_truncation_is_malformed() {
        let info = info_bytes(
            &[record(
                EntityName::client(1),
                b"c",
                (1, 2),
                &legacy_addr(0, [1, 2, 3, 4], 5),
                b"d",
            )],
            1,
            b"t",
        );
        let names = names_bytes(&[b"\0\xff", b"\xff\0"]);
        for (is_info, data) in [(true, info), (false, names)] {
            for cut in 0..data.len() {
                let data = Bytes::copy_from_slice(&data[..cut]);
                let result = if is_info {
                    decode_info(&data, 4).map(|_| ())
                } else {
                    decode_names(&data, 4).map(|_| ())
                };
                assert!(
                    matches!(result, Err(DecodeError::Malformed(_))),
                    "cut {cut}"
                );
            }
        }
    }

    #[test]
    fn trailing_bytes_after_the_reply_are_ignored() {
        let info = info_bytes(
            &[record(
                EntityName::client(1),
                b"c",
                (1, 2),
                &legacy_addr(0, [1, 2, 3, 4], 5),
                b"",
            )],
            1,
            b"",
        );
        let names = names_bytes(&[b"a"]);
        for (is_info, data) in [(true, info), (false, names)] {
            let reply_len = data.len();
            let mut trailing = data;
            trailing.extend_from_slice(&[0, 1, 2]);
            let data = Bytes::from(trailing);
            let consumed = if is_info {
                decode_info(&data, 4).unwrap().consumed
            } else {
                decode_names(&data, 4).unwrap().consumed
            };
            assert_eq!(consumed, reply_len);
        }
    }

    #[test]
    fn the_entry_limit_is_checked_before_the_records() {
        let data = Bytes::from_static(b"\x01\x01\x04\0\0\0\xff\xff\xff\xff");
        assert_eq!(decode_info(&data, 4).unwrap_err(), DecodeError::EntryLimit);
        assert_eq!(decode_names(&data, 4).unwrap_err(), DecodeError::EntryLimit);
        assert!(matches!(
            decode_names(&data, u32::MAX).unwrap_err(),
            DecodeError::Malformed(_)
        ));
    }

    #[test]
    fn a_malformed_holder_envelope_is_rejected() {
        let mut body = 1u32.to_le_bytes().to_vec();
        // Identity envelope claims more bytes than the reply holds.
        body.extend_from_slice(&[1, 1, 0xff, 0, 0, 0]);
        body.extend_from_slice(&[1]);
        field(&mut body, b"");
        let data = Bytes::from(envelope_bytes(&body));
        assert!(matches!(
            decode_info(&data, 4),
            Err(DecodeError::Malformed(_))
        ));
    }
}
