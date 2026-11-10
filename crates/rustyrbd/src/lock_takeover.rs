// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Holder report and takeover decision for the RBD header lock.
//!
//! The pinned reference binds the header lock to the watch of its owner. The
//! cookie of the lock entry carries the watch handle, so a holder whose
//! watch is gone can be separated from a holder that still watches the
//! header object.

use denc::types::{EntityAddr, EntityName};
use opwire::WatchItem;
use rustyrados::{Access, CompoundRequest, LockDecodeLimits, LockInfo, LockReply, LockReplyKind};

use crate::metadata_query::header_target;

pub use crate::lock_wire::{LOCK_NAME, WATCHER_COOKIE_PREFIX, WATCHER_LOCK_TAG};

/// One holder of the header lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockHolder {
    /// The authenticated entity of the holder.
    pub entity: EntityName,
    /// The cookie of the lock entry, carrying the watch handle.
    pub cookie: Vec<u8>,
    /// The address the holder connected from.
    pub address: EntityAddr,
    /// The description the holder wrote into the lock entry.
    pub description: Vec<u8>,
}

impl LockHolder {
    /// Legacy socket address and nonce, without a transport prefix.
    /// Unknown address families have no usable textual address.
    pub fn legacy_address(&self) -> Option<String> {
        let address = &self.address;
        if let Some(ip) = address.ipv4() {
            Some(format!(
                "{}:{}/{}",
                std::net::Ipv4Addr::from(ip),
                address.port(),
                address.nonce
            ))
        } else {
            address.ipv6().map(|ip| {
                format!(
                    "[{}]:{}/{}",
                    std::net::Ipv6Addr::from(ip),
                    address.port(),
                    address.nonce
                )
            })
        }
    }
}

/// Why the holder report could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HolderReportError {
    /// The reply did not carry a lock holder list.
    Malformed,
    /// The reply exceeded the accepted size or entry count.
    TooLarge,
}

/// Decode the reply of the class `get_info` operation.
///
/// The reply holds one record per holder. An empty holder list means that
/// the lock is free.
fn decode_info(reply: &[u8]) -> Result<LockInfo, HolderReportError> {
    let data = bytes::Bytes::copy_from_slice(reply);
    let limits = LockDecodeLimits {
        bytes: data.len(),
        entries: u32::MAX,
    };
    let decoded = match LockReply::decode(LockReplyKind::Info, 0, 0, data, limits) {
        Ok(decoded) => decoded,
        Err(rejected) => {
            return Err(match rejected.reason {
                rustyrados::LockDecodeError::ByteLimit
                | rustyrados::LockDecodeError::EntryLimit => HolderReportError::TooLarge,
                _ => HolderReportError::Malformed,
            });
        }
    };
    let LockReply::Info(info) = decoded else {
        return Err(HolderReportError::Malformed);
    };
    Ok(info)
}

/// Decode all lock holders, including external mechanisms.
pub fn decode_holders(reply: &[u8]) -> Result<Vec<LockHolder>, HolderReportError> {
    Ok(decode_info(reply)?
        .entries()
        .map(|locker| LockHolder {
            entity: locker.locker,
            cookie: locker.cookie.to_vec(),
            address: locker.address,
            description: locker.description.to_vec(),
        })
        .collect())
}

/// The watch handle of a watcher-bound lock cookie.
///
/// A cookie of another shape belongs to a lock that the pinned reference
/// treats as an external mechanism.
pub fn watch_handle(cookie: &[u8]) -> Option<u64> {
    // Formatted unsigned extraction accepts leading whitespace and a sign,
    // stops at the first nondigit, and rejects magnitude overflow. The word
    // extraction still requires a complete whitespace-delimited "auto".
    let whitespace = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let mut rest = cookie;
    while rest.first().is_some_and(whitespace) {
        rest = &rest[1..];
    }
    let word_end = rest.iter().position(whitespace)?;
    if &rest[..word_end] != WATCHER_COOKIE_PREFIX.as_bytes() {
        return None;
    }
    rest = &rest[word_end..];
    while rest.first().is_some_and(whitespace) {
        rest = &rest[1..];
    }
    let negative = rest.first() == Some(&b'-');
    if matches!(rest.first(), Some(b'+' | b'-')) {
        rest = &rest[1..];
    }
    let digits = rest.iter().take_while(|byte| byte.is_ascii_digit());
    let mut value = 0u64;
    let mut any = false;
    for byte in digits {
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
        any = true;
    }
    any.then_some(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

/// One validated internal exclusive-lock holder, selected from an ordered map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedLockHolder {
    /// Original locker identity, cookie, address and description.
    holder: LockHolder,
    /// Watch handle decoded from the original cookie.
    watch_handle: u64,
}

impl ManagedLockHolder {
    /// Original class locker tuple, retained for revalidation and exact break.
    pub fn holder(&self) -> &LockHolder {
        &self.holder
    }

    /// Watch identity decoded from the selected cookie.
    pub fn watch_handle(&self) -> u64 {
        self.watch_handle
    }

    /// Legacy socket address and nonce used by the public owner-list API.
    pub fn legacy_address(&self) -> String {
        self.holder
            .legacy_address()
            .expect("validated managed address family")
    }
}

/// Failure to obtain an internal exclusive-lock holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagedHolderError {
    /// Invalid class reply.
    Report(HolderReportError),
    /// The class reply contains no holder, regardless of stored type and tag.
    Missing,
    /// Shared/external lock, invalid cookie or unspecified address.
    Foreign,
}

/// Select and validate the first ordered holder for an exclusive request.
///
/// Only the opposing SHARED kind is rejected. Later map entries do not
/// replace an invalid first holder, and a valid map may contain several.
pub fn decode_managed_holder(reply: &[u8]) -> Result<ManagedLockHolder, ManagedHolderError> {
    let info = decode_info(reply).map_err(ManagedHolderError::Report)?;
    let first = info.entries().next().ok_or(ManagedHolderError::Missing)?;
    if info.tag() != WATCHER_LOCK_TAG.as_bytes()
        || info.stored_kind() == rustyrados::LockKind::Shared as u8
    {
        return Err(ManagedHolderError::Foreign);
    }
    let watch_handle = watch_handle(first.cookie).ok_or(ManagedHolderError::Foreign)?;
    let address = first.address;
    let nonblank = address.ipv4().is_some_and(|ip| ip != [0; 4])
        || address.ipv6().is_some_and(|ip| ip != [0; 16]);
    if !nonblank {
        return Err(ManagedHolderError::Foreign);
    }
    Ok(ManagedLockHolder {
        holder: LockHolder {
            entity: first.locker,
            cookie: first.cookie.to_vec(),
            address,
            description: first.description.to_vec(),
        },
        watch_handle,
    })
}

/// The decision taken after the liveness probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Takeover {
    /// No holder holds the lock.
    Free,
    /// The holder still watches the header object. The lock stays.
    Alive,
    /// The holder is gone. The lock can be broken.
    Stale,
    /// The lock is not a watcher-bound lock of the pinned reference. It
    /// belongs to another mechanism and must not be broken.
    Foreign,
}

/// Decide whether the lock of one holder can be broken.
///
/// The pinned reference compares the watch handle of the lock cookie with
/// the cookies of the watchers of the header object and compares the
/// address of the holder with the address of that watcher. A holder without
/// a matching watcher is gone.
pub fn decide(holder: &LockHolder, watchers: &[WatchItem]) -> Takeover {
    let Some(handle) = watch_handle(&holder.cookie) else {
        return Takeover::Foreign;
    };
    for watcher in watchers {
        if watcher.cookie != handle {
            continue;
        }
        if same_address(&holder.address, &watcher.addr) {
            return Takeover::Alive;
        }
    }
    Takeover::Stale
}

/// Compare the address of a holder with the address of a watcher.
///
/// The pinned reference compares the legacy address strings for the length
/// of the watcher string, so a holder that reports a more specific address
/// than the watcher still matches.
fn same_address(holder: &EntityAddr, watcher: &EntityAddr) -> bool {
    // A complete legacy socket address plus nonce fits in the provider's
    // 256-byte watch address. Compare its fields without transport prefixes
    // or allocating rendered strings. Unknown address families cannot prove
    // that a managed locker is alive.
    if holder.port() != watcher.port() || holder.nonce != watcher.nonce {
        return false;
    }
    match (holder.ipv4(), watcher.ipv4()) {
        (Some(left), Some(right)) => left == right,
        (None, None) => match (holder.ipv6(), watcher.ipv6()) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        },
        _ => false,
    }
}

/// Build the read request that reports the holders of the header lock.
///
/// The reply is the class `get_info` result of the pinned reference.
pub fn holders_request(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
) -> Result<CompoundRequest, crate::QueryError> {
    let target = header_target(pool, namespace, image_id)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: rustyrados::RequestContext::default(),
        operations: vec![opwire::OsdOp::call(
            b"lock",
            b"get_info",
            &crate::lock_wire::info(),
        )],
        max_output_bytes: crate::metadata_query::MAX_OBJECT_NAME_BYTES as u32,
    })
}

/// Build the read request that lists the watchers of the header object.
///
/// The reply holds one record per watcher with the entity, the watch cookie
/// and the address of the watcher.
pub fn watchers_request(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
) -> Result<CompoundRequest, crate::QueryError> {
    let target = header_target(pool, namespace, image_id)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: rustyrados::RequestContext::default(),
        operations: vec![opwire::OsdOp::list_watchers()],
        max_output_bytes: crate::metadata_query::MAX_OBJECT_NAME_BYTES as u32,
    })
}

/// Build the write request that breaks the lock of one holder.
///
/// The request names the holder, so the class operation only breaks that
/// one lock entry.
pub fn break_request(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
    holder: &LockHolder,
) -> Result<CompoundRequest, crate::QueryError> {
    let target = header_target(pool, namespace, image_id)?;
    let input = crate::lock_wire::break_lock(&holder.cookie, &holder.entity)
        .map_err(|_| crate::QueryError::InvalidTarget)?;
    Ok(CompoundRequest {
        target,
        access: Access::ReadWrite,
        context: rustyrados::RequestContext::default(),
        operations: vec![opwire::OsdOp::call(b"lock", b"break_lock", &input)],
        max_output_bytes: 0,
    })
}

/// Decode the reply of the watcher list request.
pub fn decode_watchers(reply: &[u8]) -> Result<Vec<WatchItem>, HolderReportError> {
    let response = denc::from_slice::<opwire::ObjListWatchResponse>(reply)
        .map_err(|_| HolderReportError::Malformed)?;
    Ok(response.entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::Encode;
    use denc::types::EntityName;
    use opwire::WatchItem;

    fn holder(cookie: &str, address: EntityAddr) -> LockHolder {
        LockHolder {
            entity: EntityName::client(7),
            cookie: cookie.as_bytes().to_vec(),
            address,
            description: Vec::new(),
        }
    }

    fn watcher(cookie: u64, address: EntityAddr) -> WatchItem {
        WatchItem {
            name: EntityName::client(7),
            cookie,
            timeout_s: 0,
            addr: address,
        }
    }

    #[test]
    fn a_watcher_bound_cookie_carries_the_watch_handle() {
        assert_eq!(watch_handle(b"auto 42"), Some(42));
        assert_eq!(watch_handle(b"watcher 42"), None);
        assert_eq!(watch_handle(b"auto"), None);
        assert_eq!(watch_handle(b"auto fourty-two"), None);
    }

    #[test]
    fn a_live_holder_keeps_the_lock() {
        let address = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 0, 0, 1], 3300);
        let holder = holder("auto 42", address);
        assert_eq!(decide(&holder, &[watcher(42, address)]), Takeover::Alive);
    }

    #[test]
    fn watcher_transport_prefix_does_not_change_legacy_address_identity() {
        let v4 = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 0, 0, 1], 3300);
        let v6 = EntityAddr::v6(EntityAddr::TYPE_MSGR2, 5, [1; 16], 3300, 0);
        for address in [v4, v6] {
            let mut legacy = address;
            legacy.ty = EntityAddr::TYPE_LEGACY;
            for (owner, observed) in [(address, legacy), (legacy, address)] {
                assert_eq!(
                    decide(&holder("auto 42", owner), &[watcher(42, observed)]),
                    Takeover::Alive
                );
            }
        }
    }

    #[test]
    fn legacy_address_identity_keeps_port_nonce_and_address_family() {
        let address = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 0, 0, 1], 3300);
        let owner = holder("auto 42", address);
        for observed in [
            EntityAddr::v4(EntityAddr::TYPE_LEGACY, 6, [10, 0, 0, 1], 3300),
            EntityAddr::v4(EntityAddr::TYPE_LEGACY, 5, [10, 0, 0, 1], 3301),
            EntityAddr::v6(EntityAddr::TYPE_LEGACY, 5, [1; 16], 3300, 0),
            EntityAddr::blank(),
        ] {
            assert_eq!(decide(&owner, &[watcher(42, observed)]), Takeover::Stale);
        }
    }

    #[test]
    fn a_gone_holder_loses_the_lock() {
        let address = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 0, 0, 1], 3300);
        let holder = holder("auto 42", address);
        assert_eq!(decide(&holder, &[]), Takeover::Stale);
        let other = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 6, [10, 0, 0, 2], 3300);
        assert_eq!(decide(&holder, &[watcher(42, other)]), Takeover::Stale);
        assert_eq!(decide(&holder, &[watcher(43, address)]), Takeover::Stale);
    }

    #[test]
    fn a_foreign_cookie_is_never_broken() {
        let address = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 0, 0, 1], 3300);
        let holder = holder("operator 42", address);
        assert_eq!(decide(&holder, &[]), Takeover::Foreign);
    }

    #[test]
    fn a_free_lock_has_no_holder() {
        assert!(decode_holders(&[]).is_err());
    }

    fn holder_reply(cookie: &str, address: EntityAddr) -> Vec<u8> {
        info_reply(&[holder(cookie, address)], 1, b"internal")
    }

    fn info_reply(holders: &[LockHolder], kind: u8, tag: &[u8]) -> Vec<u8> {
        let mut encoder = denc::Encoder::with_capacity(128);
        encoder
            .versioned(1, 1, |e| {
                e.count(holders.len())?;
                for holder in holders {
                    e.versioned(1, 1, |e| {
                        holder.entity.encode(e)?;
                        e.bytes(&holder.cookie)
                    })?;
                    e.versioned(1, 1, |e| {
                        denc::types::UTime::new(0, 0).encode(e)?;
                        holder.address.encode(e)?;
                        e.bytes(&holder.description)
                    })?;
                }
                e.u8(kind)?;
                e.bytes(tag)
            })
            .expect("lock info reply");
        encoder.into_vec()
    }

    #[test]
    fn formatted_cookie_extraction_accepts_whitespace_sign_and_trailing_bytes() {
        for cookie in [
            b" auto\t42tail".as_slice(),
            b"\x0bauto\x0c+42\xff",
            b"auto 00042",
        ] {
            assert_eq!(watch_handle(cookie), Some(42));
        }
        assert_eq!(watch_handle(b"auto 0"), Some(0));
        assert_eq!(watch_handle(b"auto 18446744073709551615"), Some(u64::MAX));
        assert_eq!(watch_handle(b"auto -1"), Some(u64::MAX));
        assert_eq!(watch_handle(b"auto -18446744073709551615"), Some(1));
        for cookie in [
            b"auto 18446744073709551616".as_slice(),
            b"auto -18446744073709551616",
            b"auto +",
            b"auto -",
            b"auto42",
            b"auto \xff42",
            b"auto\0 42",
        ] {
            assert_eq!(watch_handle(cookie), None, "{cookie:?}");
        }
    }

    #[test]
    fn managed_holder_validates_first_entry_and_preserves_original_tuple() {
        let address = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 0, 0, 1], 0);
        let mut first = holder(" auto\t42tail", address);
        first.description = b"first description".to_vec();
        let mut second = holder("operator", address);
        second.entity = EntityName::client(8);
        for kind in [1, 3, 0, 255] {
            let selected = decode_managed_holder(&info_reply(
                &[first.clone(), second.clone()],
                kind,
                b"internal",
            ))
            .expect("first managed holder");
            assert_eq!(selected.holder(), &first);
            assert_eq!(selected.watch_handle(), 42);
            assert_eq!(selected.legacy_address(), "10.0.0.1:0/5");
        }
        assert_eq!(
            decode_managed_holder(&info_reply(&[second], 1, b"internal")),
            Err(ManagedHolderError::Foreign)
        );
    }

    #[test]
    fn managed_holder_empty_map_precedes_type_and_tag_validation() {
        assert_eq!(
            decode_managed_holder(&info_reply(&[], 2, b"external")),
            Err(ManagedHolderError::Missing)
        );
        assert!(matches!(
            decode_managed_holder(b""),
            Err(ManagedHolderError::Report(_))
        ));
    }

    #[test]
    fn managed_holder_rejects_external_shared_and_unspecified_ip() {
        let address = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 0, 0, 1], 3300);
        for (kind, tag) in [
            (1, b"external".as_slice()),
            (2, b"internal"),
            (1, b"internal\0"),
        ] {
            assert_eq!(
                decode_managed_holder(&info_reply(&[holder("auto 42", address)], kind, tag)),
                Err(ManagedHolderError::Foreign)
            );
        }
        for address in [
            EntityAddr::blank(),
            EntityAddr::v4(1, 5, [0; 4], 3300),
            EntityAddr::v6(2, 5, [0; 16], 3300, 0),
        ] {
            assert_eq!(
                decode_managed_holder(&holder_reply("auto 42", address)),
                Err(ManagedHolderError::Foreign)
            );
        }
        let selected =
            decode_managed_holder(&holder_reply("auto 0", EntityAddr::v6(2, 5, [1; 16], 0, 0)))
                .expect("nonblank IPv6 with port0");
        assert_eq!(selected.watch_handle(), 0);
        assert_eq!(
            selected.legacy_address(),
            "[101:101:101:101:101:101:101:101]:0/5"
        );
    }

    #[test]
    fn the_holder_report_names_the_holder() {
        let address = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 0, 0, 1], 3300);
        let holders = decode_holders(&holder_reply("auto 42", address)).expect("holders");
        assert_eq!(holders.len(), 1);
        assert_eq!(holders[0].entity, EntityName::client(7));
        assert_eq!(holders[0].cookie, b"auto 42");
        assert_eq!(holders[0].address, address);
    }

    #[test]
    fn the_requests_address_the_header_lock() {
        let holders = holders_request(7, b"ns".to_vec(), b"image1").expect("holders request");
        assert_eq!(holders.operations.len(), 1);
        assert_eq!(holders.operations[0].op, opwire::op::CALL);
        let watchers = watchers_request(7, b"ns".to_vec(), b"image1").expect("watchers request");
        assert_eq!(watchers.operations[0].op, opwire::op::LIST_WATCHERS);
        let holder = LockHolder {
            entity: EntityName::client(7),
            cookie: b"auto 42".to_vec(),
            address: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 0, 0, 1], 3300),
            description: Vec::new(),
        };
        let broken = break_request(7, b"ns".to_vec(), b"image1", &holder).expect("break request");
        assert_eq!(broken.operations[0].op, opwire::op::CALL);
        assert_eq!(broken.access, Access::ReadWrite);
    }

    #[test]
    fn the_watcher_reply_decodes_to_watch_items() {
        let item = WatchItem {
            name: EntityName::client(7),
            cookie: 42,
            timeout_s: 0,
            addr: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 0, 0, 1], 3300),
        };
        let reply = denc::to_vec(&opwire::ObjListWatchResponse {
            entries: vec![item.clone()],
        })
        .expect("watcher reply");
        let decoded = decode_watchers(&reply).expect("watchers");
        assert_eq!(decoded, vec![item]);
    }
}
