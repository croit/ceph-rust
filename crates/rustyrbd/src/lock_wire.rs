// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Pinned Ceph 21.2.0 `cls_lock` requests for RBD metadata owners. The wire
//! codec is the shared [`cls_lock`] crate; this module owns the RBD lock
//! identity (name, tag, cookie) and its length preflight.

use cls_lock::Request;
use denc::types::EntityName;

/// The cookie prefix of a watcher-bound lock of the pinned reference.
pub const WATCHER_COOKIE_PREFIX: &str = "auto";

/// The tag of a watcher-bound lock of the pinned reference.
pub const WATCHER_LOCK_TAG: &str = "internal";

/// The name of the lock of the image head object.
pub const LOCK_NAME: &[u8] = b"rbd_lock";

const LOCK_TAG: &[u8] = WATCHER_LOCK_TAG.as_bytes();
const EXCLUSIVE: u8 = 1;

/// Encode one request; an over-long field or envelope is `TooLong`.
fn encode(request: Request<'_>) -> denc::Result<Vec<u8>> {
    request.encode().map_err(|_| denc::Error::TooLong)
}

/// Validate the enclosing body as well as the cookie's string field before
/// copying the cookie. A field that fits u32 can still overflow its envelope.
/// `fixed_body_length` includes the cookie's own u32 length prefix.
fn checked_cookie_length(cookie_length: usize, fixed_body_length: usize) -> denc::Result<()> {
    let body_length = cookie_length
        .checked_add(fixed_body_length)
        .ok_or(denc::Error::TooLong)?;
    cls_lock::check_envelope_body(body_length)
        .map(|_| ())
        .map_err(|_| denc::Error::TooLong)
}

fn lock(
    name: &[u8],
    kind: u8,
    cookie: &[u8],
    tag: &[u8],
    description: &[u8],
    duration: (u32, u32),
    flags: u8,
) -> Vec<u8> {
    encode(Request::Lock {
        name,
        kind,
        cookie,
        tag,
        description,
        duration_sec: duration.0,
        duration_nsec: duration.1,
        flags,
    })
    .expect("the caller bounded the lock fields")
}

fn unlock(cookie: &[u8]) -> Vec<u8> {
    encode(Request::Unlock {
        name: LOCK_NAME,
        cookie,
    })
    .expect("the caller bounded the cookie")
}

fn assert_owned(cookie: &[u8], tag: &[u8]) -> Vec<u8> {
    encode(Request::Assert {
        name: LOCK_NAME,
        kind: EXCLUSIVE,
        cookie,
        tag,
    })
    .expect("the caller bounded the cookie")
}

/// Request the holders of the lock without changing it.
pub fn info() -> Vec<u8> {
    encode(Request::GetInfo { name: LOCK_NAME }).expect("the lock name is fixed")
}

/// Break the lock of one holder.
///
/// The pinned reference names the holder by its authenticated entity and
/// repeats the cookie of the lock entry, so the class operation only breaks
/// that one entry.
pub fn break_lock(cookie: &[u8], locker: &EntityName) -> denc::Result<Vec<u8>> {
    checked_cookie_length(cookie.len(), 4 + LOCK_NAME.len() + 9 + 4)?;
    encode(Request::Break {
        name: LOCK_NAME,
        locker: *locker,
        cookie,
    })
}

/// Wire inputs bound to one owned header-watch cookie. The cookie is an
/// opaque watch identity; changing it requires Ceph's `set_cookie` handoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderLockWire {
    cookie: Vec<u8>,
}

impl HeaderLockWire {
    /// Derive Ceph's internal lock cookie from the registered watch handle.
    pub fn new(watch_cookie: u64) -> Self {
        Self {
            cookie: format!("{WATCHER_COOKIE_PREFIX} {watch_cookie}").into_bytes(),
        }
    }

    /// Opaque cookie encoded from the registration used for this request.
    pub fn cookie(&self) -> &[u8] {
        &self.cookie
    }

    /// Build a header assertion from a stored managed cookie, including the
    /// initial empty cookie. This probes remote state without granting a lease.
    /// A cookie that cannot be encoded is rejected, never truncated.
    pub fn assert_cookie(cookie: &[u8]) -> denc::Result<Vec<u8>> {
        checked_cookie_length(
            cookie.len(),
            4 + LOCK_NAME.len() + 1 + 4 + 4 + LOCK_TAG.len(),
        )?;
        Ok(assert_owned(cookie, LOCK_TAG))
    }

    /// Build a `break_lock` request for an entity name.
    ///
    /// The entity type and number are encoded by the same DENC path used by
    /// the pinned `entity_name_t`; callers must validate the textual entity
    /// name before calling this method.
    pub fn break_lock_input(
        cookie: &[u8],
        entity_type: u8,
        entity_num: i64,
    ) -> denc::Result<Vec<u8>> {
        break_lock(cookie, &EntityName::new(entity_type, entity_num))
    }

    /// Request the exclusive header lock without renewal or expiration.
    pub fn acquire(&self) -> Vec<u8> {
        lock(LOCK_NAME, EXCLUSIVE, &self.cookie, LOCK_TAG, b"", (0, 0), 0)
    }

    /// Atomically replace this owner's opaque cookie while preserving the
    /// authenticated locker, exclusive type and internal RBD tag.
    pub fn set_cookie(&self, watch_cookie: u64) -> Vec<u8> {
        let replacement = Self::new(watch_cookie);
        encode(Request::SetCookie {
            name: LOCK_NAME,
            kind: EXCLUSIVE,
            cookie: &self.cookie,
            tag: LOCK_TAG,
            new_cookie: &replacement.cookie,
        })
        .expect("watch cookies are bounded")
    }

    /// Release only this watch owner's lock entry.
    pub fn release(&self) -> Vec<u8> {
        unlock(&self.cookie)
    }

    /// Assert this owner while building an atomic metadata operation.
    pub fn assert_owned(&self) -> Vec<u8> {
        assert_owned(&self.cookie, LOCK_TAG)
    }
}

/// The head object-map lock uses an empty cookie and tag, independently of
/// the header-watch lock. It belongs to the authenticated RADOS entity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectMapLockWire;

impl ObjectMapLockWire {
    /// Acquire the map lock without renewal or expiration.
    pub fn acquire(self) -> Vec<u8> {
        lock(LOCK_NAME, EXCLUSIVE, b"", b"", b"", (0, 0), 0)
    }

    /// Release this entity's empty-cookie map lock.
    pub fn release(self) -> Vec<u8> {
        unlock(b"")
    }

    /// Assert ownership as the first operation of an atomic map mutation.
    pub fn assert_owned(self) -> Vec<u8> {
        assert_owned(b"", b"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_replacement_preserves_owner_and_lock_identity_in_own_vector() {
        let wire = HeaderLockWire::new(42);
        let mut expected = vec![1, 1, 47, 0, 0, 0];
        expected.extend_from_slice(
            b"\x08\0\0\0rbd_lock\x01\x07\0\0\0auto 42\x08\0\0\0internal\x07\0\0\0auto 99",
        );
        assert_eq!(wire.set_cookie(99), expected);
        assert_eq!(wire, HeaderLockWire::new(42));
    }

    #[test]
    fn lock_envelope_matches_pinned_dencoder_vector() {
        let encoded = lock(b"name", 2, b"cookie", b"tag", b"description", (5, 0), 1);
        assert_eq!(
            encoded.as_slice(),
            include_bytes!("../../../testdata/cls/dencoder/cls_lock_lock_op/1.bin")
        );
    }

    #[test]
    fn break_lock_uses_the_pinned_entity_name_encoding() {
        let input = HeaderLockWire::break_lock_input(b"cookie", 0x08, 0).unwrap();
        assert_eq!(input.len(), 6 + 12 + 9 + 4 + 6);
        assert_eq!(&input[..6], &[1, 1, 31, 0, 0, 0]);
        assert_eq!(&input[6..10], &8u32.to_le_bytes());
        assert_eq!(&input[10..18], b"rbd_lock");
        assert_eq!(input[18], 0x08);
        assert_eq!(&input[19..27], &0i64.to_le_bytes());
        assert_eq!(&input[27..31], &6u32.to_le_bytes());
        assert_eq!(&input[31..37], b"cookie");
    }

    #[test]
    fn cookie_fit_is_checked_at_the_wire_length_boundary() {
        let fixed = 4 + LOCK_NAME.len() + 1 + 4 + 4 + LOCK_TAG.len();
        assert_eq!(checked_cookie_length(25, fixed), Ok(()));
        assert_eq!(
            checked_cookie_length(u32::MAX as usize, fixed),
            Err(denc::Error::TooLong)
        );
        // The public constructors encode a normal cookie unchanged and keep
        // the empty probe cookie distinct from the map lock.
        assert_eq!(
            HeaderLockWire::assert_cookie(b"auto 42").unwrap(),
            HeaderLockWire::new(42).assert_owned()
        );
        assert!(HeaderLockWire::break_lock_input(b"auto 42", 0x08, 0).is_ok());
    }

    #[test]
    fn cookie_field_must_leave_room_for_the_enclosing_request() {
        // Length-only checks exercise the actual constructor preflight without
        // allocating a multi-gigabyte cookie. Both arbitrary-cookie requests
        // must fit their complete envelope, including its allocation size.
        for fixed in [
            4 + LOCK_NAME.len() + 9 + 4,
            4 + LOCK_NAME.len() + 1 + 4 + 4 + LOCK_TAG.len(),
        ] {
            let max_body = (u32::MAX as usize).min(isize::MAX as usize - 6);
            assert_eq!(checked_cookie_length(max_body - fixed, fixed), Ok(()));
            assert_eq!(
                checked_cookie_length(max_body - fixed + 1, fixed),
                Err(denc::Error::TooLong)
            );
            assert_eq!(
                checked_cookie_length(u32::MAX as usize, fixed),
                Err(denc::Error::TooLong)
            );
            assert_eq!(
                checked_cookie_length(usize::MAX, fixed),
                Err(denc::Error::TooLong)
            );
        }
    }

    #[test]
    fn header_lock_fields_follow_watch_cookie() {
        let wire = HeaderLockWire::new(42);
        let request = wire.acquire();
        assert_eq!(&request[..6], &[1, 1, 49, 0, 0, 0]);
        assert!(
            request
                .windows(b"auto 42".len())
                .any(|window| window == b"auto 42")
        );
        assert!(
            request
                .windows(LOCK_TAG.len())
                .any(|window| window == LOCK_TAG)
        );
        assert_ne!(wire.release(), wire.assert_owned());
    }

    #[test]
    fn map_lock_has_empty_cookie_and_tag() {
        let map = ObjectMapLockWire;
        let header = HeaderLockWire::new(42);
        assert_eq!(
            map.acquire().len() + b"auto 42".len() + LOCK_TAG.len(),
            header.acquire().len()
        );
        assert_eq!(
            map.assert_owned().len() + b"auto 42".len() + LOCK_TAG.len(),
            header.assert_owned().len()
        );
        assert_eq!(
            map.release().len() + b"auto 42".len(),
            header.release().len()
        );
    }

    #[test]
    fn header_probe_preserves_empty_and_attempted_cookie_identity() {
        let wire = HeaderLockWire::new(42);
        assert_eq!(wire.cookie(), b"auto 42");
        assert_eq!(
            HeaderLockWire::assert_cookie(wire.cookie()).unwrap(),
            wire.assert_owned()
        );
        let empty = HeaderLockWire::assert_cookie(b"").unwrap();
        assert_eq!(empty.len() + wire.cookie().len(), wire.assert_owned().len());
        assert_ne!(empty, ObjectMapLockWire.assert_owned());
    }
}
