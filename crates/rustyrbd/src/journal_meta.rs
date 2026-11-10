// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Journal header geometry and `cls_journal` method input encodings.
//!
//! Geometry validation follows the owner-open contract (spec
//! `doc/spec/rustyrbd/ffi-journal-io.md`): a malformed geometry reply is
//! `-EBADMSG` at the caller. The encoders produce the unenveloped class
//! inputs of `doc/spec/cls_journal.md` section 1 (plain concatenated
//! fields, little-endian ints, `u32` length + bytes for strings and
//! bufferlists); the no-arg methods (`get_order`, `get_splay_width`,
//! `get_pool_id`, `get_minimum_set`, `get_active_set`, `get_next_tag_tid`)
//! take empty input.

use crate::JournalObjectPosition;
use crate::journal_client::encode_positions;
use denc::{Error, Result};

/// `TAG_CLASS_NEW`: passed to `tag_create` to let the class allocate a class.
pub const JOURNAL_TAG_CLASS_NEW: u64 = u64::MAX;

/// Header geometry returned by the journal class getters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalGeometry {
    /// Object order; the soft data-object size is `1 << order` bytes.
    pub order: u8,
    /// Data objects per set.
    pub splay_width: u8,
    /// Journal data pool; -1 selects the metadata pool.
    pub pool_id: i64,
    /// The first set not yet fully removed.
    pub minimum_set: u64,
    /// The current, inclusive append set.
    pub active_set: u64,
}

impl JournalGeometry {
    /// Validate the geometry: order in the effective create range 12..=26,
    /// nonzero splay width, `minimum_set <= active_set`, and the final
    /// object of the active set representable as `u64`.
    pub fn validate(&self) -> Result<()> {
        if !(12..=26).contains(&self.order)
            || self.splay_width == 0
            || self.minimum_set > self.active_set
        {
            return Err(Error::BadValue("journal geometry"));
        }
        self.last_object().map(|_| ())
    }

    /// The highest data object number of the active set.
    pub fn last_object(&self) -> Result<u64> {
        set_object_end(self.active_set, self.splay_width)
    }

    /// The data object number of one set and splay:
    /// `set * splay_width + splay`.
    pub fn object_number(&self, set: u64, splay: u64) -> Result<u64> {
        let width = u64::from(self.splay_width);
        if width == 0 || splay >= width {
            return Err(Error::BadValue("journal splay"));
        }
        set.checked_mul(width)
            .and_then(|base| base.checked_add(splay))
            .ok_or(Error::TooLong)
    }

    /// Validate commit positions: at most one per splay stream, no repeated
    /// object-number remainder, and every object at or below the final
    /// object of the active set.
    pub fn validate_positions(&self, positions: &[JournalObjectPosition]) -> Result<()> {
        let width = u64::from(self.splay_width);
        if width == 0 || positions.len() > width as usize {
            return Err(Error::BadValue("journal commit positions"));
        }
        let last_object = self.last_object()?;
        let mut seen = vec![false; width as usize];
        for position in positions {
            let splay = (position.object_number % width) as usize;
            if position.object_number > last_object || seen[splay] {
                return Err(Error::BadValue("journal commit positions"));
            }
            seen[splay] = true;
        }
        Ok(())
    }
}

fn set_object_end(set: u64, splay_width: u8) -> Result<u64> {
    let width = u64::from(splay_width);
    set.checked_mul(width)
        .and_then(|first| first.checked_add(width - 1))
        .ok_or(Error::BadValue("journal geometry"))
}

/// `journal.create` input: order, splay width, pool ID.
pub fn journal_create_input(order: u8, splay_width: u8, pool_id: i64) -> Vec<u8> {
    let mut input = Vec::with_capacity(10);
    input.push(order);
    input.push(splay_width);
    input.extend_from_slice(&pool_id.to_le_bytes());
    input
}

/// `journal.set_minimum_set` input: the set number.
pub fn journal_set_minimum_set_input(set: u64) -> Vec<u8> {
    set.to_le_bytes().to_vec()
}

/// `journal.set_active_set` input: the set number.
pub fn journal_set_active_set_input(set: u64) -> Vec<u8> {
    set.to_le_bytes().to_vec()
}

/// `journal.get_client` input: the client ID string.
pub fn journal_get_client_input(id: &[u8]) -> Result<Vec<u8>> {
    enc_string(id)
}

/// `journal.client_register` input: client ID and ClientData bufferlist.
pub fn journal_client_register_input(id: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    id_and_string(id, data)
}

/// `journal.client_update_data` input: client ID and ClientData bufferlist.
pub fn journal_client_update_data_input(id: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    id_and_string(id, data)
}

/// `journal.client_update_state` input: client ID and state byte.
pub fn journal_client_update_state_input(id: &[u8], state: u8) -> Result<Vec<u8>> {
    let mut input = enc_string(id)?;
    input.push(state);
    Ok(input)
}

/// `journal.client_unregister` input: the client ID string.
pub fn journal_client_unregister_input(id: &[u8]) -> Result<Vec<u8>> {
    enc_string(id)
}

/// `journal.client_commit` input: client ID and ObjectSetPosition.
pub fn journal_client_commit_input(
    id: &[u8],
    positions: &[JournalObjectPosition],
) -> Result<Vec<u8>> {
    let mut input = enc_string(id)?;
    input.extend_from_slice(&encode_positions(positions)?);
    Ok(input)
}

/// `journal.client_list` input: start cursor and page size.
pub fn journal_client_list_input(start_after: &[u8], max_return: u64) -> Result<Vec<u8>> {
    let mut input = enc_string(start_after)?;
    input.extend_from_slice(&max_return.to_le_bytes());
    Ok(input)
}

/// `journal.get_tag` input: the tag TID.
pub fn journal_get_tag_input(tid: u64) -> Vec<u8> {
    tid.to_le_bytes().to_vec()
}

/// `journal.tag_create` input: TID, tag class, TagData bufferlist.
pub fn journal_tag_create_input(tid: u64, tag_class: u64, data: &[u8]) -> Result<Vec<u8>> {
    let mut input = Vec::with_capacity(16 + data.len());
    input.extend_from_slice(&tid.to_le_bytes());
    input.extend_from_slice(&tag_class.to_le_bytes());
    append_string(&mut input, data)?;
    Ok(input)
}

/// `journal.tag_list` input: cursor, page size, client ID, and optional tag
/// class filter (`optional<u64>`: presence byte + value).
pub fn journal_tag_list_input(
    start_after_tid: u64,
    max_return: u64,
    client_id: &[u8],
    tag_class: Option<u64>,
) -> Result<Vec<u8>> {
    let mut input = Vec::with_capacity(16 + client_id.len() + 9);
    input.extend_from_slice(&start_after_tid.to_le_bytes());
    input.extend_from_slice(&max_return.to_le_bytes());
    append_string(&mut input, client_id)?;
    input.push(u8::from(tag_class.is_some()));
    if let Some(tag_class) = tag_class {
        input.extend_from_slice(&tag_class.to_le_bytes());
    }
    Ok(input)
}

/// `journal.guard_append` input: the soft object-size limit.
pub fn journal_guard_append_input(soft_max_size: u64) -> Vec<u8> {
    soft_max_size.to_le_bytes().to_vec()
}

/// `journal.append` input: soft object-size limit and unframed payload.
pub fn journal_append_input(soft_max_size: u64, data: &[u8]) -> Result<Vec<u8>> {
    let capacity = 12usize.checked_add(data.len()).ok_or(Error::TooLong)?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(capacity)
        .map_err(|_| Error::NoSpace)?;
    input.extend_from_slice(&soft_max_size.to_le_bytes());
    append_string(&mut input, data)?;
    Ok(input)
}

fn enc_string(value: &[u8]) -> Result<Vec<u8>> {
    let mut input = Vec::with_capacity(4 + value.len());
    append_string(&mut input, value)?;
    Ok(input)
}

fn id_and_string(id: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut input = enc_string(id)?;
    append_string(&mut input, value)?;
    Ok(input)
}

fn append_string(input: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    input.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| Error::TooLong)?
            .to_le_bytes(),
    );
    input.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::Error;

    fn make_geometry(order: u8, width: u8, minimum: u64, active: u64) -> JournalGeometry {
        JournalGeometry {
            order,
            splay_width: width,
            pool_id: -1,
            minimum_set: minimum,
            active_set: active,
        }
    }

    fn position(object: u64, tag: u64, entry: u64) -> JournalObjectPosition {
        JournalObjectPosition {
            object_number: object,
            tag_tid: tag,
            entry_tid: entry,
        }
    }

    #[test]
    fn geometry_validate_accepts_the_effective_create_range() {
        assert_eq!(make_geometry(12, 1, 0, 0).validate(), Ok(()));
        assert_eq!(make_geometry(26, 4, 2, 7).validate(), Ok(()));
        for bad in [
            make_geometry(11, 1, 0, 0),
            make_geometry(27, 1, 0, 0),
            make_geometry(12, 0, 0, 0),
            make_geometry(12, 1, 2, 1),
            make_geometry(12, 2, u64::MAX, u64::MAX),
        ] {
            assert_eq!(bad.validate(), Err(Error::BadValue("journal geometry")));
        }
    }

    #[test]
    fn geometry_object_number_uses_set_times_width_plus_splay() {
        let geometry = make_geometry(24, 4, 0, 2);
        assert_eq!(geometry.object_number(0, 0), Ok(0));
        assert_eq!(geometry.object_number(2, 1), Ok(9));
        assert_eq!(
            geometry.object_number(0, 4),
            Err(Error::BadValue("journal splay"))
        );
        assert_eq!(geometry.object_number(u64::MAX, 0), Err(Error::TooLong));
        assert_eq!(
            make_geometry(24, 0, 0, 0).object_number(0, 0),
            Err(Error::BadValue("journal splay"))
        );
    }

    #[test]
    fn geometry_validates_commit_positions_against_the_active_set() {
        let geometry = make_geometry(24, 2, 0, 4);
        assert_eq!(
            geometry.validate_positions(&[position(8, 2, 3), position(9, 2, 4)]),
            Ok(())
        );
        assert_eq!(
            geometry.validate_positions(&[position(10, 2, 3)]),
            Err(Error::BadValue("journal commit positions"))
        );
        assert_eq!(
            geometry.validate_positions(&[position(8, 2, 3), position(6, 2, 4)]),
            Err(Error::BadValue("journal commit positions"))
        );
        assert_eq!(
            geometry.validate_positions(&[
                position(8, 2, 3),
                position(9, 2, 4),
                position(10, 2, 5)
            ]),
            Err(Error::BadValue("journal commit positions"))
        );
        assert_eq!(
            make_geometry(24, 0, 0, 0).validate_positions(&[]),
            Err(Error::BadValue("journal commit positions"))
        );
        assert_eq!(
            make_geometry(24, 2, u64::MAX, u64::MAX).validate_positions(&[]),
            Err(Error::BadValue("journal geometry"))
        );
    }

    #[test]
    fn create_input_encodes_order_width_and_pool() {
        let mut expected = vec![24u8, 4];
        expected.extend_from_slice(&(-1i64).to_le_bytes());
        assert_eq!(journal_create_input(24, 4, -1), expected);
        assert_eq!(journal_create_input(12, 1, 7)[2..], 7i64.to_le_bytes());
    }

    #[test]
    fn set_and_guard_inputs_encode_the_plain_scalar() {
        assert_eq!(
            journal_set_minimum_set_input(9),
            9u64.to_le_bytes().to_vec()
        );
        assert_eq!(journal_set_active_set_input(9), 9u64.to_le_bytes().to_vec());
        assert_eq!(journal_get_tag_input(9), 9u64.to_le_bytes().to_vec());
        assert_eq!(
            journal_guard_append_input(1 << 24),
            (1u64 << 24).to_le_bytes().to_vec()
        );
    }

    #[test]
    fn string_inputs_encode_the_length_prefixed_id() {
        assert_eq!(
            journal_get_client_input(b"").unwrap(),
            0u32.to_le_bytes().to_vec()
        );
        assert_eq!(
            journal_client_unregister_input(b"peer").unwrap(),
            [4u32.to_le_bytes().as_slice(), b"peer".as_slice()].concat()
        );
        assert_eq!(
            journal_client_update_state_input(b"peer", 1).unwrap(),
            [
                4u32.to_le_bytes().as_slice(),
                b"peer".as_slice(),
                &[1u8][..]
            ]
            .concat()
        );
    }

    #[test]
    fn register_and_update_data_inputs_encode_id_and_bufferlist() {
        let data = [7u8; 3];
        let expected = [
            0u32.to_le_bytes().as_slice(),
            3u32.to_le_bytes().as_slice(),
            data.as_slice(),
        ]
        .concat();
        assert_eq!(journal_client_register_input(b"", &data).unwrap(), expected);
        assert_eq!(
            journal_client_update_data_input(b"", &data).unwrap(),
            expected
        );
    }

    #[test]
    fn client_list_input_encodes_cursor_and_page_size() {
        assert_eq!(
            journal_client_list_input(b"after", 256).unwrap(),
            [
                5u32.to_le_bytes().as_slice(),
                b"after".as_slice(),
                256u64.to_le_bytes().as_slice()
            ]
            .concat()
        );
    }

    #[test]
    fn tag_create_input_encodes_tid_class_and_data() {
        let data = b"tag-data";
        assert_eq!(
            journal_tag_create_input(3, JOURNAL_TAG_CLASS_NEW, data).unwrap(),
            [
                3u64.to_le_bytes().as_slice(),
                JOURNAL_TAG_CLASS_NEW.to_le_bytes().as_slice(),
                8u32.to_le_bytes().as_slice(),
                data.as_slice(),
            ]
            .concat()
        );
    }

    #[test]
    fn tag_list_input_covers_the_optional_class_filter() {
        assert_eq!(
            journal_tag_list_input(7, 64, b"", None).unwrap(),
            [
                7u64.to_le_bytes().as_slice(),
                64u64.to_le_bytes().as_slice(),
                0u32.to_le_bytes().as_slice(),
                &[0u8][..],
            ]
            .concat()
        );
        assert_eq!(
            journal_tag_list_input(7, 64, b"", Some(4)).unwrap(),
            [
                7u64.to_le_bytes().as_slice(),
                64u64.to_le_bytes().as_slice(),
                0u32.to_le_bytes().as_slice(),
                &[1u8][..],
                4u64.to_le_bytes().as_slice(),
            ]
            .concat()
        );
    }

    #[test]
    fn append_input_encodes_soft_limit_and_bufferlist() {
        assert_eq!(
            journal_append_input(4096, b"entry").unwrap(),
            [
                4096u64.to_le_bytes().as_slice(),
                5u32.to_le_bytes().as_slice(),
                b"entry".as_slice()
            ]
            .concat()
        );
    }

    #[test]
    fn client_commit_input_encodes_id_and_positions_frame() {
        let input =
            journal_client_commit_input(b"", &[position(1, 1, 1), position(0, 1, 0)]).unwrap();
        assert_eq!(&input[..10], &[0u8, 0, 0, 0, 1, 1, 64, 0, 0, 0]);
        assert_eq!(&input[10..14], &2u32.to_le_bytes());
        let decoded = crate::journal_client::decode_positions(&input[4..]).unwrap();
        assert_eq!(decoded, vec![position(1, 1, 1), position(0, 1, 0)]);
    }
}
