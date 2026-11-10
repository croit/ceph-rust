// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Mapping of the unstriped RBD image byte stream to data objects.

use crate::{
    FEATURE_STRIPING_V2, ImageHeader, StripeGeometry, metadata_query::MAX_OBJECT_NAME_BYTES,
};

/// The pinned reference maps an image through a layout whose object size,
/// stripe unit and stripe count are 32-bit fields, so a larger value cannot
/// be mapped the way the reference maps it.
const MAX_LAYOUT_FIELD: u64 = u32::MAX as u64;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// The pinned header does not describe a usable data-object layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
    /// A u64 object size cannot be formed from the reported order.
    InvalidOrder,
    /// STRIPINGV2 requires the separately queried stripe unit and count.
    MissingStripeGeometry,
    /// Stripe geometry was supplied for a header without STRIPINGV2.
    UnexpectedStripeGeometry,
    /// Stripe unit or count cannot describe whole object stripes.
    InvalidStripeGeometry,
    /// The prefix and fixed object-number suffix exceed the OSD object-name limit.
    ObjectNameTooLong,
}

impl std::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOrder => f.write_str("invalid RBD object order"),
            Self::MissingStripeGeometry => f.write_str("RBD stripe geometry is required"),
            Self::UnexpectedStripeGeometry => f.write_str("unexpected RBD stripe geometry"),
            Self::InvalidStripeGeometry => f.write_str("invalid RBD stripe geometry"),
            Self::ObjectNameTooLong => f.write_str("RBD data-object name exceeds OSD limit"),
        }
    }
}

impl std::error::Error for LayoutError {}

/// A single contiguous part of a logical request within one data object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectExtent {
    /// Number used in the 16-digit data-object suffix.
    pub object_number: u64,
    /// Starting byte within that object.
    pub object_offset: u64,
    /// Number of logical bytes in this part.
    pub length: u64,
}

/// Complete intersection of one crypto unit and one contiguous object turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoObjectFragment {
    /// Logical image offset relative to the encrypted payload.
    pub logical_offset: u64,
    /// Full object-local range to query for allocation metadata.
    pub extent: ObjectExtent,
    /// Requested byte's offset within the returned range.
    pub skip: u64,
}

/// Immutable geometry for a v2 image, including optional STRIPINGV2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageLayout {
    image_size: u64,
    object_size: u64,
    stripe_unit: u64,
    stripe_count: u64,
    object_set_bytes: u64,
    object_prefix: Vec<u8>,
    /// Hex digits in the data-object number suffix: 16 for format 2, 12 for
    /// format 1. `write_object_name` emits exactly this many digits.
    object_number_width: u32,
}

impl ImageLayout {
    /// Construct default geometry after the header class replies have
    /// been decoded. A striped image must first query its stripe geometry.
    pub fn from_header(header: &ImageHeader) -> Result<Self, LayoutError> {
        Self::from_header_with_stripe(header, None)
    }

    /// Construct both default and STRIPINGV2 geometry from one coherent
    /// header observation and its conditional stripe getter.
    pub fn from_header_with_stripe(
        header: &ImageHeader,
        stripe: Option<StripeGeometry>,
    ) -> Result<Self, LayoutError> {
        // An object order of 64 or more has no u64 object size, and a size
        // above the layout field cannot be mapped like the reference does.
        let object_size = 1u64
            .checked_shl(u32::from(header.order))
            .filter(|size| *size <= MAX_LAYOUT_FIELD)
            .ok_or(LayoutError::InvalidOrder)?;
        let geometry = match (header.features & FEATURE_STRIPING_V2 != 0, stripe) {
            (true, Some(geometry)) => geometry,
            (true, None) => return Err(LayoutError::MissingStripeGeometry),
            (false, Some(_)) => return Err(LayoutError::UnexpectedStripeGeometry),
            (false, None) => StripeGeometry {
                unit: object_size,
                count: 1,
            },
        };
        if geometry.unit == 0
            || geometry.count == 0
            || geometry.unit > object_size
            || object_size % geometry.unit != 0
            || geometry.unit > MAX_LAYOUT_FIELD
            || geometry.count > MAX_LAYOUT_FIELD
        {
            return Err(LayoutError::InvalidStripeGeometry);
        }
        if header.object_prefix.len() > MAX_OBJECT_NAME_BYTES - 17 {
            return Err(LayoutError::ObjectNameTooLong);
        }
        // Both factors are bounded by the 32-bit layout fields, so the set
        // size fits a u64.
        let object_set_bytes = object_size
            .checked_mul(geometry.count)
            .ok_or(LayoutError::InvalidStripeGeometry)?;
        Ok(Self {
            image_size: header.size,
            object_size,
            stripe_unit: geometry.unit,
            stripe_count: geometry.count,
            object_set_bytes,
            object_prefix: header.object_prefix.clone(),
            object_number_width: 16,
        })
    }

    /// Select the format-1 data-object name width (12 hex digits) instead of
    /// the format-2 default (16). The format-2 constructor already bounds the
    /// object name to the OSD limit, and the shorter format-1 suffix is only
    /// more permissive, so this cannot fail.
    pub fn with_legacy_object_names(mut self) -> Self {
        self.object_number_width = 12;
        self
    }

    /// Logical byte length of the image at the captured header version.
    pub fn image_size(&self) -> u64 {
        self.image_size
    }

    /// Return the same mapping clipped to another observed image size.
    /// This changes geometry only, and does not authorize a resize or I/O.
    pub fn with_image_size(mut self, size: u64) -> Self {
        self.image_size = size;
        self
    }

    /// Byte length of one data object.
    pub fn object_size(&self) -> u64 {
        self.object_size
    }

    /// Number of data-object positions touched by the logical image range.
    /// A partial striped set includes only the leading objects reached by
    /// its stripe units.
    pub fn object_count(&self) -> u64 {
        let full_sets = self.image_size / self.object_set_bytes;
        let remainder = self.image_size % self.object_set_bytes;
        let tail_units = remainder.div_ceil(self.stripe_unit);
        let tail_objects = tail_units.min(self.stripe_count);
        // A full set holds one object per stripe position and a tail set
        // holds at most one object per stripe unit, so the sum stays inside
        // the image size for an unstriped layout and inside
        // `image_size / object_size + stripe_count` otherwise.
        full_sets * self.stripe_count + tail_objects
    }

    /// Number of contiguous logical bytes stored per object turn.
    pub fn stripe_unit(&self) -> u64 {
        self.stripe_unit
    }

    /// Number of objects in one stripe set.
    pub fn stripe_count(&self) -> u64 {
        self.stripe_count
    }

    /// Byte-exact prefix used before the dot and fixed object-number suffix.
    pub fn object_prefix(&self) -> &[u8] {
        &self.object_prefix
    }

    /// Return the first object-local span, clipped to both the image end and
    /// the next object boundary. A zero request or offset at/after EOF has no
    /// extent. Repeated calls with the previous offset plus returned length
    /// cover a larger request without skipping bytes.
    ///
    /// The mapping follows the pinned reference: the logical offset selects a
    /// stripe unit, the stripe unit index selects the stripe inside its set,
    /// the stripe selects the object inside the set and the stripes per
    /// object select the slot inside that object. The validated geometry
    /// keeps every step inside a u64.
    pub fn first_extent(&self, offset: u64, requested_length: u64) -> Option<ObjectExtent> {
        if requested_length == 0 || offset >= self.image_size {
            return None;
        }
        if self.stripe_count == 1 {
            // The pinned reference maps an unstriped image straight into
            // the objects, one object per object size.
            let object_offset = offset % self.object_size;
            return Some(ObjectExtent {
                object_number: offset / self.object_size,
                object_offset,
                length: requested_length
                    .min(self.image_size - offset)
                    .min(self.object_size - object_offset),
            });
        }
        // Stripe-unit index, stripe index inside its set and the position of
        // the object inside that set.
        let stripe_unit = self.stripe_unit;
        let in_unit = offset % stripe_unit;
        let block = offset / stripe_unit;
        let stripe = block / self.stripe_count;
        let stripe_position = block % self.stripe_count;
        let stripes_per_object = self.object_size / stripe_unit;
        let object_set = stripe / stripes_per_object;
        Some(ObjectExtent {
            object_number: object_set * self.stripe_count + stripe_position,
            object_offset: (stripe % stripes_per_object) * stripe_unit + in_unit,
            length: requested_length
                .min(self.image_size - offset)
                .min(stripe_unit - in_unit),
        })
    }

    /// Map a raw byte to the entire part of its crypto unit stored in the
    /// same contiguous object turn. Querying this range lets a sparse reader
    /// classify the requested byte even when it was not itself allocated.
    /// The final fragment is clipped to the raw image end.
    pub fn crypto_object_fragment(
        &self,
        raw_offset: u64,
        payload_offset: u64,
        crypto_unit: u64,
    ) -> Option<CryptoObjectFragment> {
        if crypto_unit == 0 || raw_offset < payload_offset || raw_offset >= self.image_size {
            return None;
        }
        let logical = raw_offset - payload_offset;
        let unit_start = raw_offset - logical % crypto_unit;
        let unit_end = unit_start.saturating_add(crypto_unit).min(self.image_size);
        let turn = if self.stripe_count == 1 {
            self.object_size
        } else {
            self.stripe_unit
        };
        let turn_start = raw_offset - raw_offset % turn;
        let turn_end = turn_start.saturating_add(turn).min(self.image_size);
        let start = unit_start.max(turn_start);
        let end = unit_end.min(turn_end);
        let extent = self.first_extent(start, end.checked_sub(start)?)?;
        if extent.length != end - start {
            return None;
        }
        Some(CryptoObjectFragment {
            logical_offset: start - payload_offset,
            extent,
            skip: raw_offset - start,
        })
    }

    /// Coalesce complete crypto-unit intersections within the same object
    /// turn. The returned span covers the requested prefix up to the object
    /// boundary or `max_length`; a capacity boundary never cuts a crypto unit.
    pub fn crypto_object_range(
        &self,
        raw_offset: u64,
        payload_offset: u64,
        crypto_unit: u64,
        requested_length: u64,
        max_length: u64,
    ) -> Option<CryptoObjectFragment> {
        if requested_length == 0 || max_length < crypto_unit {
            return None;
        }
        let first = self.crypto_object_fragment(raw_offset, payload_offset, crypto_unit)?;
        let start = payload_offset.checked_add(first.logical_offset)?;
        let turn = self.first_extent(start, u64::MAX)?;
        let turn_end = start.checked_add(turn.length)?;
        let requested_end = raw_offset
            .saturating_add(requested_length)
            .min(self.image_size);
        let logical_end = requested_end.checked_sub(payload_offset)?;
        let rounded = logical_end
            .checked_next_multiple_of(crypto_unit)
            .and_then(|end| payload_offset.checked_add(end))
            .unwrap_or(self.image_size)
            .min(self.image_size);
        let cap_end = start.saturating_add(max_length).min(self.image_size);
        let mut end = rounded.min(turn_end).min(cap_end);
        if end == cap_end && end < rounded && end < turn_end {
            end -= (end - payload_offset) % crypto_unit;
        }
        if end <= raw_offset {
            return None;
        }
        let extent = self.first_extent(start, end - start)?;
        if extent.length != end - start {
            return None;
        }
        Some(CryptoObjectFragment {
            logical_offset: first.logical_offset,
            extent,
            skip: first.skip,
        })
    }

    /// Map an object-local range back to its first logical image span.
    /// The returned pair is (logical offset, contiguous length), clipped to
    /// this view and the next stripe boundary. Repeat at the next object
    /// offset to materialize a striped object in object-byte order.
    pub fn object_span(
        &self,
        object_number: u64,
        object_offset: u64,
        length: u64,
    ) -> Option<(u64, u64)> {
        if object_offset >= self.object_size || length == 0 {
            return None;
        }
        let logical = if self.stripe_count == 1 {
            object_number
                .checked_mul(self.object_size)?
                .checked_add(object_offset)?
        } else {
            (object_number / self.stripe_count)
                .checked_mul(self.object_set_bytes)?
                .checked_add(
                    (object_offset / self.stripe_unit)
                        .checked_mul(self.stripe_unit.checked_mul(self.stripe_count)?)?,
                )?
                .checked_add((object_number % self.stripe_count).checked_mul(self.stripe_unit)?)?
                .checked_add(object_offset % self.stripe_unit)?
        };
        if logical >= self.image_size {
            return None;
        }
        let boundary = if self.stripe_count == 1 {
            self.object_size - object_offset
        } else {
            self.stripe_unit - object_offset % self.stripe_unit
        };
        Some((logical, length.min(boundary).min(self.image_size - logical)))
    }

    /// Return the end of the object-local prefix whose logical bytes remain
    /// below `logical_end`. Zero means this object has no remaining bytes.
    /// The layout may represent the pre-trim image; callers must retain write
    /// authority and perform the corresponding truncate/remove themselves.
    pub fn object_prefix_end(&self, object_number: u64, logical_end: u64) -> u64 {
        let (step, chunks) = if self.stripe_count == 1 {
            (self.object_size, 1)
        } else {
            (self.stripe_unit, self.object_size / self.stripe_unit)
        };
        let mut low = 0;
        let mut high = chunks;
        while low < high {
            let middle = low + (high - low) / 2;
            let offset = middle * step;
            let before_end = self
                .object_span(object_number, offset, step)
                .is_some_and(|(logical, _)| logical < logical_end);
            if before_end {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if low == 0 {
            return 0;
        }
        let offset = (low - 1) * step;
        let Some((logical, length)) = self.object_span(object_number, offset, step) else {
            return 0;
        };
        offset + length.min(logical_end.saturating_sub(logical))
    }

    /// Replace `destination` with the byte-exact data-object name. Reusing
    /// the caller's buffer avoids a temporary formatted string per extent; the
    /// capacity leaves room for the caller's NUL terminator.
    pub fn write_object_name(&self, object_number: u64, destination: &mut Vec<u8>) {
        destination.clear();
        destination.reserve(self.object_prefix.len() + (self.object_number_width as usize) + 2);
        destination.extend_from_slice(&self.object_prefix);
        destination.push(b'.');
        for shift in (0..self.object_number_width).rev() {
            destination.push(HEX[((object_number >> (shift * 4)) & 0xf) as usize]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(size: u64) -> ImageHeader {
        ImageHeader {
            order: 22,
            size,
            features: 0x3d,
            incompatible_features: 0x3d,
            object_prefix: b"rbd_data.native".to_vec(),
            data_pool_id: -1,
        }
    }

    #[test]
    fn splits_at_object_boundary_and_eof() {
        let layout = ImageLayout::from_header(&header(5_000_000)).unwrap();
        assert_eq!(layout.object_size(), 4_194_304);
        assert_eq!(layout.image_size(), 5_000_000);
        assert_eq!(
            layout.first_extent(4_194_300, 1_000_000),
            Some(ObjectExtent {
                object_number: 0,
                object_offset: 4_194_300,
                length: 4,
            })
        );
        assert_eq!(
            layout.first_extent(4_194_304, 1_000_000),
            Some(ObjectExtent {
                object_number: 1,
                object_offset: 0,
                length: 805_696,
            })
        );
        assert_eq!(layout.first_extent(5_000_000, 1), None);
        assert_eq!(layout.first_extent(0, 0), None);
    }

    #[test]
    fn striped_rollback_tail_uses_logical_prefix_per_object() {
        let mut header = header(5 * 1024 * 1024);
        header.features |= FEATURE_STRIPING_V2;
        let layout = ImageLayout::from_header_with_stripe(
            &header,
            Some(StripeGeometry {
                unit: 1024 * 1024,
                count: 2,
            }),
        )
        .unwrap();

        assert_eq!(layout.object_count(), 2);
        assert_eq!(
            layout.object_prefix_end(0, 3 * 1024 * 1024),
            2 * 1024 * 1024
        );
        assert_eq!(layout.object_prefix_end(1, 3 * 1024 * 1024), 1024 * 1024);
        assert_eq!(layout.object_prefix_end(0, 1024 * 1024), 1024 * 1024);
        assert_eq!(layout.object_prefix_end(1, 1024 * 1024), 0);
    }

    #[test]
    fn object_name_is_fixed_lowercase_hex() {
        let layout = ImageLayout::from_header(&header(u64::MAX)).unwrap();
        let mut name = Vec::new();
        layout.write_object_name(0xabcdef1234567890, &mut name);
        assert_eq!(name, b"rbd_data.native.abcdef1234567890");
        layout.write_object_name(0, &mut name);
        assert_eq!(name, b"rbd_data.native.0000000000000000");
        assert_eq!(
            layout.first_extent(u64::MAX - 1, u64::MAX),
            Some(ObjectExtent {
                object_number: (u64::MAX - 1) / 4_194_304,
                object_offset: (u64::MAX - 1) % 4_194_304,
                length: 1,
            })
        );
    }

    #[test]
    fn legacy_object_names_use_twelve_digits_but_v2_is_unchanged() {
        let layout = ImageLayout::from_header(&header(4096))
            .unwrap()
            .with_legacy_object_names();
        let mut name = Vec::new();
        layout.write_object_name(0x1234_5678_9abc, &mut name);
        assert_eq!(name, b"rbd_data.native.123456789abc");
        layout.write_object_name(0, &mut name);
        assert_eq!(name, b"rbd_data.native.000000000000");
        layout.write_object_name(0xabc, &mut name);
        assert_eq!(name, b"rbd_data.native.000000000abc");

        // The format-2 layout still emits 16 digits.
        let v2 = ImageLayout::from_header(&header(4096)).unwrap();
        let mut v2_name = Vec::new();
        v2.write_object_name(0xabc, &mut v2_name);
        assert_eq!(v2_name, b"rbd_data.native.0000000000000abc");
    }

    #[test]
    fn refuses_missing_or_impossible_geometry() {
        let mut h = header(1);
        h.features |= FEATURE_STRIPING_V2;
        assert_eq!(
            ImageLayout::from_header(&h),
            Err(LayoutError::MissingStripeGeometry)
        );
        h.features &= !FEATURE_STRIPING_V2;
        h.order = 64;
        assert_eq!(ImageLayout::from_header(&h), Err(LayoutError::InvalidOrder));
        h.order = 22;
        h.object_prefix = vec![b'x'; MAX_OBJECT_NAME_BYTES - 16];
        assert_eq!(
            ImageLayout::from_header(&h),
            Err(LayoutError::ObjectNameTooLong)
        );
    }

    #[test]
    fn striped_mapping_cycles_objects_then_advances_to_next_set() {
        let mut image = header(13_000);
        image.order = 12;
        image.features |= FEATURE_STRIPING_V2;
        let layout = ImageLayout::from_header_with_stripe(
            &image,
            Some(StripeGeometry {
                unit: 1024,
                count: 3,
            }),
        )
        .unwrap();
        assert_eq!(layout.stripe_unit(), 1024);
        assert_eq!(layout.stripe_count(), 3);
        assert_eq!(layout.object_count(), 4);
        for (logical, object_number, object_offset, length) in [
            (0, 0, 0, 1024),
            (1024, 1, 0, 1024),
            (2048, 2, 0, 1024),
            (3072, 0, 1024, 1024),
            (12_000, 2, 3808, 288),
            (12_288, 3, 0, 712),
        ] {
            assert_eq!(
                layout.first_extent(logical, 4096),
                Some(ObjectExtent {
                    object_number,
                    object_offset,
                    length
                })
            );
        }
    }

    #[test]
    fn crypto_fragment_queries_the_full_object_intersection() {
        let mut image = header(19_000);
        image.order = 12;
        image.features |= FEATURE_STRIPING_V2;
        let layout = ImageLayout::from_header_with_stripe(
            &image,
            Some(StripeGeometry {
                unit: 512,
                count: 2,
            }),
        )
        .unwrap();
        let fragment = layout.crypto_object_fragment(16_401, 16_384, 4096).unwrap();
        assert_eq!(fragment.logical_offset, 0);
        assert_eq!(fragment.skip, 17);
        assert_eq!(
            fragment.extent,
            ObjectExtent {
                object_number: 4,
                object_offset: 0,
                length: 512
            }
        );
        let next = layout.crypto_object_fragment(16_896, 16_384, 4096).unwrap();
        assert_eq!(next.logical_offset, 512);
        assert_eq!(
            next.extent,
            ObjectExtent {
                object_number: 5,
                object_offset: 0,
                length: 512
            }
        );
        assert_eq!(layout.crypto_object_fragment(16_383, 16_384, 4096), None);
        assert_eq!(layout.crypto_object_fragment(19_000, 16_384, 4096), None);
        assert_eq!(layout.crypto_object_fragment(16_384, 16_384, 0), None);

        let mut image = header(8_500);
        image.order = 12;
        let layout = ImageLayout::from_header(&image).unwrap();
        let split = layout.crypto_object_fragment(8_192, 4_112, 4096).unwrap();
        assert_eq!(split.logical_offset, 4_080);
        assert_eq!(
            split.extent,
            ObjectExtent {
                object_number: 2,
                object_offset: 0,
                length: 16
            }
        );
        let end = layout.crypto_object_fragment(8_499, 8_192, 512).unwrap();
        assert_eq!(end.extent.length, 308);
        assert_eq!(end.skip, 307);
    }

    /// Encrypted compare-and-write admission is "exactly one object extent
    /// that lies inside one stripe unit" (spec encrypted-compare-write-source
    /// "Admission" / "Croit rule"). Prove over the creatable geometries that
    /// admission always leaves the enclosing crypto-unit fragment inside the
    /// request's object and covering the request, so no "unit crosses objects"
    /// error path can exist.
    #[test]
    fn crypto_range_covers_every_admissible_compare_and_write() {
        let mut checked = 0u64;
        for order in 12u32..=22 {
            let object_size = 1u64 << order;
            for unit in [512u64, 1024, 2048, 4096, 8192, 16_384, 65_536] {
                if unit > object_size {
                    continue;
                }
                for count in 1u64..=8 {
                    let period = unit * count;
                    for crypto in [512u64, 4096] {
                        // A data offset is a whole number of stripe periods;
                        // every creatable image sizes itself mid-unit.
                        for periods in 1u64..=3 {
                            let data_offset = period * periods;
                            for tail in [0u64, 1, unit / 2, unit - 1] {
                                let data_size = period * 2 + tail;
                                let image_size = data_offset + data_size;
                                let mut image = header(image_size);
                                image.order = u8::try_from(order).unwrap();
                                // An image without STRIPINGV2 is the default
                                // geometry unit = object size, count = 1.
                                let layout = if count == 1 && unit == object_size {
                                    ImageLayout::from_header(&image).unwrap()
                                } else {
                                    image.features |= FEATURE_STRIPING_V2;
                                    ImageLayout::from_header_with_stripe(
                                        &image,
                                        Some(StripeGeometry { unit, count }),
                                    )
                                    .unwrap()
                                };
                                assert_eq!(layout.stripe_unit(), unit);
                                assert_eq!(layout.stripe_count(), count);
                                for in_unit in [0u64, 1, 2, unit / 2, unit - 1] {
                                    for length in [1u64, 2, 3, unit / 2, unit] {
                                        if in_unit + length > unit {
                                            continue;
                                        }
                                        // Request in DATA coordinates, inside
                                        // one stripe unit of the raw stream.
                                        let offset = period + in_unit;
                                        if offset + length > data_size {
                                            continue;
                                        }
                                        let raw = offset + data_offset;
                                        let req = layout
                                            .first_extent(raw, length)
                                            .expect("admissible request has an extent");
                                        if req.length != length {
                                            // Not admissible; admission refuses
                                            // it with -EINVAL before this path.
                                            continue;
                                        }
                                        let block = crypto;
                                        let end =
                                            (raw + length).checked_next_multiple_of(block).unwrap();
                                        let extended = (end > layout.image_size())
                                            .then(|| layout.clone().with_image_size(end));
                                        let fragment = extended
                                            .as_ref()
                                            .unwrap_or(&layout)
                                            .crypto_object_range(
                                                raw,
                                                data_offset,
                                                block,
                                                length,
                                                u64::MAX,
                                            )
                                            .expect("a unit fragment exists");
                                        assert_eq!(
                                            fragment.extent.object_number, req.object_number,
                                            "order {order} unit {unit} count {count} \
                                             crypto {crypto} data_offset {data_offset} \
                                             raw {raw} length {length}"
                                        );
                                        assert!(
                                            fragment.extent.length - fragment.skip >= length,
                                            "fragment does not cover the request: order \
                                             {order} unit {unit} count {count} crypto {crypto} \
                                             data_offset {data_offset} raw {raw} length \
                                             {length} fragment {fragment:?}"
                                        );
                                        checked += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(checked > 100_000, "property covered {checked} geometries");
    }

    #[test]
    fn crypto_range_coalesces_units_without_crossing_object_or_capacity() {
        let mut image = header(100_000);
        image.order = 16;
        let layout = ImageLayout::from_header(&image).unwrap();
        let range = layout
            .crypto_object_range(17, 0, 4096, 8192, 16384)
            .unwrap();
        assert_eq!(
            (range.logical_offset, range.skip, range.extent.length),
            (0, 17, 12288)
        );
        let capped = layout.crypto_object_range(17, 0, 4096, 8192, 8192).unwrap();
        assert_eq!(capped.extent.length, 8192);
        let boundary = layout
            .crypto_object_range(65_500, 0, 4096, 5000, 16384)
            .unwrap();
        assert_eq!(boundary.extent.object_number, 0);
        assert_eq!(
            boundary.extent.object_offset + boundary.extent.length,
            65536
        );
        assert_eq!(layout.crypto_object_range(17, 0, 4096, 0, 8192), None);
        assert_eq!(layout.crypto_object_range(17, 0, 4096, 1, 4095), None);

        image.features |= FEATURE_STRIPING_V2;
        let striped = ImageLayout::from_header_with_stripe(
            &image,
            Some(StripeGeometry {
                unit: 512,
                count: 2,
            }),
        )
        .unwrap();
        let fragment = striped
            .crypto_object_range(17, 0, 4096, 8192, 16384)
            .unwrap();
        assert_eq!(
            (
                fragment.extent.object_number,
                fragment.extent.length,
                fragment.skip
            ),
            (0, 512, 17)
        );
    }

    #[test]
    fn count_includes_only_objects_reached_in_partial_stripe_set() {
        let mut image = header(10 * 1024 * 1024);
        image.features |= FEATURE_STRIPING_V2;
        let layout = ImageLayout::from_header_with_stripe(
            &image,
            Some(StripeGeometry {
                unit: 64 * 1024,
                count: 4,
            }),
        )
        .unwrap();
        assert_eq!(layout.object_count(), 4);
        assert_eq!(
            layout
                .clone()
                .with_image_size(16 * 1024 * 1024)
                .object_count(),
            4
        );
        assert_eq!(
            layout
                .clone()
                .with_image_size(16 * 1024 * 1024 + 1)
                .object_count(),
            5
        );
        assert_eq!(layout.with_image_size(0).object_count(), 0);
        assert_eq!(
            ImageLayout::from_header(&header(8 * 1024 * 1024))
                .unwrap()
                .object_count(),
            2
        );
    }

    #[test]
    fn one_object_stripe_coalesces_contiguous_units() {
        let mut image = header(8192);
        image.order = 12;
        image.features |= FEATURE_STRIPING_V2;
        let layout = ImageLayout::from_header_with_stripe(
            &image,
            Some(StripeGeometry {
                unit: 1024,
                count: 1,
            }),
        )
        .unwrap();
        assert_eq!(
            layout.first_extent(500, 4096),
            Some(ObjectExtent {
                object_number: 0,
                object_offset: 500,
                length: 3596,
            })
        );
        assert_eq!(
            layout.first_extent(4096, 4096),
            Some(ObjectExtent {
                object_number: 1,
                object_offset: 0,
                length: 4096,
            })
        );
    }

    #[test]
    fn striped_mapping_keeps_wide_set_arithmetic_valid() {
        // The pinned reference maps an image through a layout whose object
        // size, stripe unit and stripe count are 32-bit fields. A geometry
        // outside that range cannot be mapped the way the reference maps it,
        // so it is refused instead of producing a wrong object number.
        let mut image = header(u64::MAX);
        image.order = 32;
        image.features |= FEATURE_STRIPING_V2;
        let geometry = StripeGeometry {
            unit: 1,
            count: u64::MAX,
        };
        assert_eq!(
            ImageLayout::from_header_with_stripe(&image, Some(geometry)),
            Err(LayoutError::InvalidOrder)
        );
        image.order = 31;
        assert_eq!(
            ImageLayout::from_header_with_stripe(&image, Some(geometry)),
            Err(LayoutError::InvalidStripeGeometry)
        );
        let geometry = StripeGeometry {
            unit: 1,
            count: u32::MAX as u64,
        };
        let layout = ImageLayout::from_header_with_stripe(&image, Some(geometry)).unwrap();
        let extent = layout.first_extent(u64::MAX - 1, 1).unwrap();
        assert_eq!(extent.length, 1);
        assert_eq!(extent.object_offset, 0);
        // The last byte of a maximal image maps to the last object of the
        // striped layout without an arithmetic overflow.
        assert_eq!(extent.object_number, 12_884_901_884);
        assert_eq!(
            ImageLayout::from_header(&image),
            Err(LayoutError::MissingStripeGeometry)
        );
        image.features &= !FEATURE_STRIPING_V2;
        assert_eq!(
            ImageLayout::from_header_with_stripe(&image, Some(geometry)),
            Err(LayoutError::UnexpectedStripeGeometry)
        );
        image.features |= FEATURE_STRIPING_V2;
        assert_eq!(
            ImageLayout::from_header_with_stripe(
                &image,
                Some(StripeGeometry { unit: 3, count: 1 })
            ),
            Err(LayoutError::InvalidStripeGeometry)
        );
    }
    #[test]
    fn inverse_object_spans_cover_striped_objects_and_partial_sets() {
        for unit in [1, 2, 4, 8, 16] {
            for count in 1..=4 {
                for size in [1, 15, 16, 17, 31, 33, 63, 97] {
                    let mut image = header(size);
                    image.order = 4;
                    image.features |= FEATURE_STRIPING_V2;
                    let layout = ImageLayout::from_header_with_stripe(
                        &image,
                        Some(StripeGeometry { unit, count }),
                    )
                    .unwrap();
                    let mut visited = vec![false; size as usize];
                    for object in 0..layout.object_count() {
                        let mut offset = 0;
                        while let Some((logical, length)) =
                            layout.object_span(object, offset, u64::MAX)
                        {
                            let extent = layout.first_extent(logical, length).unwrap();
                            assert_eq!(
                                (extent.object_number, extent.object_offset, extent.length),
                                (object, offset, length)
                            );
                            for byte in logical..logical + length {
                                assert!(!visited[byte as usize]);
                                visited[byte as usize] = true;
                            }
                            offset += length;
                        }
                    }
                    assert!(visited.iter().all(|byte| *byte));
                    assert_eq!(layout.object_span(u64::MAX, 0, 1), None);
                    assert_eq!(layout.object_span(0, 16, 1), None);
                    assert_eq!(layout.object_span(0, 0, 0), None);
                }
            }
        }
    }
}
