// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Seed-0 block checksums on a shifted grid, retaining verified source blocks.
use crate::blocks::BLK;
use crate::{POLY, apply, crc32c, crc32c_combine, crc32c_shift, reseed_4k};

/// Checksum metadata and the actual bytes hashed to construct it.
#[derive(Debug)]
pub struct ReblockedCrcs {
    pub crcs: Vec<u32>,
    /// Includes short source edges outside the requested range when used to
    /// derive a suffix/prefix. Excludes previously verified full-block bytes.
    pub hashed_bytes: usize,
}

/// One immutable, already verified source block, or a logical sparse hole.
#[derive(Clone, Copy, Debug)]
pub enum VerifiedBlock<'a> {
    Data(&'a [u8], u32),
    /// Exactly 4096 zero bytes. No payload read is needed to derive their CRC.
    Zeros,
}
impl VerifiedBlock<'_> {
    fn crc(self) -> u32 {
        match self {
            Self::Data(_, crc) => crc,
            Self::Zeros => 0,
        }
    }
    fn hash(self, range: std::ops::Range<usize>, count: &mut usize) -> u32 {
        match self {
            Self::Data(bytes, _) => hash(&bytes[range], count),
            Self::Zeros => 0,
        }
    }
}

const fn inverse_bit(value: u32) -> u32 {
    let low = value >> 31;
    ((value ^ (POLY & 0u32.wrapping_sub(low))) << 1) | low
}
const fn inverse_powers() -> [[u32; 32]; 12] {
    let mut matrix = [0; 32];
    let mut i = 0;
    while i < 32 {
        let mut value = 1u32 << i;
        let mut bit = 0;
        while bit < 8 {
            // The high bit of a reflected update identifies the old low bit.
            value = inverse_bit(value);
            bit += 1;
        }
        matrix[i] = value;
        i += 1;
    }
    let mut powers = [[0; 32]; 12];
    let mut power = 0;
    while power < powers.len() {
        powers[power] = matrix;
        let mut square = [0; 32];
        i = 0;
        while i < 32 {
            square[i] = apply(&matrix, matrix[i]);
            i += 1;
        }
        matrix = square;
        power += 1;
    }
    powers
}
// Compile-time data: no lazy initialization, lock or allocation on first use.
static INVERSE: [[u32; 32]; 12] = inverse_powers();
fn unshift(mut value: u32, mut bytes: usize) -> u32 {
    debug_assert!(bytes <= BLK / 2);
    let mut power = 0;
    while bytes != 0 {
        if bytes & 1 != 0 {
            value = apply(&INVERSE[power], value);
        }
        bytes >>= 1;
        power += 1;
    }
    value
}
// Prepare the linear operation once per READ. Applying inverse powers for
// every block is expensive for dense shift lengths (e.g. 2047 bytes).
struct ShiftMap([[u32; 256]; 4]);
impl ShiftMap {
    fn new(bytes: usize, inverse: bool) -> Self {
        // Polynomial shifts commute with the inverse bit step. Evaluate one
        // column, then derive the remaining basis columns with one step each.
        let mut column = if inverse {
            unshift(1, bytes)
        } else {
            crc32c_shift(1, bytes as u64)
        };
        let basis: [u32; 32] = std::array::from_fn(|_| {
            let value = column;
            column = inverse_bit(column);
            value
        });
        let tables = std::array::from_fn(|byte| {
            let mut table = [0; 256];
            for value in 1usize..256 {
                let low = value.trailing_zeros() as usize;
                table[value] = table[value & (value - 1)] ^ basis[byte * 8 + low];
            }
            table
        });
        Self(tables)
    }
    fn apply(&self, value: u32) -> u32 {
        let bytes = value.to_le_bytes();
        self.0[0][bytes[0] as usize]
            ^ self.0[1][bytes[1] as usize]
            ^ self.0[2][bytes[2] as usize]
            ^ self.0[3][bytes[3] as usize]
    }
}

fn hash(data: &[u8], count: &mut usize) -> u32 {
    *count += data.len();
    crc32c(0, data)
}

fn next_block<'a>(
    blocks: &mut impl Iterator<Item = VerifiedBlock<'a>>,
) -> Option<VerifiedBlock<'a>> {
    blocks.next().filter(|block| match block {
        VerifiedBlock::Data(bytes, _) => bytes.len() == BLK,
        VerifiedBlock::Zeros => true,
    })
}

/// Derive seed-0 4096-byte CRCs for `length` bytes starting at `offset` in
/// verified full source blocks. Every input slice must have 4096 bytes and its
/// supplied CRC must already describe exactly those immutable bytes with seed 0.
/// This function does not reverify that premise. It retains/copies no payload.
///
/// The iterator must contain exactly the blocks enclosing the requested range;
/// malformed geometry returns None. Aligned full blocks reuse their CRCs. For
/// shifted full blocks, hash only the shorter prefix/suffix once per source
/// block and combine it with verified CRCs; a final partial block hashes at most
/// 4095 additional bytes. `hashed_bytes` reports actual work, including edges
/// outside the range. Only the returned metadata vector allocates.
///
/// Raw CRC linearity gives, for shift r and full blocks C_i with prefix CRC P_i:
/// `out_i = shift(C_i,r) XOR shift(P_i,4096) XOR P_(i+1)`.
/// For the shorter suffix S_i of length q=4096-r the equivalent formula is
/// `out_i = unshift(shift(S_i,4096) XOR C_(i+1) XOR S_(i+1),q)`.
/// Holes supply VerifiedBlock::Zeros and require no source-byte hashing.
pub fn crc32c_reblock<'a>(
    mut blocks: impl ExactSizeIterator<Item = VerifiedBlock<'a>>,
    offset: usize,
    length: usize,
) -> Option<ReblockedCrcs> {
    if offset >= BLK {
        return None;
    }
    if length == 0 {
        return (blocks.len() == 0).then_some(ReblockedCrcs {
            crcs: Vec::new(),
            hashed_bytes: 0,
        });
    }
    if offset.checked_add(length)?.div_ceil(BLK) != blocks.len() {
        return None;
    }
    let mut result = ReblockedCrcs {
        crcs: Vec::with_capacity(length.div_ceil(BLK)),
        hashed_bytes: 0,
    };
    let full = length / BLK;
    let tail = length % BLK;
    if offset == 0 {
        for _ in 0..full {
            result.crcs.push(next_block(&mut blocks)?.crc());
        }
        if tail != 0 {
            let data = next_block(&mut blocks)?;
            result
                .crcs
                .push(data.hash(0..tail, &mut result.hashed_bytes));
        }
        return Some(result);
    }
    let q = BLK - offset;
    let mut current = next_block(&mut blocks)?;
    let prefix = offset <= q;
    let mut edge = if full == 0 {
        0
    } else {
        current.hash(
            if prefix { 0..offset } else { offset..BLK },
            &mut result.hashed_bytes,
        )
    };
    let mut prepared: Option<ShiftMap> = None;
    let mut transform = |value| {
        if value == 0 {
            return 0;
        } // A linear map preserves zero, including sparse blocks.
        prepared
            .get_or_insert_with(|| ShiftMap::new(if prefix { offset } else { q }, !prefix))
            .apply(value)
    };
    for _ in 0..full {
        let following = next_block(&mut blocks)?;
        let following_edge = following.hash(
            if prefix { 0..offset } else { offset..BLK },
            &mut result.hashed_bytes,
        );
        result.crcs.push(if prefix {
            transform(current.crc()) ^ reseed_4k(edge, 0) ^ following_edge
        } else {
            transform(reseed_4k(edge, 0) ^ following.crc() ^ following_edge)
        });
        current = following;
        edge = following_edge;
    }
    if tail != 0 {
        let crc = if tail <= q {
            if full != 0 && tail == q {
                if prefix {
                    current.crc() ^ crc32c_shift(edge, q as u64)
                } else {
                    edge
                }
            } else {
                current.hash(offset..offset + tail, &mut result.hashed_bytes)
            }
        } else {
            let suffix = if full == 0 {
                current.hash(offset..BLK, &mut result.hashed_bytes)
            } else if prefix {
                current.crc() ^ crc32c_shift(edge, q as u64)
            } else {
                edge
            };
            let following = next_block(&mut blocks)?;
            crc32c_combine(
                suffix,
                following.hash(0..tail - q, &mut result.hashed_bytes),
                (tail - q) as u64,
            )
        };
        result.crcs.push(crc);
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_zero_feeding_matches_every_short_length_and_basis() {
        for length in 0..=BLK / 2 {
            for bit in 0..32 {
                let seed = 1u32 << bit;
                assert_eq!(unshift(crc32c_shift(seed, length as u64), length), seed);
            }
        }
    }

    #[test]
    fn prepared_maps_match_every_short_shift_and_basis() {
        for bytes in 0..=BLK / 2 {
            let forward = ShiftMap::new(bytes, false);
            let inverse = ShiftMap::new(bytes, true);
            for bit in 0..32 {
                let seed = 1u32 << bit;
                assert_eq!(forward.apply(seed), crc32c_shift(seed, bytes as u64));
                assert_eq!(inverse.apply(seed), unshift(seed, bytes));
            }
        }
    }

    #[test]
    fn shifted_grids_match_bytes_and_bound_the_hashed_work() {
        let data: Vec<_> = (0..5 * BLK)
            .map(|i| ((i * 71 + i / 37) % 251) as u8)
            .collect();
        for offset in 0..BLK {
            for length in [1, 17, BLK - 1, BLK, BLK + 1, 3 * BLK + 137] {
                let end = offset + length;
                let blocks = data[..end.div_ceil(BLK) * BLK]
                    .as_chunks::<BLK>()
                    .0
                    .iter()
                    .map(|block| VerifiedBlock::Data(block.as_slice(), crc32c(0, block)));
                let result = crc32c_reblock(blocks, offset, length).unwrap();
                let expected: Vec<_> = data[offset..end]
                    .chunks(BLK)
                    .map(|block| crc32c(0, block))
                    .collect();
                assert_eq!(result.crcs, expected, "offset {offset}, length {length}");
                let bound = if offset == 0 {
                    length % BLK
                } else {
                    (length / BLK + 1) * offset.min(BLK - offset) + length % BLK
                };
                assert!(result.hashed_bytes <= bound);
            }
        }
    }

    #[test]
    fn sparse_blocks_do_not_hash_zeros_and_join_data_on_both_grids() {
        let mut data: Vec<_> = (0..5 * BLK).map(|i| (i * 17 % 251) as u8).collect();
        data[BLK..2 * BLK].fill(0);
        data[3 * BLK..4 * BLK].fill(0);
        for offset in [1, 17, 2048, 2049, 4095] {
            let length = 3 * BLK + 199;
            let blocks = data
                .as_chunks::<BLK>()
                .0
                .iter()
                .enumerate()
                .map(|(i, block)| {
                    if i == 1 || i == 3 {
                        VerifiedBlock::Zeros
                    } else {
                        VerifiedBlock::Data(block.as_slice(), crc32c(0, block))
                    }
                });
            let required = (offset + length).div_ceil(BLK);
            let result = crc32c_reblock(blocks.take(required), offset, length).unwrap();
            let expected: Vec<_> = data[offset..offset + length]
                .chunks(BLK)
                .map(|block| crc32c(0, block))
                .collect();
            assert_eq!(result.crcs, expected);
            let zeros = crc32c_reblock(
                std::iter::repeat_n(VerifiedBlock::Zeros, required),
                offset,
                length,
            )
            .unwrap();
            assert!(zeros.crcs.iter().all(|&crc| crc == 0));
            assert_eq!(zeros.hashed_bytes, 0);
        }
    }

    #[test]
    #[ignore = "targeted optimized CRC-grid measurement; run with --release --nocapture"]
    fn shifted_grid_cpu_measurement() {
        use std::{hint::black_box, time::Instant};
        let source = std::env::var("FLASHSTORE_GIT").expect("committed measurement source");
        assert!(source.len() == 40 && source.bytes().all(|b| b.is_ascii_hexdigit()));
        for length in [1 << 20, 4 << 20, 64 << 20] {
            let data: Vec<_> = (0..length + BLK)
                .map(|i| ((i * 71 + i / 37) % 251) as u8)
                .collect();
            let blocks = data.as_chunks::<BLK>().0;
            let source_crcs: Vec<_> = blocks.iter().map(|b| crc32c(0, b)).collect();
            for offset in [0, 17, 2048, 2049, 4095] {
                let reblock = || {
                    let input = blocks
                        .iter()
                        .zip(&source_crcs)
                        .take((offset + length).div_ceil(BLK))
                        .map(|(bytes, &crc)| VerifiedBlock::Data(bytes.as_slice(), crc));
                    crc32c_reblock(input, offset, length).unwrap()
                };
                let scan = || {
                    data[offset..offset + length]
                        .as_chunks::<BLK>()
                        .0
                        .iter()
                        .map(|bytes| crc32c(0, bytes))
                        .collect::<Vec<_>>()
                };
                let expected = scan();
                let initial = reblock();
                assert_eq!(initial.crcs, expected);
                let hashed = initial.hashed_bytes;
                for _ in 0..3 {
                    black_box(reblock());
                    black_box(scan());
                }
                for round in 0..4 {
                    for pass in 0..2 {
                        let derived = (round + pass) % 2 == 0;
                        let begin = Instant::now();
                        for _ in 0..16 {
                            if derived {
                                black_box(reblock().crcs);
                            } else {
                                black_box(scan());
                            }
                        }
                        let ns = begin.elapsed().as_nanos();
                        let algorithm = if derived { "reblock" } else { "scan" };
                        let hashed_bytes = if derived { hashed } else { length };
                        println!(
                            "{{\"measurement\":\"crc_grid_microbench\",\"source_commit\":\"{source}\",\"algorithm\":\"{algorithm}\",\"bytes\":{length},\"offset\":{offset},\"iterations\":16,\"round\":{round},\"wall_ns\":{ns},\"hashed_bytes_per_iteration\":{hashed_bytes}}}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn malformed_source_geometry_fails_without_accepting_partial_metadata() {
        let block = [0; BLK];
        assert!(crc32c_reblock(std::iter::empty(), 1, usize::MAX).is_none());
        assert!(crc32c_reblock(std::iter::empty(), BLK, 0).is_none());
        assert!(crc32c_reblock(std::iter::empty(), 0, BLK).is_none());
        assert!(
            crc32c_reblock([VerifiedBlock::Data(block.as_slice(), 0)].into_iter(), 0, 0).is_none()
        );
        assert!(
            crc32c_reblock(
                [VerifiedBlock::Data(&block[..BLK - 1], 0)].into_iter(),
                0,
                BLK
            )
            .is_none()
        );
        for offset in [0, 17, BLK - 1] {
            let empty = crc32c_reblock(std::iter::empty(), offset, 0).unwrap();
            assert_eq!(empty.crcs, []);
            assert_eq!(empty.hashed_bytes, 0);
        }
    }
}
