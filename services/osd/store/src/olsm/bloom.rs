// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Blocked bloom filter of one run chunk: `BLOCK_WORDS` x 64 bit blocks, a key sets `PROBES` bits inside one block
//! (one cache line per probe), sized [`super::BLOOM_BITS_PER_KEY`] bits per key. The filter depends only on the
//! chunk's keys, so a chunk moved into a merge output keeps its filter words.

/// Words of one block (512 bits = one cache line).
pub const BLOCK_WORDS: usize = 8;
/// Bits set per key: ~ln 2 x bits per key (12 bits/key -> 8.3), rounded down (fewer memory-local probes).
pub const PROBES: u32 = 8;

/// Hash of keyspace position `(id, key)` (hardware crc32c, then a 64 bit multiplicative spread).
#[inline]
pub fn hash(id: u64, key: &[u8]) -> u64 {
    let h = crc::crc32c(crc::crc32c(!0, &id.to_be_bytes()), key);
    // Fibonacci hashing constant (2^64 / golden ratio): spreads the 32 hash bits over all 64.
    (h as u64 | ((h as u64) << 32)).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Words of a filter for `n` keys (whole blocks, at least one).
pub fn words_for(n: usize) -> usize {
    let bits = n.max(1) * super::BLOOM_BITS_PER_KEY;
    bits.div_ceil(64 * BLOCK_WORDS) * BLOCK_WORDS
}

#[inline]
fn bits(h: u64, nwords: usize) -> (usize, impl Iterator<Item = (usize, u64)>) {
    let nblocks = (nwords / BLOCK_WORDS) as u64;
    let block = (((h >> 32) * nblocks) >> 32) as usize * BLOCK_WORDS;
    // Double hashing inside the 512 bit block: start and odd step from the low 18 bits.
    let (a, s) = (h as usize & 511, (h >> 9) as usize & 511 | 1);
    let it = (0..PROBES as usize).map(move |i| {
        let b = (a + i * s) & 511;
        (b / 64, 1u64 << (b % 64))
    });
    (block, it)
}

/// Add hash `h` to `words` (one chunk's filter).
pub fn add(words: &mut [u64], h: u64) {
    let (base, it) = bits(h, words.len());
    for (w, m) in it {
        words[base + w] |= m;
    }
}

/// `false` = the key is certainly absent.
#[inline]
pub fn maybe(words: &[u64], h: u64) -> bool {
    let (base, mut it) = bits(h, words.len());
    it.all(|(w, m)| words[base + w] & m != 0)
}
