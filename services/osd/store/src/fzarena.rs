// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Page images of one checkpoint (sliced freeze, adr 0021 S7) in fixed-size chunks.
//!
//! A chunk holds `chunk_pages` pages, the largest device write of the shard, so every write job of the checkpoint is a
//! slice of one chunk. Chunks are never reallocated, grown or freed: a finished checkpoint hands all of them back to the
//! tree ([`Arena::into_chunks`]) and the next freeze takes them again. A checkpoint larger than every earlier one
//! allocates only its extra chunks, one at a time where a page needs one. One contiguous arena had to be replaced
//! whole when a checkpoint outgrew it: the old block's free (EAL hugepage heap, payload allocator: zeroed on free)
//! and the new allocation ran in one piece at checkpoint start (2-12 ms, doc/perf/ckpt-holds-20261025.md).

/// Page images in push order, addressed by page index.
#[derive(Debug, Default)]
pub struct Arena {
    psz: usize,
    chunk_pages: usize,
    /// Chunks in use, every one full except the last.
    used: Vec<Vec<u8>>,
    /// Empty chunks for the next pushes.
    spare: Vec<Vec<u8>>,
    pages: usize,
}

impl Arena {
    /// An arena of `psz`-byte pages in chunks of `chunk_pages` (>= 1) pages, reusing the empty `spare` chunks.
    pub fn new(psz: usize, chunk_pages: usize, spare: Vec<Vec<u8>>) -> Arena {
        Arena {
            psz,
            chunk_pages: chunk_pages.max(1),
            used: Vec::new(),
            spare,
            pages: 0,
        }
    }

    /// Pages held.
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// Pages per chunk: a write job never crosses a multiple of it.
    pub fn chunk_pages(&self) -> usize {
        self.chunk_pages
    }

    /// Append `data` (whole pages) and return the index of its first page. A run of pages may span chunks.
    pub fn push(&mut self, data: &[u8]) -> u32 {
        debug_assert_eq!(data.len() % self.psz, 0);
        let first = self.pages as u32;
        for page in data.chunks_exact(self.psz) {
            if self.pages.is_multiple_of(self.chunk_pages) {
                let c = self
                    .spare
                    .pop()
                    .unwrap_or_else(|| Vec::with_capacity(self.chunk_pages * self.psz));
                self.used.push(c);
            }
            self.used.last_mut().expect("chunk").extend_from_slice(page);
            self.pages += 1;
        }
        first
    }

    /// `n` pages from page `idx`; they lie in one chunk (`idx / chunk_pages == (idx + n - 1) / chunk_pages`).
    pub fn slice(&self, idx: usize, n: usize) -> &[u8] {
        let (c, o) = (idx / self.chunk_pages, idx % self.chunk_pages);
        assert!(n >= 1 && o + n <= self.chunk_pages, "pages cross a chunk");
        &self.used[c][o * self.psz..(o + n) * self.psz]
    }

    /// Bytes of the chunks held (used and spare).
    pub fn bytes(&self) -> usize {
        (self.used.len() + self.spare.len()) * self.chunk_pages * self.psz
    }

    /// Every chunk, emptied, for the next arena.
    pub fn into_chunks(self) -> Vec<Vec<u8>> {
        let mut all = self.spare;
        all.extend(self.used.into_iter().map(|mut c| {
            c.clear();
            c
        }));
        all
    }
}

#[cfg(test)]
mod tests {
    use super::Arena;

    #[test]
    fn pages_span_chunks_and_chunks_are_reused() {
        let mut a = Arena::new(4, 3, Vec::new());
        assert_eq!(a.push(&[1; 8]), 0);
        assert_eq!(a.push(&[2; 8]), 2); // pages 2 (chunk 0) and 3 (chunk 1)
        assert_eq!(a.pages(), 4);
        assert_eq!(a.slice(0, 3), &[1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2]);
        assert_eq!(a.slice(3, 1), &[2; 4]);
        let chunks = a.into_chunks();
        assert_eq!(chunks.len(), 2);
        let ptrs: Vec<_> = chunks.iter().map(|c| c.as_ptr()).collect();
        let mut b = Arena::new(4, 3, chunks);
        b.push(&[3; 24]);
        assert_eq!(b.bytes(), 2 * 12);
        let again: Vec<_> = b.into_chunks().iter().map(|c| c.as_ptr()).collect();
        assert!(again.iter().all(|p| ptrs.contains(p)), "no new chunk");
    }

    #[test]
    #[should_panic(expected = "pages cross a chunk")]
    fn a_slice_never_crosses_a_chunk() {
        let mut a = Arena::new(4, 2, Vec::new());
        a.push(&[0; 12]);
        let _ = a.slice(1, 2);
    }
}
