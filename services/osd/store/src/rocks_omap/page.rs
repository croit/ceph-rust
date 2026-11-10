// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Owned scan payloads with a whole-backing charge, never iterator-backed views.
use super::*;

/// One payload owner plus compact offsets. Entries borrow this envelope instead
/// of creating two refcounted byte owners per key. Partial consumption retains
/// the complete payload charge; exported legacy entries must detach explicitly.
#[derive(Clone, Debug)]
pub(crate) struct PageEntries {
    data: Bytes,
    ends: Box<[(usize, usize)]>,
    payload_capacity: usize,
}

impl PageEntries {
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<(&[u8], &[u8])> {
        let &(middle, end) = self.ends.get(index)?;
        let start = if index == 0 {
            0
        } else {
            self.ends[index - 1].1
        };
        Some((&self.data[start..middle], &self.data[middle..end]))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        (0..self.len()).map(|i| self.get(i).expect("valid entry index"))
    }

    pub fn bytes(&self) -> usize {
        // Keep the prior 64-byte entry reservation although the retained boxed
        // offsets are smaller. This CPU experiment does not relax page credits
        // or alter the builder's tight-credit continuation decisions.
        self.payload_capacity.saturating_add(
            self.ends
                .len()
                .saturating_mul(std::mem::size_of::<(Bytes, Bytes)>()),
        )
    }

    #[cfg(test)]
    pub(super) fn to_pairs(&self) -> Vec<(Bytes, Bytes)> {
        self.iter()
            .map(|(k, v)| (Bytes::copy_from_slice(k), Bytes::copy_from_slice(v)))
            .collect()
    }

    #[cfg(test)]
    pub fn test_from_pairs(pairs: &[(&[u8], &[u8])]) -> Self {
        let mut builder = PageBuilder::default();
        for (key, value) in pairs {
            assert!(
                builder
                    .push(key, value, pairs.len(), usize::MAX, usize::MAX)
                    .unwrap()
            );
        }
        builder.finish()
    }
}

/// The first visible entry estimates a bounded initial allocation. Irregular
/// entries grow it within the same answer credits. Unused capacity is charged.
#[derive(Default)]
pub(super) struct PageBuilder {
    data: Vec<u8>,
    ends: Vec<(usize, usize)>,
}

impl PageBuilder {
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.data.capacity().saturating_add(
            self.len()
                .saturating_mul(std::mem::size_of::<(Bytes, Bytes)>()),
        )
    }

    /// False means this nonempty batch ends before this entry. The caller keeps
    /// the same first-unreturned-key continuation, including Unknown on pressure.
    pub fn push(
        &mut self,
        key: &[u8],
        value: &[u8],
        entries: usize,
        page_bytes: usize,
        limit: usize,
    ) -> Result<bool> {
        let payload = key.len().saturating_add(value.len());
        let metadata = self.len().saturating_add(1).saturating_mul(64);
        let available = limit.saturating_sub(metadata);
        let need = self.data.len().saturating_add(payload);
        if metadata > limit || need > available || self.data.capacity() > available {
            return Ok(false);
        }
        if need > self.data.capacity() {
            let target = if self.is_empty() {
                let count = (limit / payload.saturating_add(64))
                    .min(entries.clamp(1, SCAN_BATCH))
                    .max(1);
                self.ends.reserve_exact(count);
                payload
                    .saturating_mul(count)
                    .min(page_bytes.max(payload))
                    .min(limit.saturating_sub(count.saturating_mul(64)))
            } else {
                self.data.capacity().saturating_mul(2)
            }
            .max(need)
            .min(available);
            self.data.reserve_exact(target - self.data.len());
            if self.data.capacity() > available {
                return Err(StoreError::TxnTooLarge);
            }
        }
        self.data.extend_from_slice(key);
        let middle = self.data.len();
        self.data.extend_from_slice(value);
        self.ends.push((middle, self.data.len()));
        Ok(true)
    }

    pub fn finish(self) -> PageEntries {
        let payload_capacity = self.data.capacity();
        PageEntries {
            data: Bytes::from(self.data),
            // No unused descriptor capacity escapes an early-prefix result.
            ends: self.ends.into_boxed_slice(),
            payload_capacity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_batch_owns_binary_payloads_in_one_allocation() {
        let mut builder = PageBuilder::default();
        let mut key = [0, 255, 17, 0];
        let mut value = [42; 256];
        let count = 1024;
        for _ in 0..count {
            assert!(builder.push(&key, &value, count, 1 << 20, 1 << 20).unwrap());
            assert_eq!(builder.data.capacity(), count * (key.len() + value.len()));
        }
        key.fill(1);
        value.fill(2);
        let page = builder.finish();
        let start = page.get(0).unwrap().0.as_ptr() as usize;
        for (i, (k, v)) in page.iter().enumerate() {
            assert_eq!(k, &[0, 255, 17, 0]);
            assert_eq!(v, &[42; 256]);
            assert_eq!(k.as_ptr() as usize, start + i * 260);
            assert_eq!(v.as_ptr() as usize, start + i * 260 + 4);
        }
        assert_eq!(page.bytes(), count * (260 + 64));
        let clone = page.clone();
        drop(page);
        assert_eq!(clone.bytes(), count * (260 + 64));
        assert_eq!(clone.get(1023).unwrap().1, &[42; 256]);
    }

    #[test]
    fn packed_batch_capacity_not_visible_lengths_consumes_credits() {
        let mut builder = PageBuilder::default();
        assert!(builder.push(b"k", &[7; 99], 4, 1 << 20, 656).unwrap());
        assert_eq!(builder.data.capacity(), 400);
        // An irregular short next entry retains the initial unused allocation.
        assert!(builder.push(b"a", b"", 4, 1 << 20, 656).unwrap());
        assert_eq!(builder.bytes(), 400 + 2 * 64);
        assert!(!builder.push(b"long", &[8; 500], 4, 1 << 20, 656).unwrap());
        assert_eq!(builder.len(), 2);
        let page = builder.finish();
        assert_eq!(page.bytes(), 528);
        assert_eq!(
            page.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>(),
            101
        );
        assert_eq!(page.clone().bytes(), 528);
    }

    #[test]
    fn compact_offsets_finish_without_per_entry_owners_and_shrink_prefix_metadata() {
        let mut builder = PageBuilder::default();
        for i in 0..1024u32 {
            assert!(
                builder
                    .push(&i.to_be_bytes(), &[0xab; 256], 1024, 1 << 20, 1 << 20)
                    .unwrap()
            );
        }
        let mut finished = None;
        let allocations = crate::test_alloc::allocations(|| finished = Some(builder.finish()));
        assert_eq!(
            allocations, 0,
            "full preallocated batch needs no descriptor/refcount allocation at finish"
        );
        let page = finished.unwrap();
        assert_eq!(page.ends.len(), 1024);
        assert_eq!(
            page.get(1023).unwrap(),
            (1023u32.to_be_bytes().as_slice(), [0xab; 256].as_slice())
        );
        assert!(page.get(1024).is_none());
        let shared = page.clone();
        assert_eq!(shared.data.as_ptr(), page.data.as_ptr());
        assert_ne!(shared.ends.as_ptr(), page.ends.as_ptr());
        assert_eq!(shared.bytes(), page.bytes());
        drop(page);
        assert_eq!(shared.get(0).unwrap().0, &[0; 4]);

        let mut short = PageBuilder::default();
        assert!(short.push(b"", b"", 1024, 1 << 20, 1 << 20).unwrap());
        assert!(short.push(b"\0\xff", b"", 1024, 1 << 20, 1 << 20).unwrap());
        assert!(short.ends.capacity() > short.len());
        let short = short.finish();
        assert_eq!(
            short.ends.len(),
            2,
            "boxed offsets retain no unused reservation"
        );
        assert_eq!(short.get(0).unwrap(), (b"".as_slice(), b"".as_slice()));
        assert_eq!(
            short.get(1).unwrap(),
            (b"\0\xff".as_slice(), b"".as_slice())
        );
        assert_eq!(short.bytes(), short.payload_capacity + 128);
    }

    #[test]
    fn packed_batch_preserves_exact_tight_credit_and_oversized_first_entry() {
        for size in [0, 1, 4096, 300 << 10] {
            let mut builder = PageBuilder::default();
            let value = vec![9; size];
            let limit = 3 + size + 64;
            assert!(
                builder
                    .push(b"key", &value, 1024, 256 << 10, limit)
                    .unwrap()
            );
            assert_eq!(builder.bytes(), limit);
            assert!(!builder.push(b"z", b"", 1024, 256 << 10, limit).unwrap());
            assert_eq!(builder.finish().bytes(), limit);
        }
        let mut empty = PageBuilder::default();
        assert!(!empty.push(b"", b"", 1, 1, 63).unwrap());
        assert_eq!(empty.len(), 0);
        assert!(empty.push(b"", b"", 1, 1, 64).unwrap());
        assert_eq!(empty.finish().bytes(), 64);
    }
}
