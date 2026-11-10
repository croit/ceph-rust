// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Omap ops of a txn record (adr 0610 (1)): the batch blobs of `Op::OPut` / `Op::ODel` and their application to a
//! memtable without copying keys or values (entries are [`Bytes`] slices of the blob).
//!
//! `OPut` blob: per entry `le32 key length | key | le32 value length | value`, keys strictly ascending (the entry part
//! of a denc `map<string, bufferlist>`, so a client batch is taken as received). `ODel` blob: per key `le32 length |
//! key`, any order.

use super::Memtable;
use bytes::Bytes;

/// One omap op of a record: object `id` of the shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OOp {
    /// `n` entries (see the module doc).
    Put { id: u64, n: u32, blob: Bytes },
    /// Point deletes (see the module doc).
    Del { id: u64, blob: Bytes },
    /// Range delete `[first, end)`; `end = None`: to the object's last key (`first` empty: omap_clear / removal).
    Range {
        id: u64,
        first: Bytes,
        end: Option<Bytes>,
    },
}

impl OOp {
    pub fn id(&self) -> u64 {
        match self {
            OOp::Put { id, .. } | OOp::Del { id, .. } | OOp::Range { id, .. } => *id,
        }
    }
    /// Bytes the op adds to its record.
    pub fn wal_bytes(&self) -> usize {
        match self {
            OOp::Put { blob, .. } | OOp::Del { blob, .. } => blob.len(),
            OOp::Range { first, end, .. } => first.len() + end.as_ref().map_or(0, |e| e.len()),
        }
    }
    /// Apply to `mem` at `lsn` (ops of one record share its lsn; records apply in lsn order).
    pub fn apply(&self, mem: &mut Memtable, lsn: u64) {
        match self {
            OOp::Put { id, blob, .. } => mem.put_batch(lsn, *id, PutIter::new(blob)),
            OOp::Del { id, blob } => {
                for k in DelIter::new(blob) {
                    mem.del(lsn, *id, k);
                }
            }
            OOp::Range { id, first, end } => mem.del_range(lsn, *id, first.clone(), end.clone()),
        }
    }
    /// Structural check of a decoded op (lengths, strict key order of a put): `None` = corrupt.
    pub fn validate(&self) -> Option<()> {
        match self {
            OOp::Put { n, blob, .. } => {
                let (mut it, mut prev, mut c) = (PutIter::new(blob), None::<Bytes>, 0u32);
                for (k, _) in it.by_ref() {
                    if prev.as_ref().is_some_and(|p| p[..] >= k[..]) {
                        return None;
                    }
                    prev = Some(k);
                    c += 1;
                }
                (!it.bad && c == *n).then_some(())
            }
            OOp::Del { blob, .. } => {
                let mut it = DelIter::new(blob);
                it.by_ref().for_each(drop);
                (!it.bad).then_some(())
            }
            OOp::Range { first, end, .. } => end.as_ref().is_none_or(|e| first < e).then_some(()),
        }
    }
}

fn le32(b: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// Entries of an `OPut` blob; stops (and sets `bad`) at a truncated entry.
#[derive(Debug)]
pub struct PutIter<'b> {
    blob: &'b Bytes,
    pos: usize,
    pub bad: bool,
}

impl<'b> PutIter<'b> {
    pub fn new(blob: &'b Bytes) -> PutIter<'b> {
        PutIter {
            blob,
            pos: 0,
            bad: false,
        }
    }
}

impl Iterator for PutIter<'_> {
    type Item = (Bytes, Bytes);
    fn next(&mut self) -> Option<(Bytes, Bytes)> {
        if self.pos == self.blob.len() || self.bad {
            return None;
        }
        let b = &self.blob[..];
        let p = self.pos;
        let r = (|| {
            let kl = le32(b, p)?;
            let ks = p + 4;
            let vl = le32(b, ks.checked_add(kl)?)?;
            let vs = ks + kl + 4;
            (vs.checked_add(vl)? <= b.len()).then_some((ks, kl, vs, vl))
        })();
        let Some((ks, kl, vs, vl)) = r else {
            self.bad = true;
            return None;
        };
        self.pos = vs + vl;
        Some((self.blob.slice(ks..ks + kl), self.blob.slice(vs..vs + vl)))
    }
}

/// Keys of an `ODel` blob; stops (and sets `bad`) at a truncated key.
#[derive(Debug)]
pub struct DelIter<'b> {
    blob: &'b Bytes,
    pos: usize,
    pub bad: bool,
}

impl<'b> DelIter<'b> {
    pub fn new(blob: &'b Bytes) -> DelIter<'b> {
        DelIter {
            blob,
            pos: 0,
            bad: false,
        }
    }
}

impl Iterator for DelIter<'_> {
    type Item = Bytes;
    fn next(&mut self) -> Option<Bytes> {
        if self.pos == self.blob.len() || self.bad {
            return None;
        }
        let p = self.pos;
        let Some(kl) = le32(self.blob, p).filter(|kl| p + 4 + kl <= self.blob.len()) else {
            self.bad = true;
            return None;
        };
        self.pos = p + 4 + kl;
        Some(self.blob.slice(p + 4..p + 4 + kl))
    }
}

/// `OPut` blob of `pairs` (any order; a key given twice keeps its last value). Returns `(entries, blob)`.
pub fn put_blob<K: AsRef<[u8]>, V: AsRef<[u8]>>(pairs: &[(K, V)]) -> (u32, Bytes) {
    let mut ix: Vec<usize> = (0..pairs.len()).collect();
    // stable: equal keys keep their txn order, the last one wins below
    ix.sort_by(|&a, &b| pairs[a].0.as_ref().cmp(pairs[b].0.as_ref()));
    let mut out = Vec::with_capacity(
        pairs
            .iter()
            .map(|(k, v)| 8 + k.as_ref().len() + v.as_ref().len())
            .sum(),
    );
    let mut n = 0u32;
    for (j, &i) in ix.iter().enumerate() {
        let k = pairs[i].0.as_ref();
        if ix.get(j + 1).is_some_and(|&x| pairs[x].0.as_ref() == k) {
            continue;
        }
        let v = pairs[i].1.as_ref();
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
        n += 1;
    }
    (n, Bytes::from(out))
}

/// `ODel` blob of `keys`.
pub fn del_blob<K: AsRef<[u8]>>(keys: &[K]) -> Bytes {
    let mut out = Vec::with_capacity(keys.iter().map(|k| 4 + k.as_ref().len()).sum());
    for k in keys {
        out.extend_from_slice(&(k.as_ref().len() as u32).to_le_bytes());
        out.extend_from_slice(k.as_ref());
    }
    Bytes::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_blob_sorts_and_keeps_the_last_value() {
        let pairs: Vec<(&[u8], &[u8])> = vec![(b"b", b"1"), (b"a", b"2"), (b"b", b"3")];
        let (n, blob) = put_blob(&pairs);
        assert_eq!(n, 2);
        let got: Vec<(Bytes, Bytes)> = PutIter::new(&blob).collect();
        assert_eq!(got.len(), 2);
        assert_eq!((&got[0].0[..], &got[0].1[..]), (&b"a"[..], &b"2"[..]));
        assert_eq!((&got[1].0[..], &got[1].1[..]), (&b"b"[..], &b"3"[..]));
        assert!(OOp::Put { id: 1, n, blob }.validate().is_some());
    }

    #[test]
    fn validate_refuses_unsorted_and_truncated_blobs() {
        let (_, good) = put_blob(&[(b"a", b"x"), (b"b", b"y")]);
        let mut bad = good.to_vec();
        bad.pop();
        assert!(
            OOp::Put {
                id: 1,
                n: 2,
                blob: Bytes::from(bad)
            }
            .validate()
            .is_none()
        );
        assert!(
            OOp::Put {
                id: 1,
                n: 3,
                blob: good.clone()
            }
            .validate()
            .is_none()
        );
        // swap the two entries: not ascending
        let half = good.len() / 2;
        let swapped = [&good[half..], &good[..half]].concat();
        assert!(
            OOp::Put {
                id: 1,
                n: 2,
                blob: Bytes::from(swapped)
            }
            .validate()
            .is_none()
        );
        let d = del_blob(&[b"k".as_slice(), b"j"]);
        assert_eq!(DelIter::new(&d).count(), 2);
        assert!(
            OOp::Del {
                id: 1,
                blob: d.slice(..d.len() - 1)
            }
            .validate()
            .is_none()
        );
    }
}
