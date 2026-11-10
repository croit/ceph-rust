// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Ceph-shaped object transaction (the L2 API, design 2.2). All ops of one `OTxn` are applied atomically,
//! in order, to ONE shard (all collections must map to the same shard).
//!
//! Semantics (match `peering::MemStore` / replication.md 1.6):
//! * Implicit create: `Touch`, `Write`, `Zero`, `SetAttrs`, `OmapSetKeys`, `OmapSetHeader`.
//! * No-op on a missing object: `Truncate`, `Remove`, `RmAttr(s)`, `OmapRmKeys`, `OmapRmKeyRange`, `OmapClear`,
//!   `MoveRename`.
//! * `Clone` / `CloneRange` of a missing source: `Err(NoEnt)` (the txn is not applied).
//! * `Clone` and `MoveRename` replace an existing destination.
//! * Any other missing collection: `Err(NoColl)`.

use denc::types::{CollT, Ghobject};
pub type Bytes<'a> = super::dirty::Data<'a>;

/// A sorted key/value run: `n` entries of a `map<string,bufferlist>` encoding after its count ([`denc::SortedKv`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvRunData<'a> {
    n: u32,
    ents: Bytes<'a>,
}

impl<'a> KvRunData<'a> {
    /// `ents` = the entries of a [`denc::SortedKv`] (validated by its constructor).
    pub fn new(run: denc::SortedKv<'a>) -> Self {
        KvRunData {
            n: run.len() as u32,
            ents: Bytes::Borrowed(run.entries()),
        }
    }
    /// Owned run from a map encoding (count included); `None` unless its keys are strictly ascending.
    pub fn from_encoding(enc: bytes::Bytes) -> Option<KvRunData<'static>> {
        let n = match denc::SortedKv::parse(&enc) {
            Ok(denc::KvShape::Sorted(r)) => r.len() as u32,
            _ => return None,
        };
        Some(KvRunData {
            n,
            ents: Bytes::Shared(enc.slice(4..)),
        })
    }
    pub fn view(&self) -> denc::SortedKv<'_> {
        denc::SortedKv::trusted(self.n as usize, &self.ents)
    }
    pub fn len(&self) -> usize {
        self.n as usize
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    /// `(entries, blob)` of an omap LSM put (`olsm::wire::OOp::Put` has the same entry encoding); a run held as shared
    /// bytes is taken by reference, a borrowed one is copied once.
    pub fn blob(&self) -> (u32, bytes::Bytes) {
        let b = match &self.ents {
            Bytes::Shared(b) => b.clone(),
            Bytes::Owned(v) => bytes::Bytes::copy_from_slice(v),
            Bytes::Borrowed(s) => bytes::Bytes::copy_from_slice(s),
        };
        (self.n, b)
    }
    /// Entry bytes (keys and values with their length prefixes).
    pub fn bytes(&self) -> usize {
        self.ents.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TOp<'a> {
    /// `exist_ok`: creating an existing collection is a no-op instead of `Err(Exists)`.
    MkColl {
        cid: CollT,
        bits: u32,
        exist_ok: bool,
    },
    /// Collection must be empty.
    RmColl {
        cid: CollT,
    },
    SetCollBits {
        cid: CollT,
        bits: u32,
    },
    /// Data version tracking of the collection's objects on / off (adr 0593-dedup-deep-scrub-reformat). Switching it on
    /// starts a new tracking generation; repeating the current state changes nothing. Store with `FEAT_DEDUP` only.
    SetCollDvTrack {
        cid: CollT,
        on: bool,
    },
    Touch {
        cid: CollT,
        oid: Ghobject,
    },
    /// Dedup info records (adr 0593-dedup-deep-scrub-reformat, `super::dedup`) of device shard `shard`: at most one range
    /// delete, then puts, then deletes, of `D` keys only (any other key is refused). Records are hints: the caller writes them through
    /// [`super::Store::try_local`] (staged now or dropped).
    DedupKv {
        shard: u32,
        puts: Vec<(Vec<u8>, Vec<u8>)>,
        dels: Vec<Vec<u8>>,
        del_range: Option<(Vec<u8>, Vec<u8>)>,
    },
    /// Store-local rewrite of unchanged data (adr 0593-dedup-deep-scrub-reformat, deep-scrub reformat engines): `data`
    /// are the object's bytes at `off` as read; they are written again (new allocation, the txn's `comp`) only if the
    /// object still has data state `expect` (onode id, tracking generation, data version) and `off + data.len()` lies
    /// inside it. The data version is not bumped and nothing outside the store learns of it. `max_frags` > 0: applied
    /// only if the rewritten range then has fewer merged physical intervals than that. Not applied = `ObjError::Stale`,
    /// nothing staged. The txn holds no other op.
    Reformat {
        cid: CollT,
        oid: Ghobject,
        off: u64,
        data: Bytes<'a>,
        expect: super::DataVersion,
        max_frags: u32,
    },
    Write {
        cid: CollT,
        oid: Ghobject,
        off: u64,
        data: Bytes<'a>,
    },
    Zero {
        cid: CollT,
        oid: Ghobject,
        off: u64,
        len: u64,
    },
    Truncate {
        cid: CollT,
        oid: Ghobject,
        size: u64,
    },
    Remove {
        cid: CollT,
        oid: Ghobject,
    },
    SetAttrs {
        cid: CollT,
        oid: Ghobject,
        attrs: Vec<(Bytes<'a>, Bytes<'a>)>,
    },
    RmAttr {
        cid: CollT,
        oid: Ghobject,
        name: Bytes<'a>,
    },
    RmAttrs {
        cid: CollT,
        oid: Ghobject,
    },
    Clone {
        cid: CollT,
        src: Ghobject,
        dst: Ghobject,
    },
    CloneRange {
        cid: CollT,
        src: Ghobject,
        dst: Ghobject,
        src_off: u64,
        len: u64,
        dst_off: u64,
    },
    /// Move `oid` of `cid` to `doid` of `dcid` (same shard); keeps the onode (data is not copied).
    MoveRename {
        cid: CollT,
        oid: Ghobject,
        dcid: CollT,
        doid: Ghobject,
    },
    OmapSetKeys {
        cid: CollT,
        oid: Ghobject,
        pairs: Vec<(Bytes<'a>, Bytes<'a>)>,
    },
    /// `OmapSetKeys` of a run of strictly ascending keys kept as its map encoding (a client batch; same semantics).
    OmapSetRun {
        cid: CollT,
        oid: Ghobject,
        run: KvRunData<'a>,
    },
    OmapRmKeys {
        cid: CollT,
        oid: Ghobject,
        keys: Vec<Bytes<'a>>,
    },
    /// Delete keys in `[first, last)`.
    OmapRmKeyRange {
        cid: CollT,
        oid: Ghobject,
        first: Bytes<'a>,
        last: Bytes<'a>,
    },
    OmapClear {
        cid: CollT,
        oid: Ghobject,
    },
    OmapSetHeader {
        cid: CollT,
        oid: Ghobject,
        header: Bytes<'a>,
    },
}

impl TOp<'_> {
    /// Owned continuation; only used when staging yields. Successful hot submissions keep borrowing.
    pub fn into_owned(self) -> TOp<'static> {
        self.into_retained(&[])
    }
    fn into_retained(self, owners: &[bytes::Bytes]) -> TOp<'static> {
        use TOp::*;
        let b = |v: Bytes<'_>| v.retained(owners);
        match self {
            MkColl {
                cid,
                bits,
                exist_ok,
            } => MkColl {
                cid,
                bits,
                exist_ok,
            },
            RmColl { cid } => RmColl { cid },
            SetCollBits { cid, bits } => SetCollBits { cid, bits },
            SetCollDvTrack { cid, on } => SetCollDvTrack { cid, on },
            DedupKv {
                shard,
                puts,
                dels,
                del_range,
            } => DedupKv {
                shard,
                puts,
                dels,
                del_range,
            },
            Touch { cid, oid } => Touch { cid, oid },
            Reformat {
                cid,
                oid,
                off,
                data,
                expect,
                max_frags,
            } => Reformat {
                cid,
                oid,
                off,
                data: b(data),
                expect,
                max_frags,
            },
            Write {
                cid,
                oid,
                off,
                data,
            } => Write {
                cid,
                oid,
                off,
                data: b(data),
            },
            Zero { cid, oid, off, len } => Zero { cid, oid, off, len },
            Truncate { cid, oid, size } => Truncate { cid, oid, size },
            Remove { cid, oid } => Remove { cid, oid },
            SetAttrs { cid, oid, attrs } => SetAttrs {
                cid,
                oid,
                attrs: attrs.into_iter().map(|(k, v)| (b(k), b(v))).collect(),
            },
            RmAttr { cid, oid, name } => RmAttr {
                cid,
                oid,
                name: b(name),
            },
            RmAttrs { cid, oid } => RmAttrs { cid, oid },
            Clone { cid, src, dst } => Clone { cid, src, dst },
            CloneRange {
                cid,
                src,
                dst,
                src_off,
                len,
                dst_off,
            } => CloneRange {
                cid,
                src,
                dst,
                src_off,
                len,
                dst_off,
            },
            MoveRename {
                cid,
                oid,
                dcid,
                doid,
            } => MoveRename {
                cid,
                oid,
                dcid,
                doid,
            },
            OmapSetKeys { cid, oid, pairs } => OmapSetKeys {
                cid,
                oid,
                pairs: pairs.into_iter().map(|(k, v)| (b(k), b(v))).collect(),
            },
            OmapSetRun { cid, oid, run } => OmapSetRun {
                cid,
                oid,
                run: KvRunData {
                    n: run.n,
                    ents: b(run.ents),
                },
            },
            OmapRmKeys { cid, oid, keys } => OmapRmKeys {
                cid,
                oid,
                keys: keys.into_iter().map(b).collect(),
            },
            OmapRmKeyRange {
                cid,
                oid,
                first,
                last,
            } => OmapRmKeyRange {
                cid,
                oid,
                first: b(first),
                last: b(last),
            },
            OmapClear { cid, oid } => OmapClear { cid, oid },
            OmapSetHeader { cid, oid, header } => OmapSetHeader {
                cid,
                oid,
                header: b(header),
            },
        }
    }

    pub(crate) fn objects(&self) -> [Option<(&CollT, &Ghobject)>; 2] {
        use TOp::*;
        match self {
            Clone { cid, src, dst } | CloneRange { cid, src, dst, .. } => {
                [Some((cid, src)), Some((cid, dst))]
            }
            MoveRename {
                cid,
                oid,
                dcid,
                doid,
            } => [Some((cid, oid)), Some((dcid, doid))],
            MkColl { .. }
            | RmColl { .. }
            | SetCollBits { .. }
            | SetCollDvTrack { .. }
            | DedupKv { .. } => [None, None],
            Touch { cid, oid }
            | Reformat { cid, oid, .. }
            | Write { cid, oid, .. }
            | Zero { cid, oid, .. }
            | Truncate { cid, oid, .. }
            | Remove { cid, oid }
            | SetAttrs { cid, oid, .. }
            | RmAttr { cid, oid, .. }
            | RmAttrs { cid, oid }
            | OmapSetKeys { cid, oid, .. }
            | OmapSetRun { cid, oid, .. }
            | OmapRmKeys { cid, oid, .. }
            | OmapRmKeyRange { cid, oid, .. }
            | OmapClear { cid, oid }
            | OmapSetHeader { cid, oid, .. } => [Some((cid, oid)), None],
        }
    }

    /// Collections the op names.
    pub fn colls(&self) -> [Option<&CollT>; 2] {
        use TOp::*;
        match self {
            MoveRename { cid, dcid, .. } => [Some(cid), Some(dcid)],
            MkColl { cid, .. }
            | RmColl { cid }
            | SetCollBits { cid, .. }
            | SetCollDvTrack { cid, .. }
            | Touch { cid, .. }
            | Reformat { cid, .. }
            | Write { cid, .. }
            | Zero { cid, .. }
            | Truncate { cid, .. }
            | Remove { cid, .. }
            | SetAttrs { cid, .. }
            | RmAttr { cid, .. }
            | RmAttrs { cid, .. }
            | Clone { cid, .. }
            | CloneRange { cid, .. }
            | OmapSetKeys { cid, .. }
            | OmapSetRun { cid, .. }
            | OmapRmKeys { cid, .. }
            | OmapRmKeyRange { cid, .. }
            | OmapClear { cid, .. }
            | OmapSetHeader { cid, .. } => [Some(cid), None],
            DedupKv { .. } => [None, None],
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OTxn<'a> {
    pub ops: Vec<TOp<'a>>,
    /// System-class txn: may use the meta and data reserves (ADR 0021 amendment 6). Set for work that was already
    /// admitted (`Store::write_room`) or must always succeed (PG state, replica applies).
    pub sys: bool,
    /// The caller asserts this txn starts freeing space (PG removal marker; adr 0021 S4): staged as a pure shrink when it
    /// adds nothing but PG bookkeeping (pgmeta omap), like a txn with a remove op.
    pub frees: bool,
    /// Compress the chunk-aligned full-chunk writes of this txn (adr 0059 am. 1); resolved by the adapter from the pool
    /// options and the alloc hints. `None` = every write stored raw. Ignored by a store without `FEAT_COMPRESSION`.
    pub comp: Option<crate::compress::CompSpec>,
    /// Payload buffers the writes of this txn borrow from, with their receive-pass block crcs when known (adr 0061
    /// am. 4): staging writes them to the device by reference and reuses the crcs (no copy, no crc pass).
    pub payloads: Payloads,
}

/// [`OTxn::payloads`]: a hint, not content (always equal).
#[derive(Clone, Debug, Default)]
pub struct Payloads(pub Vec<crc::Payload>);

impl PartialEq for Payloads {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for Payloads {}

impl<'a> OTxn<'a> {
    /// Keep immutable write owners when translating a queued input once.
    pub(crate) fn shared(self, owners: &[bytes::Bytes]) -> OTxn<'static> {
        OTxn {
            sys: self.sys,
            frees: self.frees,
            comp: self.comp,
            payloads: self.payloads,
            ops: self
                .ops
                .into_iter()
                .map(|op| op.into_retained(owners))
                .collect(),
        }
    }

    pub(crate) fn payload_owners(&self) -> Vec<bytes::Bytes> {
        self.ops
            .iter()
            .filter_map(|op| match op {
                TOp::Write {
                    data: Bytes::Shared(data),
                    ..
                } => Some(data.clone()),
                _ => None,
            })
            .collect()
    }
    pub(crate) fn owned(&self) -> OTxn<'static> {
        OTxn {
            ops: self.ops.clone().into_iter().map(TOp::into_owned).collect(),
            sys: self.sys,
            frees: self.frees,
            comp: self.comp,
            payloads: Payloads::default(),
        }
    }

    /// Payload/metadata bytes retained by an owned continuation (allocation headers are separate).
    pub fn retained_bytes(&self) -> usize {
        self.ops
            .iter()
            .map(|op| {
                let names: usize = op
                    .objects()
                    .into_iter()
                    .flatten()
                    .map(|(_, o)| super::keys::name_key_len(o))
                    .sum();
                names
                    + std::mem::size_of::<TOp>()
                    + match op {
                        TOp::Write { data, .. } | TOp::Reformat { data, .. } => data.len(),
                        TOp::SetAttrs { attrs, .. } => {
                            attrs.iter().map(|(k, v)| k.len() + v.len()).sum()
                        }
                        TOp::RmAttr { name, .. } => name.len(),
                        TOp::OmapSetKeys { pairs, .. } => {
                            pairs.iter().map(|(k, v)| k.len() + v.len()).sum()
                        }
                        TOp::OmapSetRun { run, .. } => run.bytes(),
                        TOp::OmapRmKeys { keys, .. } => keys.iter().map(|k| k.len()).sum(),
                        TOp::OmapRmKeyRange { first, last, .. } => first.len() + last.len(),
                        TOp::OmapSetHeader { header, .. } => header.len(),
                        _ => 0,
                    }
            })
            .sum()
    }

    pub fn new() -> Self {
        OTxn::default()
    }
    pub fn push(&mut self, op: TOp<'a>) -> &mut Self {
        self.ops.push(op);
        self
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
    pub fn mkcoll(&mut self, cid: CollT) -> &mut Self {
        self.push(TOp::MkColl {
            cid,
            bits: 0,
            exist_ok: false,
        })
    }
    pub fn touch(&mut self, cid: CollT, oid: &Ghobject) -> &mut Self {
        self.push(TOp::Touch {
            cid,
            oid: oid.clone(),
        })
    }
    pub fn write(&mut self, cid: CollT, oid: &Ghobject, off: u64, data: &'a [u8]) -> &mut Self {
        self.push(TOp::Write {
            cid,
            oid: oid.clone(),
            off,
            data: Bytes::Borrowed(data),
        })
    }
    pub fn zero(&mut self, cid: CollT, oid: &Ghobject, off: u64, len: u64) -> &mut Self {
        self.push(TOp::Zero {
            cid,
            oid: oid.clone(),
            off,
            len,
        })
    }
    pub fn truncate(&mut self, cid: CollT, oid: &Ghobject, size: u64) -> &mut Self {
        self.push(TOp::Truncate {
            cid,
            oid: oid.clone(),
            size,
        })
    }
    pub fn remove(&mut self, cid: CollT, oid: &Ghobject) -> &mut Self {
        self.push(TOp::Remove {
            cid,
            oid: oid.clone(),
        })
    }
    pub fn setattr(
        &mut self,
        cid: CollT,
        oid: &Ghobject,
        name: &'a [u8],
        val: &'a [u8],
    ) -> &mut Self {
        self.push(TOp::SetAttrs {
            cid,
            oid: oid.clone(),
            attrs: vec![(Bytes::Borrowed(name), Bytes::Borrowed(val))],
        })
    }
    pub fn omap_set(&mut self, cid: CollT, oid: &Ghobject, k: &'a [u8], v: &'a [u8]) -> &mut Self {
        self.push(TOp::OmapSetKeys {
            cid,
            oid: oid.clone(),
            pairs: vec![(Bytes::Borrowed(k), Bytes::Borrowed(v))],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::{Hobject, PgT, ShardId, SnapId, SpgT};

    /// The retained-byte account of a parked txn measures an object's name key without building one: the admission
    /// path of every txn takes no heap allocation per object.
    #[test]
    fn retained_bytes_does_not_allocate() {
        let cid = CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        });
        let oid = Ghobject::new(
            Hobject::new(b"obj", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let mut t = OTxn::new();
        t.write(cid, &oid, 0, &[]);
        let n = crate::test_alloc::allocations(|| {
            let _ = t.retained_bytes();
        });
        assert_eq!(n, 0, "retained_bytes allocated a name key");
    }
}
