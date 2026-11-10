// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! In-memory journal backend and image for native journal tests.
//!
//! Testkit only: compiled out of non-test builds without feature
//! `journal-testkit`, zero cost in production. `MemJournalBackend` executes
//! the cls `journal` method semantics of `doc/spec/cls_journal.md` over
//! shared in-memory state, so native tests exercise the real codecs against
//! faithful class behavior without a cluster. `MemImage` is the in-memory
//! replay target. `FaultPlan::crash_after(k)` makes every durable mutation
//! after the k-th one (journal or image) fail with [`CRASH_ERRNO`] and
//! change nothing, modeling a process crash at every mutation boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crate::journal_backend::{
    EEXIST, EILSEQ, EINVAL, ENOENT, EOPNOTSUPP, EOVERFLOW, ESTALE, JournalBackend,
};
use crate::journal_event::{JournalEvent, JournalEventKind};
use crate::journal_recovery::ReplayTarget;
use crate::{
    JOURNAL_CLIENT_STATE_CONNECTED, JOURNAL_CLIENT_STATE_DISCONNECTED, JOURNAL_TAG_CLASS_NEW,
    JournalGeometry, JournalObjectPosition, encode_positions,
};

pub use crate::fault_plan::{CRASH_ERRNO, FaultPlan};

/// Durable journal state: header fields, clients, tags and data objects.
///
/// Shared across the process instances that model a crash and its recovery;
/// it holds exactly what the cls `journal` class stores (header fields,
/// client and tag records, plain data objects).
#[derive(Debug, Default, Clone)]
pub struct MemJournalStore {
    header: Option<Header>,
    clients: BTreeMap<Vec<u8>, ClientRec>,
    tags: BTreeMap<u64, TagRec>,
    objects: BTreeMap<u64, Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Header {
    order: u8,
    splay_width: u8,
    pool_id: i64,
    minimum_set: u64,
    active_set: u64,
    next_tag_tid: u64,
    next_tag_class: u64,
}

#[derive(Debug, Clone)]
struct ClientRec {
    id: Vec<u8>,
    data: Vec<u8>,
    positions: Vec<JournalObjectPosition>,
    state: u8,
}

#[derive(Debug, Clone)]
struct TagRec {
    tid: u64,
    tag_class: u64,
    data: Vec<u8>,
}

impl MemJournalStore {
    /// `create`: `-EEXIST` when the header exists.
    fn create(&mut self, order: u8, splay_width: u8, pool_id: i64) -> Result<(), i32> {
        if self.header.is_some() {
            return Err(EEXIST);
        }
        self.header = Some(Header {
            order,
            splay_width,
            pool_id,
            minimum_set: 0,
            active_set: 0,
            next_tag_tid: 0,
            next_tag_class: 0,
        });
        Ok(())
    }

    /// `remove_header`: `-ENOENT` when absent.
    fn remove_header(&mut self) -> Result<(), i32> {
        if self.header.take().is_none() {
            return Err(ENOENT);
        }
        Ok(())
    }

    /// The header geometry, `-ENOENT` when the header is absent.
    fn geometry(&self) -> Result<JournalGeometry, i32> {
        let header = self.header.as_ref().ok_or(ENOENT)?;
        Ok(JournalGeometry {
            order: header.order,
            splay_width: header.splay_width,
            pool_id: header.pool_id,
            minimum_set: header.minimum_set,
            active_set: header.active_set,
        })
    }

    /// `set_minimum_set`: `-ENOENT` without a journal, `-EINVAL` above the
    /// active set, `-ESTALE` backwards, no write when unchanged.
    fn set_minimum_set(&mut self, set: u64) -> Result<(), i32> {
        let header = self.header.as_mut().ok_or(ENOENT)?;
        if header.active_set < set {
            return Err(EINVAL);
        }
        if set == header.minimum_set {
            return Ok(());
        }
        if set < header.minimum_set {
            return Err(ESTALE);
        }
        header.minimum_set = set;
        Ok(())
    }

    /// `set_active_set`: `-EINVAL` below the minimum set, `-ESTALE`
    /// backwards, no write when unchanged.
    fn set_active_set(&mut self, set: u64) -> Result<(), i32> {
        let header = self.header.as_mut().ok_or(ENOENT)?;
        if header.minimum_set > set {
            return Err(EINVAL);
        }
        if set == header.active_set {
            return Ok(());
        }
        if set < header.active_set {
            return Err(ESTALE);
        }
        header.active_set = set;
        Ok(())
    }

    /// `get_client`: the raw `Client` record, `-ENOENT` when absent.
    fn get_client(&self, id: &[u8]) -> Result<Vec<u8>, i32> {
        Ok(encode_client(self.clients.get(id).ok_or(ENOENT)?))
    }

    /// `client_register`: `-ENOENT` without a journal, `-EEXIST` for a
    /// duplicate; the new client inherits the minimum commit position.
    fn client_register(&mut self, id: &[u8], data: &[u8]) -> Result<(), i32> {
        if self.header.is_none() {
            return Err(ENOENT);
        }
        if self.clients.contains_key(id) {
            return Err(EEXIST);
        }
        let positions = find_min_commit_position(&self.clients);
        self.clients.insert(
            id.to_vec(),
            ClientRec {
                id: id.to_vec(),
                data: data.to_vec(),
                positions,
                state: JOURNAL_CLIENT_STATE_CONNECTED,
            },
        );
        Ok(())
    }

    /// `client_commit`: `-ENOENT` without a journal or client, `-EINVAL`
    /// for more positions than splays, no write when unchanged.
    fn client_commit(&mut self, id: &[u8], positions: &[JournalObjectPosition]) -> Result<(), i32> {
        let width = self.header.as_ref().ok_or(ENOENT)?.splay_width as usize;
        if positions.len() > width {
            return Err(EINVAL);
        }
        let client = self.clients.get_mut(id).ok_or(ENOENT)?;
        if client.positions == positions {
            return Ok(());
        }
        client.positions = positions.to_vec();
        Ok(())
    }

    /// `client_list`: raw `set<Client>` ascending by ID after
    /// `start_after`, at most `min(max, 1024)` entries; an absent header
    /// yields the empty set.
    fn client_list(&self, start_after: &[u8], max: u64) -> Vec<u8> {
        let limit = max.min(1024) as usize;
        let clients = self
            .clients
            .iter()
            .filter(|(id, _)| start_after.is_empty() || id.as_slice() > start_after)
            .take(limit)
            .map(|(_, client)| client.clone())
            .collect::<Vec<ClientRec>>();
        encode_client_set(&clients)
    }

    /// `get_next_tag_tid`, `-ENOENT` without a journal.
    fn get_next_tag_tid(&self) -> Result<u64, i32> {
        Ok(self.header.as_ref().ok_or(ENOENT)?.next_tag_tid)
    }

    /// `get_tag`: the raw `Tag` record, `-ENOENT` when absent.
    fn get_tag(&self, tid: u64) -> Result<Vec<u8>, i32> {
        Ok(encode_tag(self.tags.get(&tid).ok_or(ENOENT)?))
    }

    /// `tag_create`: `-EEXIST` for a duplicate TID, `-ESTALE` when the TID
    /// is not the next one, class allocation for `TAG_CLASS_NEW`, then
    /// `expire_tags` and the header update.
    fn tag_create(&mut self, tid: u64, tag_class: u64, data: &[u8]) -> Result<(), i32> {
        if self.tags.contains_key(&tid) {
            return Err(EEXIST);
        }
        let class = {
            let header = self.header.as_mut().ok_or(ENOENT)?;
            if tid != header.next_tag_tid {
                return Err(ESTALE);
            }
            if tag_class == JOURNAL_TAG_CLASS_NEW {
                let class = header.next_tag_class;
                header.next_tag_class = header.next_tag_class.wrapping_add(1);
                class
            } else {
                if tag_class >= header.next_tag_class {
                    return Err(EINVAL);
                }
                tag_class
            }
        };
        expire_tags(&self.clients, &mut self.tags, &[])?;
        if let Some(header) = self.header.as_mut() {
            header.next_tag_tid = tid.wrapping_add(1);
        }
        self.tags.insert(
            tid,
            TagRec {
                tid,
                tag_class: class,
                data: data.to_vec(),
            },
        );
        Ok(())
    }

    /// `tag_list`: raw `set<Tag>` after `start_after`, hidden by the commit
    /// position of `client_id`, filtered by the optional class.
    fn tag_list(
        &self,
        start_after: u64,
        max: u64,
        client_id: &[u8],
        tag_class: Option<u64>,
    ) -> Result<Vec<u8>, i32> {
        let client = self.clients.get(client_id).ok_or(ENOENT)?;
        let min_tid = client
            .positions
            .iter()
            .map(|position| position.tag_tid)
            .min();
        let class_min = class_min_for(min_tid, &self.tags);
        let mut tags = Vec::new();
        for (tid, tag) in &self.tags {
            if start_after != 0 && *tid <= start_after {
                continue;
            }
            let visible = *tid >= class_min.get(&tag.tag_class).copied().unwrap_or(0)
                && tag_class.is_none_or(|class| tag.tag_class == class);
            if visible {
                tags.push(tag.clone());
            }
            if tags.len() as u64 >= max {
                break;
            }
        }
        Ok(encode_tag_set(&tags))
    }

    /// `append`: `-EOVERFLOW` when the object size reaches `soft_max`
    /// (nothing written); otherwise append at the current size and
    /// zero-extend to the allocation alignment.
    fn append(
        &mut self,
        object_number: u64,
        soft_max: u64,
        bytes: &[u8],
        min_alloc_size: u64,
    ) -> Result<(), i32> {
        let size = self
            .objects
            .get(&object_number)
            .map(|object| object.len() as u64)
            .unwrap_or(0);
        if size >= soft_max {
            return Err(EOVERFLOW);
        }
        let end = size + bytes.len() as u64;
        let object = self.objects.entry(object_number).or_default();
        object.extend_from_slice(bytes);
        let align = min_alloc_size.max(8);
        let padded = end.div_ceil(align) * align;
        object.resize(padded as usize, 0);
        Ok(())
    }

    /// Create an empty data object (present, zero bytes).
    fn touch_object(&mut self, object_number: u64) {
        self.objects.entry(object_number).or_default();
    }

    /// Read up to `buf` bytes at `offset`; `-ENOENT` for an absent object,
    /// a short read (including zero) means the object end.
    fn read_object(&self, object_number: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        let object = self.objects.get(&object_number).ok_or(ENOENT)?;
        let start = offset as usize;
        if start >= object.len() {
            return Ok(0);
        }
        let take = buf.len().min(object.len() - start);
        buf[..take].copy_from_slice(&object[start..start + take]);
        Ok(take)
    }

    /// Remove one data object; `-ENOENT` when absent.
    fn remove_object(&mut self, object_number: u64) -> Result<(), i32> {
        if self.objects.remove(&object_number).is_none() {
            Err(ENOENT)
        } else {
            Ok(())
        }
    }

    /// Replace one data object's bytes verbatim (no append padding); the
    /// testkit way to place hand-built or corrupt object content.
    fn write_raw_object(&mut self, object_number: u64, bytes: &[u8]) {
        self.objects.insert(object_number, bytes.to_vec());
    }
}

/// cls `find_min_commit_position` (bug-compatible): the commit position a
/// newly registered client inherits from the existing clients.
///
/// Clients are scanned in ID order in batches of 256. DISCONNECTED clients
/// are skipped; a client with empty positions resets the result and stops
/// the scan of this batch only (later batches may overwrite it, with no
/// valid candidate); otherwise the first position is the candidate and
/// replaces the result when none is valid yet or its `(tag_tid, entry_tid)`
/// is lexicographically smaller. The result is that client's whole
/// position.
fn find_min_commit_position(clients: &BTreeMap<Vec<u8>, ClientRec>) -> Vec<JournalObjectPosition> {
    let ids: Vec<&Vec<u8>> = clients.keys().collect();
    let mut inherited: Vec<JournalObjectPosition> = Vec::new();
    let mut valid = false;
    for batch in ids.chunks(256) {
        for id in batch {
            let client = &clients[*id];
            if client.state == JOURNAL_CLIENT_STATE_DISCONNECTED {
                continue;
            }
            if client.positions.is_empty() {
                inherited.clear();
                valid = false;
                break;
            }
            let candidate = client.positions[0];
            let smaller = valid
                && (candidate.tag_tid, candidate.entry_tid)
                    < (inherited[0].tag_tid, inherited[0].entry_tid);
            if !valid || smaller {
                inherited = client.positions.clone();
                valid = true;
            }
        }
        if batch.len() < 256 {
            break;
        }
    }
    inherited
}

/// Pass 1 of `tag_list` / `expire_tags`: for each tag class the highest TID
/// at or below `min_tid`; empty when `min_tid` is absent.
fn class_min_for(min_tid: Option<u64>, tags: &BTreeMap<u64, TagRec>) -> BTreeMap<u64, u64> {
    let Some(min_tid) = min_tid else {
        return BTreeMap::new();
    };
    let mut class_min = BTreeMap::new();
    for (tid, tag) in tags {
        class_min.insert(tag.tag_class, *tid);
        if *tid >= min_tid {
            break;
        }
    }
    class_min
}

/// `expire_tags(skip)`: delete every tag with a TID below the newest
/// same-class tag at or below the oldest commit TID of all connected,
/// non-empty clients; nothing is expired while any connected client has
/// empty positions or no positions exist.
fn expire_tags(
    clients: &BTreeMap<Vec<u8>, ClientRec>,
    tags: &mut BTreeMap<u64, TagRec>,
    skip: &[u8],
) -> Result<(), i32> {
    let mut min_tid: Option<u64> = None;
    for client in clients.values() {
        if client.id.as_slice() == skip {
            continue;
        }
        if client.state == JOURNAL_CLIENT_STATE_DISCONNECTED {
            continue;
        }
        if client.positions.is_empty() {
            return Ok(());
        }
        let oldest = client
            .positions
            .iter()
            .map(|position| position.tag_tid)
            .min()
            .unwrap();
        min_tid = Some(min_tid.map_or(oldest, |current| current.min(oldest)));
    }
    let Some(min_tid) = min_tid else {
        return Ok(());
    };
    let class_min = class_min_for(Some(min_tid), tags);
    let expired = tags
        .iter()
        .take_while(|(tid, _)| **tid < min_tid)
        .filter(|(tid, tag)| **tid < class_min.get(&tag.tag_class).copied().unwrap_or(0))
        .map(|(tid, _)| *tid)
        .collect::<Vec<_>>();
    for tid in expired {
        tags.remove(&tid);
    }
    Ok(())
}

/// In-memory [`JournalBackend`] executing the cls `journal` semantics of
/// `doc/spec/cls_journal.md` over shared durable state.
#[derive(Debug)]
pub struct MemJournalBackend {
    store: Arc<Mutex<MemJournalStore>>,
    plan: Arc<FaultPlan>,
    min_alloc_size: u64,
}

impl Default for MemJournalBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemJournalBackend {
    /// A fresh empty journal state, no crash plan, 4096-byte append padding.
    pub fn new() -> Self {
        Self::from_store(
            &Arc::new(Mutex::new(MemJournalStore::default())),
            &Arc::new(FaultPlan::none()),
        )
        .with_min_alloc_size(4096)
    }

    /// One process instance over shared durable state with the given crash
    /// plan and the default 4096-byte append padding.
    pub fn from_store(store: &Arc<Mutex<MemJournalStore>>, plan: &Arc<FaultPlan>) -> Self {
        Self {
            store: store.clone(),
            plan: plan.clone(),
            min_alloc_size: 4096,
        }
    }

    /// The shared durable state, to build the recovery instance after a
    /// crash.
    pub fn store(&self) -> &Arc<Mutex<MemJournalStore>> {
        &self.store
    }

    /// Set the append zero-pad alignment (the OSD minimum allocation size,
    /// rounded to the pool stripe width; 0 means 8).
    pub fn with_min_alloc_size(mut self, min_alloc_size: u64) -> Self {
        self.min_alloc_size = min_alloc_size;
        self
    }

    /// Create an empty data object (present, zero bytes); a durable
    /// mutation for the fault plan.
    pub fn touch_object(&self, object_number: u64) -> Result<(), i32> {
        self.plan.record()?;
        self.store.lock().unwrap().touch_object(object_number);
        Ok(())
    }

    /// `client_update_state`: set the state of a registered client
    /// (`-ENOENT` when absent); a durable mutation for the fault plan.
    pub fn set_client_state(&self, id: &[u8], state: u8) -> Result<(), i32> {
        self.plan.record()?;
        let mut store = self.store.lock().unwrap();
        store.clients.get_mut(id).ok_or(ENOENT)?.state = state;
        Ok(())
    }

    /// Replace one data object's bytes verbatim (no append padding); a
    /// durable mutation for the fault plan.
    pub fn write_raw_object(&self, object_number: u64, bytes: &[u8]) -> Result<(), i32> {
        self.plan.record()?;
        self.store
            .lock()
            .unwrap()
            .write_raw_object(object_number, bytes);
        Ok(())
    }
}

impl JournalBackend for MemJournalBackend {
    fn get_geometry(&self) -> Result<JournalGeometry, i32> {
        self.store.lock().unwrap().geometry()
    }

    fn get_client(&self, id: &[u8]) -> Result<Vec<u8>, i32> {
        self.store.lock().unwrap().get_client(id)
    }

    fn client_list(&self, start_after: &[u8], max: u64) -> Result<Vec<u8>, i32> {
        Ok(self.store.lock().unwrap().client_list(start_after, max))
    }

    fn client_register(&self, id: &[u8], data: &[u8]) -> Result<(), i32> {
        self.plan.record()?;
        self.store.lock().unwrap().client_register(id, data)
    }

    fn client_commit(&self, id: &[u8], positions: &[JournalObjectPosition]) -> Result<(), i32> {
        self.plan.record()?;
        self.store.lock().unwrap().client_commit(id, positions)
    }

    fn tag_list(
        &self,
        start_after: u64,
        max: u64,
        client_id: &[u8],
        tag_class: Option<u64>,
    ) -> Result<Vec<u8>, i32> {
        self.store
            .lock()
            .unwrap()
            .tag_list(start_after, max, client_id, tag_class)
    }

    fn get_tag(&self, tid: u64) -> Result<Vec<u8>, i32> {
        self.store.lock().unwrap().get_tag(tid)
    }

    fn tag_create(&self, tid: u64, tag_class: u64, data: &[u8]) -> Result<(), i32> {
        self.plan.record()?;
        self.store.lock().unwrap().tag_create(tid, tag_class, data)
    }

    fn get_next_tag_tid(&self) -> Result<u64, i32> {
        self.store.lock().unwrap().get_next_tag_tid()
    }

    fn set_active_set(&self, set: u64) -> Result<(), i32> {
        self.plan.record()?;
        self.store.lock().unwrap().set_active_set(set)
    }

    fn set_minimum_set(&self, set: u64) -> Result<(), i32> {
        self.plan.record()?;
        self.store.lock().unwrap().set_minimum_set(set)
    }

    fn append(&self, object_number: u64, soft_max: u64, bytes: &[u8]) -> Result<(), i32> {
        self.plan.record()?;
        self.store
            .lock()
            .unwrap()
            .append(object_number, soft_max, bytes, self.min_alloc_size)
    }

    fn read_object(&self, object_number: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        self.store
            .lock()
            .unwrap()
            .read_object(object_number, offset, buf)
    }

    fn remove_object(&self, object_number: u64) -> Result<(), i32> {
        self.plan.record()?;
        self.store.lock().unwrap().remove_object(object_number)
    }

    fn create(&self, order: u8, splay_width: u8, pool_id: i64) -> Result<(), i32> {
        self.plan.record()?;
        self.store
            .lock()
            .unwrap()
            .create(order, splay_width, pool_id)
    }

    fn remove_header(&self) -> Result<(), i32> {
        self.plan.record()?;
        self.store.lock().unwrap().remove_header()
    }
}

/// In-memory image: flat zero-initialized byte storage, user snapshot
/// names and image metadata, plus a crash plan.
///
/// DATA operations clip to the image size; an extent fully beyond the size
/// is a no-op. Every mutation counts toward the shared [`FaultPlan`]; reads,
/// `flush` and operations that fail before changing anything do not.
/// Operations ([`MemImage::apply_op`]): snapshot create/remove, resize,
/// metadata set/remove; any other operation is `-EOPNOTSUPP`.
#[derive(Debug)]
pub struct MemImage {
    blocks: Vec<u8>,
    snapshots: BTreeSet<Vec<u8>>,
    metadata: BTreeMap<Vec<u8>, Vec<u8>>,
    plan: Arc<FaultPlan>,
}

impl MemImage {
    /// An image of `size` bytes, no crash plan.
    pub fn new(size: u64) -> Self {
        Self::with_plan(size, &Arc::new(FaultPlan::none()))
    }

    /// An image of `size` bytes with the given crash plan.
    pub fn with_plan(size: u64, plan: &Arc<FaultPlan>) -> Self {
        Self {
            blocks: vec![0; usize::try_from(size).expect("image size fits memory")],
            snapshots: BTreeSet::new(),
            metadata: BTreeMap::new(),
            plan: plan.clone(),
        }
    }

    /// A new process instance over this image's durable state with another
    /// crash plan (the recovery side of a modeled crash).
    pub fn reopen(&self, plan: &Arc<FaultPlan>) -> Self {
        Self {
            blocks: self.blocks.clone(),
            snapshots: self.snapshots.clone(),
            metadata: self.metadata.clone(),
            plan: plan.clone(),
        }
    }

    /// The user snapshot names.
    pub fn snapshots(&self) -> &BTreeSet<Vec<u8>> {
        &self.snapshots
    }

    /// The image metadata.
    pub fn metadata(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.metadata
    }

    /// Execute one operation start event: snapshot create (`-EEXIST` when
    /// present) and remove (`-ENOENT` when absent), resize (absolute; new
    /// bytes are zero), metadata set and remove (`-ENOENT` when absent).
    /// Any other operation is `-EOPNOTSUPP`. Errors change nothing.
    pub fn apply_op(&mut self, event: &JournalEvent<'_>) -> Result<(), i32> {
        match *event {
            JournalEvent::Snapshot {
                kind: JournalEventKind::Create,
                name,
                ..
            } => {
                if self.snapshots.contains(name) {
                    return Err(EEXIST);
                }
                self.plan.record()?;
                self.snapshots.insert(name.to_vec());
            }
            JournalEvent::Snapshot {
                kind: JournalEventKind::Remove,
                name,
                ..
            } => {
                if !self.snapshots.contains(name) {
                    return Err(ENOENT);
                }
                self.plan.record()?;
                self.snapshots.remove(name);
            }
            JournalEvent::Resize { size, .. } => {
                let size = usize::try_from(size).map_err(|_| EINVAL)?;
                self.plan.record()?;
                self.blocks.resize(size, 0);
            }
            JournalEvent::MetadataSet { key, value, .. } => {
                self.plan.record()?;
                self.metadata.insert(key.to_vec(), value.to_vec());
            }
            JournalEvent::MetadataRemove { key, .. } => {
                if !self.metadata.contains_key(key) {
                    return Err(ENOENT);
                }
                self.plan.record()?;
                self.metadata.remove(key);
            }
            _ => return Err(EOPNOTSUPP),
        }
        Ok(())
    }

    /// The image size in bytes.
    pub fn size(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// The bytes at `offset` for at most `length` bytes, zero-filled past
    /// the size. Test helper, not affected by the crash plan.
    pub fn read(&self, offset: u64, length: u64) -> Vec<u8> {
        let start = (offset as usize).min(self.blocks.len());
        let end = ((offset + length) as usize).min(self.blocks.len());
        self.blocks[start..end].to_vec()
    }

    /// The clipped `[start, end)` byte range of one extent, `None` when the
    /// extent is fully beyond the image size.
    fn clipped(&self, offset: u64, length: u64) -> Option<(usize, usize)> {
        let size = self.blocks.len();
        if offset >= size as u64 {
            return None;
        }
        let start = offset as usize;
        let end = (offset + length).min(size as u64) as usize;
        Some((start, end))
    }

    /// `write(offset, data)`: store the data, clipped to the image size.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), i32> {
        self.plan.record()?;
        if let Some((start, end)) = self.clipped(offset, data.len() as u64) {
            self.blocks[start..end].copy_from_slice(&data[..end - start]);
        }
        Ok(())
    }

    /// `discard(offset, length)`: zero the clipped range.
    pub fn discard(&mut self, offset: u64, length: u64) -> Result<(), i32> {
        self.plan.record()?;
        if let Some((start, end)) = self.clipped(offset, length) {
            self.blocks[start..end].fill(0);
        }
        Ok(())
    }

    /// `write_same(offset, length, pattern)`: fill the clipped range with
    /// the repeating pattern; an empty pattern with a nonempty range is
    /// `-EINVAL`.
    pub fn write_same(&mut self, offset: u64, length: u64, pattern: &[u8]) -> Result<(), i32> {
        self.plan.record()?;
        if let Some((start, end)) = self.clipped(offset, length) {
            if pattern.is_empty() {
                return Err(EINVAL);
            }
            for (index, byte) in self.blocks[start..end].iter_mut().enumerate() {
                *byte = pattern[index % pattern.len()];
            }
        }
        Ok(())
    }

    /// `compare_and_write(offset, length, compare, data)`: replace the
    /// clipped range with `data` only when its current content equals
    /// `compare`; a mismatch is `-EILSEQ`, buffers that do not cover the
    /// clipped range are `-EINVAL`.
    pub fn compare_and_write(
        &mut self,
        offset: u64,
        length: u64,
        compare: &[u8],
        data: &[u8],
    ) -> Result<(), i32> {
        self.plan.record()?;
        let Some((start, end)) = self.clipped(offset, length) else {
            return Ok(());
        };
        if compare.len() != end - start || data.len() != end - start {
            return Err(EINVAL);
        }
        if self.blocks[start..end] != *compare {
            return Err(EILSEQ);
        }
        self.blocks[start..end].copy_from_slice(data);
        Ok(())
    }

    /// Flush barrier: the in-memory storage is always durable.
    pub fn flush(&self) -> Result<(), i32> {
        Ok(())
    }
}

impl ReplayTarget for MemImage {
    fn image_size(&self) -> u64 {
        self.size()
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), i32> {
        MemImage::write(self, offset, data)
    }

    /// Zeroes the range; the granularity alignment is the caller's.
    fn discard(
        &mut self,
        offset: u64,
        length: u64,
        _skip_partial: bool,
        _granularity: u32,
    ) -> Result<(), i32> {
        MemImage::discard(self, offset, length)
    }

    fn write_same(&mut self, offset: u64, length: u64, pattern: &[u8]) -> Result<(), i32> {
        MemImage::write_same(self, offset, length, pattern)
    }

    fn compare_and_write(
        &mut self,
        offset: u64,
        length: u64,
        compare: &[u8],
        data: &[u8],
    ) -> Result<(), i32> {
        MemImage::compare_and_write(self, offset, length, compare, data)
    }

    fn flush(&mut self) -> Result<(), i32> {
        MemImage::flush(self)
    }

    fn apply_op(&mut self, event: &JournalEvent<'_>) -> Result<(), i32> {
        MemImage::apply_op(self, event)
    }
}

/// One versioned envelope (version, compat 1, body length, body).
fn envelope(version: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![version, 1];
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// `u32` length + bytes.
fn append_length_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

/// Encode a `Client` record (id, ClientData, ObjectSetPosition, state).
fn encode_client(client: &ClientRec) -> Vec<u8> {
    let mut body = Vec::new();
    append_length_prefixed(&mut body, &client.id);
    append_length_prefixed(&mut body, &client.data);
    body.extend_from_slice(&encode_positions(&client.positions).unwrap());
    body.push(client.state);
    envelope(1, &body)
}

/// Encode a `Tag` record (tid, tag class, data).
fn encode_tag(tag: &TagRec) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&tag.tid.to_le_bytes());
    body.extend_from_slice(&tag.tag_class.to_le_bytes());
    append_length_prefixed(&mut body, &tag.data);
    envelope(1, &body)
}

/// Encode a `set<Client>`: count followed by Client records.
fn encode_client_set(clients: &[ClientRec]) -> Vec<u8> {
    let mut out = (clients.len() as u32).to_le_bytes().to_vec();
    for client in clients {
        out.extend_from_slice(&encode_client(client));
    }
    out
}

/// Encode a `set<Tag>`: count followed by Tag records.
fn encode_tag_set(tags: &[TagRec]) -> Vec<u8> {
    let mut out = (tags.len() as u32).to_le_bytes().to_vec();
    for tag in tags {
        out.extend_from_slice(&encode_tag(tag));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        JournalTagPredecessor, decode_journal_client, decode_journal_client_set,
        decode_journal_image_client, decode_journal_tag, decode_journal_tag_set,
        encode_image_client_data, encode_tag_data,
    };

    fn position(object: u64, tag: u64, entry: u64) -> JournalObjectPosition {
        JournalObjectPosition {
            object_number: object,
            tag_tid: tag,
            entry_tid: entry,
        }
    }

    fn fresh_tag_data() -> Vec<u8> {
        encode_tag_data(
            b"",
            &JournalTagPredecessor {
                mirror_uuid: Vec::new(),
                commit_valid: false,
                tag_tid: 0,
                entry_tid: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn create_initializes_the_header_and_double_create_fails() {
        let backend = MemJournalBackend::new();
        assert_eq!(backend.get_geometry(), Err(ENOENT));
        assert_eq!(backend.create(24, 4, -1), Ok(()));
        assert_eq!(
            backend.get_geometry().unwrap(),
            JournalGeometry {
                order: 24,
                splay_width: 4,
                pool_id: -1,
                minimum_set: 0,
                active_set: 0,
            }
        );
        assert_eq!(backend.get_next_tag_tid().unwrap(), 0);
        assert_eq!(backend.create(24, 4, -1), Err(EEXIST));
    }

    #[test]
    fn header_operations_fail_enoent_without_a_journal() {
        let backend = MemJournalBackend::new();
        assert_eq!(backend.set_active_set(1), Err(ENOENT));
        assert_eq!(backend.set_minimum_set(1), Err(ENOENT));
        assert_eq!(backend.get_next_tag_tid(), Err(ENOENT));
        assert_eq!(backend.tag_create(0, 0, &fresh_tag_data()), Err(ENOENT));
        assert_eq!(backend.client_register(b"", b""), Err(ENOENT));
        assert_eq!(backend.client_commit(b"", &[]), Err(ENOENT));
        assert_eq!(backend.remove_header(), Err(ENOENT));
        // The list methods read only data-object-free state: empty results.
        let wire = backend.client_list(b"", 256).unwrap();
        assert_eq!(decode_journal_client_set(&wire).unwrap(), Vec::new());
        assert_eq!(backend.tag_list(0, 256, b"", None), Err(ENOENT));
    }

    #[test]
    fn append_overflows_at_the_soft_max_without_writing() {
        let backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 1, -1).unwrap();
        let soft_max = 1u64 << 12;
        assert_eq!(
            backend.append(0, soft_max, &vec![7; soft_max as usize]),
            Ok(())
        );
        assert_eq!(backend.append(0, soft_max, &[0]), Err(EOVERFLOW));
        // The failed append wrote nothing.
        let mut buf = vec![0u8; soft_max as usize];
        assert_eq!(
            backend.read_object(0, 0, &mut buf).unwrap() as u64,
            soft_max
        );
        assert!(buf.iter().all(|&byte| byte == 7));
    }

    #[test]
    fn append_zero_pads_to_the_allocation_alignment() {
        let backend = MemJournalBackend::new();
        backend.create(12, 1, -1).unwrap();
        backend.append(0, 1 << 20, b"0123456789").unwrap();
        let mut buf = vec![0u8; 4096];
        assert_eq!(backend.read_object(0, 0, &mut buf).unwrap(), 4096);
        assert_eq!(&buf[..10], b"0123456789");
        assert!(buf[10..].iter().all(|&byte| byte == 0));
        // The padded object now reaches the default soft maximum.
        assert_eq!(backend.append(0, 4096, &[1]), Err(EOVERFLOW));
    }

    #[test]
    fn set_active_set_moves_forward_only() {
        let backend = MemJournalBackend::new();
        backend.create(24, 2, -1).unwrap();
        assert_eq!(backend.set_active_set(3), Ok(()));
        assert_eq!(backend.set_active_set(3), Ok(()));
        assert_eq!(backend.set_active_set(2), Err(ESTALE));
        assert_eq!(backend.set_active_set(4), Ok(()));
    }

    #[test]
    fn set_minimum_set_tracks_the_active_set() {
        let backend = MemJournalBackend::new();
        backend.create(24, 2, -1).unwrap();
        assert_eq!(backend.set_active_set(4), Ok(()));
        assert_eq!(backend.set_minimum_set(5), Err(EINVAL));
        assert_eq!(backend.set_minimum_set(3), Ok(()));
        assert_eq!(backend.set_minimum_set(3), Ok(()));
        assert_eq!(backend.set_minimum_set(2), Err(ESTALE));
        assert_eq!(backend.set_active_set(2), Err(EINVAL));
        assert_eq!(backend.get_geometry().unwrap().minimum_set, 3);
    }

    #[test]
    fn client_commit_rejects_more_positions_than_splays() {
        let backend = MemJournalBackend::new();
        backend.create(24, 2, -1).unwrap();
        backend
            .client_register(b"", &encode_image_client_data(0, false))
            .unwrap();
        let too_many = [position(0, 1, 0), position(1, 1, 1), position(2, 1, 2)];
        assert_eq!(backend.client_commit(b"", &too_many), Err(EINVAL));
        assert_eq!(
            backend.client_commit(b"unknown", &[position(0, 1, 0)]),
            Err(ENOENT)
        );
    }

    #[test]
    fn client_commit_stores_positions_newest_first() {
        let backend = MemJournalBackend::new();
        backend.create(24, 2, -1).unwrap();
        backend
            .client_register(b"", &encode_image_client_data(9, true))
            .unwrap();
        let positions = [position(1, 1, 1), position(0, 1, 0)];
        backend.client_commit(b"", &positions).unwrap();
        let wire = backend.get_client(b"").unwrap();
        let client = decode_journal_image_client(&wire).unwrap();
        assert_eq!(client.tag_class, 9);
        assert!(client.resync_requested);
        assert_eq!(client.commit_positions, positions);
        // Equal positions are a no-op.
        assert_eq!(backend.client_commit(b"", &positions), Ok(()));
    }

    #[test]
    fn client_register_inherits_the_minimum_commit_position() {
        let backend = MemJournalBackend::new();
        backend.create(24, 2, -1).unwrap();
        backend
            .client_register(b"a", &encode_image_client_data(0, false))
            .unwrap();
        backend
            .client_commit(b"a", &[position(3, 2, 5), position(2, 1, 0)])
            .unwrap();
        backend
            .client_register(b"b", &encode_image_client_data(0, false))
            .unwrap();
        let wire = backend.get_client(b"b").unwrap();
        let inherited = decode_journal_client(&wire).unwrap();
        assert_eq!(inherited.id, b"b");
        assert_eq!(
            inherited.commit_positions,
            [position(3, 2, 5), position(2, 1, 0)]
        );
        assert_eq!(
            backend.client_register(b"a", &encode_image_client_data(0, false)),
            Err(EEXIST)
        );
    }

    #[test]
    fn find_min_commit_position_follows_the_cls_rules() {
        fn client(id: &str, positions: Vec<JournalObjectPosition>, state: u8) -> ClientRec {
            ClientRec {
                id: id.as_bytes().to_vec(),
                data: Vec::new(),
                positions,
                state,
            }
        }
        let mut clients = BTreeMap::new();
        clients.insert(
            b"a".to_vec(),
            client("a", vec![position(1, 4, 9)], JOURNAL_CLIENT_STATE_CONNECTED),
        );
        clients.insert(
            b"b".to_vec(),
            client("b", vec![position(1, 3, 0)], JOURNAL_CLIENT_STATE_CONNECTED),
        );
        // The smallest (tag, entry) wins among valid candidates.
        assert_eq!(find_min_commit_position(&clients), [position(1, 3, 0)]);
        // A disconnected client with a smaller position is skipped.
        clients.insert(
            b"c".to_vec(),
            client(
                "c",
                vec![position(0, 1, 0)],
                JOURNAL_CLIENT_STATE_DISCONNECTED,
            ),
        );
        assert_eq!(find_min_commit_position(&clients), [position(1, 3, 0)]);
        // A connected client with empty positions resets the result and
        // stops the scan of its batch.
        clients.insert(
            b"d".to_vec(),
            client("d", Vec::new(), JOURNAL_CLIENT_STATE_CONNECTED),
        );
        assert_eq!(find_min_commit_position(&clients), Vec::new());
    }

    #[test]
    fn client_list_pages_ascending_by_id() {
        let backend = MemJournalBackend::new();
        backend.create(24, 1, -1).unwrap();
        for id in [b"a", b"b", b"c"] {
            backend
                .client_register(id, &encode_image_client_data(0, false))
                .unwrap();
        }
        let wire = backend.client_list(b"", 256).unwrap();
        let all = decode_journal_client_set(&wire).unwrap();
        assert_eq!(
            all.iter().map(|client| client.id).collect::<Vec<_>>(),
            [b"a", b"b", b"c"]
        );
        let wire = backend.client_list(b"a", 256).unwrap();
        let page = decode_journal_client_set(&wire).unwrap();
        assert_eq!(
            page.iter().map(|client| client.id).collect::<Vec<_>>(),
            [b"b", b"c"]
        );
        let wire = backend.client_list(b"", 1).unwrap();
        let capped = decode_journal_client_set(&wire).unwrap();
        assert_eq!(capped.len(), 1);
        let wire = backend.client_list(b"", 0).unwrap();
        let none = decode_journal_client_set(&wire).unwrap();
        assert_eq!(none, Vec::new());
    }

    #[test]
    fn tag_create_enforces_tid_order_and_allocates_classes() {
        let backend = MemJournalBackend::new();
        backend.create(24, 1, -1).unwrap();
        backend
            .client_register(b"", &encode_image_client_data(0, false))
            .unwrap();
        let data = fresh_tag_data();
        assert_eq!(
            backend.tag_create(1, JOURNAL_TAG_CLASS_NEW, &data),
            Err(ESTALE)
        );
        assert_eq!(backend.tag_create(0, JOURNAL_TAG_CLASS_NEW, &data), Ok(()));
        assert_eq!(backend.get_next_tag_tid().unwrap(), 1);
        assert_eq!(
            backend.tag_create(0, JOURNAL_TAG_CLASS_NEW, &data),
            Err(EEXIST)
        );
        assert_eq!(backend.tag_create(1, JOURNAL_TAG_CLASS_NEW, &data), Ok(()));
        // An explicit class must be below the next class.
        assert_eq!(backend.tag_create(2, 5, &data), Err(EINVAL));
        assert_eq!(backend.tag_create(2, 0, &data), Ok(()));
        assert_eq!(backend.get_next_tag_tid().unwrap(), 3);
        let wire = backend.tag_list(0, 256, b"", None).unwrap();
        let tags = decode_journal_tag_set(&wire).unwrap();
        assert_eq!(
            tags.iter()
                .map(|tag| (tag.tid, tag.tag_class))
                .collect::<Vec<_>>(),
            [(0, 0), (1, 1), (2, 0)]
        );
        let wire = backend.get_tag(1).unwrap();
        let tag = decode_journal_tag(&wire).unwrap();
        assert_eq!((tag.tid, tag.tag_class), (1, 1));
        assert_eq!(backend.get_tag(9), Err(ENOENT));
        assert_eq!(backend.tag_list(0, 256, b"unknown", None), Err(ENOENT));
    }

    #[test]
    fn tag_list_hides_superseded_tags_of_the_committed_class() {
        let backend = MemJournalBackend::new();
        backend.create(24, 1, -1).unwrap();
        backend
            .client_register(b"", &encode_image_client_data(0, false))
            .unwrap();
        let data = fresh_tag_data();
        backend.tag_create(0, JOURNAL_TAG_CLASS_NEW, &data).unwrap();
        backend.tag_create(1, 0, &data).unwrap();
        backend.tag_create(2, JOURNAL_TAG_CLASS_NEW, &data).unwrap();
        backend.client_commit(b"", &[position(0, 1, 4)]).unwrap();
        let wire = backend.tag_list(0, 256, b"", None).unwrap();
        let tags = decode_journal_tag_set(&wire).unwrap();
        assert_eq!(tags.iter().map(|tag| tag.tid).collect::<Vec<_>>(), [1, 2]);
        // The class filter keeps only class 1.
        let wire = backend.tag_list(0, 256, b"", Some(1)).unwrap();
        let tags = decode_journal_tag_set(&wire).unwrap();
        assert_eq!(tags.iter().map(|tag| tag.tid).collect::<Vec<_>>(), [2]);
        // The start cursor skips TIDs below it.
        let wire = backend.tag_list(1, 256, b"", None).unwrap();
        let tags = decode_journal_tag_set(&wire).unwrap();
        assert_eq!(tags.iter().map(|tag| tag.tid).collect::<Vec<_>>(), [2]);
    }

    #[test]
    fn tag_create_expires_superseded_tags() {
        let backend = MemJournalBackend::new();
        backend.create(24, 1, -1).unwrap();
        backend
            .client_register(b"", &encode_image_client_data(0, false))
            .unwrap();
        let data = fresh_tag_data();
        backend.tag_create(0, JOURNAL_TAG_CLASS_NEW, &data).unwrap();
        backend.tag_create(1, 0, &data).unwrap();
        backend.client_commit(b"", &[position(0, 1, 4)]).unwrap();
        // The new tag supersedes class 0 at the client's commit TID: tag 0
        // is expired, the committed tag 1 stays visible.
        backend.tag_create(2, JOURNAL_TAG_CLASS_NEW, &data).unwrap();
        let wire = backend.tag_list(0, 256, b"", None).unwrap();
        let tags = decode_journal_tag_set(&wire).unwrap();
        assert_eq!(tags.iter().map(|tag| tag.tid).collect::<Vec<_>>(), [1, 2]);
    }

    #[test]
    fn remove_object_and_absent_reads() {
        let backend = MemJournalBackend::new();
        backend.create(12, 1, -1).unwrap();
        assert_eq!(backend.read_object(7, 0, &mut [0u8; 4]), Err(ENOENT));
        assert_eq!(backend.remove_object(7), Err(ENOENT));
        backend.append(7, 1 << 12, b"data").unwrap();
        assert_eq!(backend.remove_object(7), Ok(()));
        assert_eq!(backend.read_object(7, 0, &mut [0u8; 4]), Err(ENOENT));
    }

    #[test]
    fn read_object_short_read_marks_the_object_end() {
        let backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 1, -1).unwrap();
        backend.append(0, 1 << 12, b"abcd").unwrap();
        let mut buf = [0u8; 8];
        // The object is padded to 8 bytes, so the read ends at 6.
        assert_eq!(backend.read_object(0, 2, &mut buf).unwrap(), 6);
        assert_eq!(&buf[..2], b"cd");
        assert_eq!(backend.read_object(0, 8, &mut buf).unwrap(), 0);
        assert_eq!(backend.read_object(0, 16, &mut buf).unwrap(), 0);
    }

    #[test]
    fn remove_header_clears_the_journal() {
        let backend = MemJournalBackend::new();
        assert_eq!(backend.remove_header(), Err(ENOENT));
        backend.create(24, 1, -1).unwrap();
        assert_eq!(backend.remove_header(), Ok(()));
        assert_eq!(backend.get_geometry(), Err(ENOENT));
        assert_eq!(backend.create(24, 1, -1), Ok(()));
    }

    #[test]
    fn fault_plan_stops_all_later_mutations() {
        let store = Arc::new(Mutex::new(MemJournalStore::default()));
        let plan = Arc::new(FaultPlan::crash_after(3));
        let backend = MemJournalBackend::from_store(&store, &plan);
        let mut image = MemImage::with_plan(4096, &plan);
        assert_eq!(backend.create(24, 1, -1), Ok(()));
        assert_eq!(backend.append(0, 1 << 24, b"abc"), Ok(()));
        assert_eq!(image.write(0, b"xyz"), Ok(()));
        assert_eq!(backend.set_active_set(1), Err(CRASH_ERRNO));
        assert_eq!(image.discard(0, 8), Err(CRASH_ERRNO));
        assert_eq!(backend.append(0, 1 << 24, b"no"), Err(CRASH_ERRNO));
        // The durable state is intact and readable after the crash.
        assert_eq!(backend.get_geometry().unwrap().active_set, 0);
        let mut buf = [0u8; 8];
        assert_eq!(backend.read_object(0, 0, &mut buf).unwrap(), 8);
        assert_eq!(&buf[..3], b"abc");
        assert_eq!(image.read(0, 3), b"xyz");
        // The recovery instance over the same state mutates normally.
        let recovered = MemJournalBackend::from_store(&store, &Arc::new(FaultPlan::none()));
        assert_eq!(recovered.set_active_set(1), Ok(()));
    }

    #[test]
    fn fault_plan_crash_before_first_mutation() {
        let store = Arc::new(Mutex::new(MemJournalStore::default()));
        let plan = Arc::new(FaultPlan::crash_after(0));
        let backend = MemJournalBackend::from_store(&store, &plan);
        let mut image = MemImage::with_plan(64, &plan);
        assert_eq!(backend.create(24, 1, -1), Err(CRASH_ERRNO));
        assert_eq!(image.write(0, b"a"), Err(CRASH_ERRNO));
        assert_eq!(backend.get_geometry(), Err(ENOENT));
    }

    #[test]
    fn mem_image_ops_clip_to_the_size_and_compare() {
        let mut image = MemImage::new(16);
        assert_eq!(image.size(), 16);
        image.write(12, b"abcdef").unwrap();
        assert_eq!(image.read(12, 8), b"abcd");
        image.write_same(4, 8, b"xy").unwrap();
        assert_eq!(image.read(4, 8), b"xyxyxyxy");
        image.discard(2, 6).unwrap();
        assert_eq!(image.read(2, 6), vec![0u8; 6]);
        assert_eq!(image.read(8, 4), b"xyxy");
        assert_eq!(image.compare_and_write(8, 4, b"xyxy", b"zzzz"), Ok(()));
        assert_eq!(image.read(8, 4), b"zzzz");
        assert_eq!(image.compare_and_write(8, 4, b"xyxy", b"nope"), Err(EILSEQ));
        assert_eq!(image.compare_and_write(8, 4, b"zz", b"zz"), Err(EINVAL));
        // Extents fully beyond the size are no-ops.
        assert_eq!(image.write(16, b"abc"), Ok(()));
        assert_eq!(image.discard(16, 4), Ok(()));
        assert_eq!(image.compare_and_write(20, 4, b"aaaa", b"bbbb"), Ok(()));
        assert_eq!(image.write_same(0, 4, b""), Err(EINVAL));
        assert_eq!(image.flush(), Ok(()));
    }
}
