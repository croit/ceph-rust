// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! In-memory [`MigrationStore`] executing the real `cls_rbd` handlers.
//!
//! Testkit only: compiled out of production builds without feature
//! `migration-testkit`. The store keeps one [`cls::mem::MemStore`] (the
//! reference `ClsCtx` implementation of `doc/spec/cls.md`) and drives the
//! pinned `cls_rbd` methods for migration records, trash, directory, identity,
//! group, mirror, children and snapshots. Administrative removal and the data
//! revert are opaque: the store performs the client-side object deletion and
//! records the revert call, because neither is a class method.
//!
//! [`crate::fault_plan::FaultPlan`] counts one durable mutation per trait
//! method; `crash_after(k)` stops the store after the k-th mutation and leaves
//! the previous state readable, modeling a process crash at every mutation
//! boundary (ADR 0705 S2).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use cls::mem::MemStore;
use cls::rbd::mirror_types::{
    IMG_DISABLING, IMG_ENABLED, MODE_DISABLED, MODE_IMAGE, MODE_INIT_ONLY, MODE_POOL,
};
use cls::rbd::types::{
    ChildImageSpec, GroupSpec, MirrorImage, PROTECTION_UNPROTECTED, ParentImageSpec, SnapNs,
    SnapRec, TrashImageSpec,
};
use cls::rbd::types_group::{GroupImageSpec, GroupImageStatus, MigrationSpec};
use denc::{Decode, Decoder, Encode, Encoder};
use rustyrados::diag;

use crate::fault_plan::FaultPlan;
use crate::journal_backend::{EEXIST, EINVAL, EIO, ENOENT, EOPNOTSUPP};
use crate::legacy_header::{
    LegacyDirectoryError, LegacyHeader, RBD_HEADER_TEXT, RBD_MIGRATE_HEADER_TEXT,
    apply_tmap_commands, build_legacy_header, decode_legacy_directory, encode_tmap_remove,
    encode_tmap_set,
};
use crate::migration_store::{
    ChildRef, DestinationImage, MigrationAbortStore, MigrationCommitStore, MigrationImportStore,
    MigrationStore, MigrationStoreRead, SnapshotInfo,
};
use crate::migration_terminal::{
    GroupRef, ImageFormat, ImageRef, MigrationRecord, MirrorState, PoolMode,
    TRASH_SOURCE_MIGRATION, TRASH_STATE_MOVING, TRASH_STATE_NORMAL, TRASH_STATE_RESTORING,
    TrashEntry,
};

const DIRECTORY_OID: &str = "rbd_directory";
const TRASH_OID: &str = "rbd_trash";
const MIRRORING_OID: &str = "rbd_mirroring";

/// One recorded opaque revert call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevertCall {
    /// Source image.
    pub source: ImageRef,
    /// Destination image.
    pub destination: ImageRef,
    /// Boundary snapshot ID, or `None` when `snap_seqs` was empty.
    pub boundary: Option<u64>,
}

/// In-memory migration store over the real `cls_rbd` handlers.
#[derive(Debug)]
pub struct MigrationMemStore {
    mem: Arc<Mutex<MemStore>>,
    plan: Arc<FaultPlan>,
    reverts: Vec<RevertCall>,
    revert_errno: Option<i32>,
    mirror_enables: Vec<(ImageRef, u8)>,
    mirror_errno: Option<i32>,
}

impl MigrationMemStore {
    /// A fresh store with an empty pool.
    pub fn new(plan: &Arc<FaultPlan>) -> Self {
        Self::from_store(&Arc::new(Mutex::new(MemStore::new())), plan)
    }

    /// A process instance over an existing pool (the crash-and-rerun model).
    pub fn from_store(mem: &Arc<Mutex<MemStore>>, plan: &Arc<FaultPlan>) -> Self {
        Self {
            mem: Arc::clone(mem),
            plan: Arc::clone(plan),
            reverts: Vec::new(),
            revert_errno: None,
            mirror_enables: Vec::new(),
            mirror_errno: None,
        }
    }

    /// The shared pool state.
    pub fn store(&self) -> &Arc<Mutex<MemStore>> {
        &self.mem
    }

    /// A new process instance over the same pool.
    pub fn reopen(&self, plan: &Arc<FaultPlan>) -> Self {
        Self::from_store(&self.mem, plan)
    }

    /// The fault plan of this instance.
    pub fn plan(&self) -> &Arc<FaultPlan> {
        &self.plan
    }

    /// The opaque revert calls this instance made.
    pub fn reverts(&self) -> &[RevertCall] {
        &self.reverts
    }

    /// Make the next revert fail with `errno` (D1 crash-point tests).
    pub fn set_revert_errno(&mut self, errno: Option<i32>) {
        self.revert_errno = errno;
    }

    /// The mirror enables this instance performed, in order (B10, B13, K5).
    pub fn mirror_enables(&self) -> &[(ImageRef, u8)] {
        &self.mirror_enables
    }

    /// Make the next mirror enable fail with `errno` (B10 best-effort tests).
    pub fn set_mirror_errno(&mut self, errno: Option<i32>) {
        self.mirror_errno = errno;
    }

    /// Create an image header, its `rbd_id.<name>` object and its directory
    /// entry, mirroring the format-2 create order.
    pub fn create_image(&mut self, image: &ImageRef, features: u64) -> Result<(), i32> {
        self.plan.record()?;
        let header = header_oid(image)?;
        let prefix = format!("rbd_data.{}", hex::encode(&image.id));
        let input = encoded(|e| {
            e.u64(1 << 20)?;
            e.u8(22)?;
            e.u64(features)?;
            prefix.as_bytes().to_vec().encode(e)?;
            e.i64(-1)
        });
        self.call(&header, "create", &input)?;
        self.create_id_object_unchecked(image)?;
        let input = encoded(|e| {
            image.name.clone().encode(e)?;
            image.id.clone().encode(e)
        });
        self.call(DIRECTORY_OID, "dir_add_image", &input)?;
        Ok(())
    }

    /// Retire the image's `rbd_id.<name>` object, as the prepare trash move
    /// does before a same-name destination is created (test setup).
    pub fn remove_id_object(&mut self, image: &ImageRef) -> Result<(), i32> {
        self.plan.record()?;
        let mut mem = self.mem.lock().expect("migration mem store lock");
        mem.objects.remove(&id_oid(image));
        Ok(())
    }

    /// Add a MIGRATION trash entry (Q2 sub-step and test setup).
    pub fn trash_add(&mut self, entry: &TrashEntry) -> Result<(), i32> {
        self.plan.record()?;
        let spec = TrashImageSpec {
            source: entry.source,
            name: entry.name.clone(),
            state: entry.state,
            ..TrashImageSpec::default()
        };
        let input = encoded(|e| {
            entry.id.clone().encode(e)?;
            spec.encode(e)
        });
        self.call(TRASH_OID, "trash_add", &input)?;
        Ok(())
    }

    /// Remove a directory name/ID pair (Q2 sub-step and test setup). A missing
    /// entry is the resumable step.
    pub fn directory_remove(&mut self, name: &[u8], id: &[u8]) -> Result<(), i32> {
        self.plan.record()?;
        let input = encoded(|e| {
            name.to_vec().encode(e)?;
            id.to_vec().encode(e)
        });
        self.call_ignore_enoent(DIRECTORY_OID, "dir_remove_image", &input)
    }

    /// Add a USER snapshot at `id`.
    pub fn add_snapshot(&mut self, image: &ImageRef, id: u64, name: &[u8]) -> Result<(), i32> {
        self.plan.record()?;
        let input = encoded(|e| {
            name.to_vec().encode(e)?;
            e.u64(id)
        });
        self.call(&header_oid(image)?, "snapshot_add", &input)?;
        Ok(())
    }

    /// Resize the image header (`set_size`), which clamps the HEAD parent
    /// overlap on a shrink (test setup for zero-overlap sources).
    pub fn set_size(&mut self, image: &ImageRef, size: u64) -> Result<(), i32> {
        self.plan.record()?;
        self.call(&header_oid(image)?, "set_size", &size.to_le_bytes())?;
        Ok(())
    }

    /// Add a trash-namespace snapshot, the non-USER revision prepare refuses
    /// with `-EBUSY`.
    pub fn add_trash_snapshot(
        &mut self,
        image: &ImageRef,
        id: u64,
        name: &[u8],
    ) -> Result<(), i32> {
        self.plan.record()?;
        let namespace = SnapNs::Trash {
            original_name: name.to_vec(),
            original_namespace_type: 0,
        };
        let input = encoded(|e| {
            name.to_vec().encode(e)?;
            e.u64(id)?;
            namespace.encode(e)
        });
        self.call(&header_oid(image)?, "snapshot_add", &input)?;
        Ok(())
    }

    /// Attach `child` to `parent`'s snapshot `snapshot_id`.
    pub fn attach_child(
        &mut self,
        parent: &ImageRef,
        snapshot_id: u64,
        child: &ImageRef,
        overlap: u64,
    ) -> Result<(), i32> {
        self.plan.record()?;
        let child_spec = ChildImageSpec {
            pool_id: child.pool_id,
            pool_namespace: child.namespace.clone(),
            image_id: child.id.clone(),
        };
        let input = encoded(|e| {
            e.u64(snapshot_id)?;
            child_spec.encode(e)
        });
        self.call(&header_oid(parent)?, "child_attach", &input)?;
        let parent_spec = ParentImageSpec {
            pool_id: parent.pool_id,
            pool_namespace: parent.namespace.clone(),
            image_id: parent.id.clone(),
            snap_id: snapshot_id,
        };
        let input = encoded(|e| {
            parent_spec.encode(e)?;
            e.u64(overlap)?;
            e.bool(true)
        });
        self.call(&header_oid(child)?, "parent_attach", &input)?;
        Ok(())
    }

    /// Set the pool mirror mode (test setup; the pool object is not part of
    /// the migration lifecycle).
    pub fn set_pool_mirror_mode(&mut self, mode: PoolMode) -> Result<(), i32> {
        self.plan.record()?;
        let uuid = b"migration-mem-pool-uuid".to_vec();
        let input = encoded(|e| uuid.encode(e));
        self.call(MIRRORING_OID, "mirror_uuid_set", &input)?;
        let value = match mode {
            PoolMode::Disabled => MODE_DISABLED,
            PoolMode::Image => MODE_IMAGE,
            PoolMode::Pool => MODE_POOL,
            PoolMode::InitOnly => MODE_INIT_ONLY,
        };
        let input = encoded(|e| e.u32(value));
        self.call(MIRRORING_OID, "mirror_mode_set", &input)?;
        Ok(())
    }

    /// The image's parent reference (`parent_get`). The class answers the
    /// default spec when no parent exists; that is `None` here.
    pub fn parent_of(&mut self, image: &ImageRef) -> Result<Option<ParentImageSpec>, i32> {
        match self.call(&header_oid(image)?, "parent_get", b"") {
            Ok(out) => {
                let spec: ParentImageSpec = decode(&out)?;
                if spec.pool_id < 0 || spec.image_id.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(spec))
                }
            }
            Err(ENOENT) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The child's HEAD parent overlap (`parent_overlap_get`), 0 when none.
    pub fn parent_overlap(&mut self, image: &ImageRef) -> Result<u64, i32> {
        Ok(self.head_parent_overlap(image)?.unwrap_or(0))
    }

    /// The recorded HEAD parent overlap; `None` means HEAD has no parent data.
    fn head_parent_overlap(&mut self, image: &ImageRef) -> Result<Option<u64>, i32> {
        let out = self.call(
            &header_oid(image)?,
            "parent_overlap_get",
            &enc(&opwire::NOSNAP),
        )?;
        decode(&out)
    }

    fn create_id_object_unchecked(&mut self, image: &ImageRef) -> Result<(), i32> {
        let oid = id_oid(image);
        {
            let mut mem = self.mem.lock().expect("migration mem store lock");
            mem.objects.entry(oid.clone()).or_default();
        }
        self.call(&oid, "set_id", &encoded(|e| image.id.clone().encode(e)))?;
        Ok(())
    }

    fn call(&self, oid: &str, method: &str, input: &[u8]) -> Result<Vec<u8>, i32> {
        let mut mem = self.mem.lock().expect("migration mem store lock");
        let reply = mem.call(oid, "rbd", method, input);
        if reply.ret < 0 {
            Err(reply.ret)
        } else {
            Ok(reply.out)
        }
    }

    fn call_ignore_enoent(&self, oid: &str, method: &str, input: &[u8]) -> Result<(), i32> {
        match self.call(oid, method, input) {
            Ok(_) | Err(ENOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// The header `size` key (source HEAD geometry) through `get_size`; a
    /// format-1 image carries its size in the header object's data bytes.
    fn head_size(&mut self, image: &ImageRef) -> Result<u64, i32> {
        if image.is_v1() {
            return match self.legacy_header_of(image)? {
                Some(header) => Ok(header.image_size),
                None => Err(ENOENT),
            };
        }
        let out = self.call(&header_oid(image)?, "get_size", &enc(&opwire::NOSNAP))?;
        let bytes: [u8; 8] = out.get(1..9).ok_or(EIO)?.try_into().map_err(|_| EIO)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// One snapshot's recorded parent overlap (`None`: the revision has no
    /// parent).
    pub fn snapshot_parent_overlap(
        &mut self,
        image: &ImageRef,
        snapshot_id: u64,
    ) -> Result<Option<u64>, i32> {
        let out = self.call(
            &header_oid(image)?,
            "parent_overlap_get",
            &enc(&snapshot_id),
        )?;
        decode(&out)
    }

    /// Replace the HEAD parent overlap for the next snapshot stage with
    /// `parent_attach(reattach)`: the parent identity is image-wide, the
    /// overlap is revision-specific (spec "Parent and overlap mapping").
    fn attach_parent_overlap(
        &mut self,
        image: &ImageRef,
        parent: &ParentImageSpec,
        overlap: u64,
    ) -> Result<(), i32> {
        let input = encoded(|e| {
            parent.encode(e)?;
            e.u64(overlap)?;
            e.bool(true)
        });
        self.call(&header_oid(image)?, "parent_attach", &input)?;
        Ok(())
    }

    /// The next destination snapshot ID above the header's `snap_seq`.
    fn allocate_snapshot(&mut self, image: &ImageRef) -> Result<u64, i32> {
        let out = self.call(&header_oid(image)?, "get_snapcontext", b"")?;
        let (sequence, ids): (u64, Vec<u64>) = decode(&out)?;
        let highest = ids.into_iter().max().unwrap_or(0);
        Ok(sequence.max(highest).saturating_add(1))
    }

    /// Create a format-1 image: the header object `<name>.rbd` with the given
    /// object order, HEAD size and USER snapshots, and its name in the
    /// `rbd_directory` TMAP (test setup of `ffi-format1-image.md` "Forced
    /// create").
    pub fn create_legacy_image(
        &mut self,
        image: &ImageRef,
        order: u8,
        size: u64,
        snapshots: &[(u64, &[u8], u64)],
    ) -> Result<(), i32> {
        self.plan.record()?;
        let header = legacy_header_bytes(order, size, snapshots)?;
        {
            let mut mem = self.mem.lock().expect("migration mem store lock");
            mem.objects.entry(header_oid(image)?).or_default().data = header;
        }
        self.tmap_update(&encode_tmap_set(&image.name).map_err(|_| EINVAL)?)
    }

    /// The decoded format-1 header of `image`, `None` when the object is
    /// absent. The migration marker is decoded like the ordinary magic: a v1
    /// source keeps its header and stays readable for the whole migration
    /// (spec "Identity and detection").
    fn legacy_header_of(&mut self, image: &ImageRef) -> Result<Option<LegacyHeader>, i32> {
        let mut data = {
            let mem = self.mem.lock().expect("migration mem store lock");
            match mem.obj(&header_oid(image)?) {
                Some(object) => object.data.clone(),
                None => return Ok(None),
            }
        };
        if data.len() >= RBD_HEADER_TEXT.len()
            && &data[..RBD_HEADER_TEXT.len()] == RBD_MIGRATE_HEADER_TEXT
        {
            data[..RBD_HEADER_TEXT.len()].copy_from_slice(RBD_HEADER_TEXT);
        }
        LegacyHeader::decode(&data).map(Some).map_err(|_| EIO)
    }

    /// The pool's format-1 names, in stored (ascending) order.
    fn legacy_directory_names(&mut self) -> Result<Vec<Vec<u8>>, i32> {
        let data = {
            let mem = self.mem.lock().expect("migration mem store lock");
            match mem.obj(DIRECTORY_OID) {
                Some(object) => object.data.clone(),
                None => return Ok(Vec::new()),
            }
        };
        decode_legacy_directory(&data)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| entry.name)
                    .collect::<Vec<_>>()
            })
            .map_err(|_| EIO)
    }

    /// Apply one TMAPUP command stream to the `rbd_directory` data bytes with
    /// the OSD semantics ([`apply_tmap_commands`]); an error leaves the object
    /// unchanged.
    fn tmap_update(&mut self, commands: &[u8]) -> Result<(), i32> {
        let data = {
            let mem = self.mem.lock().expect("migration mem store lock");
            match mem.obj(DIRECTORY_OID) {
                Some(object) => object.data.clone(),
                None => Vec::new(),
            }
        };
        let updated = apply_tmap_commands(&data, commands).map_err(|error| match error {
            LegacyDirectoryError::NotFound => ENOENT,
            LegacyDirectoryError::Truncated | LegacyDirectoryError::Malformed => EIO,
        })?;
        let mut mem = self.mem.lock().expect("migration mem store lock");
        mem.objects
            .entry(DIRECTORY_OID.to_string())
            .or_default()
            .data = updated;
        Ok(())
    }

    /// One TMAP `'r' name`; an absent key is the completed unlink (V1-2/D1).
    fn tmap_remove(&mut self, name: &[u8]) -> Result<(), i32> {
        match self.tmap_update(&encode_tmap_remove(name).map_err(|_| EINVAL)?) {
            Ok(()) | Err(ENOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// One TMAP `'s' name <empty>`; SET inserts or replaces, so it is
    /// idempotent.
    fn tmap_set(&mut self, name: &[u8]) -> Result<(), i32> {
        self.tmap_update(&encode_tmap_set(name).map_err(|_| EINVAL)?)
    }

    fn trash_set_state(&mut self, id: &[u8], state: u8) -> Result<(), i32> {
        let out = self.call(TRASH_OID, "trash_get", &enc(&id.to_vec()))?;
        let spec: TrashImageSpec = decode(&out)?;
        self.plan.record()?;
        let input = encoded(|e| {
            id.to_vec().encode(e)?;
            e.u8(state)?;
            e.u8(spec.state)
        });
        self.call(TRASH_OID, "trash_state_set", &input)?;
        Ok(())
    }

    fn directory_add(&mut self, name: &[u8], id: &[u8]) -> Result<(), i32> {
        self.plan.record()?;
        let input = encoded(|e| {
            name.to_vec().encode(e)?;
            id.to_vec().encode(e)
        });
        match self.call(DIRECTORY_OID, "dir_add_image", &input) {
            // An entry that already names this ID is the resumable step.
            Ok(_) | Err(EEXIST) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn create_id_object(&mut self, image: &ImageRef) -> Result<(), i32> {
        let object = id_oid(image);
        match self.call(&object, "get_id", b"") {
            Ok(out) => {
                if decode::<Vec<u8>>(&out)? != image.id {
                    return Err(EEXIST);
                }
                Ok(())
            }
            Err(ENOENT) => {
                self.plan.record()?;
                self.create_id_object_unchecked(image)
            }
            Err(error) => Err(error),
        }
    }

    /// The format-2 part of B10: `RESTORING`, the `rbd_id.<name>` object and
    /// the directory entry (spec "Abort", B10).
    fn trash_restore_name(&mut self, image: &ImageRef) -> Result<(), i32> {
        self.trash_set_state(&image.id, TRASH_STATE_RESTORING)?;
        if let Err(status) = self.create_id_object(image) {
            // The name belongs to another ID: reset the entry before failing so
            // a later run sees the same NORMAL state stock leaves.
            if status == EEXIST
                && let Err(rollback) = self.trash_set_state(&image.id, TRASH_STATE_NORMAL)
            {
                diag!("WARNING migration abort: trash state rollback failed ({rollback})");
            }
            return Err(status);
        }
        self.directory_add(&image.name, &image.id)
    }
}

impl MigrationStoreRead for MigrationMemStore {
    fn read_record(&mut self, image: &ImageRef) -> Result<Option<MigrationRecord>, i32> {
        match self.call(&header_oid(image)?, "migration_get", b"") {
            Ok(out) => Ok(Some(from_cls_record(decode(&out)?))),
            // A header without the MIGRATING bit answers EINVAL; an absent
            // object answers ENOENT. Both mean "no record".
            Err(ENOENT) | Err(EINVAL) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn header_present(&mut self, image: &ImageRef) -> Result<bool, i32> {
        let mem = self.mem.lock().expect("migration mem store lock");
        Ok(mem.obj(&header_oid(image)?).is_some())
    }

    fn image_features(&mut self, image: &ImageRef) -> Result<u64, i32> {
        // A format-1 header carries no feature mask; the source mask is 0
        // (spec Q0).
        if image.is_v1() {
            return Ok(0);
        }
        let out = self.call(&header_oid(image)?, "get_features", &enc(&0u64))?;
        let bytes: [u8; 8] = out.get(..8).ok_or(EIO)?.try_into().map_err(|_| EIO)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn trash_list(&mut self) -> Result<Vec<TrashEntry>, i32> {
        let input = encoded(|e| {
            Vec::<u8>::new().encode(e)?;
            e.u64(u64::MAX)
        });
        match self.call(TRASH_OID, "trash_list", &input) {
            Ok(out) => {
                let entries: BTreeMap<Vec<u8>, TrashImageSpec> = decode(&out)?;
                Ok(entries
                    .into_iter()
                    .map(|(id, spec)| TrashEntry {
                        id,
                        name: spec.name,
                        source: spec.source,
                        state: spec.state,
                    })
                    .collect())
            }
            Err(ENOENT) => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    fn directory_get(&mut self, name: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        match self.call(DIRECTORY_OID, "dir_get_id", &enc(&name.to_vec())) {
            Ok(out) => Ok(Some(decode(&out)?)),
            Err(ENOENT) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn directory_get_in(
        &mut self,
        _pool_id: i64,
        _namespace: &[u8],
        name: &[u8],
    ) -> Result<Option<Vec<u8>>, i32> {
        // One in-memory pool per store: the pool/namespace select nothing.
        self.directory_get(name)
    }

    fn id_object_present(&mut self, image: &ImageRef) -> Result<bool, i32> {
        let mem = self.mem.lock().expect("migration mem store lock");
        Ok(mem.obj(&id_oid(image)).is_some())
    }

    fn name_listed(&mut self, image: &ImageRef) -> Result<bool, i32> {
        // One in-memory pool per store: the pool/namespace of the reference
        // select nothing, as for `directory_get_in`.
        Ok(self
            .legacy_directory_names()?
            .iter()
            .any(|name| name == &image.name))
    }

    fn group_of(&mut self, image: &ImageRef) -> Result<Option<GroupRef>, i32> {
        // A format-1 image has no group reference (spec Q7).
        if image.is_v1() {
            return Ok(None);
        }
        let out = self.call(&header_oid(image)?, "image_group_get", b"")?;
        let spec: GroupSpec = decode(&out)?;
        if spec.pool_id < 0 || spec.group_id.is_empty() {
            Ok(None)
        } else {
            Ok(Some(GroupRef {
                pool_id: spec.pool_id,
                group_id: spec.group_id,
            }))
        }
    }

    fn mirror_state(&mut self, image: &ImageRef) -> Result<MirrorState, i32> {
        // A format-1 image has no mirror record; the Q1 lookup with its empty
        // ID is a no-op (spec Q1).
        if image.is_v1() {
            return Ok(MirrorState::default());
        }
        match self.call(MIRRORING_OID, "mirror_image_get", &enc(&image.id.to_vec())) {
            Ok(out) => {
                let mirror: MirrorImage = decode(&out)?;
                Ok(MirrorState {
                    record_present: true,
                    enabled: mirror.state == IMG_ENABLED,
                    mode: mirror.mode,
                })
            }
            Err(ENOENT) => Ok(MirrorState::default()),
            Err(error) => Err(error),
        }
    }

    fn pool_mirror_mode(&mut self, _pool_id: i64) -> Result<PoolMode, i32> {
        match self.call(MIRRORING_OID, "mirror_mode_get", b"") {
            Ok(out) => {
                let bytes: [u8; 4] = out.get(..4).ok_or(EIO)?.try_into().map_err(|_| EIO)?;
                match u32::from_le_bytes(bytes) {
                    MODE_DISABLED => Ok(PoolMode::Disabled),
                    MODE_IMAGE => Ok(PoolMode::Image),
                    MODE_POOL => Ok(PoolMode::Pool),
                    MODE_INIT_ONLY => Ok(PoolMode::InitOnly),
                    _ => Err(EINVAL),
                }
            }
            Err(ENOENT) => Ok(PoolMode::Disabled),
            Err(error) => Err(error),
        }
    }

    fn children_of(&mut self, image: &ImageRef, snapshot_id: u64) -> Result<Vec<ChildRef>, i32> {
        // A format-1 image has no LAYERING and can never be a parent (spec Q9).
        if image.is_v1() {
            return Ok(Vec::new());
        }
        let input = enc(&snapshot_id);
        match self.call(&header_oid(image)?, "children_list", &input) {
            Ok(out) => {
                let children: BTreeSet<ChildImageSpec> = decode(&out)?;
                Ok(children
                    .into_iter()
                    .map(|child| ChildRef {
                        pool_id: child.pool_id,
                        namespace: child.pool_namespace,
                        image_id: child.image_id,
                    })
                    .collect())
            }
            Err(ENOENT) => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    fn snapshots(&mut self, image: &ImageRef) -> Result<Vec<SnapshotInfo>, i32> {
        if image.is_v1() {
            let Some(header) = self.legacy_header_of(image)? else {
                return Ok(Vec::new());
            };
            let mut snapshots: Vec<SnapshotInfo> = header
                .snapshots
                .iter()
                .map(|snapshot| SnapshotInfo {
                    id: snapshot.id,
                    name: snapshot.name.clone(),
                    size: snapshot.image_size,
                    user: true,
                })
                .collect();
            snapshots.sort_by_key(|snapshot| snapshot.id);
            return Ok(snapshots);
        }
        let mem = self.mem.lock().expect("migration mem store lock");
        let Some(object) = mem.obj(&header_oid(image)?) else {
            return Ok(Vec::new());
        };
        let mut snapshots = Vec::new();
        for (key, value) in &object.omap {
            if !key.starts_with(b"snapshot_") {
                continue;
            }
            let record: SnapRec = decode(value)?;
            snapshots.push(SnapshotInfo {
                id: record.id,
                name: record.name,
                size: record.image_size,
                user: matches!(record.ns, SnapNs::User),
            });
        }
        snapshots.sort_by_key(|snapshot| snapshot.id);
        Ok(snapshots)
    }

    fn snapshot_exists(&mut self, image: &ImageRef, id: u64) -> Result<bool, i32> {
        if image.is_v1() {
            return Ok(self
                .snapshots(image)?
                .iter()
                .any(|snapshot| snapshot.id == id));
        }
        match self.call(&header_oid(image)?, "snapshot_get", &enc(&id)) {
            Ok(_) => Ok(true),
            Err(ENOENT) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn head_parent_present(&mut self, image: &ImageRef) -> Result<bool, i32> {
        // A format-1 image has no parent field (spec "Snapshot mapping").
        if image.is_v1() {
            return Ok(false);
        }
        Ok(self.head_parent_overlap(image)?.is_some())
    }

    fn snapshot_parent_present(&mut self, image: &ImageRef, id: u64) -> Result<bool, i32> {
        if image.is_v1() {
            return Ok(false);
        }
        Ok(self.snapshot_parent_overlap(image, id)?.is_some())
    }
}

impl MigrationImportStore for MigrationMemStore {
    fn set_record_state(
        &mut self,
        image: &ImageRef,
        state: u8,
        description: &[u8],
    ) -> Result<(), i32> {
        self.plan.record()?;
        let input = encoded(|e| {
            e.u8(state)?;
            description.to_vec().encode(e)
        });
        self.call(&header_oid(image)?, "migration_set_state", &input)?;
        Ok(())
    }

    fn remove_record(&mut self, image: &ImageRef) -> Result<(), i32> {
        self.plan.record()?;
        self.call_ignore_enoent(&header_oid(image)?, "migration_remove", b"")
    }

    fn mirror_enable(&mut self, image: &ImageRef, mode: u8) -> Result<(), i32> {
        // Idempotent: an already enabled record in the same mode is the
        // resumable step (B10 may have enabled it), another mode is refused.
        let current = self.mirror_state(image)?;
        if current.record_present && current.enabled {
            return if current.mode == mode {
                Ok(())
            } else {
                Err(EINVAL)
            };
        }
        self.plan.record()?;
        if let Some(errno) = self.mirror_errno {
            return Err(errno);
        }
        self.mirror_enables.push((image.clone(), mode));
        let mirror = MirrorImage {
            global_image_id: format!("gid-{}", hex::encode(&image.id)).into_bytes(),
            state: IMG_ENABLED,
            mode,
        };
        let input = encoded(|e| {
            image.id.clone().encode(e)?;
            mirror.encode(e)
        });
        self.call(MIRRORING_OID, "mirror_image_set", &input)?;
        Ok(())
    }

    fn group_remove_image(&mut self, image: &ImageRef) -> Result<(), i32> {
        let Some(group) = self.group_of(image)? else {
            return Ok(());
        };
        self.plan.record()?;
        let spec = GroupSpec {
            pool_id: group.pool_id,
            group_id: group.group_id,
        };
        self.call(&header_oid(image)?, "image_group_remove", &enc(&spec))?;
        Ok(())
    }

    fn remove_snapshot(&mut self, image: &ImageRef, id: u64) -> Result<(), i32> {
        // A format-1 snapshot is an entry of the header object's data bytes;
        // rewriting that array is the WP-7 S4 removal path (WP-5 S6/D2).
        if image.is_v1() {
            return Err(EOPNOTSUPP);
        }
        self.plan.record()?;
        let input = encoded(|e| {
            e.u64(id)?;
            e.u8(PROTECTION_UNPROTECTED)
        });
        self.call_ignore_enoent(&header_oid(image)?, "set_protection_status", &input)?;
        self.call_ignore_enoent(&header_oid(image)?, "snapshot_remove", &enc(&id))
    }

    fn remove_image(
        &mut self,
        image: &ImageRef,
        from_trash: bool,
        progress: &mut dyn FnMut(u64, u64) -> i32,
    ) -> Result<(), i32> {
        self.plan.record()?;
        if image.is_v1() {
            // K3 of a format-1 source: trim with the caller progress, then
            // remove `<name>.rbd` (a missing object is the completed step),
            // then the TMAP key; the TMAP result is the call result (spec K3).
            // An absent key is the completed unlink (V1-2/D1). There is no
            // trash entry, ID object, object map or journal.
            let status = progress(0, 1);
            if status < 0 {
                return Err(status);
            }
            let status = progress(1, 1);
            if status < 0 {
                return Err(status);
            }
            {
                let mut mem = self.mem.lock().expect("migration mem store lock");
                mem.objects.remove(&header_oid(image)?);
            }
            return self.tmap_remove(&image.name);
        }
        if !from_trash {
            // B9 is not from-trash: the directory entry and the ID object go
            // with the image.
            let input = encoded(|e| {
                image.name.clone().encode(e)?;
                image.id.clone().encode(e)
            });
            self.call_ignore_enoent(DIRECTORY_OID, "dir_remove_image", &input)?;
        }
        // From-trash (K3): the Q2 trash move already unlinked the name and
        // removed the ID object, and the entry stays for K4.
        {
            let mut mem = self.mem.lock().expect("migration mem store lock");
            mem.objects.remove(&header_oid(image)?);
            if !from_trash {
                mem.objects.remove(&id_oid(image));
            }
            mem.objects
                .remove(&format!("rbd_object_map.{}", hex::encode(&image.id)));
            mem.objects
                .remove(&format!("journal.{}", hex::encode(&image.id)));
        }
        // Model the trim of one logical object: start, then final 100%.
        let status = progress(0, 1);
        if status < 0 {
            return Err(status);
        }
        let status = progress(1, 1);
        if status < 0 {
            return Err(status);
        }
        Ok(())
    }
}

impl MigrationCommitStore for MigrationMemStore {
    fn trash_remove(&mut self, image: &ImageRef) -> Result<(), i32> {
        self.plan.record()?;
        self.call_ignore_enoent(TRASH_OID, "trash_remove", &enc(&image.id.to_vec()))?;
        if !self.header_present(image)? {
            // D7: K3 removed the header object; its by-ID objects survive it.
            let mut mem = self.mem.lock().expect("migration mem store lock");
            mem.objects
                .remove(&format!("rbd_object_map.{}", hex::encode(&image.id)));
            mem.objects
                .remove(&format!("journal.{}", hex::encode(&image.id)));
        }
        Ok(())
    }
}

impl MigrationAbortStore for MigrationMemStore {
    fn source_relink(&mut self, image: &ImageRef) -> Result<(), i32> {
        if image.is_v1() {
            // B10: one TMAP `'s' name <empty>`; SET is idempotent, so a re-run
            // and an already-listed name are the same success.
            self.plan.record()?;
            return self.tmap_set(&image.name);
        }
        self.trash_restore_name(image)
    }

    fn group_add_image(&mut self, group: &GroupRef, image: &ImageRef) -> Result<(), i32> {
        self.plan.record()?;
        let spec = GroupSpec {
            pool_id: group.pool_id,
            group_id: group.group_id.clone(),
        };
        self.call(&header_oid(image)?, "image_group_add", &enc(&spec))?;
        let status = GroupImageStatus {
            spec: GroupImageSpec {
                image_id: image.id.clone(),
                pool_id: image.pool_id,
            },
            state: 0,
        };
        self.call(&group_oid(group), "group_image_set", &enc(&status))?;
        Ok(())
    }

    fn relink_child(
        &mut self,
        child: &ChildRef,
        from: &ImageRef,
        from_snapshot: u64,
        to: &ImageRef,
        to_snapshot: u64,
    ) -> Result<(), i32> {
        let child_image = ImageRef {
            format: ImageFormat::V2,
            pool_id: child.pool_id,
            namespace: child.namespace.clone(),
            name: Vec::new(),
            id: child.image_id.clone(),
        };
        let parent = self
            .parent_of(&child_image)?
            .map(|parent| crate::parent_query::ParentSpec {
                pool: parent.pool_id,
                namespace: parent.pool_namespace,
                image_id: parent.image_id,
                snapshot_id: parent.snap_id,
            });
        let overlap = self.parent_overlap(&child_image)?;
        // The per-child decision is shared with the RADOS store: the parent
        // must name the source snapshot (rewrite), the target (repair) or be
        // absent; anything else is `-ESTALE`.
        let decision = crate::migration_children::relink_parent(
            parent.as_ref(),
            from,
            from_snapshot,
            to,
            to_snapshot,
        )?;
        self.plan.record()?;
        let child_spec = ChildImageSpec {
            pool_id: child.pool_id,
            pool_namespace: child.namespace.clone(),
            image_id: child.image_id.clone(),
        };
        let input = encoded(|e| {
            e.u64(from_snapshot)?;
            child_spec.encode(e)
        });
        self.call_ignore_enoent(&header_oid(from)?, "child_detach", &input)?;
        if decision == crate::migration_children::RelinkParent::Rewrite {
            let parent_spec = ParentImageSpec {
                pool_id: to.pool_id,
                pool_namespace: to.namespace.clone(),
                image_id: to.id.clone(),
                snap_id: to_snapshot,
            };
            let input = encoded(|e| {
                parent_spec.encode(e)?;
                e.u64(overlap)?;
                e.bool(true)
            });
            self.call(&header_oid(&child_image)?, "parent_attach", &input)?;
        }
        let input = encoded(|e| {
            e.u64(to_snapshot)?;
            child_spec.encode(e)
        });
        match self.call(&header_oid(to)?, "child_attach", &input) {
            Ok(_) | Err(EEXIST) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn revert_data(
        &mut self,
        source: &ImageRef,
        destination: &ImageRef,
        boundary: Option<u64>,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<(), i32> {
        // Reverting into a format-1 source writes under the v1 SnapContext and
        // its 12-hex data-object names: the WP-7 S4 copier.
        if source.is_v1() {
            return Err(EOPNOTSUPP);
        }
        self.plan.record()?;
        if let Some(errno) = self.revert_errno {
            return Err(errno);
        }
        self.reverts.push(RevertCall {
            source: source.clone(),
            destination: destination.clone(),
            boundary,
        });
        progress(0, 1);
        progress(1, 1);
        Ok(())
    }
}

impl MigrationStore for MigrationMemStore {
    fn write_record(&mut self, image: &ImageRef, record: &MigrationRecord) -> Result<(), i32> {
        self.plan.record()?;
        let spec = to_cls_record(record);
        self.call(&header_oid(image)?, "migration_set", &enc(&spec))?;
        Ok(())
    }

    fn mirror_disable(&mut self, image: &ImageRef) -> Result<(), i32> {
        let state = self.mirror_state(image)?;
        if !state.record_present {
            return Ok(());
        }
        self.plan.record()?;
        let mirror = MirrorImage {
            global_image_id: format!("gid-{}", hex::encode(&image.id)).into_bytes(),
            state: IMG_DISABLING,
            mode: state.mode,
        };
        let input = encoded(|e| {
            image.id.clone().encode(e)?;
            mirror.encode(e)
        });
        self.call(MIRRORING_OID, "mirror_image_set", &input)?;
        self.call_ignore_enoent(
            MIRRORING_OID,
            "mirror_image_remove",
            &enc(&image.id.to_vec()),
        )
    }

    fn source_unlink(&mut self, image: &ImageRef) -> Result<(), i32> {
        if image.is_v1() {
            // Q2: one TMAP `'r' name`; an absent key is the completed unlink
            // (V1-2/D1). No trash entry, ID object or directory entry exists.
            self.plan.record()?;
            return self.tmap_remove(&image.name);
        }
        // Q2 in the pinned order: MOVING entry (an existing one is the
        // resumable step), ID object, directory `(name, id)`, then NORMAL.
        let moving = TrashEntry {
            id: image.id.clone(),
            name: image.name.clone(),
            source: TRASH_SOURCE_MIGRATION,
            state: TRASH_STATE_MOVING,
        };
        match self.trash_add(&moving) {
            Ok(()) | Err(EEXIST) => {}
            Err(error) => return Err(error),
        }
        self.remove_id_object(image)?;
        self.directory_remove(&image.name, &image.id)?;
        self.trash_set_state(&image.id, TRASH_STATE_NORMAL)
    }

    fn create_destination(
        &mut self,
        destination: &ImageRef,
        image: &DestinationImage,
        parent: Option<&crate::parent_query::ParentSpec>,
        parent_overlap: u64,
    ) -> Result<(), i32> {
        // Q4 in the pinned create order: directory entry, ID object, header.
        self.plan.record()?;
        let input = encoded(|e| {
            destination.name.clone().encode(e)?;
            destination.id.clone().encode(e)
        });
        self.call(DIRECTORY_OID, "dir_add_image", &input)?;
        self.plan.record()?;
        self.create_id_object_unchecked(destination)?;
        self.plan.record()?;
        let prefix = format!("rbd_data.{}", hex::encode(&destination.id));
        let input = encoded(|e| {
            e.u64(image.size)?;
            e.u8(image.order)?;
            e.u64(image.features)?;
            prefix.as_bytes().to_vec().encode(e)?;
            e.i64(-1)
        });
        self.call(&header_oid(destination)?, "create", &input)?;
        if let Some(parent) = parent {
            let parent_image = ImageRef {
                format: ImageFormat::V2,
                pool_id: parent.pool,
                namespace: parent.namespace.clone(),
                name: Vec::new(),
                id: parent.image_id.clone(),
            };
            self.attach_child(
                &parent_image,
                parent.snapshot_id,
                destination,
                parent_overlap,
            )?;
        }
        Ok(())
    }

    fn copy_snapshot_structure(
        &mut self,
        source: &ImageRef,
        destination: &ImageRef,
        flatten: bool,
    ) -> Result<BTreeMap<u64, u64>, i32> {
        // The same Q0 rule again: a revision created between Q0 and Q5 must
        // not be copied into a mixed-parent destination.
        crate::migration_store::validate_revision_parents(self, source, flatten)?;
        let head_size = self.head_size(source)?;
        let head_parent = self.parent_of(source)?;
        let head_overlap = self.head_parent_overlap(source)?;
        let mut revisions = self.snapshots(source)?;
        revisions.sort_by_key(|revision| revision.id);
        let mut snap_seqs = BTreeMap::new();
        for revision in revisions {
            let overlap = self.snapshot_parent_overlap(source, revision.id)?;
            self.plan.record()?;
            self.call(
                &header_oid(destination)?,
                "set_size",
                &revision.size.to_le_bytes(),
            )?;
            // The parent identity is image-wide and every revision of a
            // parented source has an overlap (validate_revision_parents).
            if !flatten && let Some(parent) = &head_parent {
                self.plan.record()?;
                self.attach_parent_overlap(destination, parent, overlap.unwrap_or(0))?;
            }
            self.plan.record()?;
            let id = self.allocate_snapshot(destination)?;
            let input = encoded(|e| {
                revision.name.clone().encode(e)?;
                e.u64(id)
            });
            self.call(&header_oid(destination)?, "snapshot_add", &input)?;
            snap_seqs.insert(revision.id, id);
        }
        // HEAD returns to the source HEAD size and overlap.
        self.plan.record()?;
        self.call(
            &header_oid(destination)?,
            "set_size",
            &head_size.to_le_bytes(),
        )?;
        if !flatten && let Some(parent) = &head_parent {
            self.plan.record()?;
            self.attach_parent_overlap(destination, parent, head_overlap.unwrap_or(0))?;
        }
        Ok(snap_seqs)
    }

    fn copy_metadata(&mut self, source: &ImageRef, destination: &ImageRef) -> Result<(), i32> {
        let input = encoded(|e| {
            Vec::<u8>::new().encode(e)?;
            e.u64(u64::MAX)
        });
        let out = self.call(&header_oid(source)?, "metadata_list", &input)?;
        let entries: BTreeMap<Vec<u8>, Vec<u8>> = decode(&out)?;
        if entries.is_empty() {
            return Ok(());
        }
        self.plan.record()?;
        let input = encoded(|e| entries.encode(e));
        self.call(&header_oid(destination)?, "metadata_set", &input)?;
        Ok(())
    }

    fn notify(&mut self, _image: &ImageRef) -> Result<(), i32> {
        Ok(())
    }
}

/// The image header object: `rbd_header.<id>` for format 2, `<name>.rbd` for
/// format 1 ([`ImageRef::header_object_name`]). The in-memory pool addresses
/// objects by UTF-8 name, so a non-UTF-8 image name is `-EINVAL` (a testkit
/// limit, not a wire rule).
fn header_oid(image: &ImageRef) -> Result<String, i32> {
    String::from_utf8(image.header_object_name()).map_err(|_| EINVAL)
}

fn id_oid(image: &ImageRef) -> String {
    format!("rbd_id.{}", hex::encode(&image.name))
}

/// Encode a format-1 header object: the 112-byte fixed header, then the packed
/// `{id, image_size}` records newest-first, then the NUL-terminated names
/// (`ffi-format1-image.md` "On-disk identity and header"). Test setup: the
/// production writer lives in the format-1 create path.
fn legacy_header_bytes(
    order: u8,
    size: u64,
    snapshots: &[(u64, &[u8], u64)],
) -> Result<Vec<u8>, i32> {
    let mut revisions = snapshots.to_vec();
    revisions.sort_unstable_by_key(|revision| std::cmp::Reverse(revision.0));
    if revisions.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(EINVAL);
    }
    let snap_seq = revisions.first().map_or(0, |revision| revision.0);
    let names_len: usize = revisions
        .iter()
        .try_fold(0usize, |total, revision| {
            total.checked_add(revision.1.len() + 1)
        })
        .ok_or(EINVAL)?;
    let mut header = build_legacy_header(order, size, b"rb.1.2.3").to_vec();
    header[88..96].copy_from_slice(&snap_seq.to_le_bytes());
    header[96..100]
        .copy_from_slice(&(u32::try_from(revisions.len()).map_err(|_| EINVAL)?).to_le_bytes());
    header[104..112].copy_from_slice(&(names_len as u64).to_le_bytes());
    for (id, _, image_size) in &revisions {
        header.extend_from_slice(&id.to_le_bytes());
        header.extend_from_slice(&image_size.to_le_bytes());
    }
    for (_, name, _) in &revisions {
        header.extend_from_slice(name);
        header.push(0);
    }
    Ok(header)
}

fn group_oid(group: &GroupRef) -> String {
    format!("rbd_group_header.{}", hex::encode(&group.group_id))
}

fn enc<T: Encode + ?Sized>(value: &T) -> Vec<u8> {
    denc::to_vec(value).expect("in-memory cls encode")
}

fn encoded(f: impl FnOnce(&mut Encoder<Vec<u8>>) -> denc::Result<()>) -> Vec<u8> {
    let mut encoder = Encoder::new();
    f(&mut encoder).expect("in-memory cls encode");
    encoder.into_vec()
}

fn decode<T: for<'a> Decode<'a>>(bytes: &[u8]) -> Result<T, i32> {
    T::decode(&mut Decoder::new(bytes)).map_err(|_| EIO)
}

fn to_cls_record(record: &MigrationRecord) -> MigrationSpec {
    MigrationSpec {
        header_type: record.header_type,
        pool_id: record.pool_id,
        pool_namespace: record.pool_namespace.clone(),
        image_name: record.image_name.clone(),
        image_id: record.image_id.clone(),
        snap_seqs: record.snap_seqs.clone(),
        overlap: record.overlap,
        flatten: record.flatten,
        mirroring: record.mirroring,
        state: record.state,
        state_description: record.state_description.clone(),
        mirror_image_mode: record.mirror_image_mode,
        source_spec: record.source_spec.clone(),
    }
}

fn from_cls_record(record: MigrationSpec) -> MigrationRecord {
    MigrationRecord {
        header_type: record.header_type,
        pool_id: record.pool_id,
        pool_namespace: record.pool_namespace,
        image_name: record.image_name,
        image_id: record.image_id,
        snap_seqs: record.snap_seqs,
        overlap: record.overlap,
        flatten: record.flatten,
        mirroring: record.mirroring,
        state: record.state,
        state_description: record.state_description,
        mirror_image_mode: record.mirror_image_mode,
        source_spec: record.source_spec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault_plan::CRASH_ERRNO;
    use crate::journal_backend::ESTALE;
    use crate::migration_terminal::{
        HEADER_TYPE_SRC, MIRROR_MODE_SNAPSHOT, STATE_PREPARED, STATE_PREPARING,
        TRASH_SOURCE_MIGRATION, TRASH_STATE_MOVING, TRASH_STATE_NORMAL,
    };
    use cls::rbd::types::feature;

    const FEATURES: u64 = feature::LAYERING | feature::JOURNALING;

    fn image(id: &str, name: &str) -> ImageRef {
        ImageRef {
            format: ImageFormat::V2,
            pool_id: 7,
            namespace: Vec::new(),
            name: name.as_bytes().to_vec(),
            id: id.as_bytes().to_vec(),
        }
    }

    fn store() -> MigrationMemStore {
        MigrationMemStore::new(&Arc::new(FaultPlan::none()))
    }

    /// A format-1 image reference: the name is its identity, the ID is empty.
    fn legacy(name: &str) -> ImageRef {
        ImageRef {
            format: ImageFormat::V1,
            pool_id: 7,
            namespace: Vec::new(),
            name: name.as_bytes().to_vec(),
            id: Vec::new(),
        }
    }

    /// The first 34 data bytes of the image header object (the magic slot).
    fn header_magic(store: &MigrationMemStore, image: &ImageRef) -> Vec<u8> {
        let mem = store.store().lock().expect("migration mem store lock");
        let object = mem
            .obj(&header_oid(image).expect("utf-8 header name"))
            .expect("header object");
        object.data[..RBD_HEADER_TEXT.len()].to_vec()
    }

    fn record(header_type: u8, state: u8, peer: &str) -> MigrationRecord {
        MigrationRecord {
            header_type,
            pool_id: 7,
            pool_namespace: Vec::new(),
            image_name: peer.as_bytes().to_vec(),
            image_id: peer.as_bytes().to_vec(),
            snap_seqs: BTreeMap::new(),
            overlap: 0,
            flatten: false,
            mirroring: false,
            state,
            state_description: Vec::new(),
            mirror_image_mode: 0,
            source_spec: Vec::new(),
        }
    }

    #[test]
    fn record_roundtrip_uses_the_real_migration_handlers() {
        let mut store = store();
        let image = image("a1", "alpha");
        store.create_image(&image, FEATURES).unwrap();
        assert!(store.header_present(&image).unwrap());
        assert!(store.image_features(&image).unwrap() & feature::LAYERING != 0);
        assert_eq!(store.read_record(&image).unwrap(), None);

        let record = record(HEADER_TYPE_SRC, STATE_PREPARING, "b2");
        store.write_record(&image, &record).unwrap();
        assert_eq!(store.read_record(&image).unwrap(), Some(record.clone()));
        assert!(store.image_features(&image).unwrap() & feature::MIGRATING != 0);

        store
            .set_record_state(&image, STATE_PREPARED, b"copied")
            .unwrap();
        let read = store.read_record(&image).unwrap().unwrap();
        assert_eq!(read.state, STATE_PREPARED);
        assert_eq!(read.state_description, b"copied");

        store.remove_record(&image).unwrap();
        assert_eq!(store.read_record(&image).unwrap(), None);
        assert_eq!(
            store.image_features(&image).unwrap() & feature::MIGRATING,
            0
        );
    }

    #[test]
    fn trash_roundtrip_uses_the_real_trash_handlers() {
        let mut store = store();
        let entry = TrashEntry {
            id: b"a1".to_vec(),
            name: b"alpha".to_vec(),
            source: TRASH_SOURCE_MIGRATION,
            state: TRASH_STATE_MOVING,
        };
        store.trash_add(&entry).unwrap();
        assert_eq!(store.trash_list().unwrap(), vec![entry]);
        store.trash_set_state(b"a1", TRASH_STATE_NORMAL).unwrap();
        assert_eq!(store.trash_list().unwrap()[0].state, TRASH_STATE_NORMAL);
        store.trash_remove(&image("a1", "alpha")).unwrap();
        assert!(store.trash_list().unwrap().is_empty());
    }

    #[test]
    fn directory_and_identity_roundtrip() {
        let mut store = store();
        let image = image("a1", "alpha");
        store.create_image(&image, FEATURES).unwrap();
        assert!(store.id_object_present(&image).unwrap());
        assert_eq!(store.directory_get(b"alpha").unwrap(), Some(b"a1".to_vec()));

        store.directory_remove(b"alpha", b"a1").unwrap();
        assert_eq!(store.directory_get(b"alpha").unwrap(), None);
        store.directory_add(b"alpha", b"a1").unwrap();
        assert_eq!(store.directory_get(b"alpha").unwrap(), Some(b"a1".to_vec()));
    }

    #[test]
    fn group_roundtrip_uses_both_group_handlers() {
        let mut store = store();
        let image = image("a1", "alpha");
        store.create_image(&image, FEATURES).unwrap();
        let group = GroupRef {
            pool_id: 7,
            group_id: b"g1".to_vec(),
        };
        assert_eq!(store.group_of(&image).unwrap(), None);
        store.group_add_image(&group, &image).unwrap();
        assert_eq!(store.group_of(&image).unwrap(), Some(group.clone()));
        store.group_remove_image(&image).unwrap();
        assert_eq!(store.group_of(&image).unwrap(), None);
    }

    #[test]
    fn mirror_roundtrip_and_pool_mode() {
        let mut store = store();
        let image = image("a1", "alpha");
        store.create_image(&image, FEATURES).unwrap();
        assert_eq!(store.pool_mirror_mode(7).unwrap(), PoolMode::Disabled);
        assert_eq!(store.mirror_state(&image).unwrap(), MirrorState::default());

        store.set_pool_mirror_mode(PoolMode::Image).unwrap();
        assert_eq!(store.pool_mirror_mode(7).unwrap(), PoolMode::Image);

        store.mirror_enable(&image, MIRROR_MODE_SNAPSHOT).unwrap();
        let state = store.mirror_state(&image).unwrap();
        assert!(state.record_present);
        assert!(state.enabled);
        assert_eq!(state.mode, MIRROR_MODE_SNAPSHOT);

        store.mirror_disable(&image).unwrap();
        assert!(!store.mirror_state(&image).unwrap().record_present);
    }

    #[test]
    fn snapshot_list_exists_and_remove() {
        let mut store = store();
        let image = image("a1", "alpha");
        store.create_image(&image, FEATURES).unwrap();
        assert!(store.snapshots(&image).unwrap().is_empty());
        store.add_snapshot(&image, 11, b"first").unwrap();
        store.add_snapshot(&image, 12, b"second").unwrap();
        assert!(store.snapshot_exists(&image, 11).unwrap());
        assert!(!store.snapshot_exists(&image, 99).unwrap());
        let snapshots = store.snapshots(&image).unwrap();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].name, b"first");
        assert_eq!(snapshots[1].id, 12);

        store.remove_snapshot(&image, 11).unwrap();
        assert!(!store.snapshot_exists(&image, 11).unwrap());
    }

    #[test]
    fn children_attach_list_and_relink() {
        let mut store = store();
        let source = image("a1", "alpha");
        let destination = image("b2", "beta");
        let child = image("c3", "gamma");
        store.create_image(&source, FEATURES).unwrap();
        store.create_image(&destination, FEATURES).unwrap();
        store.create_image(&child, FEATURES).unwrap();
        store.add_snapshot(&source, 11, b"snap").unwrap();
        store.add_snapshot(&destination, 21, b"snap").unwrap();
        store.attach_child(&source, 11, &child, 1 << 20).unwrap();

        let children = store.children_of(&source, 11).unwrap();
        assert_eq!(
            children,
            vec![ChildRef {
                pool_id: 7,
                namespace: Vec::new(),
                image_id: b"c3".to_vec(),
            }]
        );
        let parent = store.parent_of(&child).unwrap().unwrap();
        assert_eq!(parent.image_id, b"a1".to_vec());
        assert_eq!(parent.snap_id, 11);

        store
            .relink_child(
                &ChildRef {
                    pool_id: 7,
                    namespace: Vec::new(),
                    image_id: b"c3".to_vec(),
                },
                &source,
                11,
                &destination,
                21,
            )
            .unwrap();
        assert!(store.children_of(&source, 11).unwrap().is_empty());
        assert_eq!(
            store.children_of(&destination, 21).unwrap(),
            vec![ChildRef {
                pool_id: 7,
                namespace: Vec::new(),
                image_id: b"c3".to_vec(),
            }]
        );
        let parent = store.parent_of(&child).unwrap().unwrap();
        assert_eq!(parent.image_id, b"b2".to_vec());
        assert_eq!(parent.snap_id, 21);
    }

    #[test]
    fn relink_child_moves_the_registration_and_the_parent_both_ways() {
        let mut store = store();
        let source = image("a1", "alpha");
        let destination = image("b2", "beta");
        let child = image("c3", "gamma");
        store.create_image(&source, FEATURES).unwrap();
        store.create_image(&destination, FEATURES).unwrap();
        store.create_image(&child, FEATURES).unwrap();
        store.add_snapshot(&source, 100, b"one").unwrap();
        store.add_snapshot(&destination, 11, b"one").unwrap();
        store.attach_child(&source, 100, &child, 1 << 20).unwrap();
        let child_ref = ChildRef {
            pool_id: 7,
            namespace: Vec::new(),
            image_id: b"c3".to_vec(),
        };

        // Forward (prepare Q9): source snapshot -> destination snapshot.
        store
            .relink_child(&child_ref, &source, 100, &destination, 11)
            .unwrap();
        assert!(store.children_of(&source, 100).unwrap().is_empty());
        assert_eq!(
            store.children_of(&destination, 11).unwrap(),
            vec![child_ref.clone()]
        );
        let parent = store.parent_of(&child).unwrap().unwrap();
        assert_eq!(parent.image_id, b"b2".to_vec());
        assert_eq!(parent.snap_id, 11);
        assert_eq!(store.parent_overlap(&child).unwrap(), 1 << 20);

        // Back (abort B6): the same call with the direction swapped.
        store
            .relink_child(&child_ref, &destination, 11, &source, 100)
            .unwrap();
        assert_eq!(store.children_of(&source, 100).unwrap(), vec![child_ref]);
        assert!(store.children_of(&destination, 11).unwrap().is_empty());
        let parent = store.parent_of(&child).unwrap().unwrap();
        assert_eq!(parent.image_id, b"a1".to_vec());
        assert_eq!(parent.snap_id, 100);
        assert_eq!(store.parent_overlap(&child).unwrap(), 1 << 20);
    }

    #[test]
    fn relink_child_repairs_a_half_moved_child() {
        // The parent reference was rewritten but the registration move was
        // interrupted: the relink only moves the registration (state 2).
        let mut store = store();
        let source = image("a1", "alpha");
        let destination = image("b2", "beta");
        let child = image("c3", "gamma");
        store.create_image(&source, FEATURES).unwrap();
        store.create_image(&destination, FEATURES).unwrap();
        store.create_image(&child, FEATURES).unwrap();
        store.add_snapshot(&source, 100, b"one").unwrap();
        store.add_snapshot(&destination, 11, b"one").unwrap();
        store.attach_child(&source, 100, &child, 1 << 20).unwrap();
        // Move the registration to the destination but leave the parent at the
        // source: the abort must repair without a parent rewrite.
        let child_ref = ChildRef {
            pool_id: 7,
            namespace: Vec::new(),
            image_id: b"c3".to_vec(),
        };
        let input = encoded(|e| {
            e.u64(100)?;
            ChildImageSpec {
                pool_id: 7,
                pool_namespace: Vec::new(),
                image_id: b"c3".to_vec(),
            }
            .encode(e)
        });
        store
            .call(&header_oid(&source).unwrap(), "child_detach", &input)
            .unwrap();
        let input = encoded(|e| {
            e.u64(11)?;
            ChildImageSpec {
                pool_id: 7,
                pool_namespace: Vec::new(),
                image_id: b"c3".to_vec(),
            }
            .encode(e)
        });
        store
            .call(&header_oid(&destination).unwrap(), "child_attach", &input)
            .unwrap();

        store
            .relink_child(&child_ref, &destination, 11, &source, 100)
            .unwrap();
        assert_eq!(store.children_of(&source, 100).unwrap(), vec![child_ref]);
        assert!(store.children_of(&destination, 11).unwrap().is_empty());
        let parent = store.parent_of(&child).unwrap().unwrap();
        assert_eq!(parent.image_id, b"a1".to_vec());
        assert_eq!(parent.snap_id, 100);
    }

    #[test]
    fn relink_child_refuses_a_foreign_parent_with_estale() {
        let mut store = store();
        let source = image("a1", "alpha");
        let destination = image("b2", "beta");
        let other = image("d4", "delta");
        let child = image("c3", "gamma");
        for image in [&source, &destination, &other, &child] {
            store.create_image(image, FEATURES).unwrap();
        }
        store.add_snapshot(&source, 100, b"one").unwrap();
        store.add_snapshot(&destination, 11, b"one").unwrap();
        store.add_snapshot(&other, 7, b"foreign").unwrap();
        store.attach_child(&other, 7, &child, 1 << 20).unwrap();
        let child_ref = ChildRef {
            pool_id: 7,
            namespace: Vec::new(),
            image_id: b"c3".to_vec(),
        };
        assert_eq!(
            store.relink_child(&child_ref, &source, 100, &destination, 11),
            Err(ESTALE)
        );
        // The foreign registration is untouched.
        assert_eq!(store.children_of(&other, 7).unwrap(), vec![child_ref]);
    }

    #[test]
    fn admin_removal_from_trash_keeps_the_entry_for_k4() {
        let mut store = store();
        let image = image("a1", "alpha");
        store.create_image(&image, FEATURES).unwrap();
        store
            .trash_add(&TrashEntry {
                id: b"a1".to_vec(),
                name: b"alpha".to_vec(),
                source: TRASH_SOURCE_MIGRATION,
                state: TRASH_STATE_NORMAL,
            })
            .unwrap();
        // K3 (from trash): the image goes, the entry and the name stay for K4.
        store.remove_image(&image, true, &mut |_, _| 0).unwrap();
        assert!(!store.header_present(&image).unwrap());
        assert_eq!(store.directory_get(b"alpha").unwrap(), Some(b"a1".to_vec()));
        assert_eq!(store.trash_list().unwrap().len(), 1);
        // K4 removes the entry and the residual by-ID objects.
        store.trash_remove(&image).unwrap();
        assert!(store.trash_list().unwrap().is_empty());
        assert!(!store.header_present(&image).unwrap());
    }

    #[test]
    fn admin_removal_not_from_trash_drops_directory_and_identity() {
        let mut store = store();
        let image = image("a1", "alpha");
        store.create_image(&image, FEATURES).unwrap();
        store.remove_image(&image, false, &mut |_, _| 0).unwrap();
        assert!(!store.header_present(&image).unwrap());
        assert!(!store.id_object_present(&image).unwrap());
        assert_eq!(store.directory_get(b"alpha").unwrap(), None);
    }

    #[test]
    fn revert_is_an_opaque_recorded_call_with_progress() {
        let mut store = store();
        let source = image("a1", "alpha");
        let destination = image("b2", "beta");
        let mut progress = Vec::new();
        store
            .revert_data(&source, &destination, Some(11), &mut |done, total| {
                progress.push((done, total));
            })
            .unwrap();
        assert_eq!(progress, vec![(0, 1), (1, 1)]);
        assert_eq!(
            store.reverts(),
            &[RevertCall {
                source,
                destination,
                boundary: Some(11),
            }]
        );
    }

    #[test]
    fn source_unlink_unlinks_the_name_and_leaves_a_migration_entry() {
        let mut store = store();
        let image = image("a1", "alpha");
        store.create_image(&image, FEATURES).unwrap();
        store.source_unlink(&image).unwrap();
        assert_eq!(
            store.trash_list().unwrap(),
            vec![TrashEntry {
                id: b"a1".to_vec(),
                name: b"alpha".to_vec(),
                source: TRASH_SOURCE_MIGRATION,
                state: TRASH_STATE_NORMAL,
            }]
        );
        assert_eq!(store.directory_get(b"alpha").unwrap(), None);
        assert!(!store.id_object_present(&image).unwrap());
        // The header survives the namespace move (Q2 is not a removal).
        assert!(store.header_present(&image).unwrap());
    }

    #[test]
    fn create_destination_writes_identity_then_the_header() {
        let mut store = store();
        let destination = image("d1", "delta");
        let geometry = DestinationImage {
            id: b"d1".to_vec(),
            size: 4 << 20,
            features: FEATURES,
            order: 20,
            stripe_unit: 1 << 20,
            stripe_count: 1,
            data_pool: None,
        };
        store
            .create_destination(&destination, &geometry, None, 0)
            .unwrap();
        assert!(store.header_present(&destination).unwrap());
        assert!(store.id_object_present(&destination).unwrap());
        assert_eq!(store.directory_get(b"delta").unwrap(), Some(b"d1".to_vec()));
        assert_eq!(store.head_size(&destination).unwrap(), 4 << 20);
        assert_eq!(store.image_features(&destination).unwrap(), FEATURES);
    }

    #[test]
    fn copy_snapshot_structure_maps_ids_and_keeps_revision_sizes() {
        let mut store = store();
        let source = image("a1", "alpha");
        let destination = image("d1", "delta");
        store.create_image(&source, FEATURES).unwrap();
        store.add_snapshot(&source, 100, b"one").unwrap();
        store.add_snapshot(&source, 200, b"two").unwrap();
        let geometry = DestinationImage {
            id: b"d1".to_vec(),
            size: 4 << 20,
            features: FEATURES,
            order: 22,
            stripe_unit: 1 << 22,
            stripe_count: 1,
            data_pool: None,
        };
        store
            .create_destination(&destination, &geometry, None, 0)
            .unwrap();
        let snap_seqs = store
            .copy_snapshot_structure(&source, &destination, true)
            .unwrap();
        assert_eq!(snap_seqs.len(), 2);
        let destination_snapshots = store.snapshots(&destination).unwrap();
        assert_eq!(destination_snapshots.len(), 2);
        assert_eq!(destination_snapshots[0].name, b"one");
        assert_eq!(destination_snapshots[1].name, b"two");
        assert!(snap_seqs[&100] < snap_seqs[&200]);
        // HEAD returns to the source HEAD size (create_image's 1 MiB), not the
        // destination creation size.
        assert_eq!(store.head_size(&destination).unwrap(), 1 << 20);
    }

    #[test]
    fn copy_metadata_carries_every_user_key() {
        let mut store = store();
        let source = image("a1", "alpha");
        let destination = image("d1", "delta");
        store.create_image(&source, FEATURES).unwrap();
        store.create_image(&destination, FEATURES).unwrap();
        let input = encoded(|e| {
            let mut map = BTreeMap::new();
            map.insert(b"key".to_vec(), b"value".to_vec());
            map.encode(e)
        });
        store
            .call(&header_oid(&source).unwrap(), "metadata_set", &input)
            .unwrap();
        store.copy_metadata(&source, &destination).unwrap();
        let out = store
            .call(
                &header_oid(&destination).unwrap(),
                "metadata_get",
                &enc(&b"key".to_vec()),
            )
            .unwrap();
        assert_eq!(decode::<Vec<u8>>(&out).unwrap(), b"value");
    }

    #[test]
    fn fault_plan_stops_after_the_kth_mutation() {
        let shared = Arc::new(Mutex::new(MemStore::new()));
        let setup = Arc::new(FaultPlan::none());
        let mut store = MigrationMemStore::from_store(&shared, &setup);
        let image = image("a1", "alpha");
        store.create_image(&image, FEATURES).unwrap();

        let crashing = Arc::new(FaultPlan::crash_after(1));
        let mut store = store.reopen(&crashing);
        let record = record(HEADER_TYPE_SRC, STATE_PREPARING, "b2");
        store.write_record(&image, &record).unwrap();
        assert_eq!(
            store.set_record_state(&image, STATE_PREPARED, b"x"),
            Err(CRASH_ERRNO)
        );
        assert_eq!(store.read_record(&image).unwrap(), Some(record));
        assert_eq!(crashing.mutations(), 2);
    }

    // ---- format-1 source (WP-7 S1): v1 headers, TMAP model, one call per stage

    #[test]
    fn legacy_image_reads_its_header_snapshots_and_tmap_name() {
        let mut store = store();
        let image = legacy("legacy");
        store
            .create_legacy_image(
                &image,
                22,
                4 << 20,
                &[(11, b"one", 1 << 20), (12, b"two", 2 << 20)],
            )
            .unwrap();
        assert!(store.header_present(&image).unwrap());
        assert!(store.name_listed(&image).unwrap());
        assert_eq!(store.image_features(&image).unwrap(), 0);
        // A format-1 image has no ID object and no directory entry.
        assert!(!store.id_object_present(&image).unwrap());
        assert_eq!(store.directory_get(b"legacy").unwrap(), None);
        assert_eq!(store.head_size(&image).unwrap(), 4 << 20);
        let snapshots = store.snapshots(&image).unwrap();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].id, 11);
        assert_eq!(snapshots[0].name, b"one");
        assert_eq!(snapshots[0].size, 1 << 20);
        assert_eq!(snapshots[1].id, 12);
        assert!(snapshots.iter().all(|snapshot| snapshot.user));
        assert!(store.snapshot_exists(&image, 12).unwrap());
        assert!(!store.snapshot_exists(&image, 99).unwrap());
        assert!(!store.head_parent_present(&image).unwrap());
        assert!(!store.snapshot_parent_present(&image, 11).unwrap());
        assert_eq!(store.group_of(&image).unwrap(), None);
        assert!(store.children_of(&image, 11).unwrap().is_empty());
        assert_eq!(store.mirror_state(&image).unwrap(), MirrorState::default());
        assert_eq!(store.read_record(&image).unwrap(), None);
        assert!(store.trash_list().unwrap().is_empty());
    }

    #[test]
    fn legacy_record_roundtrip_uses_the_v1_class_branch() {
        // Q3 writes the 34-byte marker and the `migration` key in one class op;
        // B12 restores the ordinary magic (spec "Migration marker").
        let mut store = store();
        let image = legacy("legacy");
        store.create_legacy_image(&image, 22, 1 << 20, &[]).unwrap();
        assert_eq!(header_magic(&store, &image), RBD_HEADER_TEXT.to_vec());

        let record = record(HEADER_TYPE_SRC, STATE_PREPARING, "d");
        store.write_record(&image, &record).unwrap();
        assert_eq!(store.read_record(&image).unwrap(), Some(record));
        assert_eq!(
            header_magic(&store, &image),
            RBD_MIGRATE_HEADER_TEXT.to_vec()
        );
        // A v1 header carries no feature mask: no MIGRATING bit appears.
        assert_eq!(store.image_features(&image).unwrap(), 0);

        store
            .set_record_state(&image, STATE_PREPARED, b"copied")
            .unwrap();
        assert_eq!(
            store.read_record(&image).unwrap().unwrap().state,
            STATE_PREPARED
        );
        store.remove_record(&image).unwrap();
        assert_eq!(store.read_record(&image).unwrap(), None);
        assert_eq!(header_magic(&store, &image), RBD_HEADER_TEXT.to_vec());
    }

    #[test]
    fn legacy_snapshots_stay_readable_through_the_migration_marker() {
        // A v1 source keeps its header for the whole migration and stays
        // readable; only the 34 magic bytes change.
        let mut store = store();
        let image = legacy("legacy");
        store
            .create_legacy_image(&image, 22, 4 << 20, &[(11, b"one", 1 << 20)])
            .unwrap();
        let before = {
            let mem = store.store().lock().expect("migration mem store lock");
            mem.obj(&header_oid(&image).unwrap()).unwrap().data.clone()
        };
        store
            .write_record(&image, &record(HEADER_TYPE_SRC, STATE_PREPARING, "d"))
            .unwrap();
        let after = {
            let mem = store.store().lock().expect("migration mem store lock");
            mem.obj(&header_oid(&image).unwrap()).unwrap().data.clone()
        };
        assert_eq!(after[..RBD_HEADER_TEXT.len()], RBD_MIGRATE_HEADER_TEXT[..]);
        assert_eq!(
            after[RBD_HEADER_TEXT.len()..],
            before[RBD_HEADER_TEXT.len()..]
        );
        assert_eq!(store.snapshots(&image).unwrap().len(), 1);
        assert_eq!(store.head_size(&image).unwrap(), 4 << 20);
    }

    #[test]
    fn legacy_source_unlink_is_idempotent_d1() {
        let mut store = store();
        let image = legacy("legacy");
        store.create_legacy_image(&image, 22, 1 << 20, &[]).unwrap();
        store.source_unlink(&image).unwrap();
        assert!(!store.name_listed(&image).unwrap());
        // D1: the second unlink (a crash between Q2 and Q3) is success.
        store.source_unlink(&image).unwrap();
        // Q2 is a namespace change: the header object survives it.
        assert!(store.header_present(&image).unwrap());
        // A v1 source never gains a trash entry or an ID object.
        assert!(store.trash_list().unwrap().is_empty());
        assert!(!store.id_object_present(&image).unwrap());
    }

    #[test]
    fn legacy_source_relink_sets_the_tmap_key_idempotently() {
        let mut store = store();
        let image = legacy("legacy");
        store.create_legacy_image(&image, 22, 1 << 20, &[]).unwrap();
        store.source_unlink(&image).unwrap();
        store.source_relink(&image).unwrap();
        assert!(store.name_listed(&image).unwrap());
        // SET replaces: a re-run after a B10 crash is the same success.
        store.source_relink(&image).unwrap();
        assert!(store.name_listed(&image).unwrap());
        assert!(store.trash_list().unwrap().is_empty());
    }

    #[test]
    fn legacy_removal_drops_the_header_object_then_the_tmap_key() {
        // K3 of a format-1 source: trim progress, `<name>.rbd`, TMAP key.
        let mut store = store();
        let image = legacy("legacy");
        store.create_legacy_image(&image, 22, 1 << 20, &[]).unwrap();
        let mut progress = Vec::new();
        store
            .remove_image(&image, true, &mut |done, total| {
                progress.push((done, total));
                0
            })
            .unwrap();
        assert_eq!(progress, vec![(0, 1), (1, 1)]);
        assert!(!store.header_present(&image).unwrap());
        assert!(!store.name_listed(&image).unwrap());
        // The re-run is the completed removal: an absent key is tolerated.
        store.remove_image(&image, true, &mut |_, _| 0).unwrap();
    }

    #[test]
    fn legacy_snapshot_removal_and_revert_are_left_to_s4() {
        let mut store = store();
        let source = legacy("legacy");
        let destination = image("d1", "delta");
        store
            .create_legacy_image(&source, 22, 1 << 20, &[(11, b"one", 1 << 20)])
            .unwrap();
        assert_eq!(store.remove_snapshot(&source, 11), Err(EOPNOTSUPP));
        assert_eq!(
            store.revert_data(&source, &destination, Some(11), &mut |_, _| {}),
            Err(EOPNOTSUPP)
        );
        // The refused calls mutated nothing.
        assert!(store.snapshot_exists(&source, 11).unwrap());
        assert!(store.reverts().is_empty());
    }

    #[test]
    fn legacy_name_mutations_count_one_fault_plan_step_each() {
        let shared = Arc::new(Mutex::new(MemStore::new()));
        let setup = Arc::new(FaultPlan::none());
        let mut store = MigrationMemStore::from_store(&shared, &setup);
        let image = legacy("legacy");
        store.create_legacy_image(&image, 22, 1 << 20, &[]).unwrap();

        let crashing = Arc::new(FaultPlan::crash_after(1));
        let mut run = store.reopen(&crashing);
        run.source_unlink(&image).unwrap();
        assert_eq!(run.source_relink(&image), Err(CRASH_ERRNO));
        assert_eq!(crashing.mutations(), 2);
        assert!(!run.name_listed(&image).unwrap());
    }
}
