// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Narrow storage surface for the migration terminal flow (ADR 0705 S2).
//!
//! [`MigrationStore`] names exactly the durable objects the migration
//! lifecycle reads and writes: migration records, MIGRATION trash, the
//! directory and `rbd_id.<name>` identity objects, group and mirror records,
//! children, snapshot list/remove, administrative image removal and the
//! opaque revert call. The production implementation lives in `rbd-ffi` over
//! `RadosContextPair`; the in-memory implementation used by crash-point tests
//! is [`crate::migration_mem::MigrationMemStore`] (feature `migration-testkit`).
//!
//! Every method returns a negative errno on failure. Reads never mutate;
//! mutations are the unit a `FaultPlan` counts (one trait call = one durable
//! mutation, however many class calls implement it).
//!
//! The store is format-dispatched on [`ImageRef::format`]: every header call
//! addresses the header object of the reference
//! ([`ImageRef::header_object_name`]: `rbd_header.<id>` for format 2,
//! `<name>.rbd` for format 1), and the two name mutations are one call per
//! stage for both formats ([`MigrationStore::source_unlink`] for Q2,
//! [`MigrationAbortStore::source_relink`] for B10). A format-1 image is a
//! migration source only; the destination is always format 2.
//!
//! The format-1 mutation bodies land in WP-7 S3/S4: the RADOS backend answers
//! `-EOPNOTSUPP` for `source_unlink`/`source_relink` on a format-1 reference
//! until the TMAP write path is wired, while the in-memory store already models
//! it (`legacy_header::apply_tmap_commands`).
//!
//! The read surface [`MigrationStoreRead`] is what the terminal endpoint
//! resolution (ADR 0705 S4) observes; the mutation surface comes with the
//! stage implementations, so a read-only backend implements the read trait
//! alone. The import-only terminal mutations are [`MigrationImportStore`]
//! (S5); [`MigrationCommitStore`] adds the paired commit stage K4 (S7),
//! [`MigrationAbortStore`] the paired abort mutations (S8/S9) and
//! [`MigrationStore`] the paired prepare mutations (S6).

use std::collections::BTreeMap;

use crate::migration_terminal::{
    GroupRef, ImageRef, MigrationRecord, MirrorState, PoolMode, TrashEntry,
};

/// One image snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    /// Snapshot ID.
    pub id: u64,
    /// Snapshot name.
    pub name: Vec<u8>,
    /// Image size captured by the snapshot.
    pub size: u64,
    /// The snapshot is in the USER namespace.
    pub user: bool,
}

/// A child registration (`cls::rbd::ChildImageSpec`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChildRef {
    /// Child pool ID.
    pub pool_id: i64,
    /// Child pool namespace.
    pub namespace: Vec<u8>,
    /// Child image ID.
    pub image_id: Vec<u8>,
}

/// The destination image a prepare creates (Q4) with the caller's resolved
/// geometry: source HEAD size, feature mask, object order and striping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationImage {
    /// Destination image ID. Generated at Q0 so the source record can name it
    /// before the destination object exists (spec Q3 before Q4).
    pub id: Vec<u8>,
    /// Image size in bytes (the source HEAD size).
    pub size: u64,
    /// Feature mask.
    pub features: u64,
    /// Object order (object size is `1 << order`).
    pub order: u8,
    /// Stripe unit in bytes.
    pub stripe_unit: u64,
    /// Stripe count.
    pub stripe_count: u64,
    /// Destination data pool override, when the caller named one.
    pub data_pool: Option<Vec<u8>>,
}

/// The read surface of the migration store: the durable facts the terminal
/// endpoint resolution observes. Reads never mutate.
pub trait MigrationStoreRead {
    /// Read the migration record of `image`, or `None` when the header is
    /// absent or carries no record.
    fn read_record(&mut self, image: &ImageRef) -> Result<Option<MigrationRecord>, i32>;

    /// True when the image header object exists.
    fn header_present(&mut self, image: &ImageRef) -> Result<bool, i32>;

    /// The header feature mask.
    fn image_features(&mut self, image: &ImageRef) -> Result<u64, i32>;

    /// List the MIGRATION trash entries of the pool.
    fn trash_list(&mut self) -> Result<Vec<TrashEntry>, i32>;

    /// Directory lookup: name to image ID.
    fn directory_get(&mut self, name: &[u8]) -> Result<Option<Vec<u8>>, i32>;

    /// Directory lookup in another pool/namespace (the destination of a
    /// cross-pool prepare lives outside this context's directory).
    fn directory_get_in(
        &mut self,
        pool_id: i64,
        namespace: &[u8],
        name: &[u8],
    ) -> Result<Option<Vec<u8>>, i32>;

    /// True when the `rbd_id.<name>` identity object exists.
    fn id_object_present(&mut self, image: &ImageRef) -> Result<bool, i32>;

    /// True when the image's name is listed in the pool's format-1 directory:
    /// the `rbd_directory` data bytes (the TMAP map), read in the image's pool
    /// and namespace. A format-2 image is never listed there, and a format-1
    /// name is never in the directory omap; the terminal planner consults the
    /// fact for a format-1 source only (B10/D2).
    fn name_listed(&mut self, image: &ImageRef) -> Result<bool, i32>;

    /// Group membership of an image, or `None`.
    fn group_of(&mut self, image: &ImageRef) -> Result<Option<GroupRef>, i32>;

    /// Mirror record state of an image.
    fn mirror_state(&mut self, image: &ImageRef) -> Result<MirrorState, i32>;

    /// Pool mirror mode.
    fn pool_mirror_mode(&mut self, pool_id: i64) -> Result<PoolMode, i32>;

    /// Children registered on `snapshot_id` of `image`.
    fn children_of(&mut self, image: &ImageRef, snapshot_id: u64) -> Result<Vec<ChildRef>, i32>;

    /// List the image snapshots.
    fn snapshots(&mut self, image: &ImageRef) -> Result<Vec<SnapshotInfo>, i32>;

    /// True when snapshot `id` exists.
    fn snapshot_exists(&mut self, image: &ImageRef, id: u64) -> Result<bool, i32>;

    /// True when the header records a parent overlap, i.e. HEAD bytes may
    /// resolve through the parent.
    fn head_parent_present(&mut self, image: &ImageRef) -> Result<bool, i32>;

    /// True when the snapshot records a parent overlap, i.e. that revision's
    /// bytes may resolve through the parent.
    fn snapshot_parent_present(&mut self, image: &ImageRef, id: u64) -> Result<bool, i32>;
}

/// Q0: every revision must agree with HEAD about having a parent.
///
/// `flatten` drops the parent entirely, so it is the supported path for a
/// source whose revisions disagree. Stock reaches the disagreement in its
/// snapshot copy: with DEEP_FLATTEN, `parent_detach` then strips the parent
/// from the snapshots it already copied (they read zeros where the parent had
/// data), and without it the copy fails mid-prepare with `-EEXIST`. The check
/// therefore runs before the first durable write, and again at the snapshot
/// copy for a revision created in between (ADR 0705 S6b).
pub fn validate_revision_parents<S: MigrationStoreRead + ?Sized>(
    store: &mut S,
    source: &ImageRef,
    flatten: bool,
) -> Result<(), i32> {
    if flatten {
        return Ok(());
    }
    let head = store.head_parent_present(source)?;
    for snapshot in store.snapshots(source)? {
        if store.snapshot_parent_present(source, snapshot.id)? != head {
            return Err(crate::journal_backend::EINVAL);
        }
    }
    Ok(())
}

/// The terminal (commit/abort) destination mutations of an import-only
/// migration (ADR 0705 S5). [`MigrationStore`] extends this with the paired
/// prepare/commit/abort mutations that land with S6-S9. `RadosContextPair`
/// implements exactly this subset today, so the store only exposes operations
/// its backend really performs.
pub trait MigrationImportStore: MigrationStoreRead {
    /// Update the state and description of an existing record.
    fn set_record_state(
        &mut self,
        image: &ImageRef,
        state: u8,
        description: &[u8],
    ) -> Result<(), i32>;

    /// Remove the migration record and clear the MIGRATING bit.
    fn remove_record(&mut self, image: &ImageRef) -> Result<(), i32>;

    /// Enable image mirroring in `mode`.
    fn mirror_enable(&mut self, image: &ImageRef, mode: u8) -> Result<(), i32>;

    /// Remove the image from its group.
    fn group_remove_image(&mut self, image: &ImageRef) -> Result<(), i32>;

    /// Remove snapshot `id` (unprotect first).
    fn remove_snapshot(&mut self, image: &ImageRef, id: u64) -> Result<(), i32>;

    /// Administrative full image removal. `from_trash` selects the
    /// from-trash lifecycle: the directory entry and the `rbd_id.<name>`
    /// object were already retired by the trash move, so they are skipped and
    /// the MIGRATION trash entry stays for [`MigrationCommitStore::trash_remove`]
    /// (commit K4). The trim forwards `(object_no, object_count)` progress; a
    /// negative return stops the removal and is propagated as the errno.
    ///
    /// `from_trash` applies to format 2 only: a format-1 image has neither a
    /// trash entry nor an ID object, and its removal is its own lifecycle
    /// (`<name>.rbd` then the TMAP key, spec K3).
    fn remove_image(
        &mut self,
        image: &ImageRef,
        from_trash: bool,
        progress: &mut dyn FnMut(u64, u64) -> i32,
    ) -> Result<(), i32>;
}

/// The paired commit mutations beyond the import terminal surface (ADR 0705
/// S7). Commit stages K1/D6/K2 reuse the import mutations; only the source
/// side needs more, and only K4 is a plain record deletion.
pub trait MigrationCommitStore: MigrationImportStore {
    /// Commit K4: remove the MIGRATION trash entry of `image` and, when its
    /// header object is already gone (K3 ran, D7 resume), the residual by-ID
    /// object map and journal objects. A missing entry is success.
    fn trash_remove(&mut self, image: &ImageRef) -> Result<(), i32>;
}

/// The paired abort mutations beyond the commit surface (ADR 0705 S8/S9).
///
/// Abort reuses the import mutations for B4, B7, B8, B9 and B13; the source
/// side needs the name restore (B10), the group restore (B11), the child
/// relink back (B6) and the data revert (B5).
pub trait MigrationAbortStore: MigrationCommitStore {
    /// B10: restore the source name, one call for the whole stage.
    ///
    /// Format 2 moves the image's MIGRATION trash entry back to the name: set
    /// `RESTORING`, create the `rbd_id.<name>` object (another ID is `-EEXIST`
    /// and resets the entry to `NORMAL`) and add the directory entry. Format 1
    /// writes the one TMAP `'s' name <empty>` command; SET is idempotent, so an
    /// already-listed name is the completed stage.
    fn source_relink(&mut self, image: &ImageRef) -> Result<(), i32>;

    /// B11: add the image to `group` (image side and group header).
    fn group_add_image(&mut self, group: &GroupRef, image: &ImageRef) -> Result<(), i32>;

    /// B6: move one child registration from the destination snapshot back to
    /// the source snapshot, preserving the child's parent overlap. The child's
    /// effective parent must be the destination snapshot (rewritten) or
    /// already the source snapshot (`-ESTALE` otherwise).
    fn relink_child(
        &mut self,
        child: &ChildRef,
        from: &ImageRef,
        from_snapshot: u64,
        to: &ImageRef,
        to_snapshot: u64,
    ) -> Result<(), i32>;

    /// B5: revert the destination interval `(boundary, HEAD]` into the source
    /// HEAD under the source's full snapshot context. The store owns the
    /// copier and the progress forwarding; `boundary` is
    /// [`revert_boundary`](crate::migration_revert::revert_boundary) and the
    /// callback return is ignored (spec "Terminal progress callbacks").
    fn revert_data(
        &mut self,
        source: &ImageRef,
        destination: &ImageRef,
        boundary: Option<u64>,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<(), i32>;
}

/// The full migration store contract: the abort surface plus the paired
/// prepare mutations (S6).
pub trait MigrationStore: MigrationAbortStore {
    /// Write a fresh migration record (fails `-EEXIST` when one exists).
    fn write_record(&mut self, image: &ImageRef, record: &MigrationRecord) -> Result<(), i32>;

    /// Disable and remove the image mirror record.
    fn mirror_disable(&mut self, image: &ImageRef) -> Result<(), i32>;

    /// Q2: unlink the source name, one call for the whole stage.
    ///
    /// Format 2 moves the source into the pool trash with source `MIGRATION`
    /// and delay 0. The move owns the pinned sequence (its own by-ID ownership
    /// preparation and request block, then `MOVING` entry, ID object, directory
    /// `(name, id)` and `NORMAL` state) and, unlike a user trash move, tolerates
    /// a group member. A `-EEXIST` entry is the resumable step. A partly
    /// unlinked name is repaired by abort D2. Format 1 removes the one TMAP
    /// `'r' name` key; an absent key is the completed unlink (V1-2/D1) and no
    /// trash entry, ID object or directory entry exists for it.
    fn source_unlink(&mut self, image: &ImageRef) -> Result<(), i32>;

    /// Q4: create the destination image at `image.id`. `parent` is the
    /// destination's common clone parent (spec "Parent and overlap mapping"):
    /// `None` creates a plain image, otherwise the parent is attached and the
    /// child registered.
    fn create_destination(
        &mut self,
        destination: &ImageRef,
        image: &DestinationImage,
        parent: Option<&crate::parent_query::ParentSpec>,
        parent_overlap: u64,
    ) -> Result<(), i32>;

    /// Q5: copy the source snapshot structure into the destination and return
    /// the source->destination snapshot ID mapping (`snap_seqs`).
    ///
    /// Destination snapshots are created in ascending source ID order; each
    /// carries its own source size and, when `flatten` is false, the common
    /// parent with that revision's own overlap. HEAD ends at the source HEAD
    /// size and overlap. Conflicting source parent specs are `-EINVAL`.
    fn copy_snapshot_structure(
        &mut self,
        source: &ImageRef,
        destination: &ImageRef,
        flatten: bool,
    ) -> Result<BTreeMap<u64, u64>, i32>;

    /// Q5: copy the source's user metadata onto the destination.
    fn copy_metadata(&mut self, source: &ImageRef, destination: &ImageRef) -> Result<(), i32>;

    /// Q9: notify the image header so open clients refresh (the destination's
    /// migration state after prepare). Not a durable mutation.
    fn notify(&mut self, image: &ImageRef) -> Result<(), i32>;
}
