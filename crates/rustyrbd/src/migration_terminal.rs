// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Sans-IO migration terminal-state planner (ADR 0705).
//!
//! The planner maps the observed durable state of a native paired or import-only
//! migration to the next executable stage list, or to the refusal errno. It
//! performs no I/O and owns no handles: callers observe the cluster through
//! [`MigrationStore`](crate::migration_store::MigrationStore) (or any other
//! source) and execute the returned [`Stage`] list in order.
//!
//! Inputs are exactly the durable facts stock writes (ADR 0705 "Decision"): both
//! migration records, header presence, the MIGRATION trash entry, directory and
//! ID-object mappings, the destination snapshot set including the boundary
//! snapshot, group and mirror records, and the child-relink state. No extra
//! recovery record exists, so a re-run derives its stage from these facts.
//!
//! Stage IDs are the spec's: Q* prepare, K* commit, B* abort
//! (`doc/spec/rustyrbd/migration-lifecycle.md`); D* are the ADR 0705
//! deviations. The crash tables in the ADR are the per-stage proof and the
//! unit tests below cover one row per persistent stage.

use std::collections::BTreeMap;

use crate::journal_backend::{EBUSY, EEXIST, EINVAL, ENOENT, ESTALE};

/// `MIGRATION_HEADER_TYPE_SRC`.
pub const HEADER_TYPE_SRC: u8 = 1;
/// `MIGRATION_HEADER_TYPE_DST`.
pub const HEADER_TYPE_DST: u8 = 2;

/// `MIGRATION_STATE_PREPARING`.
pub const STATE_PREPARING: u8 = 1;
/// `MIGRATION_STATE_PREPARED`.
pub const STATE_PREPARED: u8 = 2;
/// `MIGRATION_STATE_EXECUTING`.
pub const STATE_EXECUTING: u8 = 3;
/// `MIGRATION_STATE_EXECUTED`.
pub const STATE_EXECUTED: u8 = 4;
/// `MIGRATION_STATE_ABORTING`.
pub const STATE_ABORTING: u8 = 5;

/// Image mirror mode JOURNAL.
pub const MIRROR_MODE_JOURNAL: u8 = 0;
/// Image mirror mode SNAPSHOT.
pub const MIRROR_MODE_SNAPSHOT: u8 = 1;

/// Trash source MIGRATION.
pub const TRASH_SOURCE_MIGRATION: u8 = 2;
/// Trash state NORMAL.
pub const TRASH_STATE_NORMAL: u8 = 0;
/// Trash state MOVING.
pub const TRASH_STATE_MOVING: u8 = 1;
/// Trash state RESTORING.
pub const TRASH_STATE_RESTORING: u8 = 3;

/// On-disk format of an endpoint's image.
///
/// The format selects the header object, the namespace that lists the name and
/// the identity rule: a format-2 image is bound by its immutable ID, a format-1
/// image has none and is bound by its name (spec "Format-1 source").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImageFormat {
    /// Format 1: a `<name>.rbd` header object and a `rbd_directory` TMAP name.
    /// Migration source only; the destination is always format 2.
    V1,
    /// Format 2 (the default): an `rbd_header.<id>` object and a directory omap
    /// entry.
    #[default]
    V2,
}

/// One endpoint's immutable identity: pool, namespace, name and image ID.
///
/// Resolution starts from a name; every destructive stage re-checks the pair by
/// this identity (ADR 0705 "Identity"), never by the display name alone.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ImageRef {
    /// Pool ID that holds the image header.
    pub pool_id: i64,
    /// Pool namespace (empty for the default namespace).
    pub namespace: Vec<u8>,
    /// Image name at the endpoint (may be unlinked from the directory).
    pub name: Vec<u8>,
    /// Immutable image ID; empty for a format-1 image, which has none.
    pub id: Vec<u8>,
    /// On-disk format of the image.
    pub format: ImageFormat,
}

impl ImageRef {
    /// True for a format-1 image.
    pub fn is_v1(&self) -> bool {
        self.format == ImageFormat::V1
    }

    /// The image header object: `rbd_header.<id>` for format 2, `<name>.rbd`
    /// for format 1 (spec "Format-1 source", "Identity and detection").
    pub fn header_object_name(&self) -> Vec<u8> {
        if self.is_v1() {
            let mut name = self.name.clone();
            name.extend_from_slice(b".rbd");
            name
        } else {
            let mut name = b"rbd_header.".to_vec();
            name.extend_from_slice(&self.id);
            name
        }
    }
}

/// The observed `cls::rbd::MigrationSpec` of one header.
///
/// Only the fields the planner needs are carried; the codec lives in the
/// store implementation.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MigrationRecord {
    /// [`HEADER_TYPE_SRC`] or [`HEADER_TYPE_DST`].
    pub header_type: u8,
    /// Peer pool ID.
    pub pool_id: i64,
    /// Peer pool namespace.
    pub pool_namespace: Vec<u8>,
    /// Peer image name.
    pub image_name: Vec<u8>,
    /// Peer immutable image ID.
    pub image_id: Vec<u8>,
    /// Source snapshot ID to destination snapshot ID mapping.
    pub snap_seqs: BTreeMap<u64, u64>,
    /// Migration overlap in bytes.
    pub overlap: u64,
    /// Flatten requested at prepare.
    pub flatten: bool,
    /// "A mirror record existed at Q1" (source) or the captured flag (destination).
    pub mirroring: bool,
    /// [`STATE_PREPARING`] .. [`STATE_ABORTING`].
    pub state: u8,
    /// Free-form state description.
    pub state_description: Vec<u8>,
    /// Captured image mirror mode (destination record).
    pub mirror_image_mode: u8,
    /// Non-empty for import-only migrations.
    pub source_spec: Vec<u8>,
}

/// Directory mapping of an endpoint's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameMapping {
    /// The directory resolves the name to this endpoint's own ID.
    SelfId,
    /// The directory resolves the name to a different ID.
    OtherId(Vec<u8>),
    /// The name is not in the directory.
    Absent,
}

/// Destination (or source) snapshot set as seen from the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotSet {
    /// No snapshots at all.
    None,
    /// At least one snapshot and no non-USER snapshot.
    UserOnly,
    /// At least one non-USER (trash, group or mirror) snapshot.
    ContainsNonUser,
}

impl SnapshotSet {
    /// Any snapshot exists.
    pub fn has_any(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Mirror record state of one endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MirrorState {
    /// A mirror image record exists.
    pub record_present: bool,
    /// The record state is ENABLED.
    pub enabled: bool,
    /// Recorded mirror mode ([`MIRROR_MODE_JOURNAL`] or [`MIRROR_MODE_SNAPSHOT`]).
    pub mode: u8,
}

/// Pool-level mirror mode (`rbd_mirroring` object).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMode {
    /// Pool mirroring disabled (or never configured).
    Disabled,
    /// IMAGE mode.
    Image,
    /// POOL mode.
    Pool,
    /// INIT_ONLY mode.
    InitOnly,
}

/// Group membership of an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupState {
    /// The image is not in a group.
    None,
    /// The image is in the source's original group.
    Source,
    /// The image is in the destination's group (moved at Q7).
    Destination,
    /// The image is in some other group.
    Other,
}

/// Child relink state (prepare Q9 / abort B6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildrenState {
    /// No children.
    None,
    /// Every child points at the source again.
    AtSource,
    /// Every child points at the destination.
    AtDestination,
    /// The relink was interrupted: some children point at either side.
    Partial,
}

/// One MIGRATION trash entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrashEntry {
    /// Immutable image ID of the trashed image.
    pub id: Vec<u8>,
    /// Name recorded in the entry.
    pub name: Vec<u8>,
    /// Trash source (`TRASH_SOURCE_MIGRATION` for a migration entry).
    pub source: u8,
    /// Trash state (`NORMAL`, `MOVING`, `RESTORING`).
    pub state: u8,
}

/// A group identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRef {
    /// Pool ID that holds the group.
    pub pool_id: i64,
    /// Group ID.
    pub group_id: Vec<u8>,
}

/// Durable view of one migration endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Immutable identity.
    pub image: ImageRef,
    /// The header object exists.
    pub header_present: bool,
    /// The migration record, when the header carries one.
    pub record: Option<MigrationRecord>,
    /// Directory mapping of [`Self::image`].name.
    pub name_mapping: NameMapping,
    /// The image's name is listed in the pool's format-1 directory (the
    /// `rbd_directory` data bytes). Only a format-1 image can be listed; the
    /// observation leaves this `false` for a format-2 endpoint, whose name lives
    /// in the directory omap, and the planner consults it for a format-1 source
    /// only (B10/D2).
    pub name_listed: bool,
    /// The `rbd_id.<name>` object and/or the directory entry exist.
    pub identity_present: bool,
    /// Snapshot set.
    pub snapshots: SnapshotSet,
    /// Destination only: the boundary snapshot (greatest mapped source
    /// snapshot ID in `snap_seqs`, or 0 when empty) exists.
    pub boundary_present: bool,
    /// Mirror record state.
    pub mirror: MirrorState,
    /// The image header carries the JOURNALING feature.
    pub journaling: bool,
}

/// How the terminal call named its endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invocation {
    /// The name resolved to the source endpoint.
    SourceName,
    /// The name resolved to the destination endpoint.
    DestinationName,
    /// The name resolved to an ordinary (non-migrating) image.
    OrdinaryName,
    /// The name is found only in MIGRATION trash and its header is absent.
    TrashOnlyName,
    /// The name does not resolve anywhere.
    NotFound,
    /// NULL or empty name (D10).
    InvalidName,
}

/// The observed durable state for one terminal call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// How the call named its endpoint.
    pub invocation: Invocation,
    /// Source endpoint (absent for import-only migrations).
    pub source: Endpoint,
    /// Destination endpoint.
    pub destination: Endpoint,
    /// The source's MIGRATION trash entry, when present.
    pub trash: Option<TrashEntry>,
    /// Group membership.
    pub group: GroupState,
    /// Source pool mirror mode.
    pub source_pool_mode: PoolMode,
    /// Destination pool mirror mode.
    pub destination_pool_mode: PoolMode,
    /// Child relink state.
    pub children: ChildrenState,
    /// Group identity held in caller memory (B8 to B11 only, never durable).
    pub remembered_group: Option<GroupRef>,
    /// Caller-known operation mode: an import-only migration. Durable state
    /// cannot distinguish a record-less import destination from a paired
    /// post-K3 destination, so the caller supplies this (OPEN).
    pub import: bool,
}

impl Observation {
    /// Import-only migration: the destination record has a non-empty
    /// `source_spec` and there is no source endpoint.
    pub fn import_only(&self) -> bool {
        self.import
            || (self.source.record.is_none()
                && self
                    .destination
                    .record
                    .as_ref()
                    .is_some_and(|record| !record.source_spec.is_empty()))
    }
}

impl Endpoint {
    /// An endpoint whose header object is absent.
    pub fn absent(image: ImageRef) -> Self {
        Self {
            image,
            header_present: false,
            record: None,
            name_mapping: NameMapping::Absent,
            name_listed: false,
            identity_present: false,
            snapshots: SnapshotSet::None,
            boundary_present: false,
            mirror: MirrorState::default(),
            journaling: false,
        }
    }
}

/// The terminal operation a re-run executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    /// The normal paired prepare (spec Q0-Q9). Q0 (validation, no durable
    /// write) is the caller's; the plan is the Q1-Q9 list.
    Prepare,
    /// Recovery of a failed prepare (own compensation, ADR 0705 D8).
    PrepareCompensation,
    /// `rbd_migration_commit`.
    Commit,
    /// `rbd_migration_abort`.
    Abort,
}

/// One executable stage. The variant order is the execution order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// Prepare Q1: capture the source mirror flag/mode, then disable it.
    Q1,
    /// Prepare Q2: move the source to MIGRATION trash (name unlinked).
    Q2,
    /// Prepare Q3: write the source record (destination identity, PREPARING).
    Q3,
    /// Prepare Q4: create the destination identity and header.
    Q4,
    /// Prepare Q5: copy the snapshot structure and metadata.
    Q5,
    /// Prepare Q6: write the destination record (snap_seqs, PREPARING).
    Q6,
    /// Prepare Q7: move the source group membership to the destination.
    Q7,
    /// Prepare Q8: set the source, then the destination, PREPARED.
    Q8,
    /// Prepare Q9: notify the destination and relink children forward.
    Q9,
    /// Commit K1: remove the destination migration record.
    K1,
    /// Commit D6: restore destination mirroring right after K1.
    D6,
    /// Commit K2: remove source snapshots newest-first.
    K2,
    /// Commit K3: remove the source image.
    K3,
    /// Commit K4: remove the stale MIGRATION trash entry and residual
    /// by-ID/journal objects.
    K4,
    /// Commit K5: restore destination mirroring (import-only commit).
    K5,
    /// Abort B4: set ABORTING on source then destination.
    B4,
    /// Abort B5: revert destination data into the source.
    B5,
    /// Abort B6: relink children back to the source.
    B6,
    /// Abort B7: remove destination snapshots.
    B7,
    /// Abort B8: remove the destination from its group.
    B8,
    /// Abort B9: remove the destination image.
    B9,
    /// Abort B10: restore the source name from MIGRATION trash.
    B10,
    /// Abort B11: re-add the source to its remembered group.
    B11,
    /// Abort B12: remove the source migration record.
    B12,
    /// Abort B13: restore source mirroring.
    B13,
    /// D8: remove a record-less destination identity (header absent).
    D8RemoveIdentity,
    /// D8: remove a record-less destination header.
    D8RemoveDestination,
}

/// Effect of a stage on the source image data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceDataEffect {
    /// The stage does not touch source data.
    None,
    /// The stage writes source data (only the abort revert).
    Write,
    /// The stage deletes source data (only the commit removal).
    Delete,
}

impl Stage {
    /// Effect on the source image data (invariant I1).
    pub fn source_data_effect(self) -> SourceDataEffect {
        match self {
            Self::B5 => SourceDataEffect::Write,
            Self::K3 => SourceDataEffect::Delete,
            _ => SourceDataEffect::None,
        }
    }

    /// The stage deletes the destination image or its identity (I3).
    pub fn deletes_destination(self) -> bool {
        matches!(
            self,
            Self::B9 | Self::D8RemoveDestination | Self::D8RemoveIdentity
        )
    }

    /// The stage belongs to the commit flow.
    pub fn is_commit(self) -> bool {
        matches!(
            self,
            Self::K1 | Self::D6 | Self::K2 | Self::K3 | Self::K4 | Self::K5
        )
    }

    /// The stage belongs to the prepare flow.
    pub fn is_prepare(self) -> bool {
        matches!(
            self,
            Self::Q1
                | Self::Q2
                | Self::Q3
                | Self::Q4
                | Self::Q5
                | Self::Q6
                | Self::Q7
                | Self::Q8
                | Self::Q9
        )
    }
}

/// The ordered stage list to execute, or the reason none is possible.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Plan {
    stages: Vec<Stage>,
}

impl Plan {
    /// Build a plan from an ordered stage list.
    pub fn new(stages: Vec<Stage>) -> Self {
        Self { stages }
    }

    /// An empty plan: the operation is already complete (idempotent success).
    pub fn empty() -> Self {
        Self { stages: Vec::new() }
    }

    /// The ordered stages.
    pub fn stages(&self) -> &[Stage] {
        &self.stages
    }

    /// True when the operation is already complete.
    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// True when the plan contains `stage`.
    pub fn contains(&self, stage: Stage) -> bool {
        self.stages.contains(&stage)
    }

    /// Position of `stage` in the plan.
    pub fn position(&self, stage: Stage) -> Option<usize> {
        self.stages.iter().position(|candidate| *candidate == stage)
    }
}

impl From<Vec<Stage>> for Plan {
    fn from(stages: Vec<Stage>) -> Self {
        Self::new(stages)
    }
}

/// Derive the next stage list, or the refusal errno.
///
/// `observed` must describe the durable state after a crash, not an
/// intention. Every destructive stage re-reads both records; a pair that no
/// longer references each other or a moved state is refused with `-ESTALE`.
pub fn plan(terminal: Terminal, observed: &Observation) -> Result<Plan, i32> {
    if observed.invocation == Invocation::InvalidName {
        return Err(EINVAL);
    }
    if observed.invocation == Invocation::NotFound {
        return Err(ENOENT);
    }
    pair_valid(observed)?;
    match terminal {
        Terminal::Prepare => plan_prepare(observed),
        Terminal::PrepareCompensation => plan_prepare_compensation(observed),
        Terminal::Commit => plan_commit(observed),
        Terminal::Abort => plan_abort(observed),
    }
}

/// Both records must still reference each other by pool, namespace and ID.
fn pair_valid(observed: &Observation) -> Result<(), i32> {
    if observed.source.record.is_some() && !observed.source.header_present {
        return Err(EINVAL);
    }
    if observed.destination.record.is_some() && !observed.destination.header_present {
        return Err(EINVAL);
    }
    if let Some(source) = &observed.source.record {
        if source.header_type != HEADER_TYPE_SRC {
            return Err(EINVAL);
        }
        if !same_peer(
            source.pool_id,
            &source.pool_namespace,
            &source.image_name,
            &source.image_id,
            &observed.destination.image,
        ) {
            return Err(ESTALE);
        }
    }
    if let Some(destination) = &observed.destination.record {
        if destination.header_type != HEADER_TYPE_DST {
            return Err(EINVAL);
        }
        if destination.source_spec.is_empty() {
            if observed.source.record.is_none() {
                return Err(ENOENT);
            }
            if !same_peer(
                destination.pool_id,
                &destination.pool_namespace,
                &destination.image_name,
                &destination.image_id,
                &observed.source.image,
            ) {
                return Err(ESTALE);
            }
        } else if observed.source.record.is_some() {
            return Err(EINVAL);
        }
    }
    Ok(())
}

fn same_peer(
    pool_id: i64,
    namespace: &[u8],
    name: &[u8],
    image_id: &[u8],
    peer: &ImageRef,
) -> bool {
    if pool_id != peer.pool_id || namespace != peer.namespace || image_id != peer.id {
        return false;
    }
    // A format-1 endpoint has no immutable ID: its name is its identity, so a
    // record that names another format-1 image of the pool is not this peer.
    !peer.is_v1() || name == peer.name
}

/// Normal paired prepare (spec Q0-Q9). Q0 (validation without a durable
/// write) is the caller's; the plan is the Q1-Q9 list.
fn plan_prepare(observed: &Observation) -> Result<Plan, i32> {
    // Import-only prepare has its own entry point and source reader.
    if observed.import_only() {
        return Err(EINVAL);
    }
    if !observed.source.header_present {
        return Err(ENOENT);
    }
    // A source record means a migration is already in flight (Q3 ran).
    if observed.source.record.is_some() {
        return Err(EINVAL);
    }
    // Q4 creates the destination; a name that resolves to another image is
    // taken (`-EEXIST` from the creation itself). The source's own name and
    // identity are unlinked at Q2 before Q4, so the default same-name
    // destination is not a conflict.
    let taken = observed.destination.header_present
        || match &observed.destination.name_mapping {
            NameMapping::Absent | NameMapping::SelfId => false,
            NameMapping::OtherId(id) => id != &observed.source.image.id,
        };
    if taken {
        return Err(EEXIST);
    }
    // Q0: only USER snapshots migrate; trash/group/mirror snapshots are
    // refused before the first durable write. A format-1 image only ever has
    // USER snapshots (spec "Refusals stock applies"), so the refusal is
    // unreachable for it.
    if !observed.source.image.is_v1() && observed.source.snapshots == SnapshotSet::ContainsNonUser {
        return Err(EBUSY);
    }
    // Q1 captures and disables the source mirror record. A format-1 image has
    // none and the lookup with its empty ID is a no-op (D3), so the stage is
    // skipped for it. Q7 (group) and Q9 (children) stay in the list: both are
    // no-ops for a format-1 source (no group reference, never a parent).
    let mut stages = Vec::new();
    if !observed.source.image.is_v1() {
        stages.push(Stage::Q1);
    }
    stages.extend([
        Stage::Q2,
        Stage::Q3,
        Stage::Q4,
        Stage::Q5,
        Stage::Q6,
        Stage::Q7,
        Stage::Q8,
        Stage::Q9,
    ]);
    Ok(Plan::new(stages))
}

/// The name restore of a source whose Q2 already unlinked it and whose record
/// was never written: the v2 MIGRATION trash entry (D2), or the absent TMAP key
/// of a format-1 name (V1-2). `None` when the source is still reachable by name,
/// i.e. Q2 never ran.
fn plan_unlinked_source_restore(observed: &Observation) -> Result<Option<Plan>, i32> {
    let unlinked = if observed.source.image.is_v1() {
        !observed.source.name_listed
    } else {
        observed.trash.is_some()
    };
    if !unlinked {
        return Ok(None);
    }
    if !observed.source.header_present {
        return Err(ENOENT);
    }
    if destination_exists(observed) {
        return Err(EINVAL);
    }
    Ok(Some(Plan::new(vec![Stage::B10])))
}

fn plan_prepare_compensation(observed: &Observation) -> Result<Plan, i32> {
    if observed.import_only() {
        return plan_import_prepare_compensation(observed);
    }
    let Some(source) = &observed.source.record else {
        // No SRC record. An interrupted Q2 unlinked the source: restore the
        // name; no destination can exist yet.
        if let Some(plan) = plan_unlinked_source_restore(observed)? {
            return Ok(plan);
        }
        return Err(EINVAL);
    };
    if matches!(source.state, STATE_EXECUTING | STATE_EXECUTED) {
        // Execute or commit ran; this is not a prepare failure.
        return Err(EINVAL);
    }
    if observed.destination.record.is_none() && destination_exists(observed) {
        if source.state == STATE_PREPARING {
            return plan_d8(observed);
        }
        return Err(EINVAL);
    }
    if source.state == STATE_ABORTING && observed.destination.record.is_none() {
        return Err(EINVAL);
    }
    plan_full_abort(observed)
}

fn plan_abort(observed: &Observation) -> Result<Plan, i32> {
    if observed.import_only() {
        return plan_import_abort(observed);
    }
    let Some(source) = &observed.source.record else {
        // A format-1 header without a record is not migrating (endpoint
        // resolution step 2), so abort answers `-EINVAL` like stock even when
        // the name is unlisted: the V1-2 crash window has no proof of an
        // interrupted Q2, and a prepare re-run converges there.
        if !observed.source.image.is_v1()
            && let Some(plan) = plan_unlinked_source_restore(observed)?
        {
            return Ok(plan);
        }
        return Err(EINVAL);
    };
    if observed.destination.record.is_none() && destination_exists(observed) {
        return match source.state {
            STATE_PREPARING => plan_d8(observed),
            // D4: record-less destination with EXECUTED proof is a commit in
            // progress; ABORTING is the ambiguous R9 state (OQ 177).
            _ => Err(EINVAL),
        };
    }
    if source.state == STATE_EXECUTED && observed.destination.record.is_none() {
        return Err(EINVAL);
    }
    plan_full_abort(observed)
}

/// D8: the destination is record-less and the source is still PREPARING, so
/// execute/commit never ran. Remove the destination identity, then restore the
/// source.
fn plan_d8(observed: &Observation) -> Result<Plan, i32> {
    let mut stages = Vec::new();
    if observed.destination.header_present {
        stages.push(Stage::D8RemoveDestination);
    } else if observed.destination.identity_present {
        stages.push(Stage::D8RemoveIdentity);
    }
    push_restore_source(&mut stages, observed)?;
    Ok(Plan::new(stages))
}

/// Abort stages B10-B13 for the source side (also Q2/Q3 compensation).
fn push_restore_source(stages: &mut Vec<Stage>, observed: &Observation) -> Result<(), i32> {
    push_restore_name(stages, observed)?;
    if observed.source.record.is_some() {
        stages.push(Stage::B12);
        // A format-1 source has no mirror record and no journal: B13 is skipped
        // for it (D3, V1-4). The OPEN-1 guard below covers a featureless
        // format-2 source.
        if !observed.source.image.is_v1() && source_mirror_restore_needed(observed)? {
            stages.push(Stage::B13);
        }
    }
    Ok(())
}

/// D2: a restored name (no trash entry, directory maps to the source ID) is
/// done; a conflicting mapping is `-EEXIST`; a lost name is `-ENOENT`.
///
/// A format-1 name lives in the `rbd_directory` TMAP and has no directory entry
/// or ID object: an unlisted name is restored by one TMAP SET, a listed one is
/// the completed B10 (SET is idempotent, so R3 does not apply). A same-name
/// format-2 image is not a conflict (the two names live in different maps).
fn push_restore_name(stages: &mut Vec<Stage>, observed: &Observation) -> Result<(), i32> {
    if observed.source.image.is_v1() {
        if !observed.source.name_listed {
            stages.push(Stage::B10);
        }
        return Ok(());
    }
    if observed.trash.is_some() {
        stages.push(Stage::B10);
        return Ok(());
    }
    match &observed.source.name_mapping {
        NameMapping::SelfId => Ok(()),
        NameMapping::OtherId(_) => Err(EEXIST),
        NameMapping::Absent => Err(ENOENT),
    }
}

/// The paired abort flow (B4-B13) from the observed durable state.
fn plan_full_abort(observed: &Observation) -> Result<Plan, i32> {
    let destination_record = observed.destination.record.as_ref();
    // A format-1 source never has children (no LAYERING) and no group
    // reference: B6 and B11 are skipped for it (spec "Abort B0-B13").
    let v1_source = observed.source.image.is_v1();
    let mut stages = Vec::new();
    if destination_record.is_some() {
        stages.push(Stage::B4);
    }
    if let Some(record) = destination_record {
        // D9: revert runs iff snap_seqs is empty or the boundary snapshot
        // still exists. A missing boundary proves an own abort completed it.
        if record.snap_seqs.is_empty() || observed.destination.boundary_present {
            stages.push(Stage::B5);
        }
    }
    if !v1_source
        && matches!(
            observed.children,
            ChildrenState::AtDestination | ChildrenState::Partial
        )
    {
        stages.push(Stage::B6);
    }
    if observed.destination.snapshots.has_any() {
        stages.push(Stage::B7);
    }
    if observed.group == GroupState::Destination {
        stages.push(Stage::B8);
    }
    if destination_exists(observed) {
        stages.push(Stage::B9);
    }
    push_restore_source(&mut stages, observed)?;
    if !v1_source && observed.remembered_group.is_some() && observed.group != GroupState::Source {
        // B11 runs after B10; insert before B12 to keep stock's order.
        let position = stages
            .iter()
            .position(|stage| *stage == Stage::B12)
            .unwrap_or(stages.len());
        stages.insert(position, Stage::B11);
    }
    Ok(Plan::new(stages))
}

fn plan_commit(observed: &Observation) -> Result<Plan, i32> {
    if observed.import_only() {
        return plan_import_commit(observed);
    }
    if observed.destination.record.is_none() {
        return plan_commit_after_k1(observed);
    }
    plan_commit_fresh(observed)
}

/// Fresh commit (K0 passed): the destination still carries its DST record.
fn plan_commit_fresh(observed: &Observation) -> Result<Plan, i32> {
    let Some(source) = &observed.source.record else {
        return Err(EINVAL);
    };
    let Some(destination) = &observed.destination.record else {
        return Err(ENOENT);
    };
    // I2: EXECUTED proof is the first-opened record's state (endpoint
    // resolution step 5): source state when invoked by source name.
    let proof = if observed.invocation == Invocation::SourceName {
        source.state
    } else {
        destination.state
    };
    if proof != STATE_EXECUTED {
        return Err(EINVAL);
    }
    if !observed.source.header_present || !observed.destination.header_present {
        return Err(ENOENT);
    }
    let mut stages = vec![Stage::K1];
    if destination_mirror_restore_needed(observed)? {
        stages.push(Stage::D6);
    }
    push_source_snapshot_stage(&mut stages, observed)?;
    stages.push(Stage::K3);
    // A format-1 source never enters the MIGRATION trash, so K4 has nothing to
    // remove (spec "Commit K0-K5").
    if !observed.source.image.is_v1() {
        stages.push(Stage::K4);
    }
    Ok(Plan::new(stages))
}

/// D7: K1 already ran (the destination is ordinary) or the source header is
/// already gone; continue at the first missing stage.
fn plan_commit_after_k1(observed: &Observation) -> Result<Plan, i32> {
    if !observed.destination.header_present {
        // The destination is the surviving copy; never remove the source.
        return Err(ENOENT);
    }
    // D4 (V1-6): a format-1 source has no MIGRATION entry, so its EXECUTED
    // record plus the matching destination identity (`pair_valid`) are the
    // resume proof and there is no K4 cleanup.
    let v1_source = observed.source.image.is_v1();
    let Some(source) = &observed.source.record else {
        // D7 cleanup is only valid once K3 removed the source header object
        // (nothing else removes it). The stale MIGRATION entry must still be
        // there; a surviving identity object alone may be the destination's
        // own `rbd_id.<name>` because both endpoints can share the name.
        if observed.source.header_present {
            return Err(EINVAL);
        }
        if v1_source {
            // K3 removed the header object and a TMAP key is not a cleanup
            // target: nothing is left to do.
            return Err(ENOENT);
        }
        let Some(trash) = &observed.trash else {
            return Err(EINVAL);
        };
        if trash.source != TRASH_SOURCE_MIGRATION || trash.id != observed.source.image.id {
            return Err(EINVAL);
        }
        return Ok(Plan::new(vec![Stage::K4]));
    };
    if source.state != STATE_EXECUTED {
        return Err(EINVAL);
    }
    if !same_peer(
        source.pool_id,
        &source.pool_namespace,
        &source.image_name,
        &source.image_id,
        &observed.destination.image,
    ) {
        return Err(ESTALE);
    }
    if !v1_source {
        let Some(trash) = &observed.trash else {
            return Err(EINVAL);
        };
        if trash.id != observed.source.image.id {
            return Err(ESTALE);
        }
    }
    let mut stages = Vec::new();
    if destination_mirror_restore_after_k1(observed, source)? {
        stages.push(Stage::D6);
    }
    push_source_snapshot_stage(&mut stages, observed)?;
    if observed.source.header_present {
        stages.push(Stage::K3);
    }
    if !v1_source {
        stages.push(Stage::K4);
    }
    Ok(Plan::new(stages))
}

fn push_source_snapshot_stage(stages: &mut Vec<Stage>, observed: &Observation) -> Result<(), i32> {
    match observed.source.snapshots {
        SnapshotSet::None => Ok(()),
        SnapshotSet::UserOnly => {
            stages.push(Stage::K2);
            Ok(())
        }
        // Stock K2 refuses non-USER source snapshots.
        SnapshotSet::ContainsNonUser => Err(EBUSY),
    }
}

fn plan_import_commit(observed: &Observation) -> Result<Plan, i32> {
    let Some(destination) = &observed.destination.record else {
        // K1 already removed the record; the captured mirror policy is gone
        // with it, so K5 cannot be resumed (OPEN, see module docs).
        return Err(EINVAL);
    };
    if destination.state != STATE_EXECUTED {
        return Err(EINVAL);
    }
    if !observed.destination.header_present {
        return Err(ENOENT);
    }
    let mut stages = vec![Stage::K1];
    if destination_mirror_restore_needed(observed)? {
        stages.push(Stage::K5);
    }
    Ok(Plan::new(stages))
}

fn plan_import_abort(observed: &Observation) -> Result<Plan, i32> {
    let Some(destination) = &observed.destination.record else {
        // A record-less destination is ambiguous for the public abort:
        // interrupted prepare (Q4/Q5) and completed K1 look identical, and
        // deleting it after K1 would remove the only copy (I4). OPEN.
        if destination_exists(observed) {
            return Err(EINVAL);
        }
        return Ok(Plan::empty());
    };
    if destination.header_type != HEADER_TYPE_DST {
        return Err(EINVAL);
    }
    if !observed.destination.header_present {
        return Ok(Plan::empty());
    }
    let mut stages = vec![Stage::B4];
    if observed.destination.snapshots.has_any() {
        stages.push(Stage::B7);
    }
    if observed.group == GroupState::Destination {
        stages.push(Stage::B8);
    }
    if destination_exists(observed) {
        stages.push(Stage::B9);
    }
    Ok(Plan::new(stages))
}

/// Prepare compensation for an import-only migration. The internal caller
/// knows it created the destination; a record-less destination is removed by
/// its known ID (D8 analog, OPEN).
fn plan_import_prepare_compensation(observed: &Observation) -> Result<Plan, i32> {
    let Some(destination) = &observed.destination.record else {
        if observed.destination.header_present {
            return Ok(Plan::new(vec![Stage::D8RemoveDestination]));
        }
        if observed.destination.identity_present {
            return Ok(Plan::new(vec![Stage::D8RemoveIdentity]));
        }
        return Ok(Plan::empty());
    };
    if destination.state != STATE_PREPARING && destination.state != STATE_PREPARED {
        return Err(EINVAL);
    }
    plan_import_abort(observed)
}

fn destination_exists(observed: &Observation) -> bool {
    observed.destination.header_present || observed.destination.identity_present
}

/// Mirror restore is needed on the source (B13).
fn source_mirror_restore_needed(observed: &Observation) -> Result<bool, i32> {
    let (captured, mode) = match (&observed.destination.record, &observed.source.record) {
        (Some(destination), _) => (destination.mirroring, destination.mirror_image_mode),
        (None, Some(source)) => (source.mirroring, fallback_mode(observed.source.journaling)),
        (None, None) => return Ok(false),
    };
    mirror_restore_needed(
        captured,
        mode,
        observed.source_pool_mode,
        &observed.source.mirror,
        observed.source.journaling,
    )
}

/// Mirror restore is needed on the destination (D6/K5).
fn destination_mirror_restore_needed(observed: &Observation) -> Result<bool, i32> {
    let Some(destination) = &observed.destination.record else {
        return Ok(false);
    };
    mirror_restore_needed(
        destination.mirroring,
        destination.mirror_image_mode,
        observed.destination_pool_mode,
        &observed.destination.mirror,
        observed.destination.journaling,
    )
}

/// D7: after K1 the destination record is gone, so the captured flag comes
/// from the source record and the mode falls back to the destination's
/// JOURNALING feature (D3). Without this a crash between K1 and D6 would
/// never restore destination mirroring. The mode is only a fallback here,
/// so a destination already enabled in any mode counts as restored: refusing
/// a guessed-mode mismatch would strand the commit after K1.
fn destination_mirror_restore_after_k1(
    observed: &Observation,
    source: &MigrationRecord,
) -> Result<bool, i32> {
    if observed.destination.mirror.enabled {
        return Ok(false);
    }
    mirror_restore_needed(
        source.mirroring,
        fallback_mode(observed.destination.journaling),
        observed.destination_pool_mode,
        &observed.destination.mirror,
        observed.destination.journaling,
    )
}

fn fallback_mode(journaling: bool) -> u8 {
    if journaling {
        MIRROR_MODE_JOURNAL
    } else {
        MIRROR_MODE_SNAPSHOT
    }
}

/// K5/D6/B13 rules: DISABLED and INIT_ONLY skip; IMAGE skips unless the
/// captured flag is set; otherwise enable the captured mode. An image already
/// enabled in another mode is `-EINVAL`.
///
/// OPEN-1 (lead 2026-11-10): never enable JOURNAL mode on an endpoint without
/// the JOURNALING feature. Stock's call fails `-ENOENT` there — after commit
/// already deleted the source for a legacy source (V1-4) — and a format-1
/// source inherits features 0, so a featureless format-2 source has the same
/// hole.
fn mirror_restore_needed(
    captured: bool,
    mode: u8,
    pool_mode: PoolMode,
    current: &MirrorState,
    journaling: bool,
) -> Result<bool, i32> {
    if mode == MIRROR_MODE_JOURNAL && !journaling {
        return Ok(false);
    }
    match pool_mode {
        PoolMode::Disabled | PoolMode::InitOnly => Ok(false),
        PoolMode::Image if !captured => Ok(false),
        PoolMode::Image | PoolMode::Pool => {
            if current.enabled {
                if current.mode == mode {
                    Ok(false)
                } else {
                    Err(EINVAL)
                }
            } else {
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src_image() -> ImageRef {
        ImageRef {
            format: ImageFormat::V2,
            pool_id: 7,
            namespace: Vec::new(),
            name: b"src".to_vec(),
            id: b"s".to_vec(),
        }
    }

    fn dst_image() -> ImageRef {
        ImageRef {
            format: ImageFormat::V2,
            pool_id: 7,
            namespace: Vec::new(),
            name: b"dst".to_vec(),
            id: b"d".to_vec(),
        }
    }

    fn src_record(state: u8) -> MigrationRecord {
        MigrationRecord {
            header_type: HEADER_TYPE_SRC,
            pool_id: 7,
            pool_namespace: Vec::new(),
            image_name: b"dst".to_vec(),
            image_id: b"d".to_vec(),
            snap_seqs: BTreeMap::new(),
            overlap: 0,
            flatten: false,
            mirroring: false,
            state,
            state_description: Vec::new(),
            mirror_image_mode: MIRROR_MODE_JOURNAL,
            source_spec: Vec::new(),
        }
    }

    fn dst_record(state: u8) -> MigrationRecord {
        MigrationRecord {
            header_type: HEADER_TYPE_DST,
            pool_id: 7,
            pool_namespace: Vec::new(),
            image_name: b"src".to_vec(),
            image_id: b"s".to_vec(),
            snap_seqs: BTreeMap::new(),
            overlap: 0,
            flatten: false,
            mirroring: false,
            state,
            state_description: Vec::new(),
            mirror_image_mode: MIRROR_MODE_JOURNAL,
            source_spec: Vec::new(),
        }
    }

    fn import_record(state: u8) -> MigrationRecord {
        MigrationRecord {
            header_type: HEADER_TYPE_DST,
            pool_id: -1,
            pool_namespace: Vec::new(),
            image_name: Vec::new(),
            image_id: Vec::new(),
            snap_seqs: BTreeMap::new(),
            overlap: 0,
            flatten: true,
            mirroring: false,
            state,
            state_description: Vec::new(),
            mirror_image_mode: MIRROR_MODE_JOURNAL,
            source_spec: br#"{"type":"native"}"#.to_vec(),
        }
    }

    fn trash() -> TrashEntry {
        TrashEntry {
            id: b"s".to_vec(),
            name: b"src".to_vec(),
            source: TRASH_SOURCE_MIGRATION,
            state: TRASH_STATE_NORMAL,
        }
    }

    fn base() -> Observation {
        Observation {
            invocation: Invocation::SourceName,
            source: Endpoint {
                image: src_image(),
                header_present: true,
                record: None,
                name_mapping: NameMapping::SelfId,
                name_listed: false,
                identity_present: true,
                snapshots: SnapshotSet::None,
                boundary_present: false,
                mirror: MirrorState::default(),
                journaling: false,
            },
            destination: Endpoint {
                image: dst_image(),
                header_present: false,
                record: None,
                name_mapping: NameMapping::Absent,
                name_listed: false,
                identity_present: false,
                snapshots: SnapshotSet::None,
                boundary_present: false,
                mirror: MirrorState::default(),
                journaling: false,
            },
            trash: None,
            group: GroupState::None,
            source_pool_mode: PoolMode::Image,
            destination_pool_mode: PoolMode::Image,
            children: ChildrenState::None,
            remembered_group: None,
            import: false,
        }
    }

    fn with_source_record(mut observed: Observation, state: u8) -> Observation {
        observed.source.record = Some(src_record(state));
        observed
    }

    fn with_destination_record(mut observed: Observation, state: u8) -> Observation {
        observed.destination.header_present = true;
        observed.destination.identity_present = true;
        observed.destination.name_mapping = NameMapping::SelfId;
        observed.destination.record = Some(dst_record(state));
        observed
    }

    fn stages(expected: &[Stage]) -> Plan {
        Plan::new(expected.to_vec())
    }

    // ---- prepare crash table (recovery = abort), one row per persistent stage

    #[test]
    fn prepare_q1_crash_is_not_migrating() {
        // Q1: mirroring disabled, nothing else. Stock and own: -EINVAL.
        let mut observed = base();
        observed.source.mirror = MirrorState::default();
        assert_eq!(plan(Terminal::PrepareCompensation, &observed), Err(EINVAL));
        assert_eq!(plan(Terminal::Abort, &observed), Err(EINVAL));
    }

    #[test]
    fn prepare_q2_crash_restores_the_name_d2() {
        // Q2: MIGRATION entry, name partly/fully unlinked, no record.
        let mut observed = base();
        observed.trash = Some(trash());
        observed.source.name_mapping = NameMapping::Absent;
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[Stage::B10]))
        );
    }

    #[test]
    fn prepare_q3_crash_restores_name_record_and_mirroring() {
        // Q3: SRC PREPARING, no destination object.
        let mut observed = with_source_record(base(), STATE_PREPARING);
        observed.source.record.as_mut().unwrap().mirroring = true;
        observed.trash = Some(trash());
        observed.source.name_mapping = NameMapping::Absent;
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[Stage::B10, Stage::B12, Stage::B13]))
        );
    }

    #[test]
    fn prepare_q4_identity_crash_removes_identity_d8() {
        // Q4 identity only: destination ID object/directory entry, no header.
        let mut observed = with_source_record(base(), STATE_PREPARING);
        observed.trash = Some(trash());
        observed.source.name_mapping = NameMapping::Absent;
        observed.destination.identity_present = true;
        observed.destination.name_mapping = NameMapping::SelfId;
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[Stage::D8RemoveIdentity, Stage::B10, Stage::B12]))
        );
    }

    #[test]
    fn prepare_q4_q5_header_crash_removes_destination_d8() {
        // Q4/Q5 header without a record: D8 removes it, then restores.
        let mut observed = with_source_record(base(), STATE_PREPARING);
        observed.trash = Some(trash());
        observed.source.name_mapping = NameMapping::Absent;
        observed.destination.header_present = true;
        observed.destination.identity_present = true;
        observed.destination.name_mapping = NameMapping::SelfId;
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[
                Stage::D8RemoveDestination,
                Stage::B10,
                Stage::B12
            ]))
        );
    }

    fn prepared_at_q6() -> Observation {
        let mut observed = with_source_record(base(), STATE_PREPARING);
        observed.source.snapshots = SnapshotSet::UserOnly;
        observed.source.journaling = true;
        observed.trash = Some(trash());
        observed.source.name_mapping = NameMapping::Absent;
        observed.destination = Endpoint {
            image: dst_image(),
            header_present: true,
            record: Some(dst_record(STATE_PREPARING)),
            name_mapping: NameMapping::SelfId,
            name_listed: false,
            identity_present: true,
            snapshots: SnapshotSet::UserOnly,
            boundary_present: true,
            mirror: MirrorState::default(),
            // A v2 source's JOURNALING feature is inherited by the destination,
            // so its captured JOURNAL mode is enableable (OPEN-1).
            journaling: true,
        };
        observed
            .destination
            .record
            .as_mut()
            .unwrap()
            .snap_seqs
            .insert(100, 11);
        observed.destination.record.as_mut().unwrap().mirroring = true;
        observed
    }

    #[test]
    fn prepare_q6_crash_runs_the_full_abort() {
        // Q6: destination record PREPARING, snapshots copied.
        let observed = prepared_at_q6();
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[
                Stage::B4,
                Stage::B5,
                Stage::B7,
                Stage::B9,
                Stage::B10,
                Stage::B12,
                Stage::B13
            ]))
        );
    }

    #[test]
    fn prepare_q7_crash_removes_destination_from_group() {
        let mut observed = prepared_at_q6();
        observed.group = GroupState::Destination;
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[
                Stage::B4,
                Stage::B5,
                Stage::B7,
                Stage::B8,
                Stage::B9,
                Stage::B10,
                Stage::B12,
                Stage::B13
            ]))
        );
    }

    #[test]
    fn prepare_q8_crash_runs_the_full_abort() {
        let mut observed = prepared_at_q6();
        observed.group = GroupState::Destination;
        observed.source.record.as_mut().unwrap().state = STATE_PREPARED;
        observed.destination.record.as_mut().unwrap().state = STATE_PREPARED;
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[
                Stage::B4,
                Stage::B5,
                Stage::B7,
                Stage::B8,
                Stage::B9,
                Stage::B10,
                Stage::B12,
                Stage::B13
            ]))
        );
    }

    #[test]
    fn prepare_q9_crash_repairs_children() {
        let mut observed = prepared_at_q6();
        observed.group = GroupState::Destination;
        observed.children = ChildrenState::Partial;
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[
                Stage::B4,
                Stage::B5,
                Stage::B6,
                Stage::B7,
                Stage::B8,
                Stage::B9,
                Stage::B10,
                Stage::B12,
                Stage::B13
            ]))
        );
    }

    // ---- normal prepare (Q0 passed by the caller, Q1-Q9 planned here)

    #[test]
    fn prepare_plans_q1_to_q9_from_a_clean_source() {
        assert_eq!(
            plan(Terminal::Prepare, &base()),
            Ok(stages(&[
                Stage::Q1,
                Stage::Q2,
                Stage::Q3,
                Stage::Q4,
                Stage::Q5,
                Stage::Q6,
                Stage::Q7,
                Stage::Q8,
                Stage::Q9
            ]))
        );
    }

    #[test]
    fn prepare_refuses_a_source_that_already_migrates() {
        // Q3 already ran: the source carries its SRC record.
        let observed = with_source_record(base(), STATE_PREPARING);
        assert_eq!(plan(Terminal::Prepare, &observed), Err(EINVAL));
    }

    #[test]
    fn prepare_refuses_a_taken_destination_name() {
        let mut observed = base();
        observed.destination.name_mapping = NameMapping::OtherId(b"other".to_vec());
        observed.destination.identity_present = true;
        assert_eq!(plan(Terminal::Prepare, &observed), Err(EEXIST));
    }

    #[test]
    fn prepare_refuses_non_user_snapshots() {
        let mut observed = base();
        observed.source.snapshots = SnapshotSet::ContainsNonUser;
        assert_eq!(plan(Terminal::Prepare, &observed), Err(EBUSY));
    }

    #[test]
    fn prepare_refuses_a_missing_source() {
        let mut observed = base();
        observed.source.header_present = false;
        assert_eq!(plan(Terminal::Prepare, &observed), Err(ENOENT));
    }

    // ---- commit crash table

    fn executed() -> Observation {
        let mut observed = with_source_record(base(), STATE_EXECUTED);
        observed.invocation = Invocation::DestinationName;
        observed.source.snapshots = SnapshotSet::UserOnly;
        observed.trash = Some(trash());
        observed = with_destination_record(observed, STATE_EXECUTED);
        observed
    }

    #[test]
    fn commit_k0_fresh_runs_the_full_commit() {
        let observed = executed();
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[Stage::K1, Stage::K2, Stage::K3, Stage::K4]))
        );
    }

    #[test]
    fn commit_k0_restores_destination_mirroring_early_d6() {
        let mut observed = executed();
        observed.destination.record.as_mut().unwrap().mirroring = true;
        // The captured JOURNAL mode needs the destination's JOURNALING feature
        // (OPEN-1); a v2 source passes it on.
        observed.destination.journaling = true;
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[
                Stage::K1,
                Stage::D6,
                Stage::K2,
                Stage::K3,
                Stage::K4
            ]))
        );
    }

    #[test]
    fn commit_k1_crash_resumes_d7() {
        // K1: destination ordinary, SRC EXECUTED in MIGRATION trash.
        let mut observed = executed();
        observed.destination.record = None;
        assert!(k1_done(&observed));
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[Stage::K2, Stage::K3, Stage::K4]))
        );
    }

    #[test]
    fn commit_k1_d6_restores_from_source_record_in_image_pool() {
        // D7: crash between K1 and D6. The DST record is gone; the captured
        // flag comes from the source record, the mode from the destination's
        // JOURNALING feature (D3).
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.record.as_mut().unwrap().mirroring = true;
        observed.destination.journaling = false;
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[Stage::D6, Stage::K2, Stage::K3, Stage::K4]))
        );
    }

    #[test]
    fn commit_k1_d6_skips_when_source_flag_is_clear() {
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.record.as_mut().unwrap().mirroring = false;
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[Stage::K2, Stage::K3, Stage::K4]))
        );
    }

    #[test]
    fn commit_k1_d6_restores_in_pool_mode() {
        // POOL mode enables regardless of the captured flag (K5 rules).
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.record.as_mut().unwrap().mirroring = false;
        observed.destination_pool_mode = PoolMode::Pool;
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[Stage::D6, Stage::K2, Stage::K3, Stage::K4]))
        );
    }

    #[test]
    fn commit_k1_d6_skips_when_already_enabled_in_the_same_mode() {
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.record.as_mut().unwrap().mirroring = true;
        observed.destination.journaling = true;
        observed.destination.mirror = MirrorState {
            record_present: true,
            enabled: true,
            mode: MIRROR_MODE_JOURNAL,
        };
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[Stage::K2, Stage::K3, Stage::K4]))
        );
    }

    #[test]
    fn commit_k1_d6_accepts_a_different_enabled_mode() {
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.record.as_mut().unwrap().mirroring = true;
        observed.destination.journaling = false;
        observed.destination.mirror = MirrorState {
            record_present: true,
            enabled: true,
            mode: MIRROR_MODE_JOURNAL,
        };
        // The fallback mode is a guess after K1: already enabled is done.
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[Stage::K2, Stage::K3, Stage::K4]))
        );
    }

    #[test]
    fn commit_k2_crash_resumes_at_k3() {
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.snapshots = SnapshotSet::None;
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[Stage::K3, Stage::K4]))
        );
    }

    #[test]
    fn commit_k3_crash_header_kept_resumes_at_k3() {
        // K2/K3 header kept: source snapshots/data partly gone. K3 is
        // idempotent, so the resume point is still K3.
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.snapshots = SnapshotSet::None;
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[Stage::K3, Stage::K4]))
        );
    }

    #[test]
    fn commit_k3_crash_header_gone_cleans_the_entry_d7() {
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.header_present = false;
        observed.source.record = None;
        observed.source.identity_present = false;
        assert_eq!(plan(Terminal::Commit, &observed), Ok(stages(&[Stage::K4])));
    }

    #[test]
    fn commit_k3_cleanup_refuses_a_present_source_header() {
        // D7 cleanup is only valid after K3 removed the header object.
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.record = None;
        assert_eq!(plan(Terminal::Commit, &observed), Err(EINVAL));
    }

    #[test]
    fn commit_k3_cleanup_refuses_identity_without_the_migration_entry() {
        // A surviving identity object may be the destination's own
        // `rbd_id.<name>`; it is not proof of a K3 cleanup state.
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.header_present = false;
        observed.source.record = None;
        observed.source.identity_present = true;
        observed.trash = None;
        assert_eq!(plan(Terminal::Commit, &observed), Err(EINVAL));
    }

    #[test]
    fn commit_k3_cleanup_with_stale_entry_and_absent_header() {
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.header_present = false;
        observed.source.record = None;
        observed.source.identity_present = false;
        assert_eq!(plan(Terminal::Commit, &observed), Ok(stages(&[Stage::K4])));

        // A mismatched entry (wrong ID) is not the source's stale entry.
        let mut mismatched = observed.clone();
        mismatched.trash.as_mut().unwrap().id = b"other".to_vec();
        assert_eq!(plan(Terminal::Commit, &mismatched), Err(EINVAL));
    }

    #[test]
    fn commit_k4_crash_is_done() {
        let mut observed = executed();
        observed.destination.record = None;
        observed.source.header_present = false;
        observed.source.record = None;
        observed.source.identity_present = false;
        observed.trash = None;
        assert_eq!(plan(Terminal::Commit, &observed), Err(EINVAL));
    }

    #[test]
    fn commit_name_not_found_is_enoent() {
        let mut observed = executed();
        observed.invocation = Invocation::NotFound;
        assert_eq!(plan(Terminal::Commit, &observed), Err(ENOENT));
        assert_eq!(plan(Terminal::Abort, &observed), Err(ENOENT));
        assert_eq!(plan(Terminal::PrepareCompensation, &observed), Err(ENOENT));
    }

    // ---- abort crash table

    fn aborting() -> Observation {
        let mut observed = with_source_record(base(), STATE_ABORTING);
        observed.invocation = Invocation::DestinationName;
        observed.source.snapshots = SnapshotSet::UserOnly;
        observed.trash = Some(trash());
        observed = with_destination_record(observed, STATE_ABORTING);
        observed.destination.snapshots = SnapshotSet::UserOnly;
        observed.destination.boundary_present = true;
        observed
            .destination
            .record
            .as_mut()
            .unwrap()
            .snap_seqs
            .insert(100, 11);
        observed
    }

    #[test]
    fn abort_b4_crash_repeats_b4() {
        let observed = aborting();
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[
                Stage::B4,
                Stage::B5,
                Stage::B7,
                Stage::B9,
                Stage::B10,
                Stage::B12
            ]))
        );
    }

    #[test]
    fn abort_b5_crash_re_reverts() {
        // B5 part: source HEAD partly reverted. The metadata is the B4 state;
        // B5 is idempotent and stays in the plan.
        let observed = aborting();
        let planned = plan(Terminal::Abort, &observed).unwrap();
        assert!(planned.contains(Stage::B5));
    }

    #[test]
    fn abort_b6_crash_repairs_children() {
        let mut observed = aborting();
        observed.children = ChildrenState::Partial;
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[
                Stage::B4,
                Stage::B5,
                Stage::B6,
                Stage::B7,
                Stage::B9,
                Stage::B10,
                Stage::B12
            ]))
        );
    }

    #[test]
    fn abort_b7_crash_skips_the_revert_d9() {
        // B7 part: destination snapshots partly gone, the boundary is gone.
        // D9: a missing boundary proves the revert completed; skip B5.
        let mut observed = aborting();
        observed.destination.snapshots = SnapshotSet::None;
        observed.destination.boundary_present = false;
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[Stage::B4, Stage::B9, Stage::B10, Stage::B12]))
        );
    }

    #[test]
    fn abort_b8_crash_continues_without_the_group() {
        // B8: destination out of its group; the identity was memory-only (R7).
        let mut observed = aborting();
        observed.group = GroupState::None;
        let planned = plan(Terminal::Abort, &observed).unwrap();
        assert!(!planned.contains(Stage::B8));
        assert!(!planned.contains(Stage::B11));
        assert!(planned.contains(Stage::B9));
    }

    #[test]
    fn abort_b9_partial_continues_after_d9() {
        let mut observed = aborting();
        observed.destination.snapshots = SnapshotSet::None;
        observed.destination.boundary_present = false;
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[Stage::B4, Stage::B9, Stage::B10, Stage::B12]))
        );
    }

    #[test]
    fn abort_b9_crash_restores_the_source() {
        let mut observed = aborting();
        observed.destination = Endpoint {
            image: dst_image(),
            header_present: false,
            record: None,
            name_mapping: NameMapping::Absent,
            name_listed: false,
            identity_present: false,
            snapshots: SnapshotSet::None,
            boundary_present: false,
            mirror: MirrorState::default(),
            journaling: false,
        };
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[Stage::B10, Stage::B12]))
        );
    }

    #[test]
    fn abort_b10_crash_continues_d2() {
        // B10: name restored, trash entry gone.
        let mut observed = aborting();
        observed.destination = Endpoint {
            image: dst_image(),
            header_present: false,
            record: None,
            name_mapping: NameMapping::Absent,
            name_listed: false,
            identity_present: false,
            snapshots: SnapshotSet::None,
            boundary_present: false,
            mirror: MirrorState::default(),
            journaling: false,
        };
        observed.trash = None;
        observed.source.name_mapping = NameMapping::SelfId;
        assert_eq!(plan(Terminal::Abort, &observed), Ok(stages(&[Stage::B12])));
    }

    #[test]
    fn abort_b11_crash_restores_the_remembered_group() {
        let mut observed = aborting();
        observed.destination = Endpoint {
            image: dst_image(),
            header_present: false,
            record: None,
            name_mapping: NameMapping::Absent,
            name_listed: false,
            identity_present: false,
            snapshots: SnapshotSet::None,
            boundary_present: false,
            mirror: MirrorState::default(),
            journaling: false,
        };
        observed.trash = None;
        observed.source.name_mapping = NameMapping::SelfId;
        observed.remembered_group = Some(GroupRef {
            pool_id: 7,
            group_id: b"g".to_vec(),
        });
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[Stage::B11, Stage::B12]))
        );
    }

    #[test]
    fn abort_b12_crash_source_ordinary_is_einval() {
        // B12: source ordinary (record gone), destination gone, name restored.
        let mut observed = aborting();
        observed.destination = Endpoint {
            image: dst_image(),
            header_present: false,
            record: None,
            name_mapping: NameMapping::Absent,
            name_listed: false,
            identity_present: false,
            snapshots: SnapshotSet::None,
            boundary_present: false,
            mirror: MirrorState::default(),
            journaling: false,
        };
        observed.trash = None;
        observed.source.record = None;
        assert_eq!(plan(Terminal::Abort, &observed), Err(EINVAL));
    }

    #[test]
    fn abort_b13_crash_restores_source_mirroring() {
        // B13 pending: source record still present, captured mirroring true.
        let mut observed = aborting();
        observed.source.record.as_mut().unwrap().mirroring = true;
        observed.destination = Endpoint {
            image: dst_image(),
            header_present: false,
            record: None,
            name_mapping: NameMapping::Absent,
            name_listed: false,
            identity_present: false,
            snapshots: SnapshotSet::None,
            boundary_present: false,
            mirror: MirrorState::default(),
            journaling: false,
        };
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[Stage::B10, Stage::B12, Stage::B13]))
        );
    }

    #[test]
    fn abort_b13_lost_after_b12_is_einval() {
        // Crash after B12 removes the only durable captured flag; the source
        // is ordinary, so abort refuses (documented R8 loss).
        let mut observed = aborting();
        observed.source.record = None;
        observed.trash = None;
        observed.destination = Endpoint {
            image: dst_image(),
            header_present: false,
            record: None,
            name_mapping: NameMapping::Absent,
            name_listed: false,
            identity_present: false,
            snapshots: SnapshotSet::None,
            boundary_present: false,
            mirror: MirrorState::default(),
            journaling: false,
        };
        assert_eq!(plan(Terminal::Abort, &observed), Err(EINVAL));
    }

    // ---- refusals (D4, D8, D10, R9, identity, K0, K2, B10)

    #[test]
    fn abort_d4_refuses_a_commit_in_progress() {
        let mut observed = with_source_record(base(), STATE_EXECUTED);
        observed.destination.header_present = true;
        observed.destination.identity_present = true;
        observed.destination.name_mapping = NameMapping::SelfId;
        observed.trash = Some(trash());
        assert_eq!(plan(Terminal::Abort, &observed), Err(EINVAL));
    }

    #[test]
    fn abort_r9_refuses_the_ambiguous_recordless_destination() {
        let mut observed = with_source_record(base(), STATE_ABORTING);
        observed.destination.header_present = true;
        observed.destination.identity_present = true;
        observed.trash = Some(trash());
        assert_eq!(plan(Terminal::Abort, &observed), Err(EINVAL));
    }

    #[test]
    fn abort_d8_removes_a_recordless_destination_while_preparing() {
        let mut observed = with_source_record(base(), STATE_PREPARING);
        observed.destination.header_present = true;
        observed.destination.identity_present = true;
        observed.trash = Some(trash());
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[
                Stage::D8RemoveDestination,
                Stage::B10,
                Stage::B12
            ]))
        );
    }

    #[test]
    fn d10_rejects_null_or_empty_names() {
        let mut observed = base();
        observed.invocation = Invocation::InvalidName;
        for terminal in [
            Terminal::PrepareCompensation,
            Terminal::Commit,
            Terminal::Abort,
        ] {
            assert_eq!(plan(terminal, &observed), Err(EINVAL));
        }
    }

    #[test]
    fn a_pair_that_no_longer_references_itself_is_estale() {
        let mut observed = executed();
        observed.source.record.as_mut().unwrap().image_id = b"x".to_vec();
        assert_eq!(plan(Terminal::Commit, &observed), Err(ESTALE));
        assert_eq!(plan(Terminal::Abort, &observed), Err(ESTALE));
    }

    #[test]
    fn commit_k0_refuses_a_non_executed_state() {
        let mut observed = executed();
        observed.source.record.as_mut().unwrap().state = STATE_PREPARED;
        observed.destination.record.as_mut().unwrap().state = STATE_PREPARED;
        assert_eq!(plan(Terminal::Commit, &observed), Err(EINVAL));
    }

    #[test]
    fn commit_k2_refuses_non_user_source_snapshots() {
        let mut observed = executed();
        observed.source.snapshots = SnapshotSet::ContainsNonUser;
        assert_eq!(plan(Terminal::Commit, &observed), Err(EBUSY));
    }

    #[test]
    fn abort_refuses_a_name_conflict_and_a_lost_name() {
        let mut conflict = aborting();
        conflict.trash = None;
        conflict.destination = Endpoint {
            image: dst_image(),
            header_present: false,
            record: None,
            name_mapping: NameMapping::Absent,
            name_listed: false,
            identity_present: false,
            snapshots: SnapshotSet::None,
            boundary_present: false,
            mirror: MirrorState::default(),
            journaling: false,
        };
        conflict.source.name_mapping = NameMapping::OtherId(b"z".to_vec());
        assert_eq!(plan(Terminal::Abort, &conflict), Err(EEXIST));

        let mut lost = conflict.clone();
        lost.source.name_mapping = NameMapping::Absent;
        assert_eq!(plan(Terminal::Abort, &lost), Err(ENOENT));
    }

    #[test]
    fn commit_k3_never_runs_without_a_destination() {
        let mut observed = executed();
        observed.destination.header_present = false;
        observed.destination.record = None;
        observed.destination.identity_present = false;
        assert_eq!(plan(Terminal::Commit, &observed), Err(ENOENT));
    }

    // ---- import-only rows

    #[test]
    fn import_commit_runs_k1_and_k5() {
        let mut observed = base();
        observed.invocation = Invocation::DestinationName;
        observed.source = Endpoint {
            image: ImageRef::default(),
            header_present: false,
            record: None,
            name_mapping: NameMapping::Absent,
            name_listed: false,
            identity_present: false,
            snapshots: SnapshotSet::None,
            boundary_present: false,
            mirror: MirrorState::default(),
            journaling: false,
        };
        observed.destination.header_present = true;
        observed.destination.identity_present = true;
        observed.destination.name_mapping = NameMapping::SelfId;
        observed.destination.record = Some(import_record(STATE_EXECUTED));
        observed.import = true;
        assert!(observed.import_only());
        assert_eq!(plan(Terminal::Commit, &observed), Ok(stages(&[Stage::K1])));

        observed.destination.record.as_mut().unwrap().mirroring = true;
        // The captured JOURNAL mode needs the destination's JOURNALING feature
        // (OPEN-1).
        observed.destination.journaling = true;
        assert_eq!(
            plan(Terminal::Commit, &observed),
            Ok(stages(&[Stage::K1, Stage::K5]))
        );
    }

    #[test]
    fn import_abort_runs_b4_b7_b9() {
        let mut observed = base();
        observed.invocation = Invocation::DestinationName;
        observed.source.record = None;
        observed.destination.header_present = true;
        observed.destination.identity_present = true;
        observed.destination.name_mapping = NameMapping::SelfId;
        observed.destination.record = Some(import_record(STATE_PREPARED));
        observed.destination.snapshots = SnapshotSet::UserOnly;
        observed.import = true;
        assert!(observed.import_only());
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[Stage::B4, Stage::B7, Stage::B9]))
        );
    }

    #[test]
    fn import_abort_recordless_destination_is_ambiguous() {
        let mut observed = base();
        observed.import = true;
        observed.source.record = None;
        observed.source.header_present = false;
        observed.destination.header_present = true;
        observed.destination.identity_present = true;
        observed.destination.name_mapping = NameMapping::SelfId;
        assert_eq!(plan(Terminal::Abort, &observed), Err(EINVAL));
        // The internal prepare compensation knows it created the destination.
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[Stage::D8RemoveDestination]))
        );
    }

    // ---- format-1 source (WP-7 S1): crash table, own column

    fn v1_image() -> ImageRef {
        ImageRef {
            format: ImageFormat::V1,
            pool_id: 7,
            namespace: Vec::new(),
            name: b"legacy".to_vec(),
            id: Vec::new(),
        }
    }

    /// The format-2 destination a v1 prepare creates: same name, own ID.
    fn v1_destination_image() -> ImageRef {
        ImageRef {
            format: ImageFormat::V2,
            pool_id: 7,
            namespace: Vec::new(),
            name: b"legacy".to_vec(),
            id: b"d".to_vec(),
        }
    }

    /// The SRC record a v1 prepare writes at Q3: the peer is the format-2
    /// destination, named by pool/namespace/name/ID.
    fn v1_src_record(state: u8) -> MigrationRecord {
        MigrationRecord {
            header_type: HEADER_TYPE_SRC,
            pool_id: 7,
            pool_namespace: Vec::new(),
            image_name: b"legacy".to_vec(),
            image_id: b"d".to_vec(),
            snap_seqs: BTreeMap::new(),
            overlap: 0,
            flatten: false,
            mirroring: false,
            state,
            state_description: Vec::new(),
            mirror_image_mode: MIRROR_MODE_JOURNAL,
            source_spec: Vec::new(),
        }
    }

    /// The DST record a v1 prepare writes at Q6: the peer is the format-1
    /// source, named by its name with the empty image ID.
    fn v1_dst_record(state: u8) -> MigrationRecord {
        MigrationRecord {
            header_type: HEADER_TYPE_DST,
            pool_id: 7,
            pool_namespace: Vec::new(),
            image_name: b"legacy".to_vec(),
            image_id: Vec::new(),
            snap_seqs: BTreeMap::new(),
            overlap: 1 << 20,
            flatten: false,
            mirroring: false,
            state,
            state_description: Vec::new(),
            mirror_image_mode: MIRROR_MODE_JOURNAL,
            source_spec: Vec::new(),
        }
    }

    /// A clean format-1 source: header and TMAP name present, no record. Its
    /// destination inherits features 0 (plus MIGRATING at Q6), so it has no
    /// JOURNALING.
    fn v1_base() -> Observation {
        Observation {
            invocation: Invocation::SourceName,
            source: Endpoint {
                image: v1_image(),
                header_present: true,
                record: None,
                name_mapping: NameMapping::Absent,
                name_listed: true,
                identity_present: false,
                snapshots: SnapshotSet::None,
                boundary_present: false,
                mirror: MirrorState::default(),
                journaling: false,
            },
            destination: Endpoint::absent(v1_destination_image()),
            trash: None,
            group: GroupState::None,
            source_pool_mode: PoolMode::Image,
            destination_pool_mode: PoolMode::Image,
            children: ChildrenState::None,
            remembered_group: None,
            import: false,
        }
    }

    /// Q6-Q9 durable state: both records PREPARING/PREPARED, the destination
    /// snapshots copied, the source name unlinked.
    fn v1_prepared_at_q6() -> Observation {
        let mut observed = v1_base();
        observed.source.record = Some(v1_src_record(STATE_PREPARING));
        observed.source.snapshots = SnapshotSet::UserOnly;
        observed.source.name_listed = false;
        observed.destination.header_present = true;
        observed.destination.identity_present = true;
        observed.destination.name_mapping = NameMapping::SelfId;
        observed.destination.record = Some(v1_dst_record(STATE_PREPARING));
        observed.destination.snapshots = SnapshotSet::UserOnly;
        observed.destination.boundary_present = true;
        observed
            .destination
            .record
            .as_mut()
            .unwrap()
            .snap_seqs
            .insert(100, 11);
        observed
    }

    /// The EXECUTED pair right before commit K1.
    fn v1_executed() -> Observation {
        let mut observed = v1_prepared_at_q6();
        observed.invocation = Invocation::DestinationName;
        observed.source.record.as_mut().unwrap().state = STATE_EXECUTED;
        observed.destination.record.as_mut().unwrap().state = STATE_EXECUTED;
        observed
    }

    /// The ABORTING pair of the paired abort.
    fn v1_aborting() -> Observation {
        let mut observed = v1_executed();
        observed.source.record.as_mut().unwrap().state = STATE_ABORTING;
        observed.destination.record.as_mut().unwrap().state = STATE_ABORTING;
        observed
    }

    /// K1 ran: the destination is ordinary, the source record still EXECUTED.
    fn v1_after_k1() -> Observation {
        let mut observed = v1_executed();
        observed.destination.record = None;
        observed
    }

    #[test]
    fn v1_prepare_plans_q2_to_q9_without_the_source_mirror_stage() {
        // Q1 crash: nothing durable, so a re-run is the full v1 prepare.
        assert_eq!(
            plan(Terminal::Prepare, &v1_base()),
            Ok(stages(&[
                Stage::Q2,
                Stage::Q3,
                Stage::Q4,
                Stage::Q5,
                Stage::Q6,
                Stage::Q7,
                Stage::Q8,
                Stage::Q9
            ]))
        );
    }

    #[test]
    fn v1_q2_crash_re_prepares_and_refuses_abort() {
        // Q2: name gone from the TMAP, header ordinary, no record. D1 makes the
        // unlink idempotent, so a re-run converges; the public abort has no
        // record and no proof of an interrupted Q2 (V1-2).
        let mut observed = v1_base();
        observed.source.name_listed = false;
        assert_eq!(
            plan(Terminal::Prepare, &observed),
            Ok(stages(&[
                Stage::Q2,
                Stage::Q3,
                Stage::Q4,
                Stage::Q5,
                Stage::Q6,
                Stage::Q7,
                Stage::Q8,
                Stage::Q9
            ]))
        );
        assert_eq!(plan(Terminal::Abort, &observed), Err(EINVAL));
        // The internal prepare compensation restores the name (D2 analog).
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[Stage::B10]))
        );
    }

    #[test]
    fn v1_q3_crash_restores_the_name_and_the_marker() {
        // Q3: name gone, SRC PREPARING. B13 is skipped (no mirror record).
        let mut observed = v1_base();
        observed.source.record = Some(v1_src_record(STATE_PREPARING));
        observed.source.name_listed = false;
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[Stage::B10, Stage::B12]))
        );
    }

    #[test]
    fn v1_q4_identity_crash_removes_the_destination_d8() {
        let mut observed = v1_base();
        observed.source.record = Some(v1_src_record(STATE_PREPARING));
        observed.source.name_listed = false;
        observed.destination.identity_present = true;
        observed.destination.name_mapping = NameMapping::SelfId;
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[Stage::D8RemoveIdentity, Stage::B10, Stage::B12]))
        );
    }

    #[test]
    fn v1_q5_header_crash_removes_the_destination_d8() {
        let mut observed = v1_base();
        observed.source.record = Some(v1_src_record(STATE_PREPARING));
        observed.source.name_listed = false;
        observed.destination.header_present = true;
        observed.destination.identity_present = true;
        observed.destination.name_mapping = NameMapping::SelfId;
        assert_eq!(
            plan(Terminal::PrepareCompensation, &observed),
            Ok(stages(&[
                Stage::D8RemoveDestination,
                Stage::B10,
                Stage::B12
            ]))
        );
    }

    #[test]
    fn v1_q6_crash_runs_the_full_abort_without_children_group_and_mirror() {
        // Q6-Q9: both records, destination snapshots and the boundary. B6/B11
        // never run for a v1 source and B13 is skipped (V1-4).
        assert_eq!(
            plan(Terminal::Abort, &v1_prepared_at_q6()),
            Ok(stages(&[
                Stage::B4,
                Stage::B5,
                Stage::B7,
                Stage::B9,
                Stage::B10,
                Stage::B12
            ]))
        );
    }

    #[test]
    fn v1_q9_crash_ignores_a_child_relink_state() {
        // A v1 image can never be a parent, so a reported child state must not
        // add B6 (spec "Refusals stock applies").
        let mut observed = v1_prepared_at_q6();
        observed.children = ChildrenState::Partial;
        let planned = plan(Terminal::Abort, &observed).unwrap();
        assert!(!planned.contains(Stage::B6));
        assert!(planned.contains(Stage::B9));
    }

    #[test]
    fn v1_k1_crash_resumes_at_k2_d4() {
        // K1: destination ordinary, SRC EXECUTED, name gone, no trash entry.
        assert_eq!(
            plan(Terminal::Commit, &v1_after_k1()),
            Ok(stages(&[Stage::K2, Stage::K3]))
        );
    }

    #[test]
    fn v1_k2_crash_resumes_at_k3() {
        let mut observed = v1_after_k1();
        observed.source.snapshots = SnapshotSet::None;
        assert_eq!(plan(Terminal::Commit, &observed), Ok(stages(&[Stage::K3])));
    }

    #[test]
    fn v1_k3_tmap_failure_leaves_nothing_to_clean() {
        // K3 with a failing TMAP removal: the header object is gone. Q2 already
        // removed the key, so the durable state is "header gone, name not
        // listed" (the spec row also names the dangling-key variant, which only
        // `rbd_remove` can leave behind). Both variants answer `-ENOENT`: there
        // is no target and no cleanup record (V1-3).
        let mut observed = v1_after_k1();
        observed.source.header_present = false;
        observed.source.record = None;
        assert!(!observed.source.name_listed);
        assert_eq!(plan(Terminal::Commit, &observed), Err(ENOENT));
        observed.source.name_listed = true;
        assert_eq!(plan(Terminal::Commit, &observed), Err(ENOENT));
    }

    #[test]
    fn v1_k3_done_is_enoent() {
        let mut observed = v1_after_k1();
        observed.source.header_present = false;
        observed.source.record = None;
        observed.source.name_listed = false;
        assert_eq!(plan(Terminal::Commit, &observed), Err(ENOENT));
    }

    #[test]
    fn v1_b4_crash_repeats_b4() {
        assert_eq!(
            plan(Terminal::Abort, &v1_aborting()),
            Ok(stages(&[
                Stage::B4,
                Stage::B5,
                Stage::B7,
                Stage::B9,
                Stage::B10,
                Stage::B12
            ]))
        );
    }

    #[test]
    fn v1_b10_crash_continues_without_a_trash_entry() {
        // B10 done: the name is listed again and the destination is gone. R3
        // does not apply, the TMAP SET is idempotent.
        let mut observed = v1_aborting();
        observed.destination = Endpoint::absent(v1_destination_image());
        observed.source.name_listed = true;
        assert_eq!(plan(Terminal::Abort, &observed), Ok(stages(&[Stage::B12])));
        // B10 pending (the TMAP key is still absent) runs it.
        observed.source.name_listed = false;
        assert_eq!(
            plan(Terminal::Abort, &observed),
            Ok(stages(&[Stage::B10, Stage::B12]))
        );
    }

    #[test]
    fn v1_b12_crash_is_not_migrating() {
        // B12: marker restored, record gone, name listed, destination gone.
        let mut observed = v1_aborting();
        observed.destination = Endpoint::absent(v1_destination_image());
        observed.source.name_listed = true;
        observed.source.record = None;
        assert_eq!(plan(Terminal::Abort, &observed), Err(EINVAL));
    }

    #[test]
    fn v1_b13_is_skipped_in_a_pool_mode_pool() {
        // V1-4: stock enables JOURNAL mirroring with an empty image ID and fails
        // `-ENOENT` after the source is gone. Own skips the source enable, and
        // the destination (features 0, OPEN-1) gets none either.
        let mut observed = v1_aborting();
        observed.source_pool_mode = PoolMode::Pool;
        observed.destination_pool_mode = PoolMode::Pool;
        let planned = plan(Terminal::Abort, &observed).unwrap();
        assert!(!planned.contains(Stage::B13));
        let commit = plan(Terminal::Commit, &v1_after_k1()).unwrap();
        assert!(!commit.contains(Stage::D6));
        assert!(!commit.contains(Stage::K5));
    }

    #[test]
    fn v1_d4_resumes_only_with_executed_proof_and_a_matching_destination() {
        // D4: the resume proof is the EXECUTED SRC record plus the destination
        // header whose ID the record names.
        assert_eq!(
            plan(Terminal::Commit, &v1_after_k1()),
            Ok(stages(&[Stage::K2, Stage::K3]))
        );
        // No destination: never delete the source.
        let mut missing = v1_after_k1();
        missing.destination = Endpoint::absent(v1_destination_image());
        assert_eq!(plan(Terminal::Commit, &missing), Err(ENOENT));
        // A destination with another ID is not the recorded peer.
        let mut foreign = v1_after_k1();
        foreign.destination.image.id = b"x".to_vec();
        assert_eq!(plan(Terminal::Commit, &foreign), Err(ESTALE));
        // A destination record that names another format-1 image is not this
        // peer either: the empty ID is bound by the name.
        let mut named = v1_prepared_at_q6();
        named.destination.record.as_mut().unwrap().image_name = b"other".to_vec();
        assert_eq!(plan(Terminal::Abort, &named), Err(ESTALE));
        // Without EXECUTED proof K1/K3 never run.
        let mut unprepared = v1_prepared_at_q6();
        unprepared.destination.record = None;
        assert_eq!(plan(Terminal::Commit, &unprepared), Err(EINVAL));
    }

    #[test]
    fn v1_prepare_refuses_a_source_that_already_migrates() {
        let mut observed = v1_base();
        observed.source.record = Some(v1_src_record(STATE_PREPARING));
        assert_eq!(plan(Terminal::Prepare, &observed), Err(EINVAL));
    }

    #[test]
    fn v1_prepare_is_not_refused_for_snapshots_or_children() {
        // A v1 image only has USER snapshots and can never be a parent: the v2
        // -EBUSY and layering refusals must not be synthesized.
        let mut observed = v1_base();
        observed.source.snapshots = SnapshotSet::UserOnly;
        observed.children = ChildrenState::AtSource;
        assert!(plan(Terminal::Prepare, &observed).is_ok());
    }

    #[test]
    fn v1_prepare_refuses_a_taken_destination_name_and_a_missing_source() {
        let mut taken = v1_base();
        taken.destination.name_mapping = NameMapping::OtherId(b"other".to_vec());
        taken.destination.identity_present = true;
        assert_eq!(plan(Terminal::Prepare, &taken), Err(EEXIST));

        let mut missing = v1_base();
        missing.source.header_present = false;
        assert_eq!(plan(Terminal::Prepare, &missing), Err(ENOENT));
    }

    #[test]
    fn v1_b5_b7_b9_crashes_follow_the_v2_rows() {
        // B5: source HEAD partly reverted, the metadata is the B4 state, so the
        // revert stays in the plan (idempotent).
        let observed = v1_aborting();
        let planned = plan(Terminal::Abort, &observed).unwrap();
        assert!(planned.contains(Stage::B5));
        // B7: the destination snapshots and the boundary are gone, so D9 skips
        // the revert and the abort continues.
        let mut b7 = v1_aborting();
        b7.destination.snapshots = SnapshotSet::None;
        b7.destination.boundary_present = false;
        assert_eq!(
            plan(Terminal::Abort, &b7),
            Ok(stages(&[Stage::B4, Stage::B9, Stage::B10, Stage::B12]))
        );
        // B9: the destination is gone; only the source restore is left.
        let mut b9 = v1_aborting();
        b9.destination = Endpoint::absent(v1_destination_image());
        assert_eq!(
            plan(Terminal::Abort, &b9),
            Ok(stages(&[Stage::B10, Stage::B12]))
        );
    }

    /// One observation per v1 crash-table row, own column.
    fn v1_rows() -> Vec<(&'static str, Observation)> {
        let mut rows = Vec::new();
        rows.push(("v1 Q1", v1_base()));
        let mut q2 = v1_base();
        q2.source.name_listed = false;
        rows.push(("v1 Q2", q2));
        let mut q3 = v1_base();
        q3.source.record = Some(v1_src_record(STATE_PREPARING));
        q3.source.name_listed = false;
        rows.push(("v1 Q3", q3.clone()));
        let mut q4 = q3.clone();
        q4.destination.identity_present = true;
        q4.destination.name_mapping = NameMapping::SelfId;
        rows.push(("v1 Q4", q4.clone()));
        let mut q5 = q4.clone();
        q5.destination.header_present = true;
        rows.push(("v1 Q5", q5));
        rows.push(("v1 Q6", v1_prepared_at_q6()));
        let mut q9 = v1_prepared_at_q6();
        q9.children = ChildrenState::Partial;
        rows.push(("v1 Q9", q9));
        let k1 = v1_after_k1();
        rows.push(("v1 K1", k1.clone()));
        let mut k2 = k1.clone();
        k2.source.snapshots = SnapshotSet::None;
        rows.push(("v1 K2", k2));
        let mut k3_tmap = k1;
        k3_tmap.source.header_present = false;
        k3_tmap.source.record = None;
        rows.push(("v1 K3-tmap", k3_tmap.clone()));
        let mut k3 = k3_tmap;
        k3.source.name_listed = false;
        rows.push(("v1 K3", k3));
        rows.push(("v1 B4", v1_aborting()));
        let mut b10 = v1_aborting();
        b10.destination = Endpoint::absent(v1_destination_image());
        b10.source.name_listed = true;
        rows.push(("v1 B10", b10.clone()));
        let mut b12 = b10;
        b12.source.record = None;
        rows.push(("v1 B12", b12));
        rows
    }

    #[test]
    fn v1_plans_never_contain_the_v1_skipped_stages() {
        // K4, B6, B11, B13 and the source mirror stage Q1 are skipped for a
        // format-1 source. D6/K5 are destination mirror stages: absent here
        // because a v1 destination inherits features 0 (OPEN-3 default) and
        // OPEN-1 skips a JOURNAL enable on it.
        for (name, observed) in v1_rows() {
            for terminal in [
                Terminal::Prepare,
                Terminal::PrepareCompensation,
                Terminal::Commit,
                Terminal::Abort,
            ] {
                let Ok(planned) = plan(terminal, &observed) else {
                    continue;
                };
                for skipped in [
                    Stage::Q1,
                    Stage::K4,
                    Stage::K5,
                    Stage::B6,
                    Stage::B11,
                    Stage::B13,
                    Stage::D6,
                ] {
                    assert!(
                        !planned.contains(skipped),
                        "{name} {terminal:?}: {skipped:?} in a v1 plan {:?}",
                        planned.stages()
                    );
                }
            }
        }
    }

    // ---- invariants I1-I4 over every row above

    fn k1_done(observed: &Observation) -> bool {
        observed.destination.header_present
            && observed.destination.record.is_none()
            && observed
                .source
                .record
                .as_ref()
                .is_some_and(|record| record.state == STATE_EXECUTED)
            // A format-1 source never has a MIGRATION entry; its EXECUTED
            // record and the ordinary destination are the whole proof.
            && (observed.source.image.is_v1() || observed.trash.is_some())
    }

    fn proof_state(observed: &Observation) -> Option<u8> {
        if observed.invocation == Invocation::SourceName {
            observed.source.record.as_ref().map(|record| record.state)
        } else {
            observed
                .destination
                .record
                .as_ref()
                .map(|record| record.state)
        }
    }

    fn revert_done(observed: &Observation) -> bool {
        match &observed.destination.record {
            None => true,
            Some(record) => !record.snap_seqs.is_empty() && !observed.destination.boundary_present,
        }
    }

    fn all_rows() -> Vec<(&'static str, Observation)> {
        let mut rows = Vec::new();
        rows.push(("Q1", base()));
        let mut q2 = base();
        q2.trash = Some(trash());
        q2.source.name_mapping = NameMapping::Absent;
        rows.push(("Q2", q2));
        let mut q3 = with_source_record(base(), STATE_PREPARING);
        q3.source.record.as_mut().unwrap().mirroring = true;
        q3.trash = Some(trash());
        q3.source.name_mapping = NameMapping::Absent;
        rows.push(("Q3", q3.clone()));
        let mut q4 = q3.clone();
        q4.destination.identity_present = true;
        q4.destination.name_mapping = NameMapping::SelfId;
        rows.push(("Q4", q4.clone()));
        let mut q5 = q4.clone();
        q5.destination.header_present = true;
        rows.push(("Q5", q5));
        rows.push(("Q6", prepared_at_q6()));
        let mut q7 = prepared_at_q6();
        q7.group = GroupState::Destination;
        rows.push(("Q7", q7.clone()));
        let mut q8 = q7.clone();
        q8.source.record.as_mut().unwrap().state = STATE_PREPARED;
        q8.destination.record.as_mut().unwrap().state = STATE_PREPARED;
        rows.push(("Q8", q8));
        let mut q9 = q7;
        q9.children = ChildrenState::Partial;
        rows.push(("Q9", q9));

        rows.push(("K0", executed()));
        let mut k0_mirror = executed();
        k0_mirror.destination.record.as_mut().unwrap().mirroring = true;
        rows.push(("K0-D6", k0_mirror));
        let mut k1 = executed();
        k1.destination.record = None;
        rows.push(("K1", k1.clone()));
        let mut k2 = k1.clone();
        k2.source.snapshots = SnapshotSet::None;
        rows.push(("K2", k2));
        let mut k3_gone = k1;
        k3_gone.source.header_present = false;
        k3_gone.source.record = None;
        k3_gone.source.identity_present = false;
        rows.push(("K3", k3_gone.clone()));
        let mut k4 = k3_gone.clone();
        k4.trash = None;
        rows.push(("K4", k4));

        rows.push(("B4", aborting()));
        let mut b6 = aborting();
        b6.children = ChildrenState::Partial;
        rows.push(("B6", b6));
        let mut b7 = aborting();
        b7.destination.snapshots = SnapshotSet::None;
        b7.destination.boundary_present = false;
        rows.push(("B7", b7.clone()));
        let mut b9 = aborting();
        b9.destination = Endpoint {
            image: dst_image(),
            header_present: false,
            record: None,
            name_mapping: NameMapping::Absent,
            name_listed: false,
            identity_present: false,
            snapshots: SnapshotSet::None,
            boundary_present: false,
            mirror: MirrorState::default(),
            journaling: false,
        };
        rows.push(("B9", b9.clone()));
        let mut b10 = b9.clone();
        b10.trash = None;
        b10.source.name_mapping = NameMapping::SelfId;
        rows.push(("B10", b10.clone()));
        let mut b11 = b10.clone();
        b11.remembered_group = Some(GroupRef {
            pool_id: 7,
            group_id: b"g".to_vec(),
        });
        rows.push(("B11", b11));
        let mut b12 = b10.clone();
        b12.source.record = None;
        rows.push(("B12", b12));
        let mut b13 = b9;
        b13.source.record.as_mut().unwrap().mirroring = true;
        rows.push(("B13", b13));
        rows.extend(v1_rows());
        rows
    }

    #[test]
    fn invariant_i1_source_data_is_written_only_by_revert_and_deleted_only_by_k3() {
        for (name, observed) in all_rows() {
            for terminal in [
                Terminal::PrepareCompensation,
                Terminal::Commit,
                Terminal::Abort,
            ] {
                if let Ok(planned) = plan(terminal, &observed) {
                    for stage in planned.stages() {
                        match stage.source_data_effect() {
                            SourceDataEffect::Write => assert_eq!(
                                *stage,
                                Stage::B5,
                                "{name} {terminal:?} writes source data in {stage:?}"
                            ),
                            SourceDataEffect::Delete => assert_eq!(
                                *stage,
                                Stage::K3,
                                "{name} {terminal:?} deletes source data in {stage:?}"
                            ),
                            SourceDataEffect::None => {}
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn invariant_i2_k1_needs_executed_proof_and_precedes_k3() {
        for (name, observed) in all_rows() {
            let Ok(planned) = plan(Terminal::Commit, &observed) else {
                continue;
            };
            if planned.contains(Stage::K1) {
                assert_eq!(
                    proof_state(&observed),
                    Some(STATE_EXECUTED),
                    "{name}: K1 without EXECUTED proof"
                );
            }
            if planned.contains(Stage::K3) {
                assert!(
                    observed.destination.header_present,
                    "{name}: K3 without a destination"
                );
                if let Some(k1) = planned.position(Stage::K1) {
                    assert!(
                        k1 < planned.position(Stage::K3).unwrap(),
                        "{name}: K3 before K1"
                    );
                } else {
                    assert!(k1_done(&observed), "{name}: K3 without K1 proof");
                }
            }
        }
    }

    #[test]
    fn invariant_i3_destination_is_deleted_only_by_b9_after_revert_or_d8_while_preparing() {
        for (name, observed) in all_rows() {
            for terminal in [Terminal::PrepareCompensation, Terminal::Abort] {
                let Ok(planned) = plan(terminal, &observed) else {
                    continue;
                };
                if planned.contains(Stage::B9) {
                    assert!(
                        planned
                            .position(Stage::B5)
                            .is_some_and(|b5| b5 < planned.position(Stage::B9).unwrap())
                            || revert_done(&observed),
                        "{name} {terminal:?}: B9 without a completed revert"
                    );
                }
                if planned.contains(Stage::D8RemoveDestination)
                    || planned.contains(Stage::D8RemoveIdentity)
                {
                    let preparing = observed
                        .source
                        .record
                        .as_ref()
                        .is_some_and(|record| record.state == STATE_PREPARING);
                    assert!(
                        preparing || observed.import_only(),
                        "{name} {terminal:?}: D8 without PREPARING proof"
                    );
                }
            }
        }
    }

    #[test]
    fn invariant_i4_nothing_is_deleted_after_k1_except_by_commit() {
        for (name, observed) in all_rows() {
            if !k1_done(&observed) {
                continue;
            }
            let abort = plan(Terminal::Abort, &observed);
            assert!(
                matches!(abort, Err(EINVAL) | Err(ENOENT)),
                "{name}: abort after K1 returned {abort:?}"
            );
            if let Ok(planned) = plan(Terminal::Commit, &observed) {
                assert!(
                    planned.stages().iter().all(|stage| stage.is_commit()),
                    "{name}: post-K1 commit contains an abort stage"
                );
            }
        }
    }

    #[test]
    fn plans_never_mix_commit_and_abort_stages() {
        for (name, observed) in all_rows() {
            for terminal in [
                Terminal::PrepareCompensation,
                Terminal::Commit,
                Terminal::Abort,
            ] {
                if let Ok(planned) = plan(terminal, &observed) {
                    let commit = planned.stages().iter().any(|stage| stage.is_commit());
                    let abort = planned.stages().iter().any(|stage| !stage.is_commit());
                    assert!(
                        !(commit && abort),
                        "{name} {terminal:?}: mixed plan {:?}",
                        planned.stages()
                    );
                }
            }
        }
    }
}
