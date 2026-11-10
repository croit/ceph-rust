// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Caller-side preparation of ordinary object operations (rustyrados redesign, step 2).
//!
//! The submitting thread validates, places the object from the published [`ClusterView`] (one `Arc` load), builds
//! the MOSDOp with the same builder the data owner uses and encodes it. The data owner receives a ready
//! [`PreparedFrame`] and only frames and sends it. The frame carries a [`FrameKey`], the exact attempt it was
//! built for (epoch, PG, shard, hash, target OSD, peer features, flags, incarnation, retry number). The owner's
//! first dispatch keeps the frame only when its own attempt has the same key; on any difference (a newer map, a
//! different session target, changed flags, a retry) the frame is dropped and the owner re-places and re-encodes
//! in FIFO order, exactly as it did before preparation existed.
//!
//! What is prepared: ordinary compound operations on a pool without cache-tier overlay, default read policy
//! (the acting primary), replicated or erasure pools, and a peer whose features are known (some owner connected
//! to that OSD before). Everything else takes the owner path.
//!
//! The write payload's crc is not computed here: it travels as the `CrcHint` the C-ABI input copy fused with
//! its copy ([`crc::CrcHint`] on the operation's input), and the frame forwards it unchanged.

use super::{
    CompoundRequest, MessageInputs, PoolRoute, ReadRoute, Request, build_message,
    identity::IdentityField, request_flags,
};
use crate::ClusterView;
use arc_swap::ArcSwap;
use denc::types::{PgT, ShardId, SpgT};
use opwire::{flag, op};
use std::cell::RefCell;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
};

/// Features negotiated with each OSD, shared by every owner and every preparing thread. Written by the owner that
/// connects (cold), read lock-free by the caller. 0 = unknown: nothing is prepared for that OSD until an owner has
/// connected to it once.
#[derive(Debug)]
pub struct PeerFeatures {
    table: ArcSwap<Vec<AtomicU64>>,
    grow: Mutex<()>,
}

impl Default for PeerFeatures {
    fn default() -> Self {
        Self {
            table: ArcSwap::from_pointee(Vec::new()),
            grow: Mutex::new(()),
        }
    }
}

impl PeerFeatures {
    /// Record the features `osd` negotiated on its newest connection.
    pub fn record(&self, osd: i32, features: u64) {
        let Ok(index) = usize::try_from(osd) else {
            return;
        };
        if let Some(slot) = self.table.load().get(index) {
            slot.store(features, Ordering::Release);
            return;
        }
        let _grow = self.grow.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.table.load_full();
        if let Some(slot) = current.get(index) {
            slot.store(features, Ordering::Release);
            return;
        }
        let len = (index + 1).max(current.len() * 2);
        let mut next: Vec<AtomicU64> = Vec::with_capacity(len);
        next.extend(
            current
                .iter()
                .map(|v| AtomicU64::new(v.load(Ordering::Acquire))),
        );
        next.resize_with(len, || AtomicU64::new(0));
        next[index].store(features, Ordering::Release);
        self.table.store(Arc::new(next));
    }
    /// Features of `osd`, 0 when unknown.
    pub fn get(&self, osd: i32) -> u64 {
        usize::try_from(osd)
            .ok()
            .and_then(|i| self.table.load().get(i).map(|v| v.load(Ordering::Acquire)))
            .unwrap_or(0)
    }
}

/// The first attempt a [`PreparedFrame`] was built for: what the owner's route and the queue already know, so the
/// owner can trust the frame by comparing them (no placement, no message build). The retry number is always 0 (the
/// queue sends a frame only on the first attempt).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameKey {
    epoch: u32,
    pg: PgT,
    shard: ShardId,
    hash: u32,
    osd: i32,
    features: u64,
    incarnation: u32,
}

impl FrameKey {
    /// The osd map epoch the frame was placed in.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    /// The OSD the frame is addressed to.
    pub fn osd(&self) -> i32 {
        self.osd
    }
    /// The features of the peer the frame was encoded for.
    pub fn features(&self) -> u64 {
        self.features
    }
    /// The route this frame was built for, on `session` (osd map generation `generation`).
    pub fn route(&self, session: u64, generation: u64) -> ReadRoute {
        ReadRoute {
            direct_read: false,
            base_pool: self.pg.pool as i64,
            osd: self.osd,
            session,
            pg: self.pg,
            hash: self.hash,
            epoch: self.epoch,
            features: self.features,
            generation,
            pool: if self.shard == ShardId::NO_SHARD {
                PoolRoute::Replicated
            } else {
                PoolRoute::Erasure(self.shard)
            },
        }
    }
    /// Whether `route`, dispatched by a queue with client `incarnation`, is exactly the attempt of this key.
    pub(crate) fn is_attempt(&self, route: &ReadRoute, incarnation: u32) -> bool {
        self.incarnation == incarnation && *route == self.route(route.session, route.generation)
    }
}

/// An encoded MOSDOp front and its data segments, ready for the owner to frame (the tid is a header field and is
/// stamped by the owner).
#[derive(Clone, Debug)]
pub struct PreparedFrame {
    pub key: FrameKey,
    /// The request's wire flags before routing ([`request_flags`]) the frame was built with; they change only on a
    /// redirect or primary fallback, which need a retry.
    pub(crate) base_flags: u32,
    /// Flags the map pause/full policy of the send applies ([`crate::pausing_flags`]).
    pub pausing: u32,
    /// Front length of the reply this request provokes (`None` when it cannot be bounded): the owner's reply-size
    /// limit check needs no message.
    pub reply_front: Option<usize>,
    /// MOSDOp encoding version the front was written in.
    pub version: u16,
    pub segments: messages::Segments,
    /// Known crc of the data segment, default when the segment has none.
    pub data_crc: crc::CrcHint,
    pub data_more: opwire::Pieces,
}

/// Placement memo of one preparing thread: the acting primary of a PG for one published view.
#[derive(Default)]
struct Memo {
    view: Weak<ClusterView>,
    primaries: osdmap::PgHashMap<Option<osdmap::PrimaryDestination>>,
}

/// Memo entries kept per view; a full memo restarts (the bound is memory, not a policy).
const MEMO_PGS: usize = 1 << 16;

thread_local! {
    static MEMO: RefCell<Memo> = RefCell::new(Memo::default());
}

fn primary_of(
    view: &Arc<ClusterView>,
    map: &osdmap::OsdMap,
    pg: PgT,
) -> Option<osdmap::PrimaryDestination> {
    MEMO.with(|memo| {
        let mut memo = memo.borrow_mut();
        if !Weak::ptr_eq(&memo.view, &Arc::downgrade(view)) || memo.primaries.len() >= MEMO_PGS {
            memo.view = Arc::downgrade(view);
            memo.primaries.clear();
        }
        *memo.primaries.entry(pg).or_insert_with(|| {
            let mapping = map.pg_to_up_acting(pg);
            map.primary_destination(pg, &mapping)
        })
    })
}

/// What the preparing thread learned from the view ([`Preparer::prepare`]).
#[derive(Debug)]
pub struct Prepared {
    pub request: CompoundRequest,
    /// The view the request was placed in (`None` before the first publication).
    pub view: Option<Arc<ClusterView>>,
    /// Primary OSD of the object's placement group in `view`.
    pub primary: Option<i32>,
    pub frame: Option<PreparedFrame>,
}

/// Placement of an object in one view.
#[derive(Clone, Copy)]
struct Placed {
    seed: u32,
    pg: PgT,
    destination: osdmap::PrimaryDestination,
}

fn place(view: &Arc<ClusterView>, request: &Request) -> Option<Placed> {
    let Request::Compound(compound) = request else {
        return None;
    };
    place_target(view, &compound.target)
}

fn place_target(view: &Arc<ClusterView>, target: &crate::Target) -> Option<Placed> {
    let map = view.map.as_ref()?;
    let pool = map.pool(target.pool)?;
    let raw = map
        .object_to_raw_pg(
            target.pool,
            &target.object,
            &target.locator,
            &target.namespace,
            -1,
        )
        .ok()?;
    let pg = pool.raw_pg_to_pg(raw);
    Some(Placed {
        seed: raw.seed,
        pg,
        destination: primary_of(view, map, pg)?,
    })
}

/// Prepares ordinary operations of one client against its shared view.
#[derive(Clone, Debug)]
pub struct Preparer {
    view: Arc<crate::ViewCell>,
    incarnation: u32,
}

impl Preparer {
    pub fn new(view: Arc<crate::ViewCell>, incarnation: u32) -> Self {
        Self { view, incarnation }
    }

    /// The request back with what the calling thread learned from the published view: the view itself, the OSD the
    /// object's placement group has as primary (the routing key of a sharded client, known even when no frame can be
    /// prepared), and the frame when the operation is eligible and placeable now.
    pub fn prepare(&self, request: CompoundRequest) -> Prepared {
        let request = Request::Compound(request);
        let view = self.view.load();
        let placed = view.as_ref().and_then(|view| place(view, &request));
        let primary = placed.as_ref().map(|placed| placed.destination.osd);
        let frame = view
            .as_ref()
            .zip(placed)
            .and_then(|(view, placed)| self.frame(view, &request, placed));
        let Request::Compound(request) = request else {
            unreachable!("wrapped above")
        };
        Prepared {
            request,
            view,
            primary,
            frame,
        }
    }
    /// The OSD that is primary of `target`'s placement group in `view`: the home of the request on a sharded client.
    /// `None` when the view has no map, no such pool or no primary.
    pub fn primary_osd(view: &Arc<ClusterView>, target: &crate::Target) -> Option<i32> {
        place_target(view, target).map(|placed| placed.destination.osd)
    }

    fn frame(
        &self,
        view: &Arc<ClusterView>,
        request: &Request,
        placed: Placed,
    ) -> Option<PreparedFrame> {
        let Request::Compound(compound) = request else {
            return None;
        };
        let flags = request_flags(request, 0, compound.context.full_policy, false, false);
        if flags & (flag::BALANCE_READS | flag::LOCALIZE_READS | flag::EC_DIRECT_READ) != 0
            || compound.operations.is_empty()
            || compound.operations.iter().any(|o| {
                matches!(
                    o.op,
                    op::PGLS | op::PGLS_FILTER | op::PGNLS | op::PGNLS_FILTER
                ) || o.op & op::TYPE_MASK == op::TYPE_PG
            })
        {
            return None;
        }
        let map = view.map.as_ref()?;
        let pool = map.pool(compound.target.pool)?;
        if (!pool.is_replicated() && !pool.is_erasure())
            || pool.read_tier >= 0
            || pool.write_tier >= 0
            || pool.flags & osdmap::pool::flags::EIO != 0
        {
            return None;
        }
        let Placed {
            seed,
            pg,
            destination,
        } = placed;
        let features = self.view.peer_features().get(destination.osd);
        if features == 0 || (pool.is_erasure() && opwire::mosdop_version_for(features) < 8) {
            return None;
        }
        let inputs = MessageInputs {
            pgid: SpgT {
                pgid: pg,
                shard: destination.shard,
            },
            hash: seed,
            epoch: map.epoch,
            pool: pg.pool as i64,
            features,
            incarnation: self.incarnation,
            attempts: 0,
            direct_read: false,
            base_flags: flags,
        };
        let message = build_message(request, &inputs, |field: IdentityField| {
            field.bytes(request)
        });
        let version = opwire::mosdop_version_for(features);
        let (segments, data_crc, data_more) =
            message.encode_parts_version(version, features).ok()?;
        let data_crc = if data_crc.of(&segments.data).is_some() {
            data_crc
        } else {
            Default::default()
        };
        let watch_ping = matches!(message.ops.as_slice(), [o]
            if o.op == op::WATCH && o.watch().op == opwire::consts::watch_op::PING);
        Some(PreparedFrame {
            key: FrameKey {
                epoch: map.epoch,
                pg,
                shard: destination.shard,
                hash: seed,
                osd: destination.osd,
                features,
                incarnation: self.incarnation,
            },
            base_flags: flags,
            pausing: crate::pausing_flags(message.flags, watch_ping),
            reply_front: opwire::MOSDOpReply::normal_front_len(
                message.oid.len(),
                message.ops.len(),
            ),
            version,
            segments,
            data_crc,
            data_more,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{PoolRoute, ReadQueue, ReadRoute};
    use super::*;
    use crate::{Access, CompoundRequest, RequestContext, Target};
    use bytes::Bytes;
    use opwire::OsdOp;

    /// The request and its frame, as the owner tests use them.
    fn prepare(
        preparer: &Preparer,
        request: CompoundRequest,
    ) -> (CompoundRequest, Option<PreparedFrame>) {
        let prepared = preparer.prepare(request);
        (prepared.request, prepared.frame)
    }

    const FEATURES: u64 = u64::MAX >> 4;

    struct Fixture {
        cell: Arc<crate::ViewCell>,
        map: Arc<osdmap::OsdMap>,
        pool: i64,
    }

    fn fixture() -> Fixture {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/osdmap/full/0091.bin"
        );
        let map = osdmap::OsdMap::decode_from(&std::fs::read(path).unwrap()).unwrap();
        let pool = map
            .pools
            .iter()
            .find(|(_, p)| p.is_replicated() && p.read_tier < 0 && p.write_tier < 0)
            .map(|(&id, _)| id)
            .unwrap();
        let map = Arc::new(map);
        let cell = crate::ViewCell::new(5);
        let entity = cephx::none::ByteEntityName {
            ty: cephx::none::ENTITY_CLIENT,
            id: b"client".to_vec(),
        };
        cell.publish(crate::ViewInput {
            map: Some(&map),
            osd_ticket: None,
            identity: 9,
            entity: &entity,
            method: cephx::modes::AUTH_NONE,
            fsid: None,
        });
        Fixture { cell, map, pool }
    }

    fn request(pool: i64, op: OsdOp, access: Access) -> CompoundRequest {
        CompoundRequest {
            target: Target {
                pool,
                object: b"prepared-object".to_vec(),
                namespace: vec![],
                locator: vec![],
            },
            access,
            context: RequestContext::default(),
            operations: vec![op],
            max_output_bytes: 4096,
        }
    }

    /// The route the owner computes for `request` on `map`, independent of the preparer.
    fn owner_route(map: &osdmap::OsdMap, request: &CompoundRequest, epoch: u32) -> ReadRoute {
        let pool = map.pool(request.target.pool).unwrap();
        let raw = map
            .object_to_raw_pg(request.target.pool, &request.target.object, &[], &[], -1)
            .unwrap();
        let pg = pool.raw_pg_to_pg(raw);
        let mapping = map.pg_to_up_acting(pg);
        let destination = map.primary_destination(pg, &mapping).unwrap();
        ReadRoute {
            base_pool: request.target.pool,
            direct_read: false,
            osd: destination.osd,
            session: 1,
            pg,
            hash: raw.seed,
            epoch,
            features: FEATURES,
            generation: 1,
            pool: PoolRoute::Replicated,
        }
    }

    fn primary(f: &Fixture, request: &CompoundRequest) -> i32 {
        owner_route(&f.map, request, f.map.epoch).osd
    }

    fn write_request(f: &Fixture) -> CompoundRequest {
        let data = Bytes::from_static(b"payload-bytes-of-a-write");
        let mut op = OsdOp::writefull_bytes(data.clone());
        op.indata_crc = crc::CrcHint::new(&data, crc::crc32c(!0, &data));
        request(f.pool, op, Access::Write)
    }

    #[test]
    fn peer_features_grow_and_stay_per_osd() {
        let table = PeerFeatures::default();
        assert_eq!(table.get(3), 0);
        table.record(3, 7);
        table.record(100, 9);
        table.record(-1, 5);
        assert_eq!(
            (table.get(3), table.get(100), table.get(4), table.get(-1)),
            (7, 9, 0, 0)
        );
        table.record(3, 8);
        assert_eq!(table.get(3), 8);
    }

    #[test]
    fn unknown_peer_features_prepare_nothing() {
        let f = fixture();
        let preparer = Preparer::new(f.cell.clone(), 0);
        let (_, frame) = prepare(&preparer, write_request(&f));
        assert!(frame.is_none());
    }

    #[test]
    fn frame_is_the_owners_encoding_and_keeps_the_fused_write_crc() {
        let f = fixture();
        let request = write_request(&f);
        f.cell
            .peer_features()
            .record(primary(&f, &request), FEATURES);
        let preparer = Preparer::new(f.cell.clone(), 0);
        let (request, frame) = prepare(&preparer, request);
        let frame = frame.expect("eligible write is prepared");
        // the data crc is the one the C-ABI copy fused, never a second pass
        assert!(frame.data_crc.of(&frame.segments.data).is_some());
        let route = owner_route(&f.map, &request, f.map.epoch);
        let mut queue = ReadQueue::new(4, 1 << 20, 0).unwrap();
        let token = queue.submit_compound(request).unwrap();
        queue.set_prepared(token, frame.clone()).unwrap();
        let dispatch = queue.dispatch(token, route).unwrap();
        let kept = dispatch.prepared.expect("matching attempt keeps the frame");
        let fresh = dispatch
            .message
            .encode_parts_version(kept.version, route.features)
            .unwrap();
        assert_eq!(
            kept.segments, fresh.0,
            "prepared front and data are the owner's encoding"
        );
        assert_eq!(kept.data_more.len(), fresh.2.len());
    }

    #[test]
    fn frame_is_dropped_when_the_owner_attempt_differs() {
        let f = fixture();
        let request = write_request(&f);
        let osd = primary(&f, &request);
        f.cell.peer_features().record(osd, FEATURES);
        let preparer = Preparer::new(f.cell.clone(), 0);
        let (request, frame) = prepare(&preparer, request);
        let frame = frame.unwrap();
        let route = owner_route(&f.map, &request, f.map.epoch);
        let cases: [(&str, ReadRoute); 3] = [
            (
                "newer epoch",
                ReadRoute {
                    epoch: route.epoch + 1,
                    ..route
                },
            ),
            (
                "other session target",
                ReadRoute {
                    osd: route.osd + 1,
                    ..route
                },
            ),
            (
                "other peer features",
                ReadRoute {
                    features: FEATURES >> 1,
                    ..route
                },
            ),
        ];
        for (name, route) in cases {
            let mut queue = ReadQueue::new(4, 1 << 20, 0).unwrap();
            let token = queue.submit_compound(request_clone(&request)).unwrap();
            queue.set_prepared(token, frame.clone()).unwrap();
            let dispatch = queue.dispatch(token, route).unwrap();
            assert!(
                dispatch.prepared.is_none(),
                "{name}: stale frame must not be sent"
            );
            assert_eq!(dispatch.message.osdmap_epoch, route.epoch, "{name}");
        }
    }

    /// Prepared write, its route, and a queue (client incarnation `incarnation`) holding it.
    fn trusted_case(
        incarnation: u32,
    ) -> (
        ReadQueue,
        super::super::RequestToken,
        ReadRoute,
        PreparedFrame,
        CompoundRequest,
    ) {
        let f = fixture();
        let request = write_request(&f);
        f.cell
            .peer_features()
            .record(primary(&f, &request), FEATURES);
        let preparer = Preparer::new(f.cell.clone(), incarnation);
        let (request, frame) = prepare(&preparer, request);
        let frame = frame.unwrap();
        let route = owner_route(&f.map, &request, f.map.epoch);
        let mut queue = ReadQueue::new(4, 1 << 20, incarnation).unwrap();
        let token = queue.submit_compound(request_clone(&request)).unwrap();
        queue.set_prepared(token, frame.clone()).unwrap();
        (queue, token, route, frame, request)
    }

    #[test]
    fn trusted_frame_builds_no_message_and_equals_the_slow_path_on_the_wire() {
        let (mut queue, token, route, frame, request) = trusted_case(7);
        let mut dispatch = queue.dispatch(token, route).unwrap();
        assert!(dispatch.prepared.is_some(), "trusted frame is kept");
        assert!(
            !dispatch.message.is_built(),
            "the trusted attempt builds no MOSDOp (no ops clone, no identity clones)"
        );
        assert_eq!(dispatch.reply_front_len(), frame.reply_front);
        // the slow path: the same request without a frame, built and encoded by the owner
        let mut slow_queue = ReadQueue::new(4, 1 << 20, 7).unwrap();
        let slow_token = slow_queue.submit_compound(request).unwrap();
        let slow = slow_queue.dispatch(slow_token, route).unwrap();
        assert!(slow.prepared.is_none() && slow.message.is_built());
        let kept = dispatch.prepared.take().unwrap();
        let fresh = slow
            .message
            .encode_parts_version(kept.version, route.features)
            .unwrap();
        assert_eq!(kept.segments, fresh.0, "wire bytes equal the slow path");
        assert_eq!(
            kept.data_crc.of(&kept.segments.data),
            fresh.1.of(&fresh.0.data)
        );
        assert_eq!(
            kept.pausing,
            crate::pausing_flags(slow.message.flags, false)
        );
        assert_eq!(
            dispatch.reply_front_len().is_none(),
            slow.reply_front_len().is_none()
        );
        // first access builds exactly the slow path's message
        assert_eq!(dispatch.message, slow.message);
        assert!(dispatch.message.is_built());
    }

    #[test]
    fn frame_is_dropped_on_other_incarnation_changed_flags_or_retry() {
        // another client incarnation than the frame was built for
        let (mut queue, token, route, frame, request) = trusted_case(7);
        let mut other = ReadQueue::new(4, 1 << 20, 8).unwrap();
        let t = other.submit_compound(request_clone(&request)).unwrap();
        other.set_prepared(t, frame.clone()).unwrap();
        let d = other.dispatch(t, route).unwrap();
        assert!(d.prepared.is_none() && d.message.is_built(), "incarnation");
        // wire flags changed since preparation (a redirect or primary fallback adds flags)
        queue.slots[token.slot].as_mut().unwrap().redirect_flags = flag::REDIRECTED;
        let d = queue.dispatch(token, route).unwrap();
        assert!(d.prepared.is_none() && d.message.is_built(), "flags");
        // a later attempt never sends the first attempt's frame
        let (mut queue, token, route, frame, _) = trusted_case(7);
        queue.dispatch(token, route).unwrap();
        let p = queue.slots[token.slot].as_mut().unwrap();
        p.route = None;
        p.prepared = Some(frame);
        let d = queue.dispatch(token, route).unwrap();
        assert!(d.prepared.is_none(), "retry");
        assert_eq!(d.message.retry_attempt, 1);
    }

    fn request_clone(request: &CompoundRequest) -> CompoundRequest {
        CompoundRequest {
            target: request.target.clone(),
            access: request.access,
            context: request.context.clone(),
            operations: request.operations.clone(),
            max_output_bytes: request.max_output_bytes,
        }
    }

    #[test]
    fn replica_read_policy_and_pg_operations_take_the_owner_path() {
        let f = fixture();
        let probe = write_request(&f);
        f.cell.peer_features().record(primary(&f, &probe), FEATURES);
        let preparer = Preparer::new(f.cell.clone(), 0);
        let mut balanced = request(f.pool, OsdOp::read(0, 8), Access::Read);
        balanced.context.read_policy = crate::ReplicaReadPolicy::Balance;
        assert!(prepare(&preparer, balanced).1.is_none());
        let listing = request(f.pool, OsdOp::new(opwire::op::PGNLS), Access::Read);
        assert!(prepare(&preparer, listing).1.is_none());
        let plain = request(f.pool, OsdOp::read(0, 8), Access::Read);
        assert!(prepare(&preparer, plain).1.is_some());
    }
}
