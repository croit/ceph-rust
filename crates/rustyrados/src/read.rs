// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::{CompoundRequest, ControlOperation, ControlRequest, RejectedCompound, RejectedControl};
use bytes::Bytes;
use denc::types::{OsdReqId, PgT, ShardId, SpgT};
use opwire::{Extent, MOSDOpReply, MOSDOpStorage, OsdOp, flag, op};
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "request_identity.rs"]
mod identity;
use identity::IdentityField;
pub use identity::RequestIdentity;
#[path = "prepared.rs"]
mod prepared;
pub use prepared::{FrameKey, PeerFeatures, Prepared, PreparedFrame, Preparer};

static NEXT_QUEUE: AtomicU64 = AtomicU64::new(1);

/// Binary target context captured at submission. No mutable ioctx selectors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub pool: i64,
    pub object: Vec<u8>,
    pub namespace: Vec<u8>,
    pub locator: Vec<u8>,
}

/// HEAD read with a bounded positive length. Zero (wire: to EOF) is rejected.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub target: Target,
    pub offset: u64,
    pub length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOperation {
    Write { offset: u64 },
    WriteFull,
    Append,
}

/// Client-side grant of a source-pull PUT (adr 0665): how much the OSD pulls and
/// how it verifies it. The address and the READ-only rkey are the transport's
/// business (they exist only after the window was bound on the session's QP);
/// the caller owns the bytes and keeps them unchanged until the write completed
/// or was rejected.
#[cfg(feature = "source-pull")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourcePullSource {
    /// Bytes to read: the object write length of the request.
    pub length: u32,
    /// crc32c over exactly those bytes; `None` for device memory the client cannot hash.
    pub crc32c: Option<u32>,
    /// Identity of this grant, never reused while an attempt may be live.
    pub transaction: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct WriteRequest {
    pub target: Target,
    pub operation: WriteOperation,
    pub payload: Bytes,
}

#[derive(Debug)]
pub struct RejectedWrite {
    pub reason: AdmissionError,
    pub request: WriteRequest,
}

#[derive(Debug)]
enum Request {
    Read(ReadRequest),
    Write(WriteRequest),
    Compound(CompoundRequest),
    Control(crate::ContextualControlRequest),
    PgList(crate::PgListRequest),
    PgOp(crate::PgOpRequest),
}

/// Active owners contain an immutable request. An exclusively owned terminal
/// shell can be cleared and cached by its queue slot, never by a dispatch.
#[derive(Debug)]
struct RetainedRequest(Option<Request>);
impl RetainedRequest {
    fn request(&self) -> &Request {
        self.0.as_ref().expect("active request owner")
    }
}
impl std::ops::Deref for RetainedRequest {
    type Target = Request;
    fn deref(&self) -> &Request {
        self.request()
    }
}

impl Request {
    fn context(&self) -> Option<&crate::RequestContext> {
        match self {
            Self::Compound(c) => Some(&c.context),
            Self::Control(c) => Some(&c.context),
            _ => None,
        }
    }

    fn target(&self) -> &Target {
        match self {
            Self::Read(r) => &r.target,
            Self::Write(w) => &w.target,
            Self::Compound(c) => &c.target,
            Self::Control(c) => &c.target,
            Self::PgList(p) => &p.target,
            Self::PgOp(p) => &p.target,
        }
    }
    fn offset(&self) -> u64 {
        match self {
            Self::Read(r) => r.offset,
            Self::Write(w) => match w.operation {
                WriteOperation::Write { offset } => offset,
                _ => 0,
            },
            Self::Compound(_) => 0,
            Self::Control(_) => 0,
            Self::PgList(_) => 0,
            Self::PgOp(_) => 0,
        }
    }
    fn length(&self) -> u64 {
        match self {
            Self::Read(r) => u64::from(r.length),
            Self::Write(w) => w.payload.len() as u64,
            Self::Compound(c) => u64::from(c.max_output_bytes),
            Self::Control(c) => c.operation.max_output(),
            Self::PgList(p) => u64::from(p.max_output_bytes()),
            Self::PgOp(p) => u64::from(p.max_output_bytes()),
        }
    }
    fn reply_data_limit(&self) -> u64 {
        if matches!(self, Self::Write(_)) {
            0
        } else {
            self.length()
        }
    }
    fn is_write(&self) -> bool {
        matches!(self, Self::Write(_))
            || matches!(self, Self::Compound(c) if c.is_write())
            || matches!(self, Self::Control(c) if c.operation.writes())
    }
    fn wire_flags(&self) -> u32 {
        let read_api = matches!(self, Self::Compound(c) if c.context.read_op.is_some() || c.context.legacy_reply);
        let mut flags = if self.is_write() && !read_api {
            flag::WRITE | flag::RWORDERED
        } else {
            flag::READ
        };
        if matches!(self, Self::Compound(c) if c.access.reads() && c.context.write_op.is_none()) {
            flags |= flag::READ;
        }
        if matches!(self, Self::Control(c) if matches!(c.operation,
            ControlOperation::Register { .. } | ControlOperation::Reconnect { .. } | ControlOperation::Ping { .. }))
        {
            flags = flag::WRITE;
        }
        if matches!(self, Self::PgList(_) | Self::PgOp(_)) {
            flags |= flag::IGNORE_OVERLAY;
        }
        if matches!(self, Self::PgOp(p) if p.operation().op == op::SCRUBLS) {
            flags |= flag::PGOP;
        }
        flags
    }
    fn code(&self) -> u16 {
        match self {
            Self::Read(_) => op::READ,
            Self::Write(w) => match w.operation {
                WriteOperation::Write { .. } => op::WRITE,
                WriteOperation::WriteFull => op::WRITEFULL,
                WriteOperation::Append => op::APPEND,
            },
            Self::PgList(p) => p.code(),
            Self::PgOp(p) => p.operation().op,
            Self::Compound(_) => unreachable!("compound uses its own operation vector"),
            Self::Control(c) => match c.operation {
                ControlOperation::Notify { .. } => op::NOTIFY,
                ControlOperation::NotifyAck { .. } => op::NOTIFY_ACK,
                _ => op::WATCH,
            },
        }
    }
    fn wire_op(&self) -> OsdOp {
        if let Self::PgList(p) = self {
            return p.wire_op();
        }
        if let Self::PgOp(p) = self {
            return p.wire_op();
        }
        if let Self::Control(c) = self {
            return c.operation.wire_op();
        }
        let mut operation = OsdOp::new(self.code());
        operation.set_extent(Extent {
            offset: self.offset(),
            length: self.length(),
            ..Default::default()
        });
        if let Self::Write(w) = self {
            operation.indata = w.payload.clone();
        }
        operation
    }

    fn charge(&self) -> Option<u64> {
        match self {
            Self::Compound(c) => c.charge(),
            Self::PgList(p) => p.charge(),
            Self::PgOp(p) => p.charge(),
            Self::Control(c) => c.charge(),
            _ => Some(self.length()),
        }
    }

    fn logical_charge(&self) -> Result<u64, AdmissionError> {
        match self {
            Self::Compound(c) => c.logical_byte_charge(),
            Self::PgList(_) | Self::Control(_) => Ok(0),
            Self::PgOp(p) => crate::admission::logical_operation_bytes(p.operation()),
            _ => Ok(self.length()),
        }
    }
}

/// Queue-local observer identity. TID is allocated once and never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestToken {
    queue: u64,
    slot: usize,
    tid: u64,
}

impl RequestToken {
    pub fn tid(self) -> u64 {
        self.tid
    }
    /// The queue slot that holds the request: [`slot_of_tid`] of its tid.
    pub fn slot(self) -> usize {
        self.slot
    }
}

/// Bits of a tid that name the queue slot of its request (the low bits). A tid is `(sequence << TID_SLOT_BITS) |
/// slot`: the slot is the table index of the in-flight request and the sequence is the generation that makes the tid
/// unique per client identity and never reused, so a reply, a cancel or a flush finds its request by indexing, with no
/// tid map. The sequence grows with every allocation, so tid order is allocation order.
pub const TID_SLOT_BITS: u32 = 20;
/// Most slots one queue can hold (the slot field of a tid).
pub const MAX_QUEUE_SLOTS: usize = 1 << TID_SLOT_BITS;
const TID_SLOT_MASK: u64 = (1 << TID_SLOT_BITS) - 1;

/// Queue slot named by a tid allocated by a [`ReadQueue`].
pub fn slot_of_tid(tid: u64) -> usize {
    (tid & TID_SLOT_MASK) as usize
}

/// Allocation sequence of a tid; `sequence % owners` names the allocating owner of a partitioned client
/// ([`ReadQueue::partition_tids`]).
pub fn sequence_of_tid(tid: u64) -> u64 {
    tid >> TID_SLOT_BITS
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    InvalidTarget,
    InvalidExtent,
    NoCredit,
    IdentityExhausted,
    InvalidOperation,
    UnsupportedOperation,
    InvalidSnapshot,
}

/// Returned intact on rejection, before any outbound operation exists.
#[derive(Debug)]
pub struct RejectedRead {
    pub reason: AdmissionError,
    pub request: ReadRequest,
}

/// Compact terminal READ metadata moved from one already decoded reply.
/// The payload remains in the registered destination; conversion moves the
/// object name and drops unrelated wire fields without copying read bytes.
#[cfg(feature = "registered-memory")]
#[derive(Debug)]
pub struct PlacedReadReply {
    pub oid: Vec<u8>,
    pub pgid: PgT,
    pub flags: u64,
    pub result: i32,
    pub retry_attempt: i32,
    pub user_version: u64,
    pub op: u16,
    pub op_flags: u32,
    pub op_result: i32,
    pub offset: u64,
    pub length: u64,
}

#[cfg(feature = "registered-memory")]
impl TryFrom<MOSDOpReply> for PlacedReadReply {
    type Error = MOSDOpReply;

    fn try_from(mut reply: MOSDOpReply) -> Result<Self, Self::Error> {
        if reply.redirect.is_some() || reply.ops.len() != 1 || !reply.ops[0].outdata.is_empty() {
            return Err(reply);
        }
        let op = reply.ops.pop().expect("checked one operation");
        let extent = op.extent();
        Ok(Self {
            oid: reply.oid,
            pgid: reply.pgid,
            flags: reply.flags,
            result: reply.result,
            retry_attempt: reply.retry_attempt,
            user_version: reply.user_version,
            op: op.op,
            op_flags: op.flags,
            op_result: op.rval,
            offset: extent.offset,
            length: extent.length,
        })
    }
}

/// Pool-kind proof supplied by placement; shard ids retain missing EC slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolRoute {
    Replicated,
    Erasure(ShardId),
}
impl PoolRoute {
    pub fn shard(self) -> ShardId {
        match self {
            Self::Replicated => ShardId::NO_SHARD,
            Self::Erasure(shard) => shard,
        }
    }
    pub fn valid(self) -> bool {
        matches!(self, Self::Replicated) || self.shard().0 >= 0
    }
}

/// Supplied by the map/session driver, not inferred by the request engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadRoute {
    /// Captured request pool before selecting a read/write overlay.
    pub base_pool: i64,
    /// EC data-shard mode, independent of pool kind and primary identity.
    pub direct_read: bool,
    pub osd: i32,
    pub session: u64,
    pub pg: PgT,
    pub hash: u32,
    pub epoch: u32,
    pub features: u64,
    pub generation: u64,
    pub pool: PoolRoute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverError {
    Overflow,
    Stale,
    AlreadyDispatched,
    InvalidRoute,
    InvalidReply,
    NotDispatched,
    RetryExhausted,
    UnsupportedRetry,
    FenceBusy,
    IdentityExhausted,
    DeadlineAlreadySet,
    DeadlineRequired,
    BackedOff,
    /// A request moved between queues must be an ordinary compound request that nothing else references.
    NotMovable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyAction {
    Completed,
    AwaitDurable,
    Recover,
    /// Redirect consumed; route is invalidated and the replacement wire identity is allocated.
    Redirected {
        wire_tid: u64,
    },
}

/// Permanent local request rejection, distinct from transient credit or remote errno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalRequestError {
    FrameLimit,
    OutputLimit,
    ReplyLimit,
    PoolIo,
    NoPool,
    /// The server answered this request with a reply that does not fit it (operation count, codes, object or PG).
    /// Only this request fails; the session and the client keep running.
    InvalidReply,
    /// The request cannot be expressed in the wire format of its session (encoding refused it); only it fails.
    Unencodable,
    /// A registered destination could not be safely returned after provider or QP failure.
    #[cfg(feature = "registered-memory")]
    Placement,
    /// The routed session does not support registered placement.
    #[cfg(feature = "registered-memory")]
    PlacementUnavailable,
    /// The routed session did not negotiate source-pull (or the record does not
    /// fit it): the write must be sent inline instead.
    #[cfg(feature = "source-pull")]
    SourcePullUnavailable,
}
impl LocalRequestError {
    pub fn errno(self) -> i32 {
        match self {
            Self::FrameLimit | Self::OutputLimit | Self::ReplyLimit => -7,
            Self::PoolIo | Self::InvalidReply => -5,
            #[cfg(feature = "registered-memory")]
            Self::Placement => -5,
            #[cfg(feature = "registered-memory")]
            Self::PlacementUnavailable => -95,
            #[cfg(feature = "source-pull")]
            Self::SourcePullUnavailable => -95,
            Self::Unencodable => -22,
            Self::NoPool => -2,
        }
    }
}

/// Publication provenance, independent of server status and application op flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadPublication {
    /// Ordinary reply/destination demux: retain per-operation error publication.
    Reply,
    /// Verified EC collector completion. A negative result publishes no parent
    /// outputs; successful aggregate buffers contain only READ/SPARSE_READ data.
    /// Version publication is terminal, never an early child-side update. This
    /// coherent policy deliberately does not reproduce partial updates on failure
    /// (ADR0256); the reference child's version remains the terminal version.
    EcSplit,
    /// Validated reply exceeded the local output limit: no operation outputs.
    OutputLimit,
}

/// Request outcomes distinguish local rejection, transport uncertainty and server errno.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// Structurally valid dynamic output exceeded a local cap not sent to the OSD.
    /// No output published; remote scalar result/version remain known.
    ReplyTooLarge {
        result: i32,
        user_version: u64,
        bytes: u64,
        limit: u32,
    },
    LocalRejected {
        error: LocalRequestError,
        possibly_sent: bool,
    },
    Remote {
        result: i32,
        op_result: i32,
        user_version: u64,
        data: Bytes,
    },
    /// A native registered READ completed into its exclusive destination.
    /// No payload bytes are copied into this logical completion.
    #[cfg(feature = "registered-memory")]
    RemotePlaced {
        result: i32,
        op_result: i32,
        user_version: u64,
        initialized: usize,
        /// The receipt matched the destination bytes on the host. False for a device-memory (GPU) destination:
        /// the caller fences and reads it on the device instead.
        verified: bool,
    },
    RemotePgList {
        result: i32,
        op_result: i32,
        user_version: u64,
        map_epoch: u32,
        page: Option<crate::PgListPage>,
        error_data: Bytes,
    },
    ListingTooLarge {
        bytes: u64,
    },
    ListingChanged {
        pg_num: Option<u32>,
    },
    RemoteCompound {
        publication: ReadPublication,
        result: i32,
        user_version: u64,
        replay_version: denc::types::Eversion,
        operations: Vec<OsdOp>,
    },
    CanceledUnsent,
    PossiblySent,
    Deadline {
        possibly_sent: bool,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReadCompletion {
    pub token: RequestToken,
    pub outcome: ReadOutcome,
    #[cfg(feature = "registered-memory")]
    pub read_into: Option<crate::ReadIntoResult>,
}

impl ReadCompletion {
    pub fn new(token: RequestToken, outcome: ReadOutcome) -> Self {
        Self {
            token,
            outcome,
            #[cfg(feature = "registered-memory")]
            read_into: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FenceToken {
    queue: u64,
    through: u64,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteFailure {
    Remote { result: i32, op_result: i32 },
    Unsent,
    PossiblySent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceStatus {
    Pending,
    Ready(Result<(), (u64, WriteFailure)>),
}

/// Message handed to the connection driver. Header TID must be `wire_tid()`.
#[derive(Clone, Debug)]
pub struct ReadDispatch {
    pub token: RequestToken,
    pub route: ReadRoute,
    /// The attempt's MOSDOp; built on first use when the attempt carries a trusted prepared frame.
    pub message: DispatchMessage,
    /// The READ-only client grant this write pulls from (adr 0665); the
    /// transport turns it into the 48-byte middle record of this attempt.
    #[cfg(feature = "source-pull")]
    pub source_pull: Option<SourcePullSource>,
    reply_data_limit: u64,
    wire_tid: u64,
    read_version_required: bool,
    may_write: bool,
    split_child: bool,
    /// Caller-encoded frame of this attempt, present only when it matches the attempt exactly ([`FrameKey`]).
    pub prepared: Option<PreparedFrame>,
}

/// The MOSDOp of one dispatch attempt. Built eagerly by the owner's slow path; a dispatch that carries a trusted
/// [`PreparedFrame`] defers it (the frame has everything the owner needs to send), and the first access builds it
/// from the retained request exactly as the slow path would have. Dereferences to the message.
#[derive(Clone, Debug)]
pub struct DispatchMessage {
    built: std::sync::OnceLock<MOSDOpStorage<RequestIdentity>>,
    source: Option<(Arc<RetainedRequest>, MessageInputs)>,
}

impl DispatchMessage {
    fn built(message: MOSDOpStorage<RequestIdentity>) -> Self {
        Self {
            built: message.into(),
            source: None,
        }
    }
    fn deferred(request: Arc<RetainedRequest>, inputs: MessageInputs) -> Self {
        Self {
            built: Default::default(),
            source: Some((request, inputs)),
        }
    }
    /// The message exists (it was built or never deferred).
    pub fn is_built(&self) -> bool {
        self.built.get().is_some()
    }
    fn build(&self) -> MOSDOpStorage<RequestIdentity> {
        let (request, inputs) = self
            .source
            .as_ref()
            .expect("an unbuilt message keeps its source");
        build_message(request.as_ref().request(), inputs, |field| {
            RequestIdentity::request(request, field)
        })
    }
}

impl PartialEq for DispatchMessage {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl PartialEq<MOSDOpStorage<RequestIdentity>> for DispatchMessage {
    fn eq(&self, other: &MOSDOpStorage<RequestIdentity>) -> bool {
        **self == *other
    }
}

impl std::ops::Deref for DispatchMessage {
    type Target = MOSDOpStorage<RequestIdentity>;
    fn deref(&self) -> &Self::Target {
        self.built.get_or_init(|| self.build())
    }
}

impl std::ops::DerefMut for DispatchMessage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        if self.built.get().is_none() {
            let message = self.build();
            self.built = message.into();
        }
        self.built.get_mut().expect("built above")
    }
}

impl ReadDispatch {
    /// Current messenger identity; logical token ownership survives redirects.
    pub fn wire_tid(&self) -> u64 {
        self.wire_tid
    }
    pub fn read_routing(&self) -> crate::ReadRouting<'_> {
        crate::ReadRouting {
            operations: crate::ReadOperations::Compound(&self.message.ops),
            snapid: self.message.snapid,
            empty_write_context: self.message.snap_seq == 0 && self.message.snaps.is_empty(),
            version_required: self.read_version_required,
            may_write: self.may_write,
        }
    }
    /// Front length of the reply this attempt provokes, `None` when it overflows. A trusted prepared frame carries
    /// it, so no message is built to answer.
    pub fn reply_front_len(&self) -> Option<usize> {
        match &self.prepared {
            Some(frame) => frame.reply_front,
            None => MOSDOpReply::normal_front_len(self.message.oid.len(), self.message.ops.len()),
        }
    }
    pub fn is_split_child(&self) -> bool {
        self.split_child
    }
    pub(crate) fn split_dispatch(
        &self,
        route: ReadRoute,
        wire_tid: u64,
        operations: Vec<OsdOp>,
        version_required: bool,
        metadata_bytes: u64,
    ) -> Result<Self, DriverError> {
        let parent = &self.message;
        let message = MOSDOpStorage {
            ingress: parent.ingress.clone(),
            source_pull: None,
            source_pull_error: None,
            // Split children are ordinary EC reads, never the single plain READ
            // candidate whose server attempt owns a placement descriptor.
            placement_read: None,
            pgid: SpgT {
                pgid: parent.pgid.pgid,
                shard: route.pool.shard(),
            },
            hash: parent.hash,
            osdmap_epoch: route.epoch,
            flags: (parent.flags & !(flag::BALANCE_READS | flag::RETRY))
                | flag::EC_DIRECT_READ
                | flag::FORCE_OSD
                | flag::FAIL_ON_EAGAIN,
            reqid: parent.reqid,
            reassert_version: parent.reassert_version,
            trace: parent.trace,
            otel: parent.otel,
            client_inc: parent.client_inc,
            mtime: parent.mtime,
            oloc: parent.oloc.clone(),
            oid: parent.oid.clone(),
            ops: operations,
            snapid: parent.snapid,
            snap_seq: parent.snap_seq,
            snaps: parent.snaps.clone(),
            retry_attempt: 0,
            features: route.features,
            refused_data: 0,
            trailing_data_len: 0,
        };
        Ok(Self {
            token: self.token,
            route,
            message: DispatchMessage::built(message),
            reply_data_limit: self
                .reply_data_limit
                .checked_add(metadata_bytes)
                .ok_or(DriverError::InvalidRoute)?,
            wire_tid,
            read_version_required: version_required,
            may_write: false,
            split_child: true,
            prepared: None,
            // A split child is a READ fragment: it never carries a PUT grant.
            #[cfg(feature = "source-pull")]
            source_pull: None,
        })
    }
    /// Declared operation reply-data bound, independent of outgoing write bytes.
    pub fn max_reply_data(&self) -> u64 {
        self.reply_data_limit
    }
}
#[derive(Debug)]
struct Pending {
    #[cfg(feature = "registered-memory")]
    read_into: Option<crate::read_into::ReadIntoPending>,
    reserved_control: bool,
    token: RequestToken,
    wire_tid: u64,
    redirect_flags: u32,
    fallback_primary: bool,
    renew_wire_tid: bool,
    request: Arc<RetainedRequest>,
    /// Grant of a source-pull PUT; `None` sends the write inline.
    #[cfg(feature = "source-pull")]
    source_pull: Option<SourcePullSource>,
    charge: u64,
    route: Option<ReadRoute>,
    attempts: u32,
    full_policy: crate::FullPolicy,
    fail_on_eagain: bool,
    deadline: Option<u64>,
    limit_us: u64,
    terminal: bool,
    /// Frame the submitting thread encoded; the first dispatch consumes it and keeps it only on an exact match.
    prepared: Option<PreparedFrame>,
}

/// Route shape every dispatch accepts; request-kind specifics follow in [`ReadQueue::dispatch`].
fn route_shape_valid(pending: &Pending, route: ReadRoute) -> bool {
    route.pool.valid()
        && route.osd >= 0
        && route.session != 0
        && route.epoch != 0
        && route.base_pool == pending.request.target().pool
        && route.pg.pool <= i64::MAX as u64
        && (pending.request_flags() & flag::IGNORE_OVERLAY == 0
            || route.pg.pool == route.base_pool as u64)
}

impl Pending {
    fn request_flags(&self) -> u32 {
        request_flags(
            self.request.as_ref().request(),
            self.redirect_flags,
            self.full_policy,
            self.fail_on_eagain,
            self.fallback_primary,
        )
    }
}

/// The wire flags of a request before routing adds the attempt's own (ondisk, retry, direct read).
fn request_flags(
    request: &Request,
    redirect_flags: u32,
    full_policy: crate::FullPolicy,
    fail_on_eagain: bool,
    fallback_primary: bool,
) -> u32 {
    let context = request.context();
    let osd_flags = context.map_or(0, |c| c.osd_flags);
    let access = request.wire_flags();
    let read = access & flag::READ != 0 && access & flag::WRITE == 0;
    let mut flags = access
        | redirect_flags
        | osd_flags
        | full_policy.wire_flags()
        | if fail_on_eagain {
            flag::FAIL_ON_EAGAIN
        } else {
            0
        };
    if read {
        flags |= context.map_or(0, |c| c.read_policy.flags());
        if osd_flags & flag::RWORDERED != 0
            || context.is_some_and(|c| c.mask_replica_reads)
            || matches!(request, Request::Control(_))
        {
            flags &= !(flag::BALANCE_READS | flag::LOCALIZE_READS);
        }
    }
    if fallback_primary {
        flags &=
            !(flag::BALANCE_READS | flag::LOCALIZE_READS | flag::EC_DIRECT_READ | flag::FORCE_OSD);
    }
    flags
}

/// Everything besides the request itself that an attempt's MOSDOp carries.
#[derive(Clone, Debug)]
struct MessageInputs {
    pgid: SpgT,
    hash: u32,
    epoch: u32,
    pool: i64,
    features: u64,
    incarnation: u32,
    attempts: u32,
    direct_read: bool,
    base_flags: u32,
}

/// The MOSDOp of one attempt of `request`; shared by the owner's dispatch and the caller-side preparation so both
/// build the same message. `identity` yields the object, namespace and locator bytes.
fn build_message<B: AsRef<[u8]> + Default>(
    request: &Request,
    i: &MessageInputs,
    identity: impl Fn(IdentityField) -> B,
) -> MOSDOpStorage<B> {
    let mut message = MOSDOpStorage {
        source_pull: None,
        source_pull_error: None,
        pgid: i.pgid,
        hash: i.hash,
        osdmap_epoch: i.epoch,
        flags: i.base_flags
            | if i.direct_read {
                flag::EC_DIRECT_READ | flag::FORCE_OSD
            } else {
                0
            }
            | flag::ONDISK
            | flag::SUPPORTSPOOLEIO
            | flag::KNOWN_REDIR
            | if i.attempts > 0 { flag::RETRY } else { 0 },
        reqid: OsdReqId {
            inc: i.incarnation as i32,
            ..Default::default()
        },
        client_inc: i.incarnation,
        oloc: denc::types::ObjectLocatorStorage {
            pool: i.pool,
            key: identity(IdentityField::Locator),
            nspace: identity(IdentityField::Namespace),
            hash: -1,
        },
        oid: identity(IdentityField::Object),
        ops: match request {
            Request::Compound(c) => c.operations.clone(),
            Request::Control(c) if c.context.control_assert_version != 0 => vec![
                OsdOp::assert_version(c.context.control_assert_version),
                c.operation.wire_op(),
            ],
            _ => vec![request.wire_op()],
        },
        features: i.features,
        retry_attempt: i.attempts as i32,
        ..Default::default()
    };
    if let Request::Compound(c) = request {
        // Legacy C exec/read/write modes omit RETURNVEC so the server
        // suppresses mutation output/status; native default keeps the
        // vector reply.
        if !c.context.legacy_reply
            && c.context.write_op != Some(crate::WriteOpReply::Legacy)
            && c.context.read_op != Some(crate::ReadOpReply::Legacy)
        {
            message.flags |= flag::RETURNVEC;
        }
    }
    if let Some(context) = request.context() {
        message.snapid = context.snapid;
        message.snap_seq = context.snap_sequence;
        message.snaps = context.snapshots.clone();
        message.mtime = context.mtime;
    }
    if let Request::PgList(r) = request {
        message.ops[0].set_pgls(opwire::Pgls {
            count: r.max_entries() as u64,
            start_epoch: i.epoch,
        });
    }
    message
}

#[cfg(test)]
mod request_flag_tests {
    use super::*;
    use crate::{Access, CompoundRequest, ListNamespace, PgListRequest, RequestContext};
    use denc::types::Hobject;

    /// A source-pull PUT names a READ-only window: its wire op carries the object
    /// offset only (no inline bytes), its context (mtime, self-managed snap context)
    /// travels like any write, and only a well-formed grant is accepted.
    #[cfg(feature = "source-pull")]
    #[test]
    fn source_pull_write_carries_no_inline_bytes_and_needs_a_well_formed_grant() {
        let write = |op: OsdOp| CompoundRequest {
            target: Target {
                pool: 7,
                object: b"pulled".to_vec(),
                namespace: vec![],
                locator: vec![],
            },
            access: Access::Write,
            context: RequestContext {
                mtime: denc::types::UTime::new(1_700_000_000, 5),
                snap_sequence: 9,
                snapshots: vec![9, 4],
                write_op: Some(crate::WriteOpReply::Legacy),
                ..Default::default()
            },
            operations: vec![op],
            max_output_bytes: 0,
        };
        let source = SourcePullSource {
            length: 1 << 20,
            crc32c: Some(0xdead_beef),
            transaction: 11,
        };
        let mut queue = ReadQueue::with_retry_limit(1, 4096, 9, 4).unwrap();
        let token = queue
            .submit_write_from_source(write(OsdOp::write_bytes(4096, Bytes::new())), source)
            .unwrap();
        assert_eq!(
            queue.slots[token.slot].as_ref().unwrap().source_pull,
            Some(source)
        );
        let flags = queue.slots[token.slot].as_ref().unwrap().request_flags();
        assert_eq!(
            flags & (flag::WRITE | flag::RWORDERED),
            flag::WRITE | flag::RWORDERED
        );
        let route = ReadRoute {
            direct_read: false,
            base_pool: 7,
            osd: 0,
            session: 1,
            pg: PgT { pool: 7, seed: 3 },
            hash: 3,
            epoch: 1,
            features: 0,
            generation: 1,
            pool: crate::PoolRoute::Replicated,
        };
        let dispatch = queue.dispatch(token, route).unwrap();
        let message = &dispatch.message;
        assert!(message.source_pull_write_eligible());
        assert_eq!(message.ops[0].extent().offset, 4096);
        assert_eq!(
            message.ops[0].extent().length,
            0,
            "the descriptor carries the length"
        );
        assert_eq!(message.mtime, denc::types::UTime::new(1_700_000_000, 5));
        assert_eq!(
            (message.snap_seq, message.snaps.as_slice()),
            (9, &[9, 4][..])
        );
        assert_eq!(dispatch.source_pull, Some(source));
        // Inline bytes, another op, a malformed grant are refused before admission.
        for (request, wrong) in [
            (
                write(OsdOp::write_bytes(0, Bytes::from_static(b"inline"))),
                source,
            ),
            (write(OsdOp::writefull_bytes(Bytes::new())), source),
            (
                write(OsdOp::write_bytes(0, Bytes::new())),
                SourcePullSource {
                    length: 0,
                    ..source
                },
            ),
            (
                write(OsdOp::write_bytes(0, Bytes::new())),
                SourcePullSource {
                    transaction: 0,
                    ..source
                },
            ),
        ] {
            assert!(queue.submit_write_from_source(request, wrong).is_err());
        }
    }

    #[test]
    fn exclusive_request_shell_clears_payload_and_reuses_only_after_last_view() {
        struct Payload(Arc<std::sync::atomic::AtomicUsize>);
        impl AsRef<[u8]> for Payload {
            fn as_ref(&self) -> &[u8] {
                b"data"
            }
        }
        impl Drop for Payload {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let released = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let target = || Target {
            pool: 7,
            object: b"source".to_vec(),
            namespace: vec![],
            locator: vec![],
        };
        let mut queue = ReadQueue::with_retry_limit(1, 4096, 9, 4).unwrap();
        let write = queue
            .submit_write(WriteRequest {
                target: target(),
                operation: WriteOperation::WriteFull,
                payload: Bytes::from_owner(Payload(Arc::clone(&released))),
            })
            .unwrap();
        let owner = Arc::as_ptr(&queue.slots[write.slot].as_ref().unwrap().request);
        queue.cancel(write).unwrap();
        assert_eq!(queue.poll_into(&mut [None]), 1);
        assert_eq!(
            released.load(Ordering::SeqCst),
            1,
            "cache must not retain payloads"
        );
        let cached = queue.request_cache[write.slot].as_ref().unwrap();
        assert!(cached.0.is_none());
        assert_eq!(Arc::as_ptr(cached), owner);
        let next = queue
            .submit(ReadRequest {
                target: target(),
                offset: 0,
                length: 1,
            })
            .unwrap();
        let active = &queue.slots[next.slot].as_ref().unwrap().request;
        assert_eq!(Arc::as_ptr(active), owner);
        let retained = RequestIdentity::request(active, IdentityField::Object);
        queue.cancel(next).unwrap();
        assert_eq!(queue.poll_into(&mut [None]), 1);
        assert!(
            queue.request_cache[next.slot].is_none(),
            "live views must never enter the cache"
        );
        let replacement = queue
            .submit(ReadRequest {
                target: Target {
                    object: b"replacement".to_vec(),
                    ..target()
                },
                offset: 0,
                length: 1,
            })
            .unwrap();
        assert_ne!(
            Arc::as_ptr(&queue.slots[replacement.slot].as_ref().unwrap().request),
            owner
        );
        drop(queue);
        assert_eq!(retained, b"source");
    }

    #[test]
    fn compatible_control_growth_preserves_application_credit_and_deadline_ownership() {
        let mut strict = ReadQueue::with_control_reserve(1, 4096, 1, 1, 1, 1).unwrap();
        assert_eq!(
            strict.enable_compatible_control_growth(),
            Err(AdmissionError::UnsupportedOperation)
        );
        assert_eq!(
            strict.grow_compatible_control_reserve(),
            Err(AdmissionError::UnsupportedOperation)
        );
        let mut queue = ReadQueue::with_compatible_control_reserve(1, 0, 0, 1, 1, 1, 1).unwrap();
        let application = || CompoundRequest {
            target: Target {
                pool: 7,
                object: b"ordinary".to_vec(),
                namespace: vec![],
                locator: vec![],
            },
            access: Access::Read,
            context: Default::default(),
            operations: vec![OsdOp::read(0, 1)],
            max_output_bytes: 1,
        };
        let control = |cookie| ControlRequest {
            target: Target {
                pool: 7,
                object: vec![1; 64],
                namespace: vec![],
                locator: vec![],
            },
            operation: crate::ControlOperation::Register {
                cookie,
                timeout_seconds: 0,
            },
        };
        assert_eq!(
            queue
                .submit_reserved_control(control(1))
                .unwrap_err()
                .reason,
            AdmissionError::NoCredit
        );
        queue.enable_compatible_control_growth().unwrap();
        let app = queue.submit_compound(application()).unwrap();
        let mut tokens = Vec::new();
        for n in 0..8 {
            if queue.reserved_control_outstanding() == queue.reserved_control_capacity() {
                queue.grow_compatible_control_reserve().unwrap();
            }
            let token = queue.submit_reserved_control(control(n + 1)).unwrap();
            queue.set_deadline_us(token, 10 + n, 10 + n).unwrap();
            tokens.push(token);
            assert_eq!(
                queue.submit_compound(application()).unwrap_err().reason,
                AdmissionError::NoCredit
            );
        }
        assert_eq!(queue.reserved_control_capacity(), 8);
        assert_eq!(queue.reserved_control_outstanding(), 8);
        assert!(queue.reserved_control_bytes() > 1);
        for (n, token) in tokens.into_iter().enumerate() {
            assert_eq!(queue.next_deadline_us(), Some(10 + n as u64));
            queue.cancel(token).unwrap();
            assert_eq!(queue.take_reserved_completion(token).unwrap().token, token);
        }
        assert_eq!(queue.next_deadline_us(), None);
        assert_eq!(queue.reserved_control_outstanding(), 0);
        assert_eq!(queue.reserved_control_bytes(), 0);
        assert_eq!(queue.outstanding(), 1);
        queue.cancel(app).unwrap();
        assert_eq!(queue.poll_into(&mut [None]), 1);
        assert_eq!(queue.outstanding(), 0);
        queue.submit_compound(application()).unwrap();
        assert_eq!(
            queue.submit_compound(application()).unwrap_err().reason,
            AdmissionError::NoCredit
        );
    }

    #[test]
    fn wide_deadlines_and_unlimited_preserve_retry_enrollment_without_spurious_timers() {
        let end = crate::time::deadline_after(5, 1u64 << 32).unwrap();
        for deadline in [end, crate::time::NO_DEADLINE] {
            let mut queue = ReadQueue::with_retry_limit(1, 4096, 1, 3).unwrap();
            let token = queue
                .submit_compound(CompoundRequest {
                    target: Target {
                        pool: 7,
                        object: b"wide".to_vec(),
                        namespace: vec![],
                        locator: vec![],
                    },
                    access: Access::Read,
                    context: Default::default(),
                    operations: vec![OsdOp::read(0, 1)],
                    max_output_bytes: 1,
                })
                .unwrap();
            assert_eq!(
                queue.set_deadline_us(
                    token,
                    crate::time::MAX_TIME_US + 1,
                    crate::time::MAX_TIME_US + 1
                ),
                Err(DriverError::Overflow)
            );
            assert_eq!(queue.deadline_us(token), None);
            queue.set_deadline_us(token, deadline, deadline).unwrap();
            let route = ReadRoute {
                direct_read: false,
                base_pool: 7,
                osd: 0,
                session: 1,
                pg: PgT { pool: 7, seed: 3 },
                hash: 3,
                epoch: 1,
                features: 0,
                generation: 1,
                pool: crate::PoolRoute::Replicated,
            };
            queue.dispatch(token, route).unwrap();
            queue.retry(token).unwrap();
            assert_eq!(queue.deadline_us(token), Some(deadline));
            queue.dispatch(token, route).unwrap();
            if deadline == crate::time::NO_DEADLINE {
                assert_eq!(queue.next_deadline_us(), None);
                assert_eq!(queue.expire_us(crate::time::MAX_TIME_US, 1), 0);
                assert!(!queue.expire_token_us(token, u64::MAX).unwrap());
                queue.cancel(token).unwrap();
            } else {
                assert_eq!(queue.next_deadline_us(), Some(end));
                assert_eq!(queue.expire_us(end - 1, 1), 0);
                assert_eq!(queue.expire_us(end, 1), 1);
                assert_eq!(queue.expire_us(end, 1), 0);
            }
            assert_eq!(queue.poll_into(&mut [None]), 1);
            assert_eq!(queue.poll_into(&mut [None]), 0);
        }
    }

    fn submit_one(queue: &mut ReadQueue) -> u64 {
        queue
            .submit_compound(CompoundRequest {
                target: Target {
                    pool: 1,
                    object: b"partition".to_vec(),
                    namespace: vec![],
                    locator: vec![],
                },
                access: Access::Write,
                context: RequestContext::default(),
                operations: vec![OsdOp::new(op::DELETE)],
                max_output_bytes: 0,
            })
            .unwrap()
            .tid()
    }

    #[test]
    fn tid_partition_gives_each_owner_its_residue_class() {
        let mut queues: Vec<_> = (0..3)
            .map(|index| {
                let mut queue = ReadQueue::new(16, 1 << 20, 1).unwrap();
                queue.partition_tids(index, 3).unwrap();
                queue
            })
            .collect();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..5 {
            for (index, queue) in queues.iter_mut().enumerate() {
                let tid = submit_one(queue);
                assert_eq!(sequence_of_tid(tid) % 3, index as u64);
                assert!(seen.insert(tid));
            }
        }
        assert_eq!(seen.len(), 15);
    }

    #[test]
    fn withdraw_returns_the_request_whole_and_frees_slot_and_credit() {
        let mut queue = ReadQueue::new(1, 1024, 1).unwrap();
        let before = queue.charged_bytes();
        let token = queue
            .submit_compound(CompoundRequest {
                target: Target {
                    pool: 1,
                    object: b"moves".to_vec(),
                    namespace: vec![],
                    locator: vec![],
                },
                access: Access::Write,
                context: RequestContext::default(),
                operations: vec![OsdOp::new(op::DELETE)],
                max_output_bytes: 0,
            })
            .unwrap();
        assert_ne!(queue.charged_bytes(), before);
        let wire = queue.wire_tid(token).unwrap();
        let request = queue.withdraw(token).unwrap();
        assert_eq!(request.target.object, b"moves");
        assert_eq!(request.operations.len(), 1);
        assert_eq!(queue.charged_bytes(), before, "the credit came back");
        assert!(!queue.is_pending(token));
        assert!(matches!(queue.withdraw(token), Err(DriverError::Stale)));
        // The single slot is free again: the same request is admitted again, under a new tid, and takes the wire
        // identity it had.
        let again = queue.submit_compound(request).unwrap();
        assert_ne!(again.tid(), token.tid());
        queue.adopt_wire_tid(again, wire).unwrap();
        assert_eq!(queue.wire_tid(again), Some(wire));
    }

    #[test]
    fn tid_partition_is_refused_after_allocation_or_with_bad_arguments() {
        let mut queue = ReadQueue::new(1, 1024, 1).unwrap();
        assert!(queue.partition_tids(3, 3).is_err());
        assert!(queue.partition_tids(0, 0).is_err());
        submit_one(&mut queue);
        assert!(queue.partition_tids(0, 2).is_err());
    }

    #[test]
    fn explicit_osd_request_flags_are_preserved_with_required_write_flags() {
        let mut queue = ReadQueue::new(1, 1024, 1).unwrap();
        let explicit = flag::FULL_FORCE | flag::LOCALIZE_READS;
        let token = queue
            .submit_compound(CompoundRequest {
                target: Target {
                    pool: 1,
                    object: b"remove-flags".to_vec(),
                    namespace: vec![],
                    locator: vec![],
                },
                access: Access::Write,
                context: RequestContext {
                    osd_flags: explicit,
                    ..Default::default()
                },
                operations: vec![OsdOp::new(op::DELETE)],
                max_output_bytes: 0,
            })
            .unwrap();
        assert_eq!(
            queue.request_flags(token),
            Some(flag::WRITE | flag::RWORDERED | explicit)
        );
    }

    #[test]
    fn pg_listing_ignores_overlay_without_setting_the_pg_operation_message_flag() {
        let mut queue = ReadQueue::new(1, 1024, 1).unwrap();
        let token = queue
            .submit_pg_list(PgListRequest::new(
                7,
                ListNamespace::All,
                3,
                8,
                Hobject::MIN(),
                1,
                64,
            ))
            .unwrap();
        let dispatch = queue
            .dispatch(
                token,
                ReadRoute {
                    direct_read: false,
                    base_pool: 7,
                    osd: 0,
                    session: 1,
                    pg: PgT { pool: 7, seed: 3 },
                    hash: 3,
                    epoch: 1,
                    features: 0,
                    generation: 1,
                    pool: crate::PoolRoute::Replicated,
                },
            )
            .unwrap();
        assert_eq!(dispatch.message.flags & flag::PGOP, 0);
        assert_ne!(dispatch.message.flags & flag::IGNORE_OVERLAY, 0);
    }

    #[test]
    fn pg_operation_keeps_hash_route_and_encoded_operation() {
        let mut queue = ReadQueue::new(1, 1024, 1).unwrap();
        let operation = OsdOp::pg_hitset_get(12, 34);
        let token = queue
            .submit_pg_operation(crate::PgOpRequest::by_hash(
                7,
                Vec::new(),
                0x1234,
                operation.clone(),
                256,
            ))
            .unwrap();
        let dispatch = queue
            .dispatch(
                token,
                ReadRoute {
                    direct_read: false,
                    base_pool: 7,
                    osd: 0,
                    session: 1,
                    pg: PgT { pool: 7, seed: 3 },
                    hash: 0x1234,
                    epoch: 1,
                    features: 0,
                    generation: 1,
                    pool: crate::PoolRoute::Replicated,
                },
            )
            .unwrap();
        assert_eq!(dispatch.message.ops, vec![operation]);
        assert_eq!(dispatch.message.flags & flag::PGOP, 0);
        assert_ne!(dispatch.message.flags & flag::IGNORE_OVERLAY, 0);
    }
}

/// Bounded single-owner experimental queue; !Send + !Sync by construction.
/// Slots remain charged until completion consumption. Caller-owned requests and returned
/// Bytes, plus transport/codec allocations, are outside this queue's credit accounting.
/// Explicit retries are opt-in and bounded; no automatic recovery or ordering promises.
#[derive(Debug)]
pub struct ReadQueue {
    id: u64,
    incarnation: u32,
    /// Sequence of the next allocated tid (the high bits, see [`TID_SLOT_BITS`]).
    next_seq: u64,
    /// Distance between two allocated sequences: the owner count of a sharded client, 1 otherwise.
    seq_stride: u64,
    retry_limit: u32,
    mutation_retries: bool,
    application_admission: crate::ByteAdmission,
    application_count_target: u64,
    accounting: RequestAccounting,
    control_slots: usize,
    elastic_controls: bool,
    control_byte_limit: u64,
    control_outstanding: usize,
    control_charged: u64,
    fence_through: u64,
    charged: u64,
    slots: Vec<Option<Pending>>,
    request_cache: Vec<Option<Arc<RetainedRequest>>>,
    free: Vec<usize>,
    completions: VecDeque<ReadCompletion>,
    /// A completion was published since the caller last asked ([`ReadQueue::take_published`]).
    published: bool,
    first_write_failure: Option<(u64, WriteFailure)>,
    fence_epoch: u64,
    deadlines: deadline::SlotIndex,
    _owner: PhantomData<Rc<()>>,
}

/// Shared lifecycle engine for native reads and owned data writes.
pub type ObjectQueue = ReadQueue;

#[derive(Debug, Clone, Copy)]
enum RequestAccounting {
    Retained,
    Logical,
}

impl ReadQueue {
    /// One queue per authenticated client identity in this prototype. Driver must preserve
    /// that identity/incarnation through all connections. No multi-queue identity sharing.
    pub fn new(capacity: usize, byte_limit: u64, incarnation: u32) -> Option<Self> {
        Self::with_retry_limit(capacity, byte_limit, incarnation, 1)
    }

    /// Total dispatches, including the first. Driver must additionally bound retry time
    /// and preserve authenticated identity; this queue does not perform automatic retries.
    pub fn with_retry_limit(
        capacity: usize,
        byte_limit: u64,
        incarnation: u32,
        total_attempts: u32,
    ) -> Option<Self> {
        Self::with_admission(
            capacity,
            crate::ByteAdmission::strict(byte_limit),
            RequestAccounting::Retained,
            incarnation,
            total_attempts,
        )
    }

    /// Opt-in logical application admission. Zero disables each named target;
    /// finite slots and all request/wire validation remain independent.
    /// This queue does not configure compatible sessions or receive allocation.
    /// Compound write snapshot-context semantics remain server-owned.
    pub fn with_compatible_admission(
        capacity: usize,
        byte_target: u64,
        count_target: u64,
        incarnation: u32,
        total_attempts: u32,
    ) -> Option<Self> {
        let mut queue = Self::with_admission(
            capacity,
            crate::ByteAdmission::compatible(byte_target),
            RequestAccounting::Logical,
            incarnation,
            total_attempts,
        )?;
        queue.application_count_target = count_target;
        Some(queue)
    }

    fn with_admission(
        capacity: usize,
        application_admission: crate::ByteAdmission,
        accounting: RequestAccounting,
        incarnation: u32,
        total_attempts: u32,
    ) -> Option<Self> {
        if capacity == 0
            || capacity > MAX_QUEUE_SLOTS
            || total_attempts == 0
            || total_attempts > i32::MAX as u32
        {
            return None;
        }
        let id = NEXT_QUEUE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .ok()?;
        let mut deadlines = deadline::SlotIndex::default();
        for slot in 0..capacity {
            deadlines.register(slot);
        }
        Some(Self {
            id,
            incarnation,
            next_seq: 1,
            seq_stride: 1,
            retry_limit: total_attempts,
            mutation_retries: false,
            application_admission,
            application_count_target: 0,
            accounting,
            control_slots: 0,
            elastic_controls: false,
            control_byte_limit: 0,
            control_outstanding: 0,
            control_charged: 0,
            fence_through: 0,
            charged: 0,
            slots: (0..capacity).map(|_| None).collect(),
            request_cache: (0..capacity).map(|_| None).collect(),
            free: (0..capacity).rev().collect(),
            completions: VecDeque::with_capacity(capacity),
            published: false,
            first_write_failure: None,
            fence_epoch: 0,
            deadlines,
            _owner: PhantomData,
        })
    }

    /// Independent bounded control credit, sharing the application's TID allocator.
    pub fn with_control_reserve(
        application_slots: usize,
        application_bytes: u64,
        control_slots: usize,
        control_bytes: u64,
        incarnation: u32,
        total_attempts: u32,
    ) -> Option<Self> {
        if application_slots == 0
            || application_bytes == 0
            || control_slots == 0
            || control_bytes == 0
        {
            return None;
        }
        let mut q = Self::with_retry_limit(
            application_slots.checked_add(control_slots)?,
            application_bytes.checked_add(control_bytes)?,
            incarnation,
            total_attempts,
        )?;
        q.control_slots = control_slots;
        q.control_byte_limit = control_bytes;
        q.application_admission = crate::ByteAdmission::strict(application_bytes);
        Some(q)
    }

    /// Logical application byte target with an independent strict control reserve.
    /// Rejected application requests remain caller-owned; retain/retry the same
    /// pending front to prevent later ordinary submissions starving oversize work.
    pub fn with_compatible_control_reserve(
        application_slots: usize,
        application_target: u64,
        count_target: u64,
        control_slots: usize,
        control_bytes: u64,
        incarnation: u32,
        total_attempts: u32,
    ) -> Option<Self> {
        if application_slots == 0 || control_slots == 0 || control_bytes == 0 {
            return None;
        }
        let mut q = Self::with_compatible_admission(
            application_slots.checked_add(control_slots)?,
            application_target,
            count_target,
            incarnation,
            total_attempts,
        )?;
        q.control_slots = control_slots;
        q.control_byte_limit = control_bytes;
        Some(q)
    }
    /// Enable demand growth of the compatible control reserve before use.
    /// Ordinary application eligibility and strict constructors stay unchanged.
    pub fn enable_compatible_control_growth(&mut self) -> Result<(), AdmissionError> {
        if !matches!(self.accounting, RequestAccounting::Logical) || self.control_slots == 0 {
            return Err(AdmissionError::UnsupportedOperation);
        }
        if self.outstanding() != 0 {
            return Err(AdmissionError::NoCredit);
        }
        self.elastic_controls = true;
        Ok(())
    }
    pub fn compatible_control_growth(&self) -> bool {
        self.elastic_controls
    }
    pub fn reserved_control_capacity(&self) -> usize {
        self.control_slots
    }
    /// Cold growth by one logical control slot, after coordinator reservation.
    /// Failure preserves all live tokens, deadlines, charges and slot counts.
    pub fn grow_compatible_control_reserve(&mut self) -> Result<(), AdmissionError> {
        if !self.elastic_controls {
            return Err(AdmissionError::UnsupportedOperation);
        }
        let slot = self.slots.len();
        let total = slot.checked_add(1).ok_or(AdmissionError::NoCredit)?;
        if total > MAX_QUEUE_SLOTS {
            return Err(AdmissionError::NoCredit);
        }
        self.slots
            .try_reserve(1)
            .map_err(|_| AdmissionError::NoCredit)?;
        // Later releases must fit too, without an allocation on completion.
        self.free
            .try_reserve(total - self.free.len())
            .map_err(|_| AdmissionError::NoCredit)?;
        self.request_cache
            .try_reserve(1)
            .map_err(|_| AdmissionError::NoCredit)?;
        self.deadlines.register(slot);
        self.slots.push(None);
        self.request_cache.push(None);
        self.free.push(slot);
        self.control_slots += 1;
        Ok(())
    }
    pub fn reserved_control_bytes(&self) -> u64 {
        self.control_charged
    }
    pub fn reserved_control_outstanding(&self) -> usize {
        self.control_outstanding
    }
    pub fn charged_bytes(&self) -> u64 {
        self.charged
    }
    pub fn outstanding(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    /// Opt into finite-history Ceph mutation dedup semantics, not exactly-once forever.
    /// Policy cannot change while admissions/results are outstanding.
    pub fn enable_mutation_retries(&mut self) -> Result<(), DriverError> {
        if self.outstanding() != 0 {
            return Err(DriverError::AlreadyDispatched);
        }
        self.mutation_retries = true;
        Ok(())
    }

    /// Fullness override is immutable after the first conservative dispatch.
    pub fn set_full_policy(
        &mut self,
        token: RequestToken,
        policy: crate::FullPolicy,
    ) -> Result<(), DriverError> {
        let p = self.pending(token)?;
        if p.attempts != 0 {
            return Err(DriverError::AlreadyDispatched);
        }
        p.full_policy = policy;
        Ok(())
    }
    /// Publish EAGAIN without disabling independent connection-loss retries.
    /// Immutable after the first conservative dispatch, including local output waits.
    pub fn set_fail_on_eagain(
        &mut self,
        token: RequestToken,
        fail: bool,
    ) -> Result<(), DriverError> {
        let p = self.pending(token)?;
        if p.attempts != 0 {
            return Err(DriverError::AlreadyDispatched);
        }
        p.fail_on_eagain = fail;
        Ok(())
    }
    /// Attach the frame the submitting thread encoded for `token`; the first dispatch keeps it only on an exact match.
    pub fn set_prepared(
        &mut self,
        token: RequestToken,
        frame: PreparedFrame,
    ) -> Result<(), DriverError> {
        self.pending(token)?.prepared = Some(frame);
        Ok(())
    }
    /// The key of the frame prepared for `token` that no dispatch consumed yet.
    pub fn prepared_key(&self, token: RequestToken) -> Option<FrameKey> {
        self.slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .filter(|p| p.token == token && !p.terminal)
            .and_then(|p| p.prepared.as_ref().map(|f| f.key))
    }
    pub fn request_flags(&self, token: RequestToken) -> Option<u32> {
        self.slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .filter(|p| p.token == token && !p.terminal)
            .map(Pending::request_flags)
    }
    pub fn request_gate_context(&self, token: RequestToken) -> Option<crate::RequestGateContext> {
        self.slots.get(token.slot).and_then(Option::as_ref)
            .filter(|p| p.token == token && !p.terminal)
            .map(|p| crate::RequestGateContext {
                flags: p.request_flags(),
                watch_ping: matches!(p.request.as_ref().request(), Request::Control(c) if matches!(c.operation, ControlOperation::Ping { .. })),
            })
    }
    /// Arm a finite deadline; `limit_us` is the configured request limit carried
    /// into the loud expiry line. [`crate::time::NO_DEADLINE`] enrolls an
    /// unlimited request and never fires.
    pub fn set_deadline_us(
        &mut self,
        token: RequestToken,
        absolute_us: u64,
        limit_us: u64,
    ) -> Result<(), DriverError> {
        crate::time::validate_deadline(absolute_us).map_err(|_| DriverError::Overflow)?;
        let p = self.pending(token)?;
        if p.attempts != 0 {
            return Err(DriverError::AlreadyDispatched);
        }
        if p.deadline.is_some() {
            return Err(DriverError::DeadlineAlreadySet);
        }
        // Enrollment is distinct from arming: unlimited still satisfies the
        // retry/primary-fallback contract and cannot be enrolled twice.
        p.deadline = Some(absolute_us);
        p.limit_us = limit_us;
        self.deadlines
            .set(token.slot, crate::time::timer(absolute_us));
        Ok(())
    }
    pub fn next_deadline_us(&self) -> Option<u64> {
        self.deadlines.first().map(|(time, _)| time)
    }
    pub fn deadline_us(&self, token: RequestToken) -> Option<u64> {
        self.slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .filter(|p| p.token == token && !p.terminal)
            .and_then(|p| p.deadline)
    }
    pub fn expire_token_us(&mut self, token: RequestToken, now: u64) -> Result<bool, DriverError> {
        let p = self.pending(token)?;
        if p.deadline.is_none_or(|at| !crate::time::is_due(at, now)) {
            return Ok(false);
        }
        let possibly_sent = p.attempts > 0;
        diag::diag!(
            "WARNING TIMEOUT object request exceeded {}s (tid={} attempts={})",
            crate::time::budget_seconds(p.limit_us),
            token.tid(),
            p.attempts
        );
        self.finish(token, ReadOutcome::Deadline { possibly_sent })?;
        Ok(true)
    }
    pub fn expire_us(&mut self, now: u64, budget: usize) -> usize {
        let mut count = 0;
        while count < budget {
            let Some((at, slot)) = self.deadlines.first() else {
                break;
            };
            if at > now {
                break;
            }
            self.deadlines.set(slot, None);
            let Some(p) = self.slots[slot].as_ref().filter(|p| !p.terminal) else {
                continue;
            };
            let token = p.token;
            let possibly_sent = p.attempts > 0;
            diag::diag!(
                "WARNING TIMEOUT object request exceeded {}s (tid={} attempts={})",
                crate::time::budget_seconds(p.limit_us),
                token.tid(),
                p.attempts
            );
            self.finish(token, ReadOutcome::Deadline { possibly_sent })
                .expect("live indexed request");
            count += 1;
        }
        count
    }

    /// Captures a fixed queue-lifetime write prefix, not callback consumption or a global
    /// RBD flush. Failed prefixes remain failed after result consumption/slot reclamation.
    pub fn fence(&self) -> FenceToken {
        FenceToken {
            queue: self.id,
            through: self.fence_through,
            epoch: self.fence_epoch,
        }
    }

    pub fn fence_status(&self, fence: FenceToken) -> Result<FenceStatus, DriverError> {
        if fence.queue != self.id || fence.epoch != self.fence_epoch {
            return Err(DriverError::Stale);
        }
        // An idle queue (every slot free) is answered without a pass over the slot table: owners check the fence
        // whenever they go idle.
        if self.outstanding() > 0
            && self.slots.iter().flatten().any(|p| {
                !p.reserved_control
                    && p.request.is_write()
                    && p.token.tid <= fence.through
                    && !p.terminal
            })
        {
            return Ok(FenceStatus::Pending);
        }
        Ok(FenceStatus::Ready(
            match self
                .first_write_failure
                .filter(|(tid, _)| *tid <= fence.through)
            {
                Some(failure) => Err(failure),
                None => Ok(()),
            },
        ))
    }

    /// Explicitly acknowledge the entire Ready prefix, including failures. Does not
    /// change outcomes or retry writes; previous fence tokens become stale.
    pub fn retire_fence(&mut self, fence: FenceToken) -> Result<(), DriverError> {
        if self.fence_status(fence)? == FenceStatus::Pending || fence.through != self.fence_through
        {
            return Err(DriverError::FenceBusy);
        }
        let epoch = self
            .fence_epoch
            .checked_add(1)
            .ok_or(DriverError::IdentityExhausted)?;
        self.first_write_failure = None;
        self.fence_epoch = epoch;
        Ok(())
    }

    /// Partition the tid space of a sharded client (adr 0467 am. 4): owner `index` of `owners` allocates the
    /// sequences `seq * owners + index` for `seq = 1, 2, ...`, so tids stay unique per client entity across owners and
    /// `sequence_of_tid(tid) % owners` names the allocating owner. Only before the first allocation; `owners == 1`
    /// is the unpartitioned sequence 1, 2, ...
    pub fn partition_tids(&mut self, index: u64, owners: u64) -> Result<(), DriverError> {
        if owners == 0 || index >= owners || self.next_seq != 1 || self.seq_stride != 1 {
            return Err(DriverError::Stale);
        }
        self.seq_stride = owners;
        self.next_seq = owners + index;
        Ok(())
    }

    /// The next allocation would overflow the sequence field of the tid.
    fn tid_exhausted(&self) -> bool {
        self.next_seq > (u64::MAX >> TID_SLOT_BITS) - self.seq_stride
    }

    /// The next wire identity of the request in `slot`, not yet allocated: `(sequence << TID_SLOT_BITS) | slot`.
    fn next_tid_for(&self, slot: usize) -> u64 {
        (self.next_seq << TID_SLOT_BITS) | slot as u64
    }

    /// Allocate the next wire identity of the request in `slot`.
    fn allocate_tid(&mut self, slot: usize) -> u64 {
        let tid = self.next_tid_for(slot);
        self.next_seq += self.seq_stride;
        tid
    }

    /// An object read, write or compound (not a control, PG listing or PG operation): once sent, only a reply, a loss,
    /// a placement change, a backoff release or its deadline can change it.
    pub fn is_ordinary(&self, token: RequestToken) -> bool {
        self.slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .filter(|p| p.token == token)
            .is_some_and(|p| {
                matches!(
                    p.request.as_ref().request(),
                    Request::Read(_) | Request::Write(_) | Request::Compound(_)
                )
            })
    }
    pub fn is_pending(&self, token: RequestToken) -> bool {
        self.slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .is_some_and(|p| p.token == token && !p.terminal)
    }

    /// A completion was published since the last call: the caller (a C API lane, a blocking execute) has work it
    /// must run before the owner blocks, whatever produced the reply (this owner's socket, a proxy stream, a timer).
    /// Clears the notice.
    pub fn take_published(&mut self) -> bool {
        std::mem::take(&mut self.published)
    }

    pub fn request(&self, token: RequestToken) -> Option<&ReadRequest> {
        self.slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .filter(|p| p.token == token && !p.terminal)
            .and_then(|p| match p.request.as_ref().request() {
                Request::Read(r) => Some(r),
                Request::Write(_) => None,
                Request::Compound(_) => None,
                Request::Control(_) => None,
                Request::PgList(_) => None,
                Request::PgOp(_) => None,
            })
    }

    pub(crate) fn allocate_split_tid(&mut self, parent: &ReadDispatch) -> Result<u64, DriverError> {
        if self.tid_exhausted() {
            return Err(DriverError::IdentityExhausted);
        }
        let pending = self.pending(parent.token)?;
        if pending.route != Some(parent.route)
            || pending.wire_tid != parent.wire_tid()
            || parent.message.retry_attempt != (pending.attempts - 1) as i32
        {
            return Err(DriverError::Stale);
        }
        Ok(self.allocate_tid(parent.token.slot))
    }
    /// Follow a validated split-child redirect using the original logical target.
    pub fn follow_redirect(&mut self, token: RequestToken) -> Result<u64, DriverError> {
        self.redirect_identity(token, true)
    }
    fn redirect_identity(
        &mut self,
        token: RequestToken,
        at_primary: bool,
    ) -> Result<u64, DriverError> {
        if self.tid_exhausted() {
            return Err(DriverError::IdentityExhausted);
        }
        let wire_tid = self.next_tid_for(token.slot);
        let pending = self.pending(token)?;
        let route = pending.route.ok_or(DriverError::NotDispatched)?;
        if pending.attempts >= i32::MAX as u32 {
            return Err(DriverError::RetryExhausted);
        }
        pending.redirect_flags |= flag::REDIRECTED | flag::IGNORE_CACHE | flag::IGNORE_OVERLAY;
        pending.fallback_primary |= at_primary || route.direct_read;
        pending.renew_wire_tid = false;
        pending.wire_tid = wire_tid;
        pending.route = None;
        self.next_seq += self.seq_stride;
        Ok(wire_tid)
    }
    /// Restart one logical read after invalidating its split/version proof.
    pub fn retry_at_primary(&mut self, token: RequestToken) -> Result<(), DriverError> {
        let pending = self.pending(token)?;
        if pending.request.is_write()
            || !matches!(
                pending.request.as_ref().request(),
                Request::Read(_) | Request::Compound(_)
            )
        {
            return Err(DriverError::UnsupportedRetry);
        }
        pending.fallback_primary = true;
        pending.renew_wire_tid = true;
        self.retry(token)
    }
    pub fn complete_split(
        &mut self,
        completed: crate::EcSplitCompletion,
    ) -> Result<(), DriverError> {
        let pending = self.pending(completed.token)?;
        if pending.route != Some(completed.route)
            || completed.attempt != (pending.attempts - 1) as i32
            || pending.request.is_write()
        {
            return Err(DriverError::Stale);
        }
        let outcome = if let Request::Compound(compound) = pending.request.as_ref().request() {
            let bytes = completed
                .operations
                .iter()
                .try_fold(0u64, |size, operation| {
                    size.checked_add(operation.outdata.len() as u64)
                })
                .ok_or(DriverError::InvalidReply)?;
            if bytes > u64::from(compound.max_output_bytes) {
                ReadOutcome::ReplyTooLarge {
                    result: completed.result,
                    user_version: completed.user_version,
                    bytes,
                    limit: compound.max_output_bytes,
                }
            } else {
                ReadOutcome::RemoteCompound {
                    publication: ReadPublication::EcSplit,
                    result: completed.result,
                    user_version: completed.user_version,
                    replay_version: completed.replay_version,
                    operations: completed.operations,
                }
            }
        } else if matches!(pending.request.as_ref().request(), Request::Read(_)) {
            let mut operations = completed.operations;
            let operation = operations.pop();
            ReadOutcome::Remote {
                result: completed.result,
                op_result: operation.as_ref().map_or(0, |operation| operation.rval),
                user_version: completed.user_version,
                data: operation.map_or_else(Bytes::new, |operation| operation.outdata),
            }
        } else {
            return Err(DriverError::InvalidReply);
        };
        self.finish(completed.token, outcome)
    }

    /// Immutable operation/snapshot view used before selecting a data shard.
    pub fn read_routing(&self, token: RequestToken) -> Option<crate::ReadRouting<'_>> {
        let pending = self.slots.get(token.slot)?.as_ref()?;
        if pending.token != token || pending.terminal {
            return None;
        }
        match pending.request.as_ref().request() {
            Request::Read(read) => Some(crate::ReadRouting {
                operations: crate::ReadOperations::Scalar {
                    offset: read.offset,
                    length: u64::from(read.length),
                },
                snapid: opwire::NOSNAP,
                empty_write_context: true,
                version_required: true,
                may_write: false,
            }),
            Request::Compound(compound) => Some(crate::ReadRouting {
                operations: crate::ReadOperations::Compound(&compound.operations),
                snapid: compound.context.snapid,
                empty_write_context: compound.context.snap_sequence == 0
                    && compound.context.snapshots.is_empty(),
                version_required: compound.context.read_version_required,
                may_write: compound.is_write(),
            }),
            _ => None,
        }
    }

    pub fn target(&self, token: RequestToken) -> Option<&Target> {
        self.slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .filter(|p| p.token == token && !p.terminal)
            .map(|p| p.request.target())
    }
    /// Current messenger identity; the token continues to own cancellation/results.
    pub fn wire_tid(&self, token: RequestToken) -> Option<u64> {
        self.slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .filter(|p| p.token == token && !p.terminal)
            .map(|p| p.wire_tid)
    }
    pub fn snapshot(&self, token: RequestToken) -> Option<u64> {
        self.slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .filter(|p| p.token == token && !p.terminal)
            .map(|p| p.request.context().map_or(opwire::NOSNAP, |c| c.snapid))
    }

    /// Remove a live ordinary compound request without a completion: the request leaves this queue for another queue
    /// of the same client (adr 0693, map-change barrier). Its slot, charge and deadline are released; the request is
    /// returned whole and its wire identity is [`Self::wire_tid`] (the caller keeps it, a resend must not change it).
    /// `NotMovable` leaves the request untouched: a control, a non-compound request, or a dispatch that still
    /// references the retained request (the owner releases its flight first).
    pub fn withdraw(&mut self, token: RequestToken) -> Result<CompoundRequest, DriverError> {
        let p = self.pending(token)?;
        if p.reserved_control
            || !matches!(p.request.as_ref().request(), Request::Compound(_))
            || Arc::strong_count(&p.request) != 1
        {
            return Err(DriverError::NotMovable);
        }
        let mut p = self.slots[token.slot]
            .take()
            .expect("pending lookup found the slot");
        self.charged -= p.charge;
        self.deadlines.set(token.slot, None);
        let retained = Arc::get_mut(&mut p.request).expect("strong count checked");
        let Some(Request::Compound(request)) = retained.0.take() else {
            unreachable!("compound checked above")
        };
        self.request_cache[token.slot] = Some(p.request);
        self.free.push(token.slot);
        Ok(request)
    }
    /// Give a request that was admitted but not yet dispatched the wire identity it already had in another queue
    /// (`withdraw`): a write resent after a primary change must keep its tid, or the new primary cannot recognise a
    /// duplicate by request id.
    pub fn adopt_wire_tid(&mut self, token: RequestToken, tid: u64) -> Result<(), DriverError> {
        let p = self.pending(token)?;
        if p.attempts != 0 {
            return Err(DriverError::AlreadyDispatched);
        }
        p.wire_tid = tid;
        Ok(())
    }

    /// Invalidate the previous route. EAGAIN primary fallback also renews wire TID;
    /// logical ownership is unchanged. Current HEAD contents may differ. Exhaustion leaves the
    /// old attempt eligible until the caller explicitly cancels or receives its reply.
    pub fn retry(&mut self, token: RequestToken) -> Result<(), DriverError> {
        let limit = self.retry_limit;
        let mutations = self.mutation_retries;
        let next_tid = self.next_tid_for(token.slot);
        let exhausted = self.tid_exhausted();
        let p = self.pending(token)?;
        if p.renew_wire_tid
            || (matches!(p.request.as_ref().request(), Request::Compound(c) if c.access == crate::Access::Read)
                && !p.request.is_write())
        {
            if p.deadline.is_none() {
                return Err(DriverError::DeadlineRequired);
            }
        } else if !matches!(
            p.request.as_ref().request(),
            Request::Read(_) | Request::PgList(_) | Request::PgOp(_)
        ) {
            if !mutations
                || !p.request.is_write()
                || matches!(p.request.as_ref().request(), Request::Control(_))
            {
                return Err(DriverError::UnsupportedRetry);
            }
            if p.deadline.is_none() {
                return Err(DriverError::DeadlineRequired);
            }
        }
        if p.route.is_none() {
            return Err(DriverError::NotDispatched);
        }
        if p.attempts >= limit {
            return Err(DriverError::RetryExhausted);
        }
        if p.renew_wire_tid && exhausted {
            return Err(DriverError::IdentityExhausted);
        }
        if p.route.is_some_and(|route| route.direct_read) {
            p.fallback_primary = true;
        }
        p.route = None;
        if p.renew_wire_tid {
            p.wire_tid = next_tid;
            p.renew_wire_tid = false;
            self.next_seq += self.seq_stride;
        }
        Ok(())
    }

    pub fn pg_listing(&self, token: RequestToken) -> Option<&crate::PgListRequest> {
        self.slots
            .get(token.slot)?
            .as_ref()
            .filter(|p| p.token == token && !p.terminal)
            .and_then(|p| match p.request.as_ref().request() {
                Request::PgList(r) => Some(r),
                _ => None,
            })
    }
    pub fn pg_operation(&self, token: RequestToken) -> Option<&crate::PgOpRequest> {
        self.slots
            .get(token.slot)?
            .as_ref()
            .filter(|p| p.token == token && !p.terminal)
            .and_then(|p| match p.request.as_ref().request() {
                Request::PgOp(r) => Some(r),
                _ => None,
            })
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_pg_operation(
        &mut self,
        request: crate::PgOpRequest,
    ) -> Result<RequestToken, (AdmissionError, crate::PgOpRequest)> {
        self.admit(Request::PgOp(request), false)
            .map_err(|(reason, request)| {
                let Request::PgOp(request) = request else {
                    unreachable!()
                };
                (reason, request)
            })
    }
    pub fn listing_changed(
        &mut self,
        token: RequestToken,
        pg_num: Option<u32>,
    ) -> Result<(), DriverError> {
        if self.pg_listing(token).is_none() {
            return Err(DriverError::Stale);
        }
        self.finish(token, ReadOutcome::ListingChanged { pg_num })
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_pg_list(
        &mut self,
        request: crate::PgListRequest,
    ) -> Result<RequestToken, crate::RejectedPgList> {
        self.admit(Request::PgList(request), false)
            .map_err(|(reason, request)| {
                let Request::PgList(request) = request else {
                    unreachable!()
                };
                crate::RejectedPgList { reason, request }
            })
    }
    pub fn submit(&mut self, request: ReadRequest) -> Result<RequestToken, RejectedRead> {
        self.admit(Request::Read(request), false)
            .map_err(|(reason, request)| {
                let Request::Read(request) = request else {
                    unreachable!()
                };
                RejectedRead { reason, request }
            })
    }
    /// Submit an exclusive host destination. Direct-only is refused until a negotiated placement path is available.
    #[cfg(feature = "registered-memory")]
    #[expect(
        clippy::result_large_err,
        reason = "rejected admission returns the caller's original allocation"
    )]
    pub fn submit_read_into(
        &mut self,
        request: crate::ReadIntoRequest,
    ) -> Result<RequestToken, crate::RejectedReadInto> {
        use crate::{ReadIntoPolicy, ReadIntoRequest, RejectedReadInto};
        if request.policy == ReadIntoPolicy::DirectOnly {
            return Err(RejectedReadInto {
                reason: AdmissionError::UnsupportedOperation,
                request,
            });
        }
        if request
            .buffer_offset
            .checked_add(request.read.length as usize)
            .is_none_or(|end| end > request.buffer.len())
        {
            return Err(RejectedReadInto {
                reason: AdmissionError::InvalidExtent,
                request,
            });
        }
        let ReadIntoRequest {
            read,
            buffer,
            buffer_offset,
            policy,
        } = request;
        match self.submit(read) {
            Ok(token) => {
                self.pending(token)
                    .expect("freshly admitted read")
                    .read_into = Some(crate::read_into::ReadIntoPending {
                    buffer,
                    offset: buffer_offset,
                });
                Ok(token)
            }
            Err(rejected) => Err(RejectedReadInto {
                reason: rejected.reason,
                request: ReadIntoRequest {
                    read: rejected.request,
                    buffer,
                    buffer_offset,
                    policy,
                },
            }),
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_write(&mut self, request: WriteRequest) -> Result<RequestToken, RejectedWrite> {
        self.admit(Request::Write(request), false)
            .map_err(|(reason, request)| {
                let Request::Write(request) = request else {
                    unreachable!()
                };
                RejectedWrite { reason, request }
            })
    }
    /// Submit a write whose bytes the OSD pulls from `source` (adr 0665) instead
    /// of receiving them inline. The request is an ordinary compound write (its context
    /// carries mtime and the self-managed snap context like any write) with exactly one
    /// `WRITE` op naming the object offset and no inline bytes: the grant names the
    /// client's READ-only window, its length and crc32c. Refused when the write and the
    /// grant disagree.
    #[cfg(feature = "source-pull")]
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_write_from_source(
        &mut self,
        request: CompoundRequest,
        source: SourcePullSource,
    ) -> Result<RequestToken, RejectedCompound> {
        // The descriptor carries the length: the op names the object offset only.
        // A snapshot read context, a read API mode or any other op shape has no
        // source-pull form.
        let shaped = matches!(request.operations.as_slice(),
            [op] if op.op == op::WRITE && op.indata.is_empty() && op.extent().length == 0)
            && !request.access.reads()
            && request.context.snapid == opwire::NOSNAP
            && request.context.read_op.is_none()
            && !request.context.legacy_reply;
        if !shaped || source.length == 0 || source.transaction == 0 {
            return Err(RejectedCompound {
                reason: AdmissionError::InvalidExtent,
                request,
            });
        }
        match self.admit(Request::Compound(request), false) {
            Ok(token) => {
                self.pending(token)
                    .expect("freshly admitted write")
                    .source_pull = Some(source);
                Ok(token)
            }
            Err((reason, request)) => {
                let Request::Compound(request) = request else {
                    unreachable!()
                };
                Err(RejectedCompound { reason, request })
            }
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_compound(
        &mut self,
        request: CompoundRequest,
    ) -> Result<RequestToken, RejectedCompound> {
        self.admit(Request::Compound(request), false)
            .map_err(|(reason, request)| {
                let Request::Compound(request) = request else {
                    unreachable!()
                };
                RejectedCompound { reason, request }
            })
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_control(
        &mut self,
        request: ControlRequest,
    ) -> Result<RequestToken, RejectedControl> {
        self.admit(
            Request::Control(crate::ContextualControlRequest {
                request,
                context: Default::default(),
            }),
            false,
        )
        .map_err(|(reason, request)| {
            let Request::Control(request) = request else {
                unreachable!()
            };
            RejectedControl {
                reason,
                request: request.request,
            }
        })
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_control_with_context(
        &mut self,
        request: ControlRequest,
        context: crate::RequestContext,
    ) -> Result<RequestToken, crate::RejectedContextualControl> {
        self.admit(
            Request::Control(crate::ContextualControlRequest { request, context }),
            false,
        )
        .map_err(|(reason, request)| {
            let Request::Control(request) = request else {
                unreachable!()
            };
            crate::RejectedContextualControl {
                reason,
                request: request.request,
                context: request.context,
            }
        })
    }

    /// For runtime-owned controls only. Application polling never consumes these results.
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_reserved_control(
        &mut self,
        request: ControlRequest,
    ) -> Result<RequestToken, RejectedControl> {
        self.submit_reserved_control_with_context(request, Default::default())
            .map_err(|r| RejectedControl {
                reason: r.reason,
                request: r.request,
            })
    }
    /// Runtime-reserved control with immutable captured metadata.
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_reserved_control_with_context(
        &mut self,
        request: ControlRequest,
        context: crate::RequestContext,
    ) -> Result<RequestToken, crate::RejectedContextualControl> {
        self.admit(
            Request::Control(crate::ContextualControlRequest { request, context }),
            true,
        )
        .map_err(|(reason, request)| {
            let Request::Control(request) = request else {
                unreachable!()
            };
            crate::RejectedContextualControl {
                reason,
                request: request.request,
                context: request.context,
            }
        })
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    fn admit(
        &mut self,
        request: Request,
        reserved_control: bool,
    ) -> Result<RequestToken, (AdmissionError, Request)> {
        let t = request.target();
        let charge = if reserved_control || matches!(self.accounting, RequestAccounting::Retained) {
            crate::compound::target_charge(t, request.charge()).ok_or(AdmissionError::NoCredit)
        } else {
            request.logical_charge()
        };
        let reason = if !crate::compound::valid_target(
            t,
            matches!(request, Request::PgList(_) | Request::PgOp(_))
                || matches!(self.accounting, RequestAccounting::Logical),
        ) {
            Some(AdmissionError::InvalidTarget)
        } else if let Request::PgList(p) = &request {
            p.validate().err()
        } else if let Request::PgOp(p) = &request {
            p.validate(matches!(self.accounting, RequestAccounting::Logical))
                .err()
        } else if let Request::Compound(c) = &request {
            match self.accounting {
                RequestAccounting::Logical => c.validate_compatible().err(),
                RequestAccounting::Retained => c.validate().err(),
            }
        } else if let Request::Control(c) = &request {
            c.validate().err()
        } else if (!request.is_write() && request.length() == 0)
            || request.length() > u64::from(u32::MAX)
            || request.offset().checked_add(request.length()).is_none()
        {
            Some(AdmissionError::InvalidExtent)
        } else {
            None
        };
        let (used_slots, slot_limit, used_bytes, policy) = if reserved_control {
            (
                self.control_outstanding,
                self.control_slots,
                self.control_charged,
                if self.elastic_controls {
                    crate::ByteAdmission::compatible(0)
                } else {
                    crate::ByteAdmission::strict(self.control_byte_limit)
                },
            )
        } else {
            (
                self.outstanding() - self.control_outstanding,
                self.slots.len() - self.control_slots,
                self.charged - self.control_charged,
                self.application_admission,
            )
        };
        let reason = reason.or_else(|| {
            if self.tid_exhausted() {
                Some(AdmissionError::IdentityExhausted)
            } else if used_slots >= slot_limit
                || (!reserved_control
                    && self.application_count_target != 0
                    && used_slots as u64 >= self.application_count_target)
            {
                Some(AdmissionError::NoCredit)
            } else {
                match &charge {
                    Err(error) => Some(*error),
                    Ok(charge)
                        if policy.admit(used_bytes, used_slots, *charge).is_err()
                            || self.charged.checked_add(*charge).is_none() =>
                    {
                        Some(AdmissionError::NoCredit)
                    }
                    Ok(_) => None,
                }
            }
        });
        if let Some(reason) = reason {
            return Err((reason, request));
        }
        let slot = self.free.pop().expect("admission checked slot credit");
        let token = RequestToken {
            queue: self.id,
            slot,
            tid: self.allocate_tid(slot),
        };
        let charge = charge.expect("admission checked byte credit");
        self.charged += charge;
        if reserved_control {
            self.control_outstanding += 1;
            self.control_charged += charge;
        } else {
            self.fence_through = token.tid;
        }
        let full_policy = request
            .context()
            .map_or(crate::FullPolicy::Wait, |c| c.full_policy);
        let owner = match self.request_cache[slot].take() {
            Some(mut owner) => {
                let cell = Arc::get_mut(&mut owner).expect("cached request owner is exclusive");
                assert!(cell.0.is_none());
                cell.0 = Some(request);
                owner
            }
            None => Arc::new(RetainedRequest(Some(request))),
        };
        self.slots[slot] = Some(Pending {
            #[cfg(feature = "registered-memory")]
            read_into: None,
            reserved_control,
            token,
            wire_tid: token.tid(),
            redirect_flags: 0,
            fallback_primary: false,
            renew_wire_tid: false,
            request: owner,
            #[cfg(feature = "source-pull")]
            source_pull: None,
            charge,
            route: None,
            attempts: 0,
            full_policy,
            fail_on_eagain: false,
            deadline: None,
            limit_us: 0,
            terminal: false,
            prepared: None,
        });
        Ok(token)
    }

    fn pending(&mut self, token: RequestToken) -> Result<&mut Pending, DriverError> {
        self.slots
            .get_mut(token.slot)
            .and_then(Option::as_mut)
            .filter(|p| p.token == token && !p.terminal)
            .ok_or(DriverError::Stale)
    }

    /// Conservative handoff: cancellation/loss is possibly sent even before socket IO.
    /// Only reject_unaccepted of an owned never-accepted dispatch can prove the
    /// current attempt unsent. Retries preserve logical identity.
    pub fn dispatch(
        &mut self,
        token: RequestToken,
        route: ReadRoute,
    ) -> Result<ReadDispatch, DriverError> {
        let incarnation = self.incarnation;
        let p = self.pending(token)?;
        if p.route.is_some() {
            return Err(DriverError::AlreadyDispatched);
        }
        if !route_shape_valid(p, route) {
            return Err(DriverError::InvalidRoute);
        }
        if let Request::PgList(r) = p.request.as_ref().request()
            && (route.pg.pool != r.target.pool as u64
                || route.pg.seed != r.pg
                || route.hash != r.pg)
        {
            return Err(DriverError::InvalidRoute);
        }
        if let Request::PgOp(r) = p.request.as_ref().request() {
            if route.pg.pool != r.pool() as u64 {
                return Err(DriverError::InvalidRoute);
            }
            match r.route() {
                crate::PgOpRoute::Hash(hash) if route.hash != hash => {
                    return Err(DriverError::InvalidRoute);
                }
                crate::PgOpRoute::Pgid(pg) if route.hash != pg => {
                    return Err(DriverError::InvalidRoute);
                }
                _ => {}
            }
        }
        if route.direct_read
            && (!matches!(route.pool, PoolRoute::Erasure(_))
                || p.request.is_write()
                || p.request_flags()
                    & (flag::READ | flag::WRITE | flag::BALANCE_READS | flag::RWORDERED)
                    != (flag::READ | flag::BALANCE_READS)
                || matches!(p.request.as_ref().request(), Request::Compound(compound) if !compound.operations.iter().any(|operation| matches!(operation.op, op::READ | op::SPARSE_READ)))
                || p.request.context().is_some_and(|context| {
                    context.snapid != opwire::NOSNAP
                        || context.snap_sequence != 0
                        || !context.snapshots.is_empty()
                })
                || !matches!(
                    p.request.as_ref().request(),
                    Request::Read(_) | Request::Compound(_)
                ))
        {
            return Err(DriverError::InvalidRoute);
        }
        if p.attempts >= i32::MAX as u32 {
            return Err(DriverError::RetryExhausted);
        }
        let inputs = MessageInputs {
            pgid: SpgT {
                pgid: route.pg,
                shard: route.pool.shard(),
            },
            hash: route.hash,
            epoch: route.epoch,
            pool: route.pg.pool as i64,
            features: route.features,
            incarnation,
            attempts: p.attempts,
            direct_read: route.direct_read,
            base_flags: p.request_flags(),
        };
        // A frame the submitting thread built for exactly this first attempt is trusted: the owner placed nothing and
        // builds no message (the dispatch defers it). Anything else (newer map, other session target or features,
        // retry, changed flags) drops the frame and the message is built and encoded here as before.
        let prepared = p.prepared.take().filter(|frame| {
            p.attempts == 0
                && !route.direct_read
                && frame.key.is_attempt(&route, incarnation)
                && frame.base_flags == inputs.base_flags
        });
        let message = if prepared.is_some() {
            DispatchMessage::deferred(p.request.clone(), inputs)
        } else {
            let request = &p.request;
            DispatchMessage::built(build_message(
                request.as_ref().request(),
                &inputs,
                |field| RequestIdentity::request(request, field),
            ))
        };
        p.route = Some(route);
        p.attempts += 1;
        Ok(ReadDispatch {
            token,
            route,
            message,
            reply_data_limit: p.request.reply_data_limit(),
            wire_tid: p.wire_tid,
            read_version_required: p.request.context().is_none_or(|c| c.read_version_required),
            may_write: p.request.is_write(),
            split_child: false,
            prepared,
            #[cfg(feature = "source-pull")]
            source_pull: p.source_pull,
        })
    }

    /// Consume a current dispatch rejected before messenger acceptance. Never use
    /// after handoff; previous attempts retain conservative uncertainty.
    pub fn reject_unaccepted(
        &mut self,
        dispatch: ReadDispatch,
        error: LocalRequestError,
    ) -> Result<(), DriverError> {
        let token = dispatch.token;
        let p = self.pending(token)?;
        if p.route != Some(dispatch.route)
            || p.attempts == 0
            || dispatch.message.retry_attempt != (p.attempts - 1) as i32
        {
            return Err(DriverError::Stale);
        }
        let possibly_sent = p.attempts > 1;
        self.finish(
            token,
            ReadOutcome::LocalRejected {
                error,
                possibly_sent,
            },
        )
    }

    /// Driver-validated permanent map policy; handed-off attempts retain
    /// uncertainty. For an owned unaccepted dispatch use reject_unaccepted.
    pub fn reject_policy(
        &mut self,
        token: RequestToken,
        error: LocalRequestError,
    ) -> Result<(), DriverError> {
        let p = self.pending(token)?;
        let possibly_sent = p.attempts != 0;
        self.finish(
            token,
            ReadOutcome::LocalRejected {
                error,
                possibly_sent,
            },
        )
    }

    /// Driver-only: caller must still own this dispatch, never accepted by messenger.
    /// Rebuild the current attempt without changing conservative certainty or retry budget.
    pub fn refresh_unaccepted(
        &mut self,
        dispatch: &mut ReadDispatch,
        route: ReadRoute,
    ) -> Result<(), DriverError> {
        let token = dispatch.token;
        let p = self.pending(token)?;
        if p.route != Some(dispatch.route)
            || p.attempts == 0
            || dispatch.message.retry_attempt != (p.attempts - 1) as i32
        {
            return Err(DriverError::Stale);
        }
        let previous = p.route;
        let attempts = p.attempts;
        p.route = None;
        p.attempts -= 1;
        match self.dispatch(token, route) {
            Ok(fresh) => {
                *dispatch = fresh;
                Ok(())
            }
            Err(error) => {
                let p = self
                    .pending(token)
                    .expect("refresh validation cannot finish a request");
                p.route = previous;
                p.attempts = attempts;
                Err(error)
            }
        }
    }
    pub fn dispatch_with_backoff(
        &mut self,
        token: RequestToken,
        route: ReadRoute,
        table: &crate::BackoffTable,
    ) -> Result<ReadDispatch, DriverError> {
        let p = self.pending(token)?;
        if p.route.is_some() {
            return Err(DriverError::AlreadyDispatched);
        }
        if !route_shape_valid(p, route) {
            return Err(DriverError::InvalidRoute);
        }
        let snapshot = p.request.context().map_or(opwire::NOSNAP, |c| c.snapid);
        if table.blocked(route, p.request.target(), snapshot) {
            return Err(DriverError::BackedOff);
        }
        self.dispatch(token, route)
    }

    /// Only after the connection driver validated the entire frame/authentication and
    /// message type/version. Invalid reply faults that connection; call cancel to resolve
    /// its outstanding requests. No successful output is exposed on parse failure.
    pub fn reply(
        &mut self,
        token: RequestToken,
        osd: i32,
        session: u64,
        reply: MOSDOpReply,
    ) -> Result<bool, DriverError> {
        self.receive_reply(token, osd, session, reply, false)
            .map(|action| action == ReplyAction::Completed)
    }

    /// Validated EAGAIN recovery with deadline/attempt credit; mutators require retry opt-in.
    /// Recover retains the request and publishes no completion. Driver schedules the primary fallback.
    pub fn reply_for_recovery(
        &mut self,
        token: RequestToken,
        osd: i32,
        session: u64,
        reply: MOSDOpReply,
    ) -> Result<ReplyAction, DriverError> {
        let action = self.receive_reply(token, osd, session, reply, true)?;
        if action == ReplyAction::Recover {
            let p = self.pending(token)?;
            p.fallback_primary = true;
            p.renew_wire_tid = true;
        }
        Ok(action)
    }

    /// Resolve an authenticated placed READ after the transport verified its
    /// receipt, LOCAL_INV and exact registered destination. This never stages
    /// payload bytes through an ordinary reply buffer.
    ///
    /// # Safety
    /// The caller must prove `reply` came from the exact READY RC attempt and
    /// `initialized` is the verified destination length after remote and local
    /// access retirement. Numeric reply fields alone are not that proof.
    #[cfg(feature = "registered-memory")]
    pub unsafe fn reply_placed_for_recovery(
        &mut self,
        token: RequestToken,
        osd: i32,
        session: u64,
        reply: PlacedReadReply,
        initialized: usize,
        verified: bool,
    ) -> Result<ReplyAction, DriverError> {
        let limit = self.retry_limit;
        let p = self.pending(token)?;
        let route = p.route.ok_or(DriverError::Stale)?;
        if route.osd != osd
            || route.session != session
            || reply.retry_attempt != (p.attempts - 1) as i32
        {
            return Err(DriverError::Stale);
        }
        let Request::Read(read) = p.request.as_ref().request() else {
            return Err(DriverError::InvalidReply);
        };
        let count = u64::try_from(initialized).map_err(|_| DriverError::InvalidReply)?;
        if p.read_into.is_some()
            || route.direct_read
            || reply.oid != read.target.object
            || reply.pgid != route.pg
            || reply.op != op::READ
            || reply.op_flags != 0
            || reply.flags & u64::from(flag::ACK | flag::ONDISK) == 0
            || count > u64::from(read.length)
            || (reply.result >= 0
                && (reply.result != 0
                    || reply.op_result != 0
                    || reply.offset != read.offset
                    || reply.length != count))
            || (reply.result < 0 && (reply.op_result >= 0 || initialized != 0))
        {
            return Err(DriverError::InvalidReply);
        }
        let recover =
            reply.result == -11 && !p.fail_on_eagain && p.deadline.is_some() && p.attempts < limit;
        if recover {
            let p = self.pending(token)?;
            p.fallback_primary = true;
            p.renew_wire_tid = true;
            return Ok(ReplyAction::Recover);
        }
        let outcome = ReadOutcome::RemotePlaced {
            result: reply.result,
            op_result: reply.op_result,
            user_version: reply.user_version,
            initialized,
            verified,
        };
        self.finish(token, outcome)?;
        Ok(ReplyAction::Completed)
    }

    fn receive_reply(
        &mut self,
        token: RequestToken,
        osd: i32,
        session: u64,
        mut reply: MOSDOpReply,
        allow_recovery: bool,
    ) -> Result<ReplyAction, DriverError> {
        let limit = self.retry_limit;
        let mutation_retries = self.mutation_retries;
        let p = self.pending(token)?;
        let route = p.route.ok_or(DriverError::Stale)?;
        if route.osd != osd
            || route.session != session
            || reply.retry_attempt != (p.attempts - 1) as i32
        {
            return Err(DriverError::Stale);
        }
        // Redirects carry no ordinary per-operation result vector. Authenticate the
        // attempt before consuming one, then preserve the logical request unchanged.
        if allow_recovery && reply.redirect.is_some() {
            if reply.oid != p.request.target().object || reply.pgid != route.pg {
                return Err(DriverError::InvalidReply);
            }
            let wire_tid = self.redirect_identity(token, false)?;
            return Ok(ReplyAction::Redirected { wire_tid });
        }
        let write = p.request.is_write();
        let recover = allow_recovery
            && (!write || mutation_retries)
            && reply.result == -11
            && !p.fail_on_eagain
            && p.deadline.is_some()
            && p.attempts < limit;
        if let Request::Control(c) = p.request.as_ref().request() {
            let expected = c.operation.wire_op();
            let prefix = usize::from(c.context.control_assert_version != 0);
            if reply.oid != c.target.object
                || reply.pgid != route.pg
                || reply.redirect.is_some()
                || reply.ops.len() != 1 + prefix
                || (prefix != 0 && {
                    let guard = &reply.ops[0];
                    let expected = OsdOp::assert_version(c.context.control_assert_version);
                    guard.op != expected.op
                        || guard.flags != 0
                        || !guard.outdata.is_empty()
                        || (reply.result >= 0 && guard.rval < 0)
                })
                || reply.ops[prefix].op != expected.op
                || reply.ops[prefix].flags != 0
                || reply.flags & u64::from(flag::ACK | flag::ONDISK) == 0
                || (expected.op == op::WATCH && reply.ops[prefix].watch() != expected.watch())
                || (reply.result >= 0
                    && (reply.result != 0
                        || reply.ops[prefix].rval != 0
                        || reply.ops[prefix].outdata.len() as u64 != c.operation.max_output()))
                || (reply.result < 0 && !reply.ops[prefix].outdata.is_empty())
            {
                return Err(DriverError::InvalidReply);
            }
            if write && reply.result >= 0 && reply.flags & u64::from(flag::ONDISK) == 0 {
                return Ok(ReplyAction::AwaitDurable);
            }
            if recover {
                return Ok(ReplyAction::Recover);
            }
            let operation = reply.ops.pop().unwrap();
            let outcome = ReadOutcome::Remote {
                result: reply.result,
                op_result: operation.rval,
                user_version: reply.user_version,
                data: operation.outdata,
            };
            self.finish(token, outcome)?;
            return Ok(ReplyAction::Completed);
        }
        if let Request::PgList(r) = p.request.as_ref().request() {
            if reply.oid != r.target.object
                || reply.pgid != route.pg
                || reply.redirect.is_some()
                || reply.ops.len() != 1
                || reply.ops[0].op != r.code()
                || reply.ops[0].flags != 0
                || reply.flags & u64::from(flag::ACK | flag::ONDISK) == 0
            {
                return Err(DriverError::InvalidReply);
            }
            if reply.result >= 0 && reply.ops[0].rval < 0 {
                return Err(DriverError::InvalidReply);
            }
            if reply.ops[0].outdata.len() > r.max_output_bytes() as usize {
                let bytes = reply.ops[0].outdata.len() as u64;
                self.finish(token, ReadOutcome::ListingTooLarge { bytes })?;
                return Ok(ReplyAction::Completed);
            }
            if recover {
                return Ok(ReplyAction::Recover);
            }
            if reply.result == 0 && reply.ops[0].outdata.is_empty() {
                self.finish(token, ReadOutcome::ListingChanged { pg_num: None })?;
                return Ok(ReplyAction::Completed);
            }
            let op = reply.ops.pop().unwrap();
            let page = if reply.result >= 0 {
                Some(crate::PgListPage::decode(
                    r,
                    reply.result,
                    reply.osdmap_epoch,
                    op.outdata.clone(),
                )?)
            } else {
                None
            };
            let error_data = if reply.result < 0 {
                op.outdata
            } else {
                Bytes::new()
            };
            self.finish(
                token,
                ReadOutcome::RemotePgList {
                    result: reply.result,
                    op_result: op.rval,
                    user_version: reply.user_version,
                    map_epoch: reply.osdmap_epoch,
                    page,
                    error_data,
                },
            )?;
            return Ok(ReplyAction::Completed);
        }
        if let Request::Compound(c) = p.request.as_ref().request() {
            let size = reply
                .ops
                .iter()
                .try_fold(0u64, |n, o| n.checked_add(o.outdata.len() as u64));
            if reply.oid != c.target.object
                || reply.pgid != route.pg
                || reply.redirect.is_some()
                || reply.ops.len() != c.operations.len()
                || reply.ops.iter().zip(&c.operations).any(|(a, b)| {
                    !crate::compound::op_reply_shape_valid(
                        b,
                        a,
                        reply.result,
                        route.direct_read,
                        (c.context.legacy_reply
                            || c.context.write_op == Some(crate::WriteOpReply::Legacy)
                            || c.context.read_op == Some(crate::ReadOpReply::Legacy))
                            && write,
                    )
                })
                || size.is_none()
                || reply.flags & u64::from(flag::ACK | flag::ONDISK) == 0
            {
                return Err(DriverError::InvalidReply);
            }
            // The response cap is local, never transmitted to the OSD. Dynamic
            // outputs can legitimately exceed it; malformed descriptors above
            // remain protocol errors and cannot hide behind this local limit.
            let limit = c.max_output_bytes;
            if let Some(bytes) = size.filter(|n| *n > u64::from(limit)) {
                self.finish(
                    token,
                    ReadOutcome::ReplyTooLarge {
                        result: reply.result,
                        user_version: reply.user_version,
                        bytes,
                        limit,
                    },
                )?;
                return Ok(ReplyAction::Completed);
            }
            if write && reply.result >= 0 && reply.flags & u64::from(flag::ONDISK) == 0 {
                return Ok(ReplyAction::AwaitDurable);
            }
            if recover {
                return Ok(ReplyAction::Recover);
            }
            // Classic OSDs may return the tail-ZERO execution rewrite. Keep the
            // native result associated with the submitted operation after validation.
            for (returned, requested) in reply.ops.iter_mut().zip(&c.operations) {
                if requested.op == op::ZERO && returned.op == op::TRUNCATE {
                    returned.op = op::ZERO;
                }
            }
            let outcome = ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: reply.result,
                user_version: reply.user_version,
                replay_version: reply.replay_version,
                operations: reply.ops,
            };
            self.finish(token, outcome)?;
            return Ok(ReplyAction::Completed);
        }
        if reply.oid != p.request.target().object
            || reply.pgid != route.pg
            || reply.redirect.is_some()
            || reply.ops.len() != 1
            || reply.ops[0].op != p.request.code()
            || reply.ops[0].flags != 0
            || reply.ops[0].outdata.len() as u64 > if write { 0 } else { p.request.length() }
            || reply.flags & u64::from(flag::ACK | flag::ONDISK) == 0
            || (reply.result >= 0
                && ((!matches!(p.request.as_ref().request(), Request::PgOp(_))
                    && (reply.result != 0 || reply.ops[0].rval != 0))
                    || (!write
                        && !matches!(p.request.as_ref().request(), Request::PgOp(_))
                        && (reply.ops[0].extent().offset != p.request.offset()
                            || if route.direct_read {
                                reply.ops[0].extent().length > p.request.length()
                                    || reply.ops[0].extent().length
                                        < reply.ops[0].outdata.len() as u64
                            } else {
                                reply.ops[0].extent().length != reply.ops[0].outdata.len() as u64
                            }))))
            || (!matches!(p.request.as_ref().request(), Request::PgOp(_))
                && (reply.result < 0 || reply.ops[0].rval < 0)
                && !reply.ops[0].outdata.is_empty())
        {
            return Err(DriverError::InvalidReply);
        }
        if recover {
            return Ok(ReplyAction::Recover);
        }
        if write && reply.result >= 0 && reply.flags & u64::from(flag::ONDISK) == 0 {
            return Ok(ReplyAction::AwaitDurable);
        }
        let op = reply.ops.pop().expect("validated op count");
        let outcome = ReadOutcome::Remote {
            result: reply.result,
            op_result: op.rval,
            user_version: reply.user_version,
            data: op.outdata,
        };
        self.finish(token, outcome)?;
        Ok(ReplyAction::Completed)
    }

    fn finish(&mut self, token: RequestToken, outcome: ReadOutcome) -> Result<(), DriverError> {
        let p = self.pending(token)?;
        let failure = if !p.reserved_control && p.request.is_write() {
            match &outcome {
                ReadOutcome::Remote {
                    result, op_result, ..
                } if *result < 0 || *op_result < 0 => Some(WriteFailure::Remote {
                    result: *result,
                    op_result: *op_result,
                }),
                ReadOutcome::RemoteCompound {
                    result, operations, ..
                } => {
                    let failed = operations.iter().find(|o| o.rval < 0).map(|o| o.rval);
                    if *result < 0 || failed.is_some() {
                        Some(WriteFailure::Remote {
                            result: *result,
                            op_result: failed.unwrap_or(0),
                        })
                    } else {
                        None
                    }
                }
                ReadOutcome::ReplyTooLarge { .. } => Some(WriteFailure::PossiblySent),
                ReadOutcome::LocalRejected { possibly_sent, .. } => Some(if *possibly_sent {
                    WriteFailure::PossiblySent
                } else {
                    WriteFailure::Unsent
                }),
                ReadOutcome::CanceledUnsent => Some(WriteFailure::Unsent),
                ReadOutcome::PossiblySent => Some(WriteFailure::PossiblySent),
                ReadOutcome::Deadline { possibly_sent } => Some(if *possibly_sent {
                    WriteFailure::PossiblySent
                } else {
                    WriteFailure::Unsent
                }),
                _ => None,
            }
        } else {
            None
        };
        #[cfg(feature = "registered-memory")]
        let (outcome, read_into) = match p.read_into.take() {
            Some(destination) => destination.complete(outcome),
            None => (outcome, None),
        };
        p.terminal = true;
        self.deadlines.set(token.slot, None);
        if let Some(failure) = failure
            && self
                .first_write_failure
                .is_none_or(|(tid, _)| token.tid < tid)
        {
            self.first_write_failure = Some((token.tid, failure));
        }
        self.completions.push_back(ReadCompletion {
            token,
            outcome,
            #[cfg(feature = "registered-memory")]
            read_into,
        });
        self.published = true;
        Ok(())
    }

    /// Stops local interest; never claims remote rollback. Late events become stale.
    pub fn cancel(&mut self, token: RequestToken) -> Result<(), DriverError> {
        let p = self.pending(token)?;
        let sent = p.attempts > 0;
        self.finish(
            token,
            if sent {
                ReadOutcome::PossiblySent
            } else {
                ReadOutcome::CanceledUnsent
            },
        )
    }

    fn consume_completion(&mut self, done: &ReadCompletion) {
        let mut p = self.slots[done.token.slot]
            .take()
            .expect("completion reserves its slot");
        self.charged -= p.charge;
        if p.reserved_control {
            self.control_outstanding -= 1;
            self.control_charged -= p.charge;
        }
        // A live dispatch must keep the original request immutable. Never
        // cache its owner: doing so would delay final payload/callback release
        // after the last dispatch drops. Only exclusive empty shells survive.
        let retired = if let Some(cell) = Arc::get_mut(&mut p.request) {
            let retired = cell.0.take();
            self.request_cache[done.token.slot] = Some(p.request);
            retired
        } else {
            None
        };
        self.free.push(done.token.slot);
        // Finish the slot transition before running any input-owner destructor,
        // matching the uncached path's completion/callback ordering.
        drop(retired);
    }
    /// Consume only an exact terminal reserved control. Leaves application results owned.
    pub fn take_reserved_completion(&mut self, token: RequestToken) -> Option<ReadCompletion> {
        let p = self.slots.get(token.slot)?.as_ref()?;
        if p.token != token || !p.reserved_control || !p.terminal {
            return None;
        }
        let i = self.completions.iter().position(|c| c.token == token)?;
        let done = self.completions.remove(i)?;
        self.consume_completion(&done);
        Some(done)
    }
    /// Move application results only, in application completion order, without allocation.
    /// Occupied slots are not overwritten; filling stops at the first occupied slot.
    pub fn poll_into(&mut self, output: &mut [Option<ReadCompletion>]) -> usize {
        let mut count = 0;
        for dst in output {
            if dst.is_some() {
                break;
            }
            let Some(i) = self
                .completions
                .iter()
                .position(|c| !self.slots[c.token.slot].as_ref().unwrap().reserved_control)
            else {
                break;
            };
            let done = self.completions.remove(i).expect("indexed completion");
            self.consume_completion(&done);
            *dst = Some(done);
            count += 1;
        }
        count
    }
}
