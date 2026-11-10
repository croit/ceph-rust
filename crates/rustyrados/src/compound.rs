// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::{AdmissionError, Target};
use denc::types::UTime;
use opwire::{OsdOp, op, opflag};

pub(crate) fn valid_target(target: &Target, empty_allowed: bool) -> bool {
    target.pool >= 0
        && (empty_allowed || !target.object.is_empty())
        && [
            target.object.len(),
            target.namespace.len(),
            target.locator.len(),
        ]
        .iter()
        .all(|&length| length <= u32::MAX as usize)
}
pub(crate) fn target_charge(target: &Target, charge: Option<u64>) -> Option<u64> {
    charge?
        .checked_add(target.object.capacity() as u64)?
        .checked_add(target.namespace.capacity() as u64)?
        .checked_add(target.locator.capacity() as u64)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}

#[cfg(test)]
mod control_tests {
    use super::*;

    #[test]
    fn compatible_empty_vectors_are_real_read_or_durable_write_requests() {
        for access in [Access::Read, Access::ReadWrite] {
            for pool in [
                crate::PoolRoute::Replicated,
                crate::PoolRoute::Erasure(denc::types::ShardId(2)),
            ] {
                for result in [0, -2] {
                    let request = CompoundRequest {
                        target: Target {
                            pool: 7,
                            object: b"empty".to_vec(),
                            namespace: vec![],
                            locator: vec![],
                        },
                        access,
                        context: RequestContext {
                            read_op: (!access.writes()).then_some(ReadOpReply::Legacy),
                            write_op: access.writes().then_some(crate::WriteOpReply::Legacy),
                            ..Default::default()
                        },
                        operations: vec![],
                        max_output_bytes: 0,
                    };
                    assert_eq!(request.preflight_compatible(), Ok(0));
                    assert_eq!(
                        request.preflight(4096),
                        Err(AdmissionError::InvalidOperation)
                    );
                    let mut queue =
                        crate::ObjectQueue::with_compatible_admission(1, 4096, 0, 7, 1).unwrap();
                    let token = queue.submit_compound(request).unwrap();
                    let route = crate::ReadRoute {
                        direct_read: false,
                        base_pool: 7,
                        osd: 2,
                        session: 3,
                        pg: denc::types::PgT::new(7, 0),
                        hash: 0,
                        epoch: 1,
                        features: 0,
                        generation: 1,
                        pool,
                    };
                    let dispatch = queue.dispatch(token, route).unwrap();
                    assert!(dispatch.message.ops.is_empty());
                    let encoded = dispatch.message.encode_version(9, 0).unwrap();
                    let decoded =
                        opwire::MOSDOp::decode_shared(9, &encoded.front, &encoded.data).unwrap();
                    assert!(decoded.ops.is_empty());
                    assert_eq!(decoded.pgid, dispatch.message.pgid);
                    assert_eq!(dispatch.message.pgid.shard, pool.shard());
                    assert_eq!(
                        dispatch.message.flags & opwire::flag::WRITE != 0,
                        access.writes()
                    );
                    let mut reply = opwire::MOSDOpReply::for_request(&dispatch.message, 1);
                    reply.result = result;
                    reply.user_version = 73;
                    reply.flags = u64::from(opwire::flag::ACK);
                    if access.writes() && result == 0 {
                        assert!(!queue.reply(token, 2, 3, reply.clone()).unwrap());
                        assert_eq!(queue.poll_into(&mut [None]), 0);
                        reply.flags |= u64::from(opwire::flag::ONDISK);
                    }
                    assert!(queue.reply(token, 2, 3, reply).unwrap());
                    let mut completed = [None];
                    assert_eq!(queue.poll_into(&mut completed), 1);
                    assert!(matches!(completed[0].take().unwrap().outcome,
                        crate::ReadOutcome::RemoteCompound { result: actual, user_version: 73, operations, .. }
                        if actual == result && operations.is_empty()));
                    assert_eq!(queue.poll_into(&mut [None]), 0);
                }
            }
        }
    }

    #[test]
    fn compatible_empty_names_are_ordinary_remote_errors_and_strict_names_stay_checked() {
        for write in [false, true] {
            for pool in [
                crate::PoolRoute::Replicated,
                crate::PoolRoute::Erasure(denc::types::ShardId(2)),
            ] {
                let request = || CompoundRequest {
                    target: Target {
                        pool: 7,
                        object: vec![],
                        namespace: b"ns".to_vec(),
                        locator: b"key".to_vec(),
                    },
                    access: if write {
                        Access::ReadWrite
                    } else {
                        Access::Read
                    },
                    context: RequestContext {
                        read_op: (!write).then_some(ReadOpReply::ReturnVector),
                        write_op: write.then_some(crate::WriteOpReply::ReturnVector),
                        ..Default::default()
                    },
                    operations: vec![if write {
                        OsdOp::writefull(b"data".to_vec())
                    } else {
                        OsdOp::read(0, 4)
                    }],
                    max_output_bytes: 4,
                };
                assert!(request().preflight_compatible().is_ok());
                assert_eq!(
                    request().preflight(4096),
                    Err(AdmissionError::InvalidTarget)
                );
                let mut strict = crate::ObjectQueue::new(1, 4096, 7).unwrap();
                assert_eq!(
                    strict.submit_compound(request()).unwrap_err().reason,
                    AdmissionError::InvalidTarget
                );
                let mut queue =
                    crate::ObjectQueue::with_compatible_admission(1, 4096, 0, 7, 1).unwrap();
                let token = queue.submit_compound(request()).unwrap();
                let dispatch = queue
                    .dispatch(
                        token,
                        crate::ReadRoute {
                            direct_read: false,
                            base_pool: 7,
                            osd: 2,
                            session: 3,
                            pg: denc::types::PgT::new(7, 3),
                            hash: 3,
                            epoch: 1,
                            features: 0,
                            generation: 1,
                            pool,
                        },
                    )
                    .unwrap();
                assert!(dispatch.message.oid.is_empty());
                assert_eq!(dispatch.message.pgid.shard, pool.shard());
                assert_eq!(dispatch.message.flags & opwire::flag::PGOP, 0);
                assert_eq!(dispatch.message.oloc.key, b"key");
                let encoded = dispatch.message.encode_version(9, 0).unwrap();
                let decoded =
                    opwire::MOSDOp::decode_shared(9, &encoded.front, &encoded.data).unwrap();
                assert!(decoded.oid.is_empty());
                let mut reply = opwire::MOSDOpReply::for_request(&dispatch.message, 1);
                reply.result = -22;
                reply.user_version = 0;
                reply.flags = u64::from(opwire::flag::ACK);
                assert!(queue.reply(token, 2, 3, reply).unwrap());
                let mut completed = [None];
                assert_eq!(queue.poll_into(&mut completed), 1);
                assert!(matches!(completed[0].take().unwrap().outcome,
                    crate::ReadOutcome::RemoteCompound { result: -22, user_version: 0, operations, .. }
                    if operations.len() == 1 && operations[0].rval == 0));
                assert_eq!(queue.poll_into(&mut [None]), 0);
            }
        }
        for compatible in [false, true] {
            let mut queue = if compatible {
                crate::ObjectQueue::with_compatible_admission(1, 4096, 0, 7, 1).unwrap()
            } else {
                crate::ObjectQueue::new(1, 4096, 7).unwrap()
            };
            let control = crate::ControlRequest {
                target: Target {
                    pool: 7,
                    object: vec![],
                    namespace: vec![],
                    locator: vec![],
                },
                operation: crate::ControlOperation::NotifyAck {
                    cookie: 1,
                    notify_id: 2,
                    response: bytes::Bytes::new(),
                },
            };
            assert_eq!(queue.submit_control(control).is_ok(), compatible);
        }
    }

    #[test]
    fn compatible_class_lookup_keeps_empty_wire_names_server_owned() {
        for (class, method) in [
            (b"".as_slice(), b"method".as_slice()),
            (b"class".as_slice(), b"".as_slice()),
            (b"".as_slice(), b"".as_slice()),
        ] {
            let request = CompoundRequest {
                target: Target {
                    pool: 1,
                    object: b"object".to_vec(),
                    namespace: vec![],
                    locator: vec![],
                },
                access: Access::ReadWrite,
                context: RequestContext {
                    legacy_reply: true,
                    ..Default::default()
                },
                operations: vec![OsdOp::call(class, method, &[])],
                max_output_bytes: 0,
            };
            assert!(request.preflight_compatible().is_ok());
            assert_eq!(
                request.preflight(u64::MAX),
                Err(AdmissionError::InvalidOperation)
            );
            let call = request.operations[0].cls_call().unwrap();
            assert_eq!(call.class, class);
            assert_eq!(call.method, method);
        }
    }

    #[test]
    fn write_version_guards_admit_without_read_access_but_data_reads_do_not() {
        for policy in [
            None,
            Some(WriteOpReply::Legacy),
            Some(WriteOpReply::ReturnVector),
        ] {
            let mut request = CompoundRequest {
                target: Target {
                    pool: 1,
                    object: b"guarded".to_vec(),
                    namespace: Vec::new(),
                    locator: Vec::new(),
                },
                access: Access::Write,
                context: RequestContext {
                    write_op: policy,
                    ..Default::default()
                },
                operations: vec![
                    OsdOp::assert_version(7),
                    OsdOp::writefull(b"data".to_vec()),
                    OsdOp::assert_version(7),
                ],
                max_output_bytes: 0,
            };
            assert_eq!(request.preflight_compatible(), Ok(4));
            assert!(request.preflight(u64::MAX).is_ok());
            request.operations[0] = OsdOp::read(0, 1);
            assert_eq!(
                request.preflight_compatible(),
                Err(AdmissionError::InvalidOperation)
            );
            request.operations[0] = OsdOp::assert_version(7);
            let mut queue = crate::ObjectQueue::new(1, u64::MAX, 1).unwrap();
            let token = queue.submit_compound(request).unwrap();
            let flags = queue.request_flags(token).unwrap();
            assert_ne!(flags & opwire::flag::WRITE, 0);
            assert_eq!(flags & opwire::flag::READ, 0);
        }
    }

    #[test]
    fn legacy_call_accepts_a_version_guard_without_widening_other_prefixes() {
        let mut request = CompoundRequest {
            target: Target {
                pool: 1,
                object: b"object".to_vec(),
                namespace: vec![],
                locator: vec![],
            },
            access: Access::Read,
            context: RequestContext {
                legacy_reply: true,
                ..Default::default()
            },
            operations: vec![
                OsdOp::assert_version(7),
                OsdOp::call(b"rbd", b"get_size", &[]),
            ],
            max_output_bytes: 64,
        };
        assert_eq!(request.validate(), Ok(()));
        request.operations[0] = OsdOp::read(0, 4);
        assert_eq!(request.validate(), Err(AdmissionError::InvalidOperation));
    }

    #[test]
    fn dirty_and_cache_read_controls_preserve_admission_guards() {
        for opcode in [
            op::ISDIRTY,
            op::CACHE_FLUSH,
            op::CACHE_TRY_FLUSH,
            op::CACHE_EVICT,
            op::TIER_FLUSH,
            op::TIER_EVICT,
        ] {
            let mut request = CompoundRequest {
                target: Target {
                    pool: 1,
                    object: b"control".to_vec(),
                    namespace: vec![],
                    locator: vec![],
                },
                access: Access::Read,
                context: RequestContext {
                    read_op: Some(ReadOpReply::Legacy),
                    ..Default::default()
                },
                operations: vec![OsdOp::new(opcode)],
                max_output_bytes: 1,
            };
            assert_eq!(request.validate(), Ok(()));
            assert!(!request.is_write());
            request.access = Access::Write;
            assert_eq!(request.validate(), Err(AdmissionError::InvalidOperation));
            request.access = Access::Read;
            request.operations[0].indata = vec![1].into();
            assert_eq!(request.validate(), Err(AdmissionError::InvalidOperation));
            request.operations[0].indata = Default::default();
            request.operations[0].flags = 1 << 31;
            assert!(request.validate().is_err());
            request.operations[0].flags = 0;
            request.context.snapid = 7;
            assert_eq!(request.validate(), Ok(()));
            request.context.snap_sequence = 1;
            assert_eq!(request.validate(), Err(AdmissionError::InvalidSnapshot));
            request.context.snap_sequence = 0;
            request.context.legacy_reply = true;
            assert!(request.validate().is_err());
        }
    }

    #[test]
    fn set_chunk_is_a_validated_read_only_cache_operation() {
        use denc::Encode;
        let locator = denc::types::ObjectLocator {
            pool: 7,
            key: b"key".to_vec(),
            nspace: b"target-ns".to_vec(),
            hash: -1,
        };
        let mut encoder = denc::Encoder::new();
        3u64.encode(&mut encoder).unwrap();
        19u64.encode(&mut encoder).unwrap();
        locator.encode(&mut encoder).unwrap();
        encoder.bytes(b"target-object").unwrap();
        41u64.encode(&mut encoder).unwrap();
        let mut request = CompoundRequest {
            target: Target {
                pool: 1,
                object: b"source".to_vec(),
                namespace: vec![],
                locator: vec![],
            },
            access: Access::Read,
            context: RequestContext {
                read_op: Some(ReadOpReply::Legacy),
                ..Default::default()
            },
            operations: vec![OsdOp {
                op: op::SET_CHUNK,
                flags: opflag::FADVISE_RANDOM,
                indata: encoder.into_vec().into(),
                ..Default::default()
            }],
            max_output_bytes: 0,
        };
        assert_eq!(request.validate(), Ok(()));
        assert!(!request.is_write());
        request.operations[0].flags = 0x80;
        assert_eq!(request.validate(), Err(AdmissionError::InvalidOperation));
        request.operations[0].flags = opflag::FADVISE_RANDOM;
        request.access = Access::Write;
        assert_eq!(request.validate(), Err(AdmissionError::InvalidOperation));
        request.access = Access::Read;
        request.operations[0].indata = vec![0; 12].into();
        assert_eq!(request.validate(), Err(AdmissionError::InvalidOperation));
    }

    #[test]
    fn tmap_update_is_read_modify_write_with_explicit_write_policy() {
        for policy in [None, Some(WriteOpReply::Legacy)] {
            let mut operation = OsdOp::new(op::TMAPUP);
            operation.indata = vec![0, 255].into(); // Command parsing belongs to OSD.
            let mut request = CompoundRequest {
                target: Target {
                    pool: 1,
                    object: b"tmap".to_vec(),
                    namespace: vec![],
                    locator: vec![],
                },
                access: Access::ReadWrite,
                context: RequestContext {
                    write_op: policy,
                    ..Default::default()
                },
                operations: vec![operation],
                max_output_bytes: 0,
            };
            assert_eq!(request.validate(), Ok(()));
            for access in [Access::Read, Access::Write] {
                request.access = access;
                assert!(request.validate().is_err());
            }
            request.access = Access::ReadWrite;
            request.context.snapid = 7;
            assert_eq!(request.validate(), Err(AdmissionError::InvalidSnapshot));
            request.context.snapid = opwire::NOSNAP;
            request.operations[0].flags = 1 << 31;
            assert!(request.validate().is_err());
        }
    }
    #[test]
    fn write_controls_require_write_access_and_preserve_policy_guards() {
        for operation in [
            OsdOp::rollback(7),
            OsdOp::omap_set_header(vec![]),
            OsdOp::omap_set_header(vec![0, 255, 7]),
            OsdOp::new(op::UNDIRTY),
            OsdOp::new(op::TIER_PROMOTE),
            OsdOp::new(op::UNSET_MANIFEST),
        ] {
            let mut request = CompoundRequest {
                target: Target {
                    pool: 1,
                    object: b"control".to_vec(),
                    namespace: vec![],
                    locator: vec![],
                },
                access: Access::Write,
                context: RequestContext::default(),
                operations: vec![operation],
                max_output_bytes: 0,
            };
            assert_eq!(request.validate(), Ok(()));
            request.context.write_op = Some(WriteOpReply::Legacy);
            assert_eq!(request.validate(), Ok(()));
            request.access = Access::ReadWrite;
            assert_eq!(request.validate(), Ok(()));
            request.access = Access::Read;
            assert!(request.validate().is_err());
            request.context.write_op = None;
            assert!(request.validate().is_err());
            request.access = Access::Write;
            request.context.snapid = 7;
            assert_eq!(request.validate(), Err(AdmissionError::InvalidSnapshot));
            request.context.snapid = opwire::NOSNAP;
            request.operations[0].flags = 1 << 31;
            assert!(request.validate().is_err());
            request.operations[0].flags = 0;
            request.operations[0].op = 0xffff;
            assert_eq!(
                request.validate(),
                Err(AdmissionError::UnsupportedOperation)
            );
        }
    }
}
impl Access {
    pub(crate) fn reads(self) -> bool {
        self != Self::Write
    }
    pub(crate) fn writes(self) -> bool {
        self != Self::Read
    }
}

/// Bounded C write-operation reply policy (spec140/158).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOpReply {
    Legacy,
    ReturnVector,
}

/// Explicit C read-operation reply policy (spec158).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadOpReply {
    Legacy,
    ReturnVector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    /// Private guard captured by a control API builder, not a caller operation.
    /// Zero means absent. Only contextual control submissions may set this.
    pub control_assert_version: u64,
    pub snapid: u64,
    pub snap_sequence: u64,
    pub snapshots: Vec<u64>,
    pub mtime: UTime,
    /// Captured fullness policy; explicit pre-dispatch setter may override.
    pub full_policy: crate::FullPolicy,
    /// Additional translated OSD request flags supplied by C++ operations.
    /// These are ORed with the Rust client's required access flags.
    pub osd_flags: u32,
    /// Captured client-wide replica policy; caller flags remain independent.
    pub read_policy: crate::ReplicaReadPolicy,
    /// Whether read routing must preserve authoritative object-version publication.
    pub read_version_required: bool,
    /// Exec-specific IoCtx policy masks replica flags after caller/global combination.
    pub mask_replica_reads: bool,
    /// Legacy C exec wire mode: the single CALL goes out without RETURNVEC,
    /// so the server suppresses mutation output and successful status.
    pub legacy_reply: bool,
    /// Select the bounded C write-operation API with WRITE-only map policy,
    /// independently of read guards permitted by Access::ReadWrite.
    /// None preserves native behavior; mutually exclusive with legacy_reply.
    pub write_op: Option<WriteOpReply>,
    /// C read-vector wire policy; arbitrary CALL methods remain server-authoritative.
    pub read_op: Option<ReadOpReply>,
}
impl Default for RequestContext {
    fn default() -> Self {
        Self {
            control_assert_version: 0,
            snapid: opwire::NOSNAP,
            snap_sequence: 0,
            snapshots: vec![],
            mtime: UTime::default(),
            full_policy: crate::FullPolicy::Wait,
            osd_flags: 0,
            read_policy: crate::ReplicaReadPolicy::Default,
            read_version_required: true,
            mask_replica_reads: false,
            legacy_reply: false,
            write_op: None,
            read_op: None,
        }
    }
}

/// Ordered immutable object transaction. Result output cap is explicit native policy,
/// not a server setting. Native CALL admission follows pinned_class_access;
/// explicit C read policy delegates class classification to the server.
#[derive(Debug)]
pub struct CompoundRequest {
    pub target: Target,
    pub access: Access,
    pub context: RequestContext,
    pub operations: Vec<OsdOp>,
    pub max_output_bytes: u32,
}

#[derive(Debug)]
pub struct RejectedCompound {
    pub reason: AdmissionError,
    pub request: CompoundRequest,
}

#[derive(Clone, Copy)]
enum ValidationPolicy {
    Strict,
    Compatible,
}

/// Reply shape of one operation whose request was sent in full. The ordinary compound path and the EC split path must
/// publish exactly the same shapes, so both validate through this one rule. `direct_read` accepts a placed READ whose
/// extent describes the destination rather than the returned data; `legacy_call` accepts the legacy CALL reply that
/// suppresses its data on a successful mutation.
pub(crate) fn op_reply_shape_valid(
    requested: &OsdOp,
    returned: &OsdOp,
    result: i32,
    direct_read: bool,
    legacy_call: bool,
) -> bool {
    if returned.op != requested.op
        && !(requested.op == op::ZERO
            && returned.op == op::TRUNCATE
            && requested.extent().length > 0
            && returned.u == requested.u
            && returned.rval <= 0
            && returned.outdata.is_empty())
    {
        return false;
    }
    if returned.flags != requested.flags {
        return false;
    }
    if returned.rval < 0 {
        return true;
    }
    // An early server error can echo an unexecuted request descriptor.
    if result < 0 && returned.rval == 0 && returned.outdata.is_empty() && returned.u == requested.u
    {
        return true;
    }
    let returned_extent = returned.extent();
    let requested_extent = requested.extent();
    match requested.op {
        op::READ | op::SYNC_READ => {
            returned_extent.offset == requested_extent.offset
                && if direct_read {
                    returned_extent.length <= requested_extent.length
                        && returned_extent.length >= returned.outdata.len() as u64
                } else {
                    returned_extent.length == returned.outdata.len() as u64
                }
                && (requested_extent.length == 0
                    || returned.outdata.len() as u64 <= requested_extent.length)
                && returned_extent
                    .offset
                    .checked_add(returned_extent.length)
                    .is_some()
        }
        op::CALL => {
            returned_extent.length == returned.outdata.len() as u64
                || (legacy_call && result == 0 && returned.outdata.is_empty())
        }
        op::SPARSE_READ => {
            returned_extent.offset == requested_extent.offset
                && denc::from_slice::<opwire::SparseReadView<'_>>(&returned.outdata).is_ok_and(
                    |view| {
                        (if direct_read {
                            returned_extent.length <= requested_extent.length
                                && returned_extent.length >= view.data().len() as u64
                        } else {
                            returned_extent.length == view.data().len() as u64
                        }) && view
                            .validate_range(
                                requested_extent.offset,
                                if direct_read {
                                    returned_extent.length
                                } else {
                                    requested_extent.length
                                },
                            )
                            .is_ok()
                    },
                )
        }
        op::WRITE
        | op::WRITEFULL
        | op::APPEND
        | op::ZERO
        | op::TRUNCATE
        | op::TRIMTRUNC
        | op::DELETE
        | op::CREATE => returned.outdata.is_empty(),
        _ => true,
    }
}

impl CompoundRequest {
    /// Logical operation bytes under the explicit compatible queue policy.
    /// Excludes declared reply capacity and retained metadata; callers still
    /// validate API/operations/actual frames independently.
    pub fn logical_byte_charge(&self) -> Result<u64, AdmissionError> {
        self.operations.iter().try_fold(0u64, |total, operation| {
            total
                .checked_add(crate::admission::logical_operation_bytes(operation)?)
                .ok_or(AdmissionError::NoCredit)
        })
    }
    /// Validate immutable submission arguments and return logical operation bytes.
    /// A soft aggregate target is not a permanent single-request ceiling; native
    /// queue/session admission remains separate and consumes no identity here.
    /// Write snapshot-context semantics are server-owned under this policy.
    pub fn preflight_compatible(&self) -> Result<u64, AdmissionError> {
        if !valid_target(&self.target, true) {
            return Err(AdmissionError::InvalidTarget);
        }
        self.validate_compatible()?;
        self.logical_byte_charge()
    }
    /// Validate immutable submission arguments and permanent byte capacity
    /// without consuming native identity, slots or mutable owner state.
    pub fn preflight(&self, byte_limit: u64) -> Result<u64, AdmissionError> {
        if !valid_target(&self.target, false) {
            return Err(AdmissionError::InvalidTarget);
        }
        self.validate()?;
        let charge = target_charge(&self.target, self.charge()).ok_or(AdmissionError::NoCredit)?;
        crate::ByteAdmission::strict(byte_limit)
            .check_request(charge)
            .map_err(|_| AdmissionError::NoCredit)?;
        Ok(charge)
    }
    pub(crate) fn is_write(&self) -> bool {
        self.access.writes()
            || ((self.context.read_op.is_some() || self.context.legacy_reply)
                && self.operations.iter().any(|operation| {
                    operation.op == op::CALL
                        && operation.cls_call().map_or(true, |call| {
                            crate::pinned_class_access(call.class, call.method) != Access::Read
                        })
                }))
    }
    pub(crate) fn charge(&self) -> Option<u64> {
        let base = u64::from(self.max_output_bytes)
            .checked_add(
                (self.operations.capacity() as u64).checked_mul(size_of::<OsdOp>() as u64)?,
            )?
            .checked_add((self.context.snapshots.capacity() as u64).checked_mul(8)?)?;
        self.operations
            .iter()
            .try_fold(base, |n, o| n.checked_add(o.indata_len() as u64))
    }

    pub(crate) fn validate(&self) -> Result<(), AdmissionError> {
        self.validate_with_policy(ValidationPolicy::Strict)
    }
    pub(crate) fn validate_compatible(&self) -> Result<(), AdmissionError> {
        self.validate_with_policy(ValidationPolicy::Compatible)
    }
    fn validate_with_policy(&self, policy: ValidationPolicy) -> Result<(), AdmissionError> {
        let invalid = AdmissionError::InvalidOperation;
        if self.context.control_assert_version != 0 {
            return Err(invalid);
        }
        if self.context.read_op.is_some()
            && (self.access != Access::Read
                || self.context.legacy_reply
                || self.context.write_op.is_some())
        {
            return Err(invalid);
        }
        if (self.operations.is_empty() && matches!(policy, ValidationPolicy::Strict))
            || self.operations.len() > u16::MAX as usize
        {
            return Err(invalid);
        }
        // C write-operation policy gate (spec140): mutually exclusive with
        // legacy_reply, write-capable access only, bounded operation allowlist.
        // Normal operation/access/extent/snapshot/per-op validation follows.
        if self.context.write_op.is_some()
            && (self.context.legacy_reply
                || !self.access.writes()
                || self.operations.iter().any(|o| {
                    !matches!(
                        o.op,
                        op::WRITE
                            | op::WRITEFULL
                            | op::APPEND
                            | op::TMAPUP
                            | op::ZERO
                            | op::TRUNCATE
                            | op::DELETE
                            | op::CREATE
                            | op::WRITESAME
                            | op::SETXATTR
                            | op::RMXATTR
                            | op::CMPXATTR
                            | op::ASSERT_VER
                            | op::STAT
                            | op::CMPEXT
                            | op::OMAP_CMP
                            | op::OMAP_SET_VALS
                            | op::OMAP_SET_HEADER
                            | op::OMAP_CLEAR
                            | op::OMAP_RM_KEYS
                            | op::OMAP_RM_KEY_RANGE
                            | op::SET_ALLOC_HINT
                            | op::CACHE_PIN
                            | op::CACHE_UNPIN
                            | op::ROLLBACK
                            | op::UNDIRTY
                            | op::TIER_PROMOTE
                            | op::UNSET_MANIFEST
                            | op::COPY_FROM
                            | op::COPY_FROM2
                            | op::SET_REDIRECT
                            | op::CALL
                    )
                }))
        {
            return Err(invalid);
        }
        if (self.access.writes() && self.context.snapid != opwire::NOSNAP)
            || (!self.access.writes()
                && (self.context.snap_sequence != 0 || !self.context.snapshots.is_empty()))
            || (matches!(policy, ValidationPolicy::Compatible)
                && u32::try_from(self.context.snapshots.len()).is_err())
            // Compatible writes carry the submitted context unchanged. Its
            // effective semantics belong to the server, which may replace/filter
            // it before validation (explicit-write-snapshot-contract.md).
            || (matches!(policy, ValidationPolicy::Strict)
                && (self.context.snapshots.first().is_some_and(|&s| s > self.context.snap_sequence)
                    || self.context.snapshots.windows(2).any(|s| s[0] <= s[1])
                    || self.context.snap_sequence >= opwire::NOSNAP
                    || self.context.snapshots.iter().any(|&s| s >= opwire::NOSNAP)))
        {
            return Err(AdmissionError::InvalidSnapshot);
        }
        if self.context.legacy_reply
            && !matches!(self.operations.as_slice(), [call] if call.op == op::CALL)
            && !matches!(self.operations.as_slice(), [guard, call] if guard.op == op::ASSERT_VER && call.op == op::CALL)
        {
            return Err(invalid);
        }
        let mut total = 0u64;
        for o in &self.operations {
            let supported = matches!(
                o.op,
                op::READ
                    | op::SYNC_READ
                    | op::MAPEXT
                    | op::SPARSE_READ
                    | op::STAT
                    | op::ISDIRTY
                    | op::CACHE_FLUSH
                    | op::CACHE_TRY_FLUSH
                    | op::CACHE_EVICT
                    | op::TIER_FLUSH
                    | op::TIER_EVICT
                    | op::ASSERT_VER
                    | op::LIST_SNAPS
                    | op::LIST_WATCHERS
                    | op::SET_CHUNK
                    | op::CHECKSUM
                    | op::CMPEXT
                    | op::WRITE
                    | op::WRITEFULL
                    | op::APPEND
                    | op::TMAPUP
                    | op::ZERO
                    | op::TRUNCATE
                    | op::TRIMTRUNC
                    | op::DELETE
                    | op::CREATE
                    | op::ROLLBACK
                    | op::WRITESAME
                    | op::SET_ALLOC_HINT
                    | op::CACHE_PIN
                    | op::CACHE_UNPIN
                    | op::UNDIRTY
                    | op::TIER_PROMOTE
                    | op::UNSET_MANIFEST
                    | op::COPY_FROM
                    | op::COPY_FROM2
                    | op::SET_REDIRECT
                    | op::GETXATTR
                    | op::GETXATTRS
                    | op::CMPXATTR
                    | op::SETXATTR
                    | op::RMXATTR
                    | op::OMAP_GET_KEYS
                    | op::OMAP_GET_VALS
                    | op::OMAP_GET_HEADER
                    | op::OMAP_GET_VALS_BY_KEYS
                    | op::OMAP_CMP
                    | op::OMAP_SET_VALS
                    | op::OMAP_SET_HEADER
                    | op::OMAP_CLEAR
                    | op::OMAP_RM_KEYS
                    | op::OMAP_RM_KEY_RANGE
                    | op::CALL
            );
            if !supported {
                return Err(AdmissionError::UnsupportedOperation);
            }
            if o.flags
                & !(opflag::EXCL
                    | opflag::FAILOK
                    | opflag::FADVISE_RANDOM
                    | opflag::FADVISE_SEQUENTIAL
                    | opflag::FADVISE_WILLNEED
                    | opflag::FADVISE_DONTNEED
                    | opflag::FADVISE_NOCACHE)
                != 0
                || !o.outdata.is_empty()
                || o.rval != 0
                || o.indata_len() > u32::MAX as usize
            {
                return Err(invalid);
            }
            total = total.checked_add(o.indata_len() as u64).ok_or(invalid)?;
            if total > u64::from(u32::MAX) {
                return Err(invalid);
            }
            // ASSERT_VER is a write guard too: its wire read mode does not
            // require promoting a write transaction to data-read access.
            if o.op == op::CALL {
                let call = o.cls_call().map_err(|_| invalid)?;
                let reader = crate::pinned_class_access(call.class, call.method) == Access::Read;
                if !self.access.reads()
                    || (!reader
                        && !self.access.writes()
                        && self.context.read_op.is_none()
                        && !self.context.legacy_reply)
                {
                    return Err(invalid);
                }
                if matches!(policy, ValidationPolicy::Strict)
                    && (call.class.is_empty() || call.method.is_empty())
                {
                    return Err(invalid);
                }
            } else if (opwire::reads(o.op) && o.op != op::ASSERT_VER && !self.access.reads())
                || (opwire::modifies(o.op) && !self.access.writes())
            {
                return Err(invalid);
            }
            match o.op {
                op::ISDIRTY
                | op::CACHE_FLUSH
                | op::CACHE_TRY_FLUSH
                | op::CACHE_EVICT
                | op::TIER_FLUSH
                | op::TIER_EVICT => {
                    if !self.access.reads() || !o.indata.is_empty() {
                        return Err(invalid);
                    }
                }
                op::SET_CHUNK => {
                    if self.access != Access::Read || decode_set_chunk(&o.indata).is_err() {
                        return Err(invalid);
                    }
                }
                op::READ | op::SYNC_READ | op::MAPEXT | op::SPARSE_READ => {
                    let e = o.extent();
                    if e.offset.checked_add(e.length).is_none() || !o.indata.is_empty() {
                        return Err(AdmissionError::InvalidExtent);
                    }
                }
                op::WRITE | op::WRITEFULL | op::APPEND | op::CMPEXT => {
                    let e = o.extent();
                    if e.length != o.indata_len() as u64 || e.offset.checked_add(e.length).is_none()
                    {
                        return Err(AdmissionError::InvalidExtent);
                    }
                }
                op::ZERO | op::TRUNCATE | op::TRIMTRUNC => {
                    let e = o.extent();
                    if e.offset.checked_add(e.length).is_none() {
                        return Err(AdmissionError::InvalidExtent);
                    }
                }
                op::WRITESAME => {
                    let e = o.write_same();
                    if e.data_length == 0
                        || e.length % e.data_length != 0
                        || e.data_length != o.indata_len() as u64
                        || e.offset.checked_add(e.length).is_none()
                    {
                        return Err(AdmissionError::InvalidExtent);
                    }
                }
                op::GETXATTR | op::GETXATTRS | op::SETXATTR | op::RMXATTR | op::CMPXATTR
                    if o.op != op::GETXATTRS =>
                {
                    let x = o.xattr();
                    let len = u64::from(x.name_len) + u64::from(x.value_len);
                    if len != o.indata_len() as u64
                        || (matches!(o.op, op::GETXATTR | op::RMXATTR) && x.value_len != 0)
                    {
                        return Err(invalid);
                    }
                    o.xattr_name_value().map_err(|_| invalid)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn decode_set_chunk(bytes: &[u8]) -> Result<(), denc::Error> {
    use denc::Decode;
    let mut decoder = denc::Decoder::new(bytes);
    let _source_offset = decoder.u64()?;
    let _source_length = decoder.u64()?;
    let locator = denc::types::ObjectLocator::decode(&mut decoder)?;
    let _object = decoder.bytes()?;
    let _target_offset = decoder.u64()?;
    if locator.pool < 0 || !decoder.is_empty() {
        return Err(denc::Error::BadValue("set-chunk target"));
    }
    Ok(())
}
