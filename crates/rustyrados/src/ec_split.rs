// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! EC split ownership and assembly (ec-split-{version,merge}-contract.md).
use crate::{DriverError, ReadDispatch, ReadRoute, RequestToken};
use bytes::Bytes;
use denc::types::{Eversion, ShardId};
use opwire::{MOSDOpReply, OsdOp, flag, op};
use std::collections::BTreeMap;

/// Map-derived geometry and canonical acting slots, not OSD-id-sorted positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcReadLayout {
    pub chunk_size: u64,
    pub pool_size: u8,
    pub raw_to_shard: Vec<ShardId>,
    pub acting: Vec<i32>,
}
#[derive(Debug)]
struct Child {
    shard: ShardId,
    osd: i32,
    indices: Vec<usize>,
    dispatch: Option<ReadDispatch>,
    accepted: bool,
    reply: Option<MOSDOpReply>,
}
#[derive(Debug)]
pub struct EcSplitRead {
    parent: ReadDispatch,
    layout: EcReadLayout,
    children: Vec<Child>,
    reference: usize,
    raw_to_child: Vec<Option<usize>>,
}
/// Only a completed, verified split can construct this publication capability.
#[derive(Debug)]
pub struct EcSplitCompletion {
    pub(crate) token: RequestToken,
    pub(crate) route: ReadRoute,
    pub(crate) attempt: i32,
    pub(crate) result: i32,
    pub(crate) user_version: u64,
    pub(crate) replay_version: Eversion,
    pub(crate) operations: Vec<OsdOp>,
}
#[derive(Debug)]
pub enum EcSplitResult {
    Retry,
    Complete(EcSplitCompletion),
}
struct Versions<'a> {
    entries: &'a [u8],
}
impl<'a> Versions<'a> {
    fn parse(bytes: &'a [u8], max_shards: usize) -> Result<Self, DriverError> {
        let invalid = DriverError::InvalidReply;
        let count = u32::from_le_bytes(bytes.get(..4).ok_or(invalid)?.try_into().unwrap()) as usize;
        let entries = bytes.get(4..).ok_or(invalid)?;
        if count > max_shards || count.checked_mul(13) != Some(entries.len()) {
            return Err(invalid);
        }
        let mut previous = None;
        for entry in entries.as_chunks::<13>().0 {
            let key = entry[0] as i8;
            if previous.is_some_and(|old| old >= key) {
                return Err(invalid);
            }
            previous = Some(key);
        }
        Ok(Self { entries })
    }
    fn get(&self, shard: ShardId) -> Option<Eversion> {
        let mut low = 0;
        let mut high = self.entries.len() / 13;
        while low < high {
            let mid = low + (high - low) / 2;
            let entry = &self.entries[mid * 13..][..13];
            match (entry[0] as i8).cmp(&shard.0) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => {
                    return Some(Eversion {
                        version: u64::from_le_bytes(entry[1..9].try_into().unwrap()),
                        epoch: u32::from_le_bytes(entry[9..13].try_into().unwrap()),
                    });
                }
            }
        }
        None
    }
}

impl EcSplitRead {
    #[expect(
        clippy::result_large_err,
        reason = "Ineligible optimization returns caller-owned dispatch without allocation"
    )]
    pub fn new(parent: ReadDispatch, layout: EcReadLayout) -> Result<Self, ReadDispatch> {
        let Some((children, reference)) = Self::plan(&parent, &layout) else {
            return Err(parent);
        };
        let raw_to_child = layout
            .raw_to_shard
            .iter()
            .map(|shard| {
                children
                    .binary_search_by_key(&shard.0, |child| child.shard.0)
                    .ok()
            })
            .collect();
        Ok(Self {
            parent,
            layout,
            children,
            reference,
            raw_to_child,
        })
    }
    fn plan(parent: &ReadDispatch, layout: &EcReadLayout) -> Option<(Vec<Child>, usize)> {
        let read = parent.read_routing();
        let flags = parent.message.flags;
        let primary = parent.route.pool.shard();
        let primary_slot = usize::try_from(primary.0).ok()?;
        let k = layout.raw_to_shard.len();
        if parent.route.direct_read
            || primary.0 < 0
            || layout.chunk_size == 0
            || k == 0
            || k > usize::from(layout.pool_size)
            || layout.acting.get(primary_slot).copied() != Some(parent.route.osd)
            || !read.split_eligible(flags)
        {
            return None;
        }
        let mut indices = BTreeMap::<i8, Vec<usize>>::new();
        let mut used_raw = BTreeMap::<i8, usize>::new();
        let mut data = false;
        for (index, operation) in parent.message.ops.iter().enumerate() {
            match operation.op {
                op::READ | op::SPARSE_READ => {
                    let extent = operation.extent();
                    if extent.length == 0 {
                        return None;
                    }
                    let end = extent.offset.checked_add(extent.length - 1)?;
                    let first = extent.offset / layout.chunk_size;
                    let count = (end / layout.chunk_size - first + 1).min(k as u64);
                    for delta in 0..count {
                        let raw = ((first % k as u64 + delta) % k as u64) as usize;
                        let shard = layout.raw_to_shard[raw].0;
                        if shard < 0 || shard as usize >= usize::from(layout.pool_size) {
                            return None;
                        }
                        if used_raw
                            .insert(shard, raw)
                            .is_some_and(|previous| previous != raw)
                        {
                            return None;
                        }
                        indices.entry(shard).or_default().push(index);
                    }
                    data = true;
                }
                code if crate::is_primary_only_split_read(code) => {
                    indices.entry(primary.0).or_default().push(index);
                }
                _ => return None,
            }
        }
        if !data {
            return None;
        }
        // The reference is authoritative even for a vector of individually
        // single-chunk reads on several non-primary data shards.
        indices.entry(primary.0).or_default();
        let reference = indices.keys().position(|&shard| shard == primary.0)?;
        let children = indices
            .into_iter()
            .map(|(shard, indices)| {
                let osd = *layout.acting.get(shard as usize)?;
                // One trailing version query must also fit the wire's op count.
                if osd < 0 || indices.len() >= u16::MAX as usize {
                    return None;
                }
                Some(Child {
                    shard: ShardId(shard),
                    osd,
                    indices,
                    dispatch: None,
                    accepted: false,
                    reply: None,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some((children, reference))
    }
    pub fn layout(&self) -> &EcReadLayout {
        &self.layout
    }
    pub fn child_outstanding(&self, index: usize) -> bool {
        self.children
            .get(index)
            .is_some_and(|child| child.accepted && child.reply.is_none())
    }
    pub fn token(&self) -> RequestToken {
        self.parent.token
    }
    pub fn child_count(&self) -> usize {
        self.children.len()
    }
    pub fn child_target(&self, index: usize) -> Option<(i32, ShardId)> {
        self.children
            .get(index)
            .map(|child| (child.osd, child.shard))
    }
    pub fn child_dispatch(&self, index: usize) -> Option<&ReadDispatch> {
        self.children.get(index)?.dispatch.as_ref()
    }
    pub fn child_sent(&self, index: usize) -> bool {
        self.children.get(index).is_some_and(|child| child.accepted)
    }
    pub fn all_sent(&self) -> bool {
        self.children.iter().all(|child| child.accepted)
    }
    pub fn wire_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.children
            .iter()
            .filter_map(|child| child.dispatch.as_ref().map(ReadDispatch::wire_tid))
    }
    pub fn mark_sent(&mut self, index: usize) -> Result<(), DriverError> {
        let child = self.children.get_mut(index).ok_or(DriverError::Stale)?;
        if child.dispatch.is_none() || child.accepted || child.reply.is_some() {
            return Err(DriverError::Stale);
        }
        child.accepted = true;
        Ok(())
    }
}

impl EcSplitRead {
    pub fn prepare_child(
        &mut self,
        queue: &mut crate::ReadQueue,
        index: usize,
        route: ReadRoute,
    ) -> Result<u64, DriverError> {
        let child = self.children.get(index).ok_or(DriverError::Stale)?;
        if !route.direct_read
            || route.pool != crate::PoolRoute::Erasure(child.shard)
            || route.osd != child.osd
            || route.pg != self.parent.route.pg
            || route.hash != self.parent.route.hash
            || route.base_pool != self.parent.route.base_pool
            || route.generation < self.parent.route.generation
            || route.epoch < self.parent.route.epoch
        {
            return Err(DriverError::Stale);
        }
        if let Some(dispatch) = &child.dispatch {
            if child.accepted || child.reply.is_some() {
                return Err(DriverError::Stale);
            }
            let wire_tid = dispatch.wire_tid();
            let dispatch = self.children[index].dispatch.as_mut().unwrap();
            dispatch.route = route;
            dispatch.message.osdmap_epoch = route.epoch;
            dispatch.message.features = route.features;
            return Ok(wire_tid);
        }
        let mut operations = child
            .indices
            .iter()
            .map(|&index| self.parent.message.ops[index].clone())
            .collect::<Vec<_>>();
        operations.push(OsdOp::new(op::GET_INTERNAL_VERSIONS));
        let wire_tid = queue.allocate_split_tid(&self.parent)?;
        let metadata_bytes = 4 + u64::from(self.layout.pool_size) * (1 + 8 + 4);
        let dispatch = self.parent.split_dispatch(
            route,
            wire_tid,
            operations,
            index == self.reference,
            metadata_bytes,
        )?;
        self.children[index].dispatch = Some(dispatch);
        Ok(wire_tid)
    }
    pub fn rearm_child(&mut self, index: usize) -> Result<(), DriverError> {
        let child = self.children.get_mut(index).ok_or(DriverError::Stale)?;
        if child.reply.is_some() || !child.accepted {
            return Ok(());
        }
        let dispatch = child.dispatch.as_mut().ok_or(DriverError::Stale)?;
        dispatch.message.retry_attempt = dispatch
            .message
            .retry_attempt
            .checked_add(1)
            .ok_or(DriverError::RetryExhausted)?;
        dispatch.message.flags |= flag::RETRY;
        child.accepted = false;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcChildProgress {
    Pending,
    Ready,
    Redirect,
}
impl EcSplitRead {
    pub fn receive_child(
        &mut self,
        index: usize,
        wire_tid: u64,
        osd: i32,
        session: u64,
        reply: MOSDOpReply,
    ) -> Result<EcChildProgress, DriverError> {
        let child = self.children.get_mut(index).ok_or(DriverError::Stale)?;
        let dispatch = child.dispatch.as_ref().ok_or(DriverError::Stale)?;
        if !child.accepted
            || dispatch.wire_tid() != wire_tid
            || dispatch.route.osd != osd
            || dispatch.route.session != session
            || dispatch.message.retry_attempt != reply.retry_attempt
        {
            return Err(DriverError::Stale);
        }
        if child.reply.is_some() {
            return Ok(EcChildProgress::Pending);
        }
        let request = &dispatch.message;
        if reply.oid != request.oid || reply.pgid != request.pgid.pgid {
            return Err(DriverError::InvalidReply);
        }
        if reply.redirect.is_some() {
            return Ok(EcChildProgress::Redirect);
        }
        let size = reply.ops.iter().try_fold(0u64, |size, operation| {
            size.checked_add(operation.outdata.len() as u64)
        });
        if reply.ops.len() != request.ops.len()
            || reply.flags & u64::from(flag::ACK | flag::ONDISK) == 0
            || size.is_none_or(|size| size > dispatch.max_reply_data())
        {
            return Err(DriverError::InvalidReply);
        }
        for (actual, expected) in reply.ops.iter().zip(&request.ops) {
            if actual.op != expected.op || actual.flags != expected.flags {
                return Err(DriverError::InvalidReply);
            }
            if actual.rval < 0 {
                continue;
            }
            if reply.result < 0
                && actual.rval == 0
                && actual.outdata.is_empty()
                && actual.u == expected.u
            {
                continue;
            }
            let requested = expected.extent();
            let returned = actual.extent();
            match expected.op {
                op::READ | op::SPARSE_READ => {
                    if actual.rval != 0
                        || returned.offset != requested.offset
                        || returned.length > requested.length
                        || returned.offset.checked_add(returned.length).is_none()
                    {
                        return Err(DriverError::InvalidReply);
                    }
                    if expected.op == op::READ {
                        if actual.outdata.len() as u64 > returned.length {
                            return Err(DriverError::InvalidReply);
                        }
                    } else {
                        let view = denc::from_slice::<opwire::SparseReadView<'_>>(&actual.outdata)
                            .map_err(|_| DriverError::InvalidReply)?;
                        if view.data().len() as u64 > returned.length
                            || view
                                .validate_range(returned.offset, returned.length)
                                .is_err()
                        {
                            return Err(DriverError::InvalidReply);
                        }
                        for (offset, length) in view.extents() {
                            let first = offset / self.layout.chunk_size;
                            let end = offset
                                .checked_add(length)
                                .ok_or(DriverError::InvalidReply)?;
                            if length == 0 {
                                continue;
                            }
                            if (end - 1) / self.layout.chunk_size != first
                                || self.layout.raw_to_shard
                                    [(first % self.layout.raw_to_shard.len() as u64) as usize]
                                    != child.shard
                            {
                                return Err(DriverError::InvalidReply);
                            }
                        }
                    }
                }
                op::GET_INTERNAL_VERSIONS => {
                    if actual.rval != 0 || actual.u != expected.u {
                        return Err(DriverError::InvalidReply);
                    }
                    Versions::parse(&actual.outdata, usize::from(self.layout.pool_size))?;
                }
                // Primary-only operations are published from the reference child, so their shape must be the one the
                // ordinary compound path accepts. A split is always a read: legacy CALL suppression never applies.
                _ => {
                    if !crate::compound::op_reply_shape_valid(
                        expected,
                        actual,
                        reply.result,
                        true,
                        false,
                    ) {
                        return Err(DriverError::InvalidReply);
                    }
                }
            }
        }
        child.reply = Some(reply);
        Ok(if self.children.iter().all(|child| child.reply.is_some()) {
            EcChildProgress::Ready
        } else {
            EcChildProgress::Pending
        })
    }
    fn child_versions(&self, index: usize) -> Result<Versions<'_>, DriverError> {
        let reply = self.children[index]
            .reply
            .as_ref()
            .ok_or(DriverError::Stale)?;
        let query = reply.ops.last().ok_or(DriverError::InvalidReply)?;
        Versions::parse(&query.outdata, usize::from(self.layout.pool_size))
    }
    fn version_mismatch(&self) -> Result<bool, DriverError> {
        let reference = self.child_versions(self.reference)?;
        for (index, child) in self.children.iter().enumerate() {
            if index == self.reference {
                continue;
            }
            let own = self.child_versions(index)?;
            match (reference.get(child.shard), own.get(child.shard)) {
                (Some(expected), Some(actual)) if expected == actual => {}
                _ => return Ok(true),
            }
        }
        Ok(false)
    }
    pub fn assemble(&self) -> Result<EcSplitResult, DriverError> {
        if self.children.iter().any(|child| child.reply.is_none()) {
            return Err(DriverError::Stale);
        }
        let reference = self.children[self.reference].reply.as_ref().unwrap();
        let mut retry = false;
        let mut result = reference.result;
        for child in &self.children {
            let value = child.reply.as_ref().unwrap().result;
            if value == -11 {
                retry = true;
            } else if value < 0 {
                result = value;
                break;
            }
        }
        if (result >= 0 || result == -11) && (retry || self.version_mismatch()?) {
            return Ok(EcSplitResult::Retry);
        }
        let user_version = reference.user_version;
        let replay_version = reference.replay_version;
        let mut operations = Vec::new();
        if result >= 0 {
            operations = self.parent.message.ops.clone();
            for (index, operation) in operations.iter_mut().enumerate() {
                // FAILOK permits overall success while one data sub-operation
                // failed. Publish that operation's error before merging: an
                // empty failed shard is not EOF, nor an encoded sparse map.
                if matches!(operation.op, op::READ | op::SPARSE_READ)
                    && let Some(failed) = self
                        .children
                        .iter()
                        .enumerate()
                        .filter_map(|(child, _)| self.operation(child, index))
                        .find(|returned| returned.rval < 0)
                {
                    operation.rval = failed.rval;
                    operation.outdata = Bytes::new();
                    continue;
                }
                match operation.op {
                    op::READ => {
                        operation.outdata = self.merge_read(index)?;
                        let mut extent = operation.extent();
                        extent.length = operation.outdata.len() as u64;
                        operation.set_extent(extent);
                    }
                    op::SPARSE_READ => {
                        let merged = self.merge_sparse(index)?;
                        let mut extent = operation.extent();
                        extent.length = merged.data.len() as u64;
                        operation.set_extent(extent);
                        operation.outdata = denc::Encode::encode_to_vec(&merged)
                            .map_err(|_| DriverError::InvalidReply)?
                            .into();
                    }
                    _ => {
                        let child = &self.children[self.reference];
                        let position = child
                            .indices
                            .binary_search(&index)
                            .map_err(|_| DriverError::InvalidReply)?;
                        *operation = reference.ops[position].clone();
                    }
                }
            }
        }
        Ok(EcSplitResult::Complete(EcSplitCompletion {
            token: self.parent.token,
            route: self.parent.route,
            attempt: self.parent.message.retry_attempt,
            result,
            user_version,
            replay_version,
            operations,
        }))
    }
}

impl EcSplitRead {
    fn operation(&self, child: usize, parent_index: usize) -> Option<&OsdOp> {
        let child = &self.children[child];
        let position = child.indices.binary_search(&parent_index).ok()?;
        child.reply.as_ref()?.ops.get(position)
    }
    fn merge_read(&self, index: usize) -> Result<Bytes, DriverError> {
        let extent = self.parent.message.ops[index].extent();
        let invalid = DriverError::InvalidReply;
        let total = self
            .children
            .iter()
            .enumerate()
            .filter_map(|(child, _)| self.operation(child, index))
            .try_fold(0usize, |total, operation| {
                total.checked_add(operation.outdata.len())
            })
            .ok_or(invalid)?;
        let mut output = Vec::with_capacity(total);
        let mut positions = vec![0usize; self.children.len()];
        let mut offset = extent.offset;
        let end = offset.checked_add(extent.length).ok_or(invalid)?;
        while offset < end {
            let raw = (offset / self.layout.chunk_size) % self.layout.raw_to_shard.len() as u64;
            let child = self.raw_to_child[raw as usize].ok_or(invalid)?;
            let source = self.operation(child, index).ok_or(invalid)?;
            let remaining = &source.outdata[positions[child]..];
            if remaining.is_empty() {
                break;
            }
            let piece =
                (self.layout.chunk_size - offset % self.layout.chunk_size).min(end - offset);
            let copied = usize::try_from(piece)
                .unwrap_or(usize::MAX)
                .min(remaining.len());
            output.extend_from_slice(&remaining[..copied]);
            positions[child] += copied;
            offset += copied as u64;
            if (copied as u64) < piece {
                break;
            }
        }
        Ok(output.into())
    }
    fn merge_sparse(&self, index: usize) -> Result<opwire::SparseReadOut, DriverError> {
        use std::{cmp::Reverse, collections::BinaryHeap};
        let invalid = DriverError::InvalidReply;
        let sources = self
            .children
            .iter()
            .enumerate()
            .filter_map(|(child, _)| self.operation(child, index))
            .map(|operation| {
                denc::from_slice::<opwire::SparseReadView<'_>>(&operation.outdata)
                    .map_err(|_| invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let total = sources
            .iter()
            .try_fold(0usize, |total, view| total.checked_add(view.data().len()))
            .ok_or(invalid)?;
        let mut merged = opwire::SparseReadOut {
            extents: BTreeMap::new(),
            data: Vec::with_capacity(total),
        };
        let mut cursors = sources
            .iter()
            .map(|view| view.extents())
            .collect::<Vec<_>>();
        let mut positions = vec![0usize; sources.len()];
        let mut heap = BinaryHeap::new();
        for (child, cursor) in cursors.iter_mut().enumerate() {
            if let Some((offset, length)) = cursor.find(|(_, length)| *length != 0) {
                heap.push(Reverse((offset, child, length)));
            }
        }
        let mut last: Option<(u64, u64)> = None;
        while let Some(Reverse((offset, child, length))) = heap.pop() {
            if let Some((start, size)) = last {
                let end = start.checked_add(size).ok_or(invalid)?;
                if end > offset {
                    return Err(invalid);
                }
                if end == offset {
                    let size = size.checked_add(length).ok_or(invalid)?;
                    merged.extents.insert(start, size);
                    last = Some((start, size));
                } else {
                    merged.extents.insert(offset, length);
                    last = Some((offset, length));
                }
            } else {
                merged.extents.insert(offset, length);
                last = Some((offset, length));
            }
            let length = usize::try_from(length).map_err(|_| invalid)?;
            let end = positions[child].checked_add(length).ok_or(invalid)?;
            merged.data.extend_from_slice(
                sources[child]
                    .data()
                    .get(positions[child]..end)
                    .ok_or(invalid)?,
            );
            positions[child] = end;
            if let Some((offset, length)) = cursors[child].find(|(_, length)| *length != 0) {
                heap.push(Reverse((offset, child, length)));
            }
        }
        if positions
            .iter()
            .zip(&sources)
            .any(|(&position, view)| position != view.data().len())
        {
            return Err(invalid);
        }
        Ok(merged)
    }
}
