// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Signalled host RDMA WRITE on the existing RC SQ. The remote grant is supplied by the caller.
use super::{
    Core, Device, ReadReceipt, RetirementKind, RetirementRecord, WindowDescriptor, ZcMem, ffi,
    post_failure, wr_id,
};
use crate::completion::{self, Marker};
use crate::memory::MemoryRange;
use crate::ring::NO_SLOT;
use bytes::Bytes;
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};
use std::{cell::Cell, fmt, io};

mod buffer;
pub use buffer::{
    AdvertisedWriteBuffer, LocalWriteBuffer, PreparedWriteBuffer, SharedWriteBuffer,
    WriteBufferBindError,
};

/// WRITE sources retained permanently after a fault or uncertain completion.
pub fn quarantined_write_sources() -> u64 {
    completion::QUARANTINED_WRITE_SOURCES.load(Ordering::Relaxed)
}

/// A checked remote address and opaque provider key. Construction requires a live peer grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteWriteTarget {
    range: MemoryRange,
    rkey: u32,
}

impl RemoteWriteTarget {
    /// # Safety
    /// The caller must obtain `rkey` and `range` from the authenticated peer for the same RC
    /// connection and attempt, and keep that grant live until WRITE completion or QP retirement.
    /// Numeric bounds alone do not establish that the remote memory is registered or authorized.
    pub unsafe fn from_raw_parts(address: u64, length: u64, rkey: u32) -> io::Result<Self> {
        Ok(Self {
            range: MemoryRange::new(address, length)?,
            rkey,
        })
    }

    pub fn range(self) -> MemoryRange {
        self.range
    }

    /// A checked portion of the same peer grant; the provider key stays opaque.
    pub fn subrange(self, offset: u64, length: u64) -> io::Result<Self> {
        Ok(Self {
            range: self.range.subrange(offset, length)?,
            rkey: self.rkey,
        })
    }
}

/// Registration rejection returns the exact immutable input without publishing an MR.
#[derive(Debug)]
pub struct WriteSourceRegistrationError {
    pub error: io::Error,
    pub data: Bytes,
}

/// Preflight rejection returns every original piece before any WRITE has been posted.
#[derive(Debug)]
pub struct WriteSourcesRegistrationError {
    pub error: io::Error,
    pub parts: Vec<Bytes>,
}

/// Immutable owned host bytes and their local-only MR. Construction is a control-thread operation.
pub struct WriteSource {
    registration: Arc<ZcMem>,
    data: Bytes,
    range: MemoryRange,
    completion: Arc<AtomicU8>,
}

impl fmt::Debug for WriteSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteSource")
            .field("range", &self.range)
            .finish_non_exhaustive()
    }
}

impl WriteSource {
    /// Register immutable host storage once; moving this handle never moves its allocation.
    pub fn register(dev: &Arc<Device>, data: Bytes) -> Result<Self, WriteSourceRegistrationError> {
        let range = match MemoryRange::new(data.as_ptr() as u64, data.len() as u64) {
            Ok(range) => range,
            Err(error) => {
                return Err(WriteSourceRegistrationError {
                    error: error.into(),
                    data,
                });
            }
        };
        let registration = match ZcMem::register_owned(dev, data.clone()) {
            Ok(registration) => registration,
            Err(error) => return Err(WriteSourceRegistrationError { error, data }),
        };
        Ok(Self {
            registration,
            data,
            range,
            completion: Arc::new(AtomicU8::new(completion::IDLE)),
        })
    }

    pub fn range(&self) -> MemoryRange {
        self.range
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// No WRITE was accepted; the source is still owned by the caller.
#[derive(Debug)]
pub struct WritePostError {
    pub error: io::Error,
    pub source: WriteSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteState {
    Pending,
    Complete,
    Failed,
}

/// One posted WRITE. Completion proves local provider retirement, not remote application acceptance or integrity.
#[derive(Debug)]
pub struct WriteHandle {
    source: Option<WriteSource>,
}

impl WriteHandle {
    fn data(&self) -> &[u8] {
        self.source.as_ref().expect("write owns source").data()
    }
    pub fn state(&self) -> WriteState {
        match self
            .source
            .as_ref()
            .expect("write owns source")
            .completion
            .load(Ordering::Acquire)
            & completion::WRITE_STATE_MASK
        {
            completion::WRITE_PENDING => WriteState::Pending,
            completion::WRITE_DONE => WriteState::Complete,
            _ => WriteState::Failed,
        }
    }

    /// Return the registered source only after a successful CQ retirement. All other states retain ownership.
    pub fn into_source(mut self) -> Result<WriteSource, Self> {
        if self.state() == WriteState::Complete {
            Ok(self.source.take().expect("completed write owns source"))
        } else {
            Err(self)
        }
    }
}

/// Ordered WRITEs for one placed READ on an authenticated RC connection. Consuming this owner
/// before a terminal reply prevents a later WRITE from following that reply.
#[derive(Debug)]
pub struct PlacedReadWrite {
    descriptor: WindowDescriptor,
    qpn: u32,
    writes: Vec<WriteHandle>,
    retired_prefix: Cell<usize>,
    accepted: usize,
    pieces: usize,
    written_len: u64,
    cancelled: bool,
    faulted: bool,
}

impl PlacedReadWrite {
    /// The caller validates the descriptor's live attempt, peer identity, negotiated placement
    /// and matching RC QP before constructing this owner.
    pub fn new(descriptor: WindowDescriptor, qpn: u32) -> Self {
        Self {
            descriptor,
            qpn,
            writes: Vec::new(),
            retired_prefix: Cell::new(0),
            accepted: 0,
            pieces: 0,
            written_len: 0,
            cancelled: false,
            faulted: false,
        }
    }

    /// Post the next immutable source directly after previously accepted pieces. A queue-full
    /// refusal returns the source and leaves this attempt open for another posting attempt.
    ///
    /// # Safety
    /// The caller must have authenticated the descriptor on this live QP and must retain the
    /// peer's grant until a terminal reply or QP retirement. A numeric descriptor alone is not
    /// proof that its address and key are authorized.
    pub unsafe fn post(
        &mut self,
        core: &mut Core,
        source: WriteSource,
    ) -> Result<(), WritePostError> {
        if self.cancelled
            || self.faulted
            || self.accepted != self.pieces
            || self.writes.len() != self.accepted
        {
            return Err(WritePostError {
                error: io::ErrorKind::InvalidInput.into(),
                source,
            });
        }
        let range = source.range();
        let target_range = match self
            .descriptor
            .range
            .subrange(self.written_len, range.length())
        {
            Ok(range) => range,
            Err(error) => {
                return Err(WritePostError {
                    error: error.into(),
                    source,
                });
            }
        };
        if let Err(error) = self.writes.try_reserve(1) {
            return Err(WritePostError {
                error: io::Error::other(error),
                source,
            });
        }
        // SAFETY: the caller established the live same-QP grant; this subrange stays within it.
        let target = match unsafe {
            RemoteWriteTarget::from_raw_parts(
                target_range.address(),
                target_range.length(),
                self.descriptor.rkey,
            )
        } {
            Ok(target) => target,
            Err(error) => return Err(WritePostError { error, source }),
        };
        match core.write(self.qpn, source, range, target) {
            Ok(write) => {
                self.writes.push(write);
                self.accepted += 1;
                self.pieces += 1;
                self.written_len += range.length();
            }
            Err(error) => {
                self.faulted = error.error.kind() != io::ErrorKind::WouldBlock;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Prepare all registered source pieces before posting any WRITE. Reusing a
    /// terminal owner retains its metadata capacity and per-piece markers. The
    /// method touches descriptors only; it neither reads nor copies payloads.
    /// Rejection returns the original pieces before any RMA can begin.
    pub fn prepare(
        &mut self,
        core: &Core,
        descriptor: WindowDescriptor,
        qpn: u32,
        parts: Vec<Bytes>,
        expected_len: u64,
    ) -> Result<(), WriteSourcesRegistrationError> {
        if !self.cancelled || self.accepted != 0 {
            return Err(WriteSourcesRegistrationError {
                error: io::ErrorKind::InvalidInput.into(),
                parts,
            });
        }
        let registration =
            match core.preflight_write_parts(&parts, expected_len, descriptor.range.length()) {
                Ok(registration) => registration,
                Err(error) => return Err(WriteSourcesRegistrationError { error, parts }),
            };
        if let Err(error) = self
            .writes
            .try_reserve(parts.len().saturating_sub(self.writes.len()))
        {
            return Err(WriteSourcesRegistrationError {
                error: io::Error::other(error),
                parts,
            });
        }
        let pieces = parts.len();
        for (i, data) in parts.into_iter().enumerate() {
            // Preflight checked the address, length and registered arena.
            let range =
                MemoryRange::new(data.as_ptr() as u64, data.len() as u64).expect("preflight range");
            let registration = registration
                .as_ref()
                .expect("nonempty pieces have a registration");
            if let Some(slot) = self.writes.get_mut(i) {
                let source = slot.source.as_mut().expect("reusable source slot");
                source.data = data;
                source.range = range;
                if !Arc::ptr_eq(&source.registration, registration) {
                    source.registration = registration.clone();
                }
            } else {
                self.writes.push(WriteHandle {
                    source: Some(WriteSource {
                        registration: registration.clone(),
                        data,
                        range,
                        completion: Arc::new(AtomicU8::new(completion::IDLE)),
                    }),
                });
            }
        }
        self.descriptor = descriptor;
        self.qpn = qpn;
        self.pieces = pieces;
        self.cancelled = false;
        self.faulted = false;
        self.written_len = 0;
        self.retired_prefix.set(0);
        Ok(())
    }

    /// Whether this owner still has unposted pieces. A completed prefix alone
    /// never qualifies as success while this returns true.
    pub fn has_pending(&self) -> bool {
        self.accepted < self.pieces
    }

    /// Post one prepared source, keeping its slot intact on SQ refusal.
    ///
    /// # Safety
    /// The descriptor passed to `prepare` must be an authenticated grant for
    /// this live QP and remain owned until retirement of this attempt.
    pub unsafe fn post_next(&mut self, core: &mut Core) -> io::Result<()> {
        if self.cancelled || self.faulted || !self.has_pending() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let i = self.accepted;
        let source = self.writes[i].source.take().expect("unposted source");
        let range = source.range();
        let target_range = self
            .descriptor
            .range
            .subrange(self.written_len, range.length())
            .expect("preflight extent");
        let target = RemoteWriteTarget {
            range: target_range,
            rkey: self.descriptor.rkey,
        };
        match core.write(self.qpn, source, range, target) {
            Ok(write) => {
                self.writes[i] = write;
                self.accepted += 1;
                self.written_len += range.length();
                Ok(())
            }
            Err(error) => {
                self.writes[i].source = Some(error.source);
                self.faulted = error.error.kind() != io::ErrorKind::WouldBlock;
                Err(error.error)
            }
        }
    }

    /// Encode a terminal successful receipt without consuming reusable metadata.
    pub fn receipt_verified(&self, block_crcs: &[u32]) -> io::Result<Vec<u8>> {
        let written = self.success_len().ok_or(io::ErrorKind::WouldBlock)?;
        ReadReceipt::encode(self.descriptor, written, block_crcs)
    }

    /// Return retired source slots to the owner cache. Provider registration and
    /// completion markers stay live; payload owners are released only after
    /// every accepted WRITE completed successfully. A fault cannot be recycled.
    pub fn recycle(&mut self) -> io::Result<()> {
        if self.faulted || matches!(self.state(), Some(WriteState::Pending | WriteState::Failed)) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        for write in &mut self.writes[..self.pieces] {
            let source = write.source.as_mut().expect("retired source slot");
            source.data = Bytes::new();
            source.completion.store(completion::IDLE, Ordering::Release);
        }
        self.accepted = 0;
        self.pieces = 0;
        self.retired_prefix.set(0);
        self.written_len = 0;
        self.cancelled = true;
        Ok(())
    }

    /// Stop admission before any terminal proof. Pending WRs still need successful CQEs.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub fn state(&self) -> Option<WriteState> {
        let mut retired = self.retired_prefix.get();
        let mut state = (self.accepted != 0).then_some(WriteState::Complete);
        for (i, write) in self.writes[..self.accepted]
            .iter()
            .enumerate()
            .skip(retired)
        {
            match write.state() {
                WriteState::Failed => return Some(WriteState::Failed),
                WriteState::Pending => state = Some(WriteState::Pending),
                WriteState::Complete if i == retired => retired += 1,
                WriteState::Complete => {}
            }
        }
        // Complete is terminal for an individual WRITE; its marker cannot be
        // rebound while this handle owns it. Inspect each retired prefix once.
        self.retired_prefix.set(retired);
        state
    }

    fn success_len(&self) -> Option<usize> {
        if self.cancelled
            || self.faulted
            || self.accepted != self.pieces
            || matches!(self.state(), Some(WriteState::Pending | WriteState::Failed))
        {
            return None;
        }
        usize::try_from(self.written_len).ok()
    }

    /// Build the exact success receipt only after the WRITE CQE. The caller must send it as a
    /// successful MOSDOpReply on this same RC QP; this method cannot authenticate that frame.
    /// Rejection returns the owner unchanged, including a pending or failed WRITE. When the
    /// store has verified block CRCs, use [`Self::finish_success_verified`] to avoid this byte pass.
    pub fn finish_success(mut self) -> Result<(Vec<u8>, Vec<WriteHandle>), Self> {
        let Some(written_len) = self.success_len() else {
            return Err(self);
        };
        let Ok(receipt) = ReadReceipt::encode_parts(
            self.descriptor,
            written_len,
            self.writes.iter().map(WriteHandle::data),
        ) else {
            return Err(self);
        };
        self.writes.truncate(self.accepted);
        Ok((receipt, std::mem::take(&mut self.writes)))
    }

    /// Build the receipt from source-bound seed-0 CRCs already verified by the store, without
    /// rereading the payload. The slice covers the concatenated WRITE bytes on the logical
    /// 4096-byte grid, including a final partial block. A wrong count or an unfinished WRITE
    /// returns the entire owner unchanged. The client still verifies the placed bytes.
    pub fn finish_success_verified(
        mut self,
        block_crcs: &[u32],
    ) -> Result<(Vec<u8>, Vec<WriteHandle>), Self> {
        let Some(written_len) = self.success_len() else {
            return Err(self);
        };
        let Ok(receipt) = ReadReceipt::encode(self.descriptor, written_len, block_crcs) else {
            return Err(self);
        };
        self.writes.truncate(self.accepted);
        Ok((receipt, std::mem::take(&mut self.writes)))
    }

    /// Build an error/cancel retirement record only after every accepted WRITE completed.
    /// A failed CQE cannot prove peer retirement and must be handled by QP retirement/quarantine.
    pub fn finish_cancel(mut self) -> Result<(RetirementRecord, Vec<WriteHandle>), Self> {
        if !self.cancelled
            || self.faulted
            || matches!(self.state(), Some(WriteState::Pending | WriteState::Failed))
        {
            return Err(self);
        }
        self.writes.truncate(self.accepted);
        Ok((
            RetirementRecord {
                kind: RetirementKind::Retired,
                descriptor: self.descriptor,
            },
            std::mem::take(&mut self.writes),
        ))
    }
}

impl Drop for WriteHandle {
    fn drop(&mut self) {
        if let Some(source) = self.source.as_ref()
            && matches!(
                source.completion.load(Ordering::Acquire) & completion::WRITE_STATE_MASK,
                completion::WRITE_PENDING | completion::FAILED
            )
        {
            // A failed observer can precede QP quiescence. A permanent arena MR
            // retains mappings, not the allocator's individual payload lease.
            // Keep the exact Bytes owner as well as its registration. On success
            // the CQ marker must not become the registration's final owner: that
            // would run provider teardown and Bytes destruction inside Core::poll.
            completion::quarantine_write_source(&source.completion);
            std::mem::forget(self.source.take().expect("pending write owns source"));
        }
    }
}

impl Core {
    fn preflight_write_parts(
        &self,
        parts: &[Bytes],
        expected_len: u64,
        capacity: u64,
    ) -> io::Result<Option<Arc<ZcMem>>> {
        let invalid = |what: std::fmt::Arguments<'_>| {
            io::Error::new(io::ErrorKind::InvalidInput, what.to_string())
        };
        if expected_len > capacity {
            return Err(invalid(format_args!(
                "{expected_len} reply bytes exceed the {capacity}-byte destination window"
            )));
        }
        if parts.is_empty() && expected_len == 0 {
            return Ok(None);
        }
        let (registration, _) = self.zc.as_ref().ok_or(io::ErrorKind::Unsupported)?;
        let mut total = 0u64;
        for (i, data) in parts.iter().enumerate() {
            let range = MemoryRange::new(data.as_ptr() as u64, data.len() as u64)?;
            total = total
                .checked_add(range.length())
                .ok_or_else(|| invalid(format_args!("piece {i} length overflows the reply")))?;
            if total > capacity {
                return Err(invalid(format_args!(
                    "pieces reach {total} bytes, beyond the {capacity}-byte destination window"
                )));
            }
            if range.length() > u32::MAX as u64 {
                return Err(invalid(format_args!(
                    "piece {i} is {} bytes (one SGE holds at most {} bytes)",
                    range.length(),
                    u32::MAX
                )));
            }
            if registration.lkey(range.address(), data.len()).is_none() {
                return Err(invalid(format_args!(
                    "piece {i} at {:#x}+{} is outside this core's registered payload arena",
                    range.address(),
                    range.length()
                )));
            }
        }
        if total != expected_len {
            return Err(invalid(format_args!(
                "source pieces total {total} bytes, reply length {expected_len}"
            )));
        }
        Ok(Some(registration.clone()))
    }

    /// Check every source piece against this core's registered payload arena, the exact
    /// reply length and the offered destination capacity before the first WRITE. Empty
    /// input represents a successful EOF only when the reply length is also zero.
    /// No provider registration or WRITE occurs. On rejection every original `Bytes` is returned
    /// in order, so the caller can use the ordinary SEND path while no RMA has begun.
    pub fn prepare_write_sources(
        &self,
        mut parts: Vec<Bytes>,
        expected_len: u64,
        capacity: u64,
    ) -> Result<Vec<WriteSource>, WriteSourcesRegistrationError> {
        let reject = |error, mut parts: Vec<Bytes>, sources: Vec<WriteSource>| {
            for (part, source) in parts.iter_mut().zip(sources) {
                *part = source.data;
            }
            Err(WriteSourcesRegistrationError { error, parts })
        };
        if expected_len > capacity {
            return reject(io::ErrorKind::InvalidInput.into(), parts, Vec::new());
        }
        if parts.is_empty() && expected_len == 0 {
            return Ok(Vec::new());
        }
        let Some((registration, _)) = &self.zc else {
            return reject(io::ErrorKind::Unsupported.into(), parts, Vec::new());
        };
        let mut sources = Vec::new();
        if let Err(error) = sources.try_reserve_exact(parts.len()) {
            return reject(io::Error::other(error), parts, sources);
        }
        let mut total = 0u64;
        for i in 0..parts.len() {
            let part = &parts[i];
            let range = match MemoryRange::new(part.as_ptr() as u64, part.len() as u64) {
                Ok(range) => range,
                Err(error) => return reject(error.into(), parts, sources),
            };
            total = match total.checked_add(range.length()) {
                Some(total) if total <= capacity && range.length() <= u32::MAX as u64 => total,
                _ => return reject(io::ErrorKind::InvalidInput.into(), parts, sources),
            };
            if registration
                .lkey(range.address(), range.length() as usize)
                .is_none()
            {
                return reject(io::ErrorKind::InvalidInput.into(), parts, sources);
            }
            sources.push(WriteSource {
                registration: registration.clone(),
                data: std::mem::take(&mut parts[i]),
                range,
                completion: Arc::new(AtomicU8::new(completion::IDLE)),
            });
        }
        if total != expected_len {
            return reject(io::ErrorKind::InvalidInput.into(), parts, sources);
        }
        Ok(sources)
    }

    /// Post one signalled WRITE on the same RC SQ as SEND and local window operations. Takes no SEND credit.
    /// Admission refusal returns the unchanged source. The caller supplies an authenticated remote grant;
    /// this primitive does not send, parse or retire descriptors.
    pub fn write(
        &mut self,
        qpn: u32,
        source: WriteSource,
        source_range: MemoryRange,
        target: RemoteWriteTarget,
    ) -> Result<WriteHandle, WritePostError> {
        let reject = |error, source| Err(WritePostError { error, source });
        if !source
            .range
            .contains(source_range.address(), source_range.length())
            || source_range.length() != target.range.length()
            || source_range.length() > u32::MAX as u64
        {
            return reject(io::ErrorKind::InvalidInput.into(), source);
        }
        if self.broken.is_some() {
            return reject(io::ErrorKind::ConnectionAborted.into(), source);
        }
        let Some(c) = self.conns.get_mut(&qpn) else {
            return reject(io::ErrorKind::NotConnected.into(), source);
        };
        if !Arc::ptr_eq(&c.qp.dev, &source.registration._dev) {
            return reject(io::ErrorKind::InvalidInput.into(), source);
        }
        if c.faulted || !c.qp.connected.get() {
            return reject(io::ErrorKind::NotConnected.into(), source);
        }
        if c.tx.sq.full() {
            self.stats.tx_write_sq_stalls += 1;
            return reject(io::ErrorKind::WouldBlock.into(), source);
        }
        let Some(lkey) = source
            .registration
            .lkey(source_range.address(), source_range.length() as usize)
        else {
            return reject(io::ErrorKind::InvalidInput.into(), source);
        };
        let seq = c.tx.sq.push_signaled(NO_SLOT);
        // SAFETY: exact owned immutable source range and same PD; caller obtained the live remote grant.
        let post = || unsafe {
            ffi::rv_post_write(
                c.qp.p,
                wr_id(c.epoch, seq),
                source_range.address(),
                source_range.length() as u32,
                lkey,
                target.range.address(),
                target.rkey,
            )
        };
        #[cfg(test)]
        let rc = self.write_post_error.take().unwrap_or_else(post);
        #[cfg(not(test))]
        let rc = post();
        self.stats.tx_doorbells += 1;
        self.stats.tx_write_doorbells += 1;
        if rc != 0 {
            c.fail();
            self.stats.faults += 1;
            self.post_failed.push(qpn);
            // The QP is already failed. A provider EAGAIN must not be
            // confused with the retryable SQ-full refusal above.
            return reject(post_failure(rc), source);
        }
        self.stats.tx_write_wrs += 1;
        self.stats.tx_write_bytes += source_range.length();
        source
            .completion
            .store(completion::WRITE_PENDING, Ordering::Release);
        let hold: Arc<dyn Send + Sync> = source.registration.clone();
        c.tx.sq.mark(Marker {
            state: source.completion.clone(),
            ready: completion::WRITE_DONE,
            retire_qp: None,
            source: Some(hold),
        });
        #[cfg(feature = "fault-inject")]
        if crate::fault::take_write_qp_err() {
            let result = c.qp.to_err();
            crate::fault::record_write_qp_err(result.is_ok());
            diag::diag!("rdma: fault-inject: accepted WRITE seq={seq} QP={qpn} to ERR: {result:?}");
            // Preserve all NIC access owners. Even a WRITE that wins the ERR
            // race must not yield an ordinary successful placement receipt.
            c.fail();
            self.stats.faults += 1;
            self.post_failed.push(qpn);
        }
        Ok(WriteHandle {
            source: Some(source),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verbs::WindowAttempt;

    #[test]
    fn provider_post_errors_are_fatal_and_keep_the_errno_cause() {
        for errno in [1, 5, 11, 12, 22] {
            let error = post_failure(-errno);
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(errno)
            );
        }
    }

    /// A provider EAGAIN is fatal after an earlier accepted WRITE: it is
    /// not an SQ-room refusal and cannot leave the prepared owner retryable.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_prepared_write_post_failure_retains_earlier_source() {
        use crate::verbs::{HostDestination, UnboundWindow, WindowState};
        use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
        struct Lease {
            data: Bytes,
            released: Arc<AtomicUsize>,
        }
        impl AsRef<[u8]> for Lease {
            fn as_ref(&self) -> &[u8] {
                &self.data
            }
        }
        impl Drop for Lease {
            fn drop(&mut self) {
                self.released.fetch_add(1, Relaxed);
            }
        }
        let ip = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .unwrap()
            .parse()
            .unwrap();
        let dev = Device::open(crate::gid_of(ip)).unwrap();
        let (mut sender, mut receiver, qs, qr) = super::super::rxe_tests::linked(&dev);
        let destination = HostDestination::register(&dev, vec![0; 4096]).unwrap();
        let range = destination.range();
        let local = receiver
            .bind_window(qr, UnboundWindow::allocate(destination).unwrap(), range)
            .unwrap();
        let start = std::time::Instant::now();
        while local.state() != WindowState::Bound {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "WARNING TIMEOUT WRITE failure BIND exceeded 10s"
            );
            receiver.poll(|_, _| {});
        }
        let grant = local
            .advertise(
                &receiver,
                WindowAttempt {
                    connection: 3,
                    tid: 7,
                    retry: 0,
                },
            )
            .unwrap();
        let descriptor = grant.descriptor();
        let data = Bytes::from(vec![0xa3; 4096]);
        sender
            .set_zero_copy(ZcMem::register_owned(&dev, data.clone()).unwrap(), 4096)
            .unwrap();
        let released: Vec<_> = (0..2).map(|_| Arc::new(AtomicUsize::new(0))).collect();
        let parts = (0..2)
            .map(|i| {
                Bytes::from_owner(Lease {
                    data: data.slice(i * 2048..(i + 1) * 2048),
                    released: released[i].clone(),
                })
            })
            .collect();
        let mut owner = PlacedReadWrite::new(descriptor, qs);
        owner.recycle().unwrap();
        owner.prepare(&sender, descriptor, qs, parts, 4096).unwrap();
        // Keep the first accepted WRITE outstanding: no CQ is polled before
        // the next provider call fails. Both endpoints retain the exact grant.
        // SAFETY: the fixture owns this authenticated grant on the same live QP.
        unsafe { owner.post_next(&mut sender) }.unwrap();
        const EAGAIN: i32 = 11; // Linux provider errno ABI; no extra test dependency.
        assert_eq!(
            io::Error::from_raw_os_error(EAGAIN).kind(),
            io::ErrorKind::WouldBlock
        );
        sender.inject_write_post_error(-EAGAIN);
        // SAFETY: the fixture still owns the original same-QP grant.
        let error = unsafe { owner.post_next(&mut sender) }.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(sender.stats.tx_write_wrs, 1);
        assert_eq!(sender.stats.tx_write_doorbells, 2);
        assert_eq!(owner.state(), Some(WriteState::Failed));
        assert!(owner.receipt_verified(&[0]).is_err());
        owner.cancel();
        let owner = owner.finish_cancel().unwrap_err();
        drop(owner);
        assert_eq!(
            released[0].load(Relaxed),
            0,
            "accepted source stays pinned without a consumed CQE"
        );
        assert_eq!(
            released[1].load(Relaxed),
            1,
            "rejected piece was never accepted"
        );
        drop(sender.detach(qs));
        drop(receiver.detach(qr));
        drop(grant);
        assert_eq!(
            released[0].load(Relaxed),
            0,
            "uncertain source cannot return on teardown"
        );
    }

    /// Warmed source slots retain the same markers across differing fragment
    /// counts. CPU payload access happens only after final window retirement.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_reusable_placed_read_keeps_markers_and_copies_no_payload() {
        use crate::verbs::{Event, HostDestination, UnboundWindow, WindowState};
        let ip = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .unwrap()
            .parse()
            .unwrap();
        let dev = Device::open(crate::gid_of(ip)).unwrap();
        let (mut sender, mut receiver, qs, qr) = super::super::rxe_tests::linked(&dev);
        let destination = HostDestination::register(&dev, vec![0; 4096]).unwrap();
        let range = destination.range();
        let local = receiver
            .bind_window(qr, UnboundWindow::allocate(destination).unwrap(), range)
            .unwrap();
        let wait = |core: &mut Core, done: &mut dyn FnMut() -> bool| {
            let start = std::time::Instant::now();
            while !done() {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(10),
                    "WARNING TIMEOUT reusable READ completion exceeded 10s"
                );
                core.poll(|_, event| assert!(!matches!(event, Event::Fault(_)), "{event:?}"));
            }
        };
        wait(&mut receiver, &mut || local.state() == WindowState::Bound);
        let attempt = WindowAttempt {
            connection: 1,
            tid: 2,
            retry: 0,
        };
        let mut grant = local.advertise(&receiver, attempt).unwrap();
        let descriptor = grant.descriptor();
        let data = Bytes::from((0..4096).map(|i| (i % 251) as u8).collect::<Vec<_>>());
        let original = data.as_ptr();
        sender
            .set_zero_copy(ZcMem::register_owned(&dev, data.clone()).unwrap(), 4096)
            .unwrap();
        let mut owner = PlacedReadWrite::new(descriptor, qs);
        owner.recycle().unwrap();
        let mut markers = Vec::new();
        let mut last_receipt = Vec::new();
        for (round, count) in [8, 2, 8, 8, 8].into_iter().enumerate() {
            let width = data.len() / count;
            let parts = (0..count)
                .map(|i| data.slice(i * width..(i + 1) * width))
                .collect();
            let (prepared, allocations) =
                crate::test_alloc::count(|| owner.prepare(&sender, descriptor, qs, parts, 4096));
            prepared.unwrap();
            if round > 0 {
                assert_eq!(
                    allocations, 0,
                    "warmed preflight allocates no markers or source Vec"
                );
            }
            if round == 0 {
                markers = owner
                    .writes
                    .iter()
                    .map(|w| Arc::as_ptr(&w.source.as_ref().unwrap().completion))
                    .collect();
            }
            assert_eq!(
                owner.writes.len(),
                8,
                "smaller READ retains spare marker slots"
            );
            for (i, slot) in owner.writes.iter().enumerate() {
                assert_eq!(
                    Arc::as_ptr(&slot.source.as_ref().unwrap().completion),
                    markers[i]
                );
            }
            assert_eq!(
                owner.writes[0].source.as_ref().unwrap().data.as_ptr(),
                original
            );
            if round == 3 {
                // Leave unposted pieces behind a single accepted WRITE. CANCEL
                // must wait for its CQE; none of those source slots may escape.
                // SAFETY: the fixture retains this exact live peer grant.
                unsafe { owner.post_next(&mut sender) }.unwrap();
                owner.cancel();
                assert!(owner.has_pending());
                assert_eq!(
                    owner.recycle().unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                wait(&mut sender, &mut || {
                    owner.state() == Some(WriteState::Complete)
                });
                assert!(owner.receipt_verified(&[crc::crc32c(0, &data)]).is_err());
                let (recycled, allocations) = crate::test_alloc::count(|| owner.recycle());
                recycled.unwrap();
                assert_eq!(allocations, 0);
                continue;
            }
            while owner.has_pending() {
                // SAFETY: the fixture retains this exact live remote grant on both endpoints.
                let (posted, allocations) =
                    crate::test_alloc::count(|| unsafe { owner.post_next(&mut sender) });
                assert_eq!(allocations, 0);
                posted.unwrap();
            }
            wait(&mut sender, &mut || {
                owner.state() == Some(WriteState::Complete)
            });
            last_receipt = owner.receipt_verified(&[crc::crc32c(0, &data)]).unwrap();
            let (recycled, allocations) = crate::test_alloc::count(|| owner.recycle());
            recycled.unwrap();
            assert_eq!(allocations, 0);
        }
        let outside = Bytes::from(vec![0x11; 4096]);
        let outside_address = outside.as_ptr();
        let rejected = owner
            .prepare(&sender, descriptor, qs, vec![outside], 4096)
            .unwrap_err();
        assert_eq!(rejected.parts[0].as_ptr(), outside_address);
        assert!(!owner.has_pending());
        assert_eq!(owner.state(), None);
        // SAFETY: both endpoints are owned here, every posted WRITE completed,
        // and the sender owner was recycled so it cannot post another WRITE.
        assert!(unsafe { grant.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        grant.invalidate(&mut receiver).unwrap();
        wait(&mut receiver, &mut || grant.state() == WindowState::Retired);
        let buffer = grant
            .into_unbound()
            .unwrap()
            .into_destination()
            .unwrap()
            .into_buffer()
            .unwrap();
        ReadReceipt::decode(&last_receipt, descriptor)
            .unwrap()
            .verify(&buffer)
            .unwrap();
        assert_eq!(&buffer, data.as_ref());
        drop(sender.detach(qs));
        drop(receiver.detach(qr));
    }

    #[test]
    fn zero_byte_read_and_cancel_have_terminal_records_without_a_write() {
        let descriptor = WindowDescriptor {
            attempt: WindowAttempt {
                connection: 7,
                tid: 9,
                retry: 2,
            },
            range: MemoryRange::new(0x1000, 8192).unwrap(),
            rkey: 11,
        };
        let (wire, writes) = PlacedReadWrite::new(descriptor, 3)
            .finish_success()
            .expect("EOF needs no WRITE");
        assert!(writes.is_empty());
        ReadReceipt::decode(&wire, descriptor)
            .unwrap()
            .verify(&[])
            .unwrap();
        let (verified, writes) = PlacedReadWrite::new(descriptor, 3)
            .finish_success_verified(&[])
            .expect("verified EOF needs no WRITE or CRC");
        assert_eq!(wire, verified);
        assert!(writes.is_empty());
        let mut cancelled = PlacedReadWrite::new(descriptor, 3);
        cancelled.cancel();
        let (retired, writes) = cancelled.finish_cancel().expect("empty cancel");
        assert!(writes.is_empty());
        assert_eq!(retired.kind, RetirementKind::Retired);
    }
}
