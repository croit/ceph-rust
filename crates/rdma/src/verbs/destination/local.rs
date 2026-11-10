// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Local BIND/LOCAL_INV and exclusive ownership across optional descriptor publication.
use super::super::{
    Core, ReadReceipt, RemoteInvalidation, ffi, post_failure, report_teardown, wr_id,
};
use super::{MemoryRange, UnboundWindow, WindowAttempt, WindowDescriptor};
use crate::completion::{self, Marker};
use crate::ring::NO_SLOT;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::{fmt, io};

static QUARANTINED_WINDOWS: AtomicU64 = AtomicU64::new(0);

/// How a placed READ's bytes were checked after peer retirement and LOCAL_INV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadVerification {
    /// The receipt matched the destination bytes on the host.
    Cpu,
    /// The destination is device memory: the host has no mapping, so the receipt is retained for a device-side
    /// check (the caller's fence and read) instead of a claimed host verification.
    DeviceMemory,
}

/// Windows abandoned before safe retirement was confirmed. Each retains its backing and device.
pub fn quarantined_windows() -> u64 {
    QUARANTINED_WINDOWS.load(Ordering::Relaxed)
}

pub(in crate::verbs) fn count_quarantined_windows(n: usize) {
    QUARANTINED_WINDOWS.fetch_add(n as u64, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowState {
    Binding,
    Bound,
    Invalidating,
    Retired,
    Failed,
}

/// A published type-2 window and its exclusive backing. Neither local invalidation nor drop
/// may return the allocation before the peer's ordered retirement has been proved.
#[derive(Debug)]
pub struct AdvertisedWindow {
    local: Option<LocalWindow>,
    descriptor: WindowDescriptor,
    peer_retired: bool,
}

impl AdvertisedWindow {
    /// Return a descriptor that was prepared but never queued to a peer to
    /// local ownership. The caller must then post LOCAL_INV and wait for its
    /// CQE before recovering the backing allocation.
    ///
    /// # Safety
    /// The descriptor must never have been queued, sent, or otherwise exposed
    /// to the peer. A rejected `send_placed_read` proves this only when no
    /// other copy of the descriptor escaped.
    pub unsafe fn retract_unpublished(mut self) -> LocalWindow {
        self.local.take().expect("advertised window owner")
    }

    /// QP on which this window was bound; the session owner must still map to it.
    pub fn qpn(&self) -> u32 {
        self.local.as_ref().expect("advertised window owner").qpn()
    }

    pub fn descriptor(&self) -> WindowDescriptor {
        self.descriptor
    }

    pub fn state(&self) -> WindowState {
        self.local
            .as_ref()
            .expect("advertised window owner")
            .state()
    }

    /// Check the placed bytes in their original allocation after both peer
    /// retirement and the LOCAL_INV CQE. This reads only the bound subrange,
    /// without copying it into a reply buffer. A failed check never marks data
    /// as initialized for the application.
    ///
    /// A borrowed (GPU) destination has no host mapping for real device memory: the check is then reported as
    /// [`ReadVerification::DeviceMemory`] instead of claiming a verification the host did not perform.
    pub fn verify_retired_read(&self, receipt: &ReadReceipt<'_>) -> io::Result<ReadVerification> {
        if !self.peer_retired || self.state() != WindowState::Retired {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if receipt.descriptor() != self.descriptor {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let local = self.local.as_ref().expect("advertised window owner");
        let destination = local
            .owner()
            .destination
            .as_ref()
            .expect("bound window owns destination");
        #[cfg(feature = "gpu")]
        if let Some(region) = destination.borrowed_region() {
            // A borrowed (GPU) window is narrowed to its leased subrange: offsets are relative to the region, and
            // only the retired subrange is borrowed (another window may be writing the rest of the region).
            if region.host_span().is_none() {
                return Ok(ReadVerification::DeviceMemory);
            }
            let (offset, len) =
                borrowed_read_span(region.address(), local.range, receipt.written_len())?;
            let bytes = destination
                .borrowed_host_bytes(offset, len)
                .ok_or(io::ErrorKind::InvalidData)?;
            receipt.verify(bytes)?;
            return Ok(ReadVerification::Cpu);
        }
        let parent = destination.range();
        let start = local
            .range
            .address()
            .checked_sub(parent.address())
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(io::ErrorKind::InvalidData)?;
        let end = start
            .checked_add(receipt.written_len())
            .ok_or(io::ErrorKind::InvalidData)?;
        let bytes = destination
            .buffer()
            .get(start..end)
            .ok_or(io::ErrorKind::InvalidData)?;
        receipt.verify(bytes)?;
        Ok(ReadVerification::Cpu)
    }

    /// Record a matching peer retirement proof. A matching numeric key alone is insufficient.
    ///
    /// # Safety
    /// The caller must have authenticated this attempt on the same live connection and proved
    /// that the peer cannot post more WRs for it and that all earlier WRs have retired, either
    /// by an ordered protocol receipt or by retirement of both RC QP endpoints. The reported
    /// key must come from the same receipt; this method checks only numeric identity.
    pub unsafe fn confirm_peer_retired_unchecked(
        &mut self,
        attempt: WindowAttempt,
        rkey: u32,
    ) -> bool {
        if self.descriptor.attempt != attempt || self.descriptor.rkey != rkey {
            return false;
        }
        self.peer_retired = true;
        true
    }

    /// Check an invalidation event against the exact provider QP identity, attempt and rkey.
    /// Numeric QPN reuse or a matching rkey on another QP cannot match this owner.
    pub fn matches_remote_invalidation(
        &self,
        attempt: WindowAttempt,
        event: &RemoteInvalidation,
    ) -> bool {
        let local = self.local.as_ref().expect("advertised window owner");
        self.descriptor.attempt == attempt
            && self.descriptor.rkey == event.key
            && Arc::ptr_eq(&local.identity, &event.identity)
    }

    /// Confirm a matching provider event after validating the application reply.
    ///
    /// # Safety
    /// The caller must authenticate and validate the ordered application reply for this
    /// attempt, and enforce that the peer issues no future WRs for the retired descriptor.
    pub unsafe fn confirm_remote_invalidation(
        &mut self,
        attempt: WindowAttempt,
        event: &RemoteInvalidation,
    ) -> bool {
        if !self.matches_remote_invalidation(attempt, event) {
            return false;
        }
        self.peer_retired = true;
        true
    }

    /// The local owner for [`Core::abandon_window`], whose QP teardown replaces the peer's retirement proof.
    pub(in crate::verbs) fn into_abandoned(mut self) -> LocalWindow {
        self.local.take().expect("advertised window owner")
    }

    /// Post local invalidation only after the peer can no longer use this descriptor.
    pub fn invalidate(&mut self, core: &mut Core) -> io::Result<()> {
        if !self.peer_retired {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.local
            .as_mut()
            .expect("advertised window owner")
            .invalidate(core)
    }

    /// Recover the exact parent only after both peer retirement and local invalidation CQE.
    #[expect(
        clippy::result_large_err,
        reason = "rejected recovery returns the unique window owner without allocation"
    )]
    pub fn into_unbound(mut self) -> Result<UnboundWindow, Self> {
        if !self.peer_retired || self.state() != WindowState::Retired {
            return Err(self);
        }
        let local = self.local.take().expect("advertised window owner");
        match local.into_unbound() {
            Ok(window) => Ok(window),
            Err(_) => unreachable!("retired local window must return its owner"),
        }
    }
}

/// No WR was accepted: the exact unbound owner remains reusable by the caller.
#[derive(Debug)]
pub struct WindowBindError {
    pub error: io::Error,
    pub window: UnboundWindow,
}

/// A bound host range before any descriptor is published. Poll the Core, inspect state, invalidate
/// on that same QP, then recover ownership; publication consumes this handle.
/// Dropping any state except Retired retains the complete window/parent permanently. No timeout grants memory reuse.
pub struct LocalWindow {
    window: Option<UnboundWindow>,
    range: MemoryRange,
    qpn: u32,
    identity: Arc<completion::WindowQpScope>,
}

impl fmt::Debug for LocalWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalWindow")
            .field("range", &self.range)
            .field("qpn", &self.qpn)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl LocalWindow {
    /// QP on which BIND was posted; a later session remap cannot adopt this window.
    pub fn qpn(&self) -> u32 {
        self.qpn
    }

    fn owner(&self) -> &UnboundWindow {
        self.window
            .as_ref()
            .expect("live local window owns registration")
    }

    /// Last local WR state; Bound is not a peer receipt or proof that the connection remains live.
    pub fn state(&self) -> WindowState {
        match self.owner().completion().load(Ordering::Acquire) {
            completion::BINDING => WindowState::Binding,
            completion::BOUND => WindowState::Bound,
            completion::INVALIDATING => WindowState::Invalidating,
            completion::RETIRED => WindowState::Retired,
            _ => WindowState::Failed,
        }
    }

    pub fn range(&self) -> MemoryRange {
        self.range
    }

    /// Publish one checked descriptor only after bind completion on the same live QP. The
    /// returned owner is the sole path to invalidation and backing recovery after publication.
    #[expect(
        clippy::result_large_err,
        reason = "failed advertisement returns the retained range/window owner without allocating"
    )]
    pub fn advertise(self, core: &Core, attempt: WindowAttempt) -> Result<AdvertisedWindow, Self> {
        if self.state() != WindowState::Bound || core.broken.is_some() {
            return Err(self);
        }
        let Some(c) = core.conns.get(&self.qpn) else {
            return Err(self);
        };
        if c.faulted || !c.qp.connected.get() || !Arc::ptr_eq(&self.identity, &c.qp.window_identity)
        {
            return Err(self);
        }
        // SAFETY: bound MW remains owned by the returned AdvertisedWindow.
        let rkey = unsafe { ffi::rv_window_rkey(self.owner().mw()) };
        let descriptor = WindowDescriptor {
            attempt,
            range: self.range,
            rkey,
        };
        Ok(AdvertisedWindow {
            local: Some(self),
            descriptor,
            peer_retired: false,
        })
    }

    /// Test-only raw grant for the connected peer; production advertisement requires the retirement protocol.
    #[cfg(test)]
    pub(crate) fn test_target(&self) -> super::super::write::RemoteWriteTarget {
        assert_eq!(self.state(), WindowState::Bound);
        // SAFETY: the test owns the connected peer and keeps this binding live until its WRITE CQE.
        unsafe {
            super::super::write::RemoteWriteTarget::from_raw_parts(
                self.range.address(),
                self.range.length(),
                ffi::rv_window_rkey(self.owner().mw()),
            )
            .expect("bound window range")
        }
    }

    #[cfg(test)]
    pub(crate) fn test_rkey(&self) -> u32 {
        // SAFETY: the window owner keeps this MW allocated.
        unsafe { ffi::rv_window_rkey(self.owner().mw()) }
    }

    /// Post LOCAL_INV on the exact owning QP. Requires Bound and SQ room, but consumes no receive credit.
    /// WouldBlock leaves Bound unchanged; retry after CQ progress. Post failure faults the connection and retains memory.
    pub fn invalidate(&mut self, core: &mut Core) -> io::Result<()> {
        if self.state() != WindowState::Bound {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "window is not Bound",
            ));
        }
        if core.broken.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "RDMA core is broken",
            ));
        }
        let c = core
            .conns
            .get_mut(&self.qpn)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "window QP is detached"))?;
        if !Arc::ptr_eq(&self.identity, &c.qp.window_identity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "window belongs to another QP",
            ));
        }
        if c.faulted {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "window QP is faulted",
            ));
        }
        if c.tx.sq.full() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let seq = c.tx.sq.push_signaled(NO_SLOT);
        // SAFETY: this owner keeps the same PD/MW and backing alive; the QP identity is retained and matched above.
        let rc = unsafe {
            ffi::rv_post_window_invalidate(c.qp.p, self.owner().mw(), wr_id(c.epoch, seq))
        };
        core.stats.tx_doorbells += 1;
        if rc != 0 {
            self.owner()
                .completion()
                .store(completion::FAILED, Ordering::Release);
            c.fail();
            core.stats.faults += 1;
            core.post_failed.push(self.qpn);
            return Err(post_failure(rc));
        }
        self.owner()
            .completion()
            .store(completion::INVALIDATING, Ordering::Release);
        c.tx.sq.mark(Marker {
            state: self.owner().completion().clone(),
            ready: completion::RETIRED,
            retire_qp: Some(self.identity.clone()),
            source: None,
        });
        Ok(())
    }

    /// Recover after successful local invalidation. An advertised window is instead owned by
    /// [`AdvertisedWindow`], which additionally requires peer retirement before calling this.
    #[expect(
        clippy::result_large_err,
        reason = "unfinished retirement returns the retained range/window owner without allocating"
    )]
    pub fn into_unbound(mut self) -> Result<UnboundWindow, Self> {
        if self.state() == WindowState::Retired {
            Ok(self
                .window
                .take()
                .expect("retired window owns registration"))
        } else {
            Err(self)
        }
    }
}

/// Region-relative offset and length of the bytes a placed READ wrote through a borrowed window bound over `bound`
/// of the region starting at `region_address`. The window was narrowed to its leased subrange, so the offset is that
/// subrange's distance from the region start (never 0 for a lease that starts later).
#[cfg(feature = "gpu")]
fn borrowed_read_span(
    region_address: u64,
    bound: MemoryRange,
    written: usize,
) -> io::Result<(u64, usize)> {
    let offset = bound
        .address()
        .checked_sub(region_address)
        .ok_or(io::ErrorKind::InvalidData)?;
    if written as u64 > bound.length() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok((offset, written))
}

impl LocalWindow {
    /// Deallocate the MW of an abandoned window ([`Core::abandon_window`]) and return its QP binding; the returned
    /// parent (MR and backing) must be kept until the QP is destroyed. A Retired window returns as is. An uncertain
    /// deallocation keeps window, parent and backing for good (loud, counted) and keeps the binding, which refuses the
    /// QP's destroy.
    ///
    /// # Safety
    /// The window's QP must be in ERR: no peer access through the MW can follow.
    pub(in crate::verbs) unsafe fn release_on_err_qp(mut self) -> Option<UnboundWindow> {
        let retired = self.state() == WindowState::Retired;
        let mut window = self
            .window
            .take()
            .expect("live local window owns registration");
        if retired {
            return Some(window);
        }
        // Not Retired: the window holds the binding its BIND post took (a successful LOCAL_INV would have returned
        // it; the detach failed every outstanding marker, so none returns it later).
        match window.retire() {
            Ok(()) => {
                self.identity.bindings.fetch_sub(1, Ordering::AcqRel);
                Some(window)
            }
            Err(_) => {
                // `retire` reported it and retained the parent; the MW keeps its QP reference.
                QUARANTINED_WINDOWS.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}

impl Drop for LocalWindow {
    fn drop(&mut self) {
        // into_unbound already transferred the owner; normal Retired Drop safely releases MW before parent MR.
        if self.window.is_none() || self.state() == WindowState::Retired {
            return;
        }
        let state = self.state();
        std::mem::forget(self.window.take());
        QUARANTINED_WINDOWS.fetch_add(1, Ordering::Relaxed);
        report_teardown(format_args!(
            "rdma: unfinished window quarantined (QP {}, state {state:?}; MW, parent MR and backing retained)",
            self.qpn
        ));
    }
}

/// Runs once when a QP's destroy released an abandoned window's parent MR and backing
/// ([`Core::abandon_published_window`]); never runs while they may still be DMA-written.
pub struct ReleaseHook(Box<dyn FnOnce() + Send>);

impl ReleaseHook {
    pub fn new(released: impl FnOnce() + Send + 'static) -> Self {
        Self(Box::new(released))
    }

    /// Run by the owner that proved the release (the QP teardown).
    pub fn run(self) {
        (self.0)()
    }
}

impl fmt::Debug for ReleaseHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReleaseHook")
    }
}

impl Core {
    /// Give up a window without its retirement proof (its session ends; the peer may hold its key): the QP it is
    /// bound on keeps it until that QP is torn down. Teardown moves the QP to ERR, deallocates the MW, destroys the
    /// QP and only then drops the parent MR and its backing; an uncertain deallocation or destroy keeps them for good
    /// (loud, counted). Call before [`Core::detach`] of that QP. Without its QP (already detached, or another QP
    /// under the same number) the window is quarantined for good (loud, counted). No provider call.
    pub fn abandon_window(&mut self, window: LocalWindow) {
        self.abandon_window_with(window, None);
    }

    /// [`Core::abandon_window`]; `on_release` runs once the QP's destroy succeeded and the parent MR and backing
    /// were released, and is dropped un-run whenever they stay quarantined.
    fn abandon_window_with(&mut self, window: LocalWindow, on_release: Option<ReleaseHook>) {
        match self.conns.get_mut(&window.qpn) {
            Some(c) if Arc::ptr_eq(&window.identity, &c.qp.window_identity) => {
                c.qp.retained().windows.push((window, on_release));
            }
            _ => {
                diag::diag!(
                    "WARNING rdma: qpn {}: abandoned window without its QP: quarantined for good",
                    window.qpn
                );
                drop(window); // quarantined, counted
            }
        }
    }

    /// [`Core::abandon_window`] for a published window whose session ends without the peer's retirement proof: the
    /// QP's teardown (ERR, MW deallocation, destroy) replaces that proof. `on_release` runs once that teardown
    /// released the parent MR and backing (e.g. to return the caller's registration budget); an uncertain teardown
    /// or a missing QP drops it un-run.
    pub fn abandon_published_window(
        &mut self,
        window: AdvertisedWindow,
        on_release: Option<ReleaseHook>,
    ) {
        self.abandon_window_with(window.into_abandoned(), on_release);
    }

    /// Bind an owned, never-advertised host range on the existing RC SQ; no remote key is exposed.
    /// Rejection returns the original owner. The caller must poll the Core and invalidate the bound window to recover it.
    pub fn bind_window(
        &mut self,
        qpn: u32,
        window: UnboundWindow,
        range: MemoryRange,
    ) -> Result<LocalWindow, WindowBindError> {
        self.bind_window_inner(qpn, window, range, false)
    }

    pub(super) fn bind_window_inner(
        &mut self,
        qpn: u32,
        window: UnboundWindow,
        range: MemoryRange,
        read_only: bool,
    ) -> Result<LocalWindow, WindowBindError> {
        let reject = |error, window| Err(WindowBindError { error, window });
        let parent = window
            .destination
            .as_ref()
            .expect("unbound window owns parent");
        if !read_only
            && matches!(
                parent.backing,
                Some(super::HostBacking::ReadOnly(_) | super::HostBacking::ReadOnlyArena(_))
            )
        {
            return reject(io::ErrorKind::PermissionDenied.into(), window);
        }
        if !parent.range.contains(range.address(), range.length()) {
            return reject(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "window range exceeds its parent MR",
                ),
                window,
            );
        }
        if self.broken.is_some() {
            return reject(
                io::Error::new(io::ErrorKind::ConnectionAborted, "RDMA core is broken"),
                window,
            );
        }
        let Some(c) = self.conns.get_mut(&qpn) else {
            return reject(
                io::Error::new(io::ErrorKind::NotConnected, "unknown RDMA QP"),
                window,
            );
        };
        if !Arc::ptr_eq(&c.qp.dev, &parent.dev) {
            return reject(
                io::Error::new(io::ErrorKind::InvalidInput, "window belongs to another PD"),
                window,
            );
        }
        if c.faulted || !c.qp.connected.get() {
            return reject(
                io::Error::new(io::ErrorKind::NotConnected, "RDMA QP is not live"),
                window,
            );
        }
        if read_only && c.qp.read_depths().incoming() == 0 {
            return reject(io::ErrorKind::Unsupported.into(), window);
        }
        if c.tx.sq.full() {
            return reject(io::ErrorKind::WouldBlock.into(), window);
        }
        let seq = c.tx.sq.push_signaled(NO_SLOT);
        // SAFETY: checked parent range, same PD, retained exclusive owner; the signalled WR shares ordinary SQ order.
        let rc = unsafe {
            ffi::rv_post_window_bind(
                c.qp.p,
                window.mw(),
                parent.mr,
                wr_id(c.epoch, seq),
                range.address(),
                range.length(),
                i32::from(read_only),
            )
        };
        self.stats.tx_doorbells += 1;
        if rc != 0 {
            c.fail();
            self.stats.faults += 1;
            self.post_failed.push(qpn);
            return reject(post_failure(rc), window);
        }
        c.qp.window_identity.bindings.fetch_add(1, Ordering::AcqRel);
        window
            .completion()
            .store(completion::BINDING, Ordering::Release);
        c.tx.sq.mark(Marker {
            state: window.completion().clone(),
            ready: completion::BOUND,
            retire_qp: None,
            source: None,
        });
        Ok(LocalWindow {
            window: Some(window),
            range,
            qpn,
            identity: c.qp.window_identity.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verbs::{Device, HostDestination};

    /// A window leased at region offset 4096 is checked against the bytes at 4096, not against the region prefix
    /// (whose bytes differ): the span is region-relative and never wider than the bound window.
    #[cfg(feature = "gpu")]
    #[test]
    fn borrowed_read_span_is_relative_to_the_region_not_the_window() {
        let mut region = vec![0xAAu8; 3 * 4096];
        region[4096..8192].fill(0x5C);
        let base = 0x10_0000u64;
        let bound = MemoryRange::new(base + 4096, 4096).unwrap();
        let (offset, len) = borrowed_read_span(base, bound, 4096).unwrap();
        assert_eq!((offset, len), (4096, 4096));
        let checked = &region[offset as usize..offset as usize + len];
        assert!(checked.iter().all(|b| *b == 0x5C));
        assert_ne!(
            checked,
            &region[..len],
            "the prefix is a different subrange"
        );
        // A short placed READ covers only its written prefix of the window.
        assert_eq!(borrowed_read_span(base, bound, 100).unwrap(), (4096, 100));
        // More bytes than the window, or a window before the region, is a malformed receipt.
        assert!(borrowed_read_span(base, bound, 4097).is_err());
        assert!(borrowed_read_span(base + 8192, bound, 1).is_err());
    }

    #[test]
    fn descriptor_v1_exact_bytes_and_untrusted_shape() {
        let descriptor = WindowDescriptor {
            attempt: WindowAttempt {
                connection: 1,
                tid: 2,
                retry: 3,
            },
            rkey: 0x1122_3344,
            range: MemoryRange::new(0x1000, 0x2000).unwrap(),
        };
        let expected: [u8; WindowDescriptor::ENCODED_LEN] = [
            1, 1, 0, 0, // version, read destination, reserved
            1, 0, 0, 0, 0, 0, 0, 0, // connection
            2, 0, 0, 0, 0, 0, 0, 0, // tid
            3, 0, 0, 0, // retry
            0x44, 0x33, 0x22, 0x11, // rkey
            0, 0x10, 0, 0, 0, 0, 0, 0, // address
            0, 0x20, 0, 0, 0, 0, 0, 0, // length
        ];
        assert_eq!(descriptor.encode(), expected);
        assert_eq!(WindowDescriptor::decode(&expected).unwrap(), descriptor);
        for i in [0, 1, 2, 3] {
            let mut bad = expected;
            bad[i] = 0xff;
            assert!(WindowDescriptor::decode(&bad).is_err(), "header byte {i}");
        }
        let mut bad = expected;
        bad[36..44].fill(0);
        assert!(WindowDescriptor::decode(&bad).is_err(), "zero length");
        bad = expected;
        bad[28..36].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(WindowDescriptor::decode(&bad).is_err(), "address overflow");
        assert!(WindowDescriptor::decode(&expected[..43]).is_err());
        assert!(WindowDescriptor::decode(&[expected.as_slice(), &[0]].concat()).is_err());
    }

    /// Simulate colliding QPNs across cores; the retained QP identity must reject invalidation before a provider post.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_local_window_rejects_another_qp_even_with_a_colliding_numeric_identity() {
        let ip = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .unwrap()
            .parse()
            .unwrap();
        let dev = Device::open(crate::gid_of(ip)).unwrap();
        let (mut sc, mut rc, qs, qr) = crate::verbs::rxe_tests::linked(&dev);
        let destination = HostDestination::register(&dev, vec![0; 4096]).unwrap();
        let range = destination.range();
        let mut local = sc
            .bind_window(qs, UnboundWindow::allocate(destination).unwrap(), range)
            .unwrap();
        let wait = |core: &mut Core, local: &LocalWindow, state| {
            let start = std::time::Instant::now();
            while local.state() != state {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(10),
                    "WARNING TIMEOUT local window identity completion exceeded 10s"
                );
                core.poll(|_, event| {
                    assert!(!matches!(event, crate::verbs::Event::Fault(_)), "{event:?}")
                });
            }
        };
        wait(&mut sc, &local, WindowState::Bound);
        local.qpn = qr; // Test-only collision: the other core has this number but owns a different provider QP.
        assert_eq!(
            local.invalidate(&mut rc).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(local.state(), WindowState::Bound);
        local.qpn = qs;
        local.invalidate(&mut sc).unwrap();
        wait(&mut sc, &local, WindowState::Retired);
        drop(local.into_unbound().unwrap());
    }
}
