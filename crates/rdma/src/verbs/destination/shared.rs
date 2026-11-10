// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! One host MR with bounded prepared MWs and independent range ownership.
use super::{
    Device, ForeignDestinationRegistrationError, HostBacking, HostDestination, MemoryRange,
    PreparedWindow, TEARDOWN_FAILURES, ffi, report_teardown,
};
use crate::host_memory::{
    ForeignHostAllocation, ForeignHostBacking, ForeignHostLease, ForeignHostSlab,
    HostRangeLeaseError,
};
use std::{fmt, io, ptr, sync::Arc};

/// Cold setup rejection. No MR retains the returned allocation. A supplementary
/// retainer is returned too, so a caller can release a pre-registration charge.
pub struct SharedRegistrationRejected {
    pub error: io::Error,
    pub allocation: ForeignHostAllocation,
    pub retainer: Option<Box<dyn Send + Sync>>,
}
impl fmt::Debug for SharedRegistrationRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedRegistrationRejected")
            .field("error", &self.error)
            .field("allocation", &self.allocation)
            .field("has_retainer", &self.retainer.is_some())
            .finish()
    }
}

/// Busy preserves the usable controller. Retained means provider teardown was
/// uncertain and backing/retainer/device remain held until process exit.
#[derive(Debug)]
pub enum SharedReleaseError {
    Busy(SharedHostRegistration),
    Retained(io::Error),
}

struct SharedParent {
    dev: Arc<Device>,
    mr: *mut ffi::Opaque,
    backing: Option<ForeignHostBacking>,
    retainer: Option<Box<dyn Send + Sync>>,
    #[cfg(test)]
    dereg_error: Option<i32>,
}
// SAFETY: parent MR identity is immutable while shared; distinct MWs bind only
// checked disjoint owned ranges. No CPU byte views are created through parent.
// Verbs control objects support cross-thread movement; final release is a
// control-path operation and occurs only after the last child releases its Arc.
unsafe impl Send for SharedParent {}
unsafe impl Sync for SharedParent {}

impl SharedParent {
    fn retire(&mut self) -> io::Result<()> {
        if self.mr.is_null() {
            return Ok(());
        }
        // SAFETY: the unique parent has no child MW owner. Idle MWs were freed
        // before reaching the last Arc; failed MW teardown leaks a parent Arc.
        let rc = unsafe { ffi::rv_dereg(self.mr) };
        #[cfg(test)]
        let rc = self.dereg_error.take().unwrap_or(rc);
        self.mr = ptr::null_mut();
        if rc == 0 {
            drop(self.backing.take());
            drop(self.retainer.take());
            return Ok(());
        }
        std::mem::forget(self.backing.take());
        std::mem::forget(self.retainer.take());
        std::mem::forget(self.dev.clone());
        TEARDOWN_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let error = io::Error::from_raw_os_error(rc.abs());
        report_teardown(format_args!(
            "rdma: shared host MR deregistration failed: {error} (backing, retainer and device retained)"
        ));
        Err(error)
    }
}
impl Drop for SharedParent {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}

pub(super) struct SharedOwner {
    parent: Arc<SharedParent>,
    slot: usize,
}

/// Cold-created shared host registration. A single controller grants arbitrary
/// nonoverlapping ranges from a bounded prepared MW pool. Claims/reclaims do
/// not allocate or call providers; existing BIND/peer-proof/LOCAL_INV contracts
/// apply to each returned destination. One range cannot recover the parent.
///
/// Construction, missing-window preparation, final release and final Drop are
/// control-path operations. Supplementary retainer Drop runs only after proved
/// MR release or pre-registration rejection; provider uncertainty retains it.
/// GPU memory does not satisfy the underlying foreign host contract.
pub struct SharedHostRegistration {
    windows: Vec<Option<Box<PreparedWindow>>>,
    slab: Option<ForeignHostSlab>,
    parent: Option<Arc<SharedParent>>,
}
// SAFETY: moving the sole controller preserves stable backing and immutable MR
// identity. Pool MWs are unbound and exclusively owned; live children retain
// separate range/parent owners. Provider control objects allow thread transfer.
unsafe impl Send for SharedHostRegistration {}

impl fmt::Debug for SharedHostRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedHostRegistration")
            .field("range", &self.range())
            .field("capacity", &self.windows.len())
            .finish_non_exhaustive()
    }
}
impl SharedHostRegistration {
    /// Prepare every MW before registering one parent MR. The optional
    /// control-state retainer can hold a parent registration charge. It grants
    /// no byte access and is never released on uncertain provider teardown.
    pub fn register(
        dev: &Arc<Device>,
        allocation: ForeignHostAllocation,
        capacity: usize,
        retainer: Option<Box<dyn Send + Sync>>,
    ) -> Result<Self, SharedRegistrationRejected> {
        let (slab, windows, mr) = match prepare(dev, allocation, capacity) {
            Ok(prepared) => prepared,
            Err(rejected) => {
                return Err(SharedRegistrationRejected {
                    error: rejected.error,
                    allocation: rejected.allocation,
                    retainer,
                });
            }
        };
        let backing = slab.retain_backing();
        Ok(Self {
            windows,
            slab: Some(slab),
            parent: Some(Arc::new(SharedParent {
                dev: dev.clone(),
                mr,
                backing: Some(backing),
                retainer,
                #[cfg(test)]
                dereg_error: None,
            })),
        })
    }

    pub fn range(&self) -> MemoryRange {
        self.slab.as_ref().expect("live shared controller").range()
    }

    pub fn try_lease(
        &mut self,
        offset: u64,
        length: u64,
    ) -> Result<HostDestination, HostRangeLeaseError> {
        let lease = self
            .slab
            .as_mut()
            .expect("live shared controller")
            .claim_where(offset, length, |slot| self.windows[slot].is_some())?;
        let slot = lease.slot();
        let range = lease.range();
        let parent = self.parent.as_ref().expect("live shared parent");
        Ok(HostDestination {
            dev: parent.dev.clone(),
            backing: Some(HostBacking::Leased(lease)),
            range,
            mr: parent.mr,
            prepared: self.windows[slot].take(),
            shared: Some(SharedOwner {
                parent: parent.clone(),
                slot,
            }),
            #[cfg(test)]
            dereg_error: None,
        })
    }

    /// Return an unbound prepared child to its exact controller. Rejection
    /// returns the unchanged destination. No provider calls or allocation.
    pub fn reclaim(&mut self, mut destination: HostDestination) -> Result<(), HostDestination> {
        let Some(owner) = &destination.shared else {
            return Err(destination);
        };
        if !Arc::ptr_eq(
            &owner.parent,
            self.parent.as_ref().expect("live shared parent"),
        ) || self.windows[owner.slot].is_some()
            || destination.prepared.is_none()
        {
            return Err(destination);
        }
        self.windows[owner.slot] = destination.prepared.take();
        destination.mr = ptr::null_mut();
        drop(destination);
        Ok(())
    }

    /// Return an unbound prepared child's window to this controller but keep
    /// its exact range claimed: the returned lease owns the bytes (CPU view,
    /// transferable to any thread, e.g. as a `Bytes` owner) and releases the
    /// range when it drops; only then can a later [`Self::try_lease`] reuse it.
    /// For a READ destination after its exact successful CQ (no device access
    /// remains). Rejection returns the unchanged destination. No provider calls
    /// or allocation.
    pub fn reclaim_range(
        &mut self,
        destination: HostDestination,
    ) -> Result<ForeignHostLease, HostDestination> {
        self.take_range(destination).map(|(lease, _)| lease)
    }

    /// Return an unbound prepared child's window to this controller while a
    /// device may still write its range (a READ without a successful CQE):
    /// the range stays claimed, and the MR registered, until the returned owner
    /// drops, which a caller does only after the QP the READ was posted on was
    /// destroyed ([`super::super::Core::abandon_read`]). No byte access, no
    /// provider calls or allocation. Rejection returns the unchanged destination.
    pub fn retain_range(
        &mut self,
        destination: HostDestination,
    ) -> Result<RetainedRange, HostDestination> {
        self.take_range(destination)
            .map(|(lease, parent)| RetainedRange {
                _lease: lease,
                _parent: parent,
            })
    }

    /// The ranges claimed now (live, retained or quarantined), at most the
    /// capacity: first-fit placement looks for room behind each of them.
    pub fn claimed(&self) -> impl Iterator<Item = MemoryRange> + '_ {
        self.slab
            .as_ref()
            .expect("live shared controller")
            .claimed()
    }

    fn take_range(
        &mut self,
        mut destination: HostDestination,
    ) -> Result<(ForeignHostLease, Arc<SharedParent>), HostDestination> {
        let Some(owner) = &destination.shared else {
            return Err(destination);
        };
        if !Arc::ptr_eq(
            &owner.parent,
            self.parent.as_ref().expect("live shared parent"),
        ) || self.windows[owner.slot].is_some()
            || destination.prepared.is_none()
            || !matches!(destination.backing, Some(HostBacking::Leased(_)))
        {
            return Err(destination);
        }
        let parent = owner.parent.clone();
        self.windows[owner.slot] = destination.prepared.take();
        destination.mr = ptr::null_mut();
        let Some(HostBacking::Leased(lease)) = destination.backing.take() else {
            unreachable!("leased backing checked above");
        };
        drop(destination);
        Ok((lease, parent))
    }

    /// Replace windows whose child was safely dropped instead of reclaimed.
    /// Active/quarantined slots are never replenished. Control path only.
    pub fn prepare_missing(&mut self) -> io::Result<usize> {
        let slab = self.slab.as_ref().expect("live shared controller");
        let parent = self.parent.as_ref().expect("live shared parent");
        let mut prepared = 0;
        for (slot, window) in self.windows.iter_mut().enumerate() {
            if window.is_none() && !slab.slot_is_occupied(slot) {
                *window = Some(PreparedWindow::allocate(&parent.dev)?);
                prepared += 1;
            }
        }
        Ok(prepared)
    }

    /// Recover the exact original allocation only after all child destinations
    /// return or retire. Busy preserves the controller. Uncertain teardown
    /// never returns backing or the supplementary retainer.
    pub fn into_foreign(mut self) -> Result<ForeignHostAllocation, SharedReleaseError> {
        let parent = self.parent.as_ref().expect("live shared parent");
        if Arc::strong_count(parent) != 1
            || !self
                .slab
                .as_ref()
                .expect("live shared controller")
                .is_exclusive_with(parent.backing.as_ref().expect("live parent backing"))
        {
            return Err(SharedReleaseError::Busy(self));
        }
        self.retire_windows()
            .map_err(SharedReleaseError::Retained)?;
        let parent = self.parent.take().expect("live shared parent");
        let mut parent =
            Arc::try_unwrap(parent).unwrap_or_else(|_| unreachable!("unique shared parent"));
        parent.retire().map_err(SharedReleaseError::Retained)?;
        Ok(self
            .slab
            .take()
            .expect("live shared controller")
            .try_into_allocation()
            .unwrap_or_else(|_| unreachable!("all claims and registration guard retired")))
    }

    fn retire_windows(&mut self) -> io::Result<()> {
        let mut failure = None;
        for window in &mut self.windows {
            if let Some(mut window) = window.take()
                && let Err(error) = window.retire()
            {
                failure.get_or_insert(error);
            }
        }
        if let Some(error) = failure {
            // Even a refused idle MW release keeps this MR and its backing.
            std::mem::forget(self.parent.as_ref().expect("live shared parent").clone());
            return Err(error);
        }
        Ok(())
    }
}
/// A range a device may still write ([`SharedHostRegistration::retain_range`]):
/// keeps the range claimed and the MR registered until dropped. Opaque: no byte
/// access. Dropping it is a statement that no device access remains.
pub struct RetainedRange {
    // declaration order = drop order: the range is released before the MR can retire
    _lease: ForeignHostLease,
    _parent: Arc<SharedParent>,
}

impl fmt::Debug for RetainedRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedRange")
            .field("range", &self._lease.range())
            .finish_non_exhaustive()
    }
}

impl Drop for SharedHostRegistration {
    fn drop(&mut self) {
        let _ = self.retire_windows();
    }
}

type Prepared = (
    ForeignHostSlab,
    Vec<Option<Box<PreparedWindow>>>,
    *mut ffi::Opaque,
);
fn prepare(
    dev: &Arc<Device>,
    allocation: ForeignHostAllocation,
    capacity: usize,
) -> Result<Prepared, ForeignDestinationRegistrationError> {
    let slab = ForeignHostSlab::new(allocation, capacity).map_err(|rejected| {
        ForeignDestinationRegistrationError {
            error: rejected.error,
            allocation: rejected.allocation,
        }
    })?;
    let mut windows = Vec::new();
    let setup = (|| {
        windows
            .try_reserve_exact(capacity)
            .map_err(io::Error::other)?;
        for _ in 0..capacity {
            windows.push(Some(PreparedWindow::allocate(dev)?));
        }
        // SAFETY: the slab still has exclusive initialized CPU backing, with
        // writable provenance. No range or registration guard has escaped.
        let mr = unsafe {
            ffi::rv_reg_destination(
                dev.p,
                slab.range().address() as *mut _,
                slab.range().length(),
            )
        };
        if mr.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(mr)
    })();
    match setup {
        Ok(mr) => Ok((slab, windows, mr)),
        Err(error) => {
            let mut failed = false;
            for mut window in windows.into_iter().flatten() {
                failed |= window.retire().is_err();
            }
            if failed {
                std::mem::forget(dev.clone());
            }
            Err(ForeignDestinationRegistrationError {
                error,
                allocation: slab
                    .try_into_allocation()
                    .expect("unexposed slab is exclusive"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verbs::{
        Core, Event, RemoteWriteTarget, UnboundWindow, WindowAttempt, WindowState, WriteSource,
        WriteState,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Owner {
        bytes: Vec<u8>,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct Retainer(Arc<AtomicUsize>);
    impl Drop for Retainer {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn device() -> Arc<Device> {
        let ip = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .unwrap()
            .parse()
            .unwrap();
        Device::open(crate::gid_of(ip)).unwrap()
    }
    fn registered(
        dev: &Arc<Device>,
        capacity: usize,
    ) -> (SharedHostRegistration, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let dropped = Arc::new(AtomicUsize::new(0));
        let retired = Arc::new(AtomicUsize::new(0));
        let mut owner = Owner {
            bytes: vec![0x5a; 12288],
            dropped: dropped.clone(),
        };
        let address = owner.bytes.as_mut_ptr() as u64;
        // SAFETY: this owner retains initialized exclusive writable host bytes.
        let allocation =
            unsafe { ForeignHostAllocation::from_raw_parts(address, 12288, owner) }.unwrap();
        let root = SharedHostRegistration::register(
            dev,
            allocation,
            capacity,
            Some(Box::new(Retainer(retired.clone()))),
        )
        .unwrap();
        (root, dropped, retired)
    }
    fn poll_until(core: &mut Core, mut done: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while !done() {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "WARNING TIMEOUT shared host window completion exceeded 10s"
            );
            core.poll(|_, event| assert!(!matches!(event, Event::Fault(_)), "{event:?}"));
        }
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_shared_parent_reuses_one_mr_and_prepared_ranges_without_allocating() {
        let dev = device();
        let (mut root, dropped, retired) = registered(&dev, 2);
        let address = root.range().address();
        let mr = root.parent.as_ref().unwrap().mr;
        let markers: Vec<_> = root
            .windows
            .iter()
            .map(|w| w.as_ref().unwrap().mw)
            .collect();
        let (_, allocations) = crate::test_alloc::count(|| {
            for _ in 0..260 {
                let mut left = root.try_lease(64, 1024).unwrap();
                let right = root.try_lease(2048, 1024).unwrap();
                assert_eq!(left.mr, mr);
                assert_eq!(right.mr, mr);
                assert_eq!(left.prepared.as_ref().unwrap().mw, markers[0]);
                assert_eq!(right.prepared.as_ref().unwrap().mw, markers[1]);
                left.buffer_mut().fill(0x17);
                assert_eq!(left.buffer().len(), 1024);
                assert_eq!(left.buffer().as_ptr() as u64, address + 64);
                assert!(matches!(
                    root.try_lease(65, 1),
                    Err(HostRangeLeaseError::Range(_))
                ));
                root.reclaim(left).unwrap();
                root.reclaim(right).unwrap();
            }
        });
        assert_eq!(allocations, 0);
        assert_eq!(retired.load(Ordering::Relaxed), 0);
        let allocation = root.into_foreign().unwrap();
        assert_eq!(retired.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert_eq!(allocation.range().address(), address);
        assert!(allocation.buffer()[64..1088].iter().all(|&b| b == 0x17));
        drop(allocation);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_shared_parent_busy_and_drop_keep_all_live_children() {
        let dev = device();
        let (mut root, dropped, retired) = registered(&dev, 2);
        let left = root.try_lease(0, 1024).unwrap();
        let mut right = root.try_lease(2048, 1024).unwrap();
        let root = match root.into_foreign().unwrap_err() {
            SharedReleaseError::Busy(root) => root,
            error => panic!("unexpected release: {error:?}"),
        };
        drop(root);
        left.release().unwrap();
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert_eq!(retired.load(Ordering::Relaxed), 0);
        right.buffer_mut().fill(0x28);
        right.release().unwrap();
        assert_eq!(retired.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_shared_parent_only_prepares_missing_retired_slots_and_rejects_wrong_reclaim() {
        let dev = device();
        let (mut root, dropped, retired) = registered(&dev, 1);
        let (mut other, _, _) = registered(&dev, 1);
        let child = root.try_lease(0, 1024).unwrap();
        assert_eq!(root.prepare_missing().unwrap(), 0);
        let child = other.reclaim(child).unwrap_err();
        assert_eq!(child.range().address(), root.range().address());
        assert_eq!(
            child.into_foreign().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(matches!(
            root.try_lease(0, 1024),
            Err(HostRangeLeaseError::Capacity)
        ));
        assert_eq!(root.prepare_missing().unwrap(), 1);
        let child = root.try_lease(0, 1024).unwrap();
        root.reclaim(child).unwrap();
        drop(root.into_foreign().unwrap());
        assert_eq!(retired.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        drop(other.into_foreign().unwrap());
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_shared_parent_release_preserves_controller_while_reclaimed_range_is_live() {
        let dev = device();
        let (mut root, dropped, retired) = registered(&dev, 1);
        let child = root.try_lease(0, 4096).unwrap();
        let mut lease = root.reclaim_range(child).unwrap();
        let root = match root.into_foreign().unwrap_err() {
            SharedReleaseError::Busy(root) => root,
            error => panic!("live CPU range must preserve controller: {error:?}"),
        };
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert_eq!(retired.load(Ordering::Relaxed), 0);
        lease.buffer_mut().fill(0x37);
        drop(lease);
        let allocation = root.into_foreign().unwrap();
        assert_eq!(&allocation.buffer()[..4096], &[0x37; 4096]);
        assert_eq!(retired.load(Ordering::Relaxed), 1);
        drop(allocation);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_reclaimed_range_keeps_its_claim_until_the_lease_drops_on_another_thread() {
        let dev = device();
        let (mut root, dropped, retired) = registered(&dev, 1);
        let (mut other, _, _) = registered(&dev, 1);
        let child = root.try_lease(4096, 4097).unwrap();
        let child = other.reclaim_range(child).unwrap_err();
        let lease = root.reclaim_range(child).unwrap();
        assert_eq!(lease.range().length(), 4097);
        assert_eq!(lease.buffer()[0], 0x5a);
        // the window is back, the range is not: an overlapping claim is refused
        assert!(matches!(
            root.try_lease(8192, 4096),
            Err(HostRangeLeaseError::Range(_))
        ));
        std::thread::spawn(move || drop(lease)).join().unwrap();
        let child = root.try_lease(8192, 4096).unwrap();
        root.reclaim(child).unwrap();
        drop(root.into_foreign().unwrap());
        assert_eq!(retired.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        drop(other.into_foreign().unwrap());
    }

    /// The range of an abandoned READ stays claimed while its QP lives, returns once the QP was
    /// destroyed, and stays claimed for good (counted) after an uncertain destroy.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_retained_read_range_returns_after_its_qp_is_destroyed() {
        use crate::verbs::{CoreCfg, Qp, quarantined_read_targets};
        let dev = device();
        let core = Core::new(&dev, CoreCfg::default()).unwrap();
        let (mut root, _, _) = registered(&dev, 2);
        for (uncertain, at) in [(false, 0), (true, 4096)] {
            let mut qp = Qp::create(&dev, core.handles(), 1).unwrap();
            let child = root.try_lease(at, 4096).unwrap();
            qp.retained().reads.push(root.retain_range(child).unwrap());
            assert!(matches!(
                root.try_lease(at, 4096),
                Err(HostRangeLeaseError::Range(_))
            ));
            let before = quarantined_read_targets();
            if uncertain {
                qp.destroy_error = Some(5);
                assert!(qp.destroy().is_err());
                assert_eq!(quarantined_read_targets(), before + 1);
                assert!(root.try_lease(at, 4096).is_err());
            } else {
                qp.destroy().unwrap();
                assert_eq!(quarantined_read_targets(), before);
                let again = root.try_lease(at, 4096).unwrap();
                root.reclaim(again).unwrap();
            }
        }
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_shared_parent_uncertain_child_idle_or_mr_teardown_retains_both_owners() {
        let dev = device();
        for failure in 0..3 {
            let (mut root, dropped, retired) = registered(&dev, 1);
            match failure {
                0 => root.windows[0].as_mut().unwrap().dealloc_error = Some(5),
                1 => {
                    Arc::get_mut(root.parent.as_mut().unwrap())
                        .unwrap()
                        .dereg_error = Some(5)
                }
                _ => {
                    let mut child = root.try_lease(0, 1024).unwrap();
                    child.prepared.as_mut().unwrap().dealloc_error = Some(5);
                    assert!(child.release().is_err());
                }
            }
            match root.into_foreign().unwrap_err() {
                SharedReleaseError::Busy(root) if failure == 2 => drop(root),
                SharedReleaseError::Retained(error) if failure != 2 => {
                    assert_eq!(error.raw_os_error(), Some(5))
                }
                error => panic!("unexpected release: {error:?}"),
            }
            assert_eq!(retired.load(Ordering::Relaxed), 0);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_shared_parent_two_qps_write_disjoint_grants_with_a_third_cpu_view() {
        let dev = device();
        let (mut root, dropped, retired) = registered(&dev, 3);
        let (mut send1, mut recv1, sq1, rq1) = crate::verbs::rxe_tests::linked(&dev);
        let (mut send2, mut recv2, sq2, rq2) = crate::verbs::rxe_tests::linked(&dev);
        let left = root.try_lease(0, 4096).unwrap();
        let right = root.try_lease(4096, 4096).unwrap();
        let mut cpu = root.try_lease(8192, 4096).unwrap();
        let (lr, rr) = (left.range(), right.range());
        let left = recv1
            .bind_window(rq1, UnboundWindow::allocate(left).unwrap(), lr)
            .unwrap();
        let right = recv2
            .bind_window(rq2, UnboundWindow::allocate(right).unwrap(), rr)
            .unwrap();
        poll_until(&mut recv1, || left.state() == WindowState::Bound);
        poll_until(&mut recv2, || right.state() == WindowState::Bound);
        let a1 = WindowAttempt {
            connection: 1,
            tid: 1,
            retry: 0,
        };
        let a2 = WindowAttempt {
            connection: 2,
            tid: 2,
            retry: 0,
        };
        let mut left = left.advertise(&recv1, a1).unwrap();
        let mut right = right.advertise(&recv2, a2).unwrap();
        // SAFETY: the controlled peers retain these exact same-QP grants and
        // issue no further WRITE after their recorded completion.
        let target = |d: crate::placement::WindowDescriptor| unsafe {
            RemoteWriteTarget::from_raw_parts(d.range.address(), d.range.length(), d.rkey).unwrap()
        };
        let source1 = WriteSource::register(&dev, bytes::Bytes::from(vec![1; 4096])).unwrap();
        let source2 = WriteSource::register(&dev, bytes::Bytes::from(vec![2; 4096])).unwrap();
        let (sr1, sr2) = (source1.range(), source2.range());
        let write1 = send1
            .write(sq1, source1, sr1, target(left.descriptor()))
            .unwrap();
        let write2 = send2
            .write(sq2, source2, sr2, target(right.descriptor()))
            .unwrap();
        // Both grants are live and unretired. Actual simultaneous NIC work is
        // not inferred from the local handles still being pending.
        cpu.buffer_mut().fill(3);
        poll_until(&mut send1, || write1.state() == WriteState::Complete);
        poll_until(&mut send2, || write2.state() == WriteState::Complete);
        // SAFETY: these controlled peers completed their only WRITEs and will
        // never use either descriptor again. This is the test's peer proof.
        unsafe {
            assert!(left.confirm_peer_retired_unchecked(a1, left.descriptor().rkey));
            assert!(right.confirm_peer_retired_unchecked(a2, right.descriptor().rkey));
        }
        left.invalidate(&mut recv1).unwrap();
        right.invalidate(&mut recv2).unwrap();
        poll_until(&mut recv1, || left.state() == WindowState::Retired);
        poll_until(&mut recv2, || right.state() == WindowState::Retired);
        let left = left.into_unbound().unwrap().into_prepared_destination();
        let right = right.into_unbound().unwrap().into_prepared_destination();
        assert!(left.buffer().iter().all(|&b| b == 1));
        assert!(right.buffer().iter().all(|&b| b == 2));
        assert!(cpu.buffer().iter().all(|&b| b == 3));
        root.reclaim(left).unwrap();
        root.reclaim(right).unwrap();
        root.reclaim(cpu).unwrap();
        drop(write1.into_source().unwrap());
        drop(write2.into_source().unwrap());
        drop(send1.detach(sq1));
        drop(recv1.detach(rq1));
        drop(send2.detach(sq2));
        drop(recv2.detach(rq2));
        drop(root.into_foreign().unwrap());
        assert_eq!(retired.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
}
