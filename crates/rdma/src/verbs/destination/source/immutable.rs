// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Immutable shared host source registration. The private window parent never
//! escapes as writable HostDestination/UnboundWindow; no foreign exclusive-memory
//! promise is made for Bytes that the store or other readers may still share.
use super::super::{Device, HostBacking, HostDestination, PreparedWindow, ffi};
use super::{
    AdvertisedReadSource, Core, LocalReadSource, MemoryRange, ReadSourceDescriptor, UnboundWindow,
    WindowAttempt, WindowState,
};
use bytes::Bytes;
use std::{io, sync::Arc};

/// Registration refusal preserves the exact immutable payload and its address.
#[derive(Debug)]
pub struct ReadSourceRegistrationError {
    pub error: io::Error,
    pub data: Bytes,
}

/// Cold registered immutable host payload and prepared READ-only source MW.
/// Arbitrary immutable Bytes aliases may coexist. No local/remote write access,
/// parent rkey or writable destination owner is exposed. GPU memory is excluded.
#[derive(Debug)]
pub struct PreparedReadSource {
    window: UnboundWindow,
}

impl PreparedReadSource {
    /// Retain the exact Bytes allocation without a payload copy. Prepare the
    /// MW, completion metadata and MW_BIND-only MR outside request progress.
    /// Only the later type-2 window can grant remote READ permission.
    pub fn register(
        device: &Arc<Device>,
        data: Bytes,
    ) -> Result<Self, ReadSourceRegistrationError> {
        let range = match MemoryRange::new(data.as_ptr() as u64, data.len() as u64) {
            Ok(range) => range,
            Err(error) => {
                return Err(ReadSourceRegistrationError {
                    error: error.into(),
                    data,
                });
            }
        };
        let mut prepared = match PreparedWindow::allocate(device) {
            Ok(prepared) => prepared,
            Err(error) => return Err(ReadSourceRegistrationError { error, data }),
        };
        // SAFETY: retained immutable Bytes owns these stable initialized CPU
        // bytes; MR has no LOCAL_WRITE or remote permission. A read-only MW
        // and all accepted peer work retain the same owner until retirement.
        let mr = unsafe {
            ffi::rv_reg_read_window_source(device.p, data.as_ptr().cast(), range.length())
        };
        if mr.is_null() {
            let error = io::Error::last_os_error();
            if prepared.retire().is_err() {
                std::mem::forget(device.clone());
            }
            return Err(ReadSourceRegistrationError { error, data });
        }
        let destination = HostDestination {
            dev: device.clone(),
            backing: Some(HostBacking::ReadOnly(data)),
            range,
            mr,
            prepared: Some(prepared),
            shared: None,
            #[cfg(test)]
            dereg_error: None,
        };
        // Prepared MW is consumed with no provider call; this cannot fail.
        let window = UnboundWindow::allocate(destination).expect("source MW already prepared");
        Ok(Self { window })
    }

    /// Cold-prepare a window for immutable bytes inside an existing explicitly
    /// window-capable arena. The exact Bytes and its registration remain held.
    /// This allocates a provider window and must not run per request.
    pub fn from_arena(
        registration: Arc<super::super::super::ZcMem>,
        data: Bytes,
    ) -> Result<Self, ReadSourceRegistrationError> {
        let range = match MemoryRange::new(data.as_ptr() as u64, data.len() as u64) {
            Ok(range) => range,
            Err(error) => {
                return Err(ReadSourceRegistrationError {
                    error: error.into(),
                    data,
                });
            }
        };
        let mr = if registration.read_windows {
            registration
                .regions
                .iter()
                .find(|(r, _, _)| r.contains(range.address(), range.length()))
                .map(|(_, _, mr)| *mr)
        } else {
            None
        };
        let Some(mr) = mr else {
            return Err(ReadSourceRegistrationError {
                error: io::ErrorKind::InvalidInput.into(),
                data,
            });
        };
        let prepared = match PreparedWindow::allocate(&registration._dev) {
            Ok(window) => window,
            Err(error) => return Err(ReadSourceRegistrationError { error, data }),
        };
        let destination = HostDestination {
            dev: registration._dev.clone(),
            backing: Some(HostBacking::ReadOnlyArena(Box::new((data, registration)))),
            range,
            mr,
            prepared: Some(prepared),
            shared: None,
            #[cfg(test)]
            dereg_error: None,
        };
        let window = UnboundWindow::allocate(destination).expect("arena MW already prepared");
        Ok(Self { window })
    }

    /// Replace the immutable payload in a retired arena-backed source without
    /// re-registering or reallocating its prepared window. The replacement must
    /// lie in the same parent MR. Refusal returns the exact supplied Bytes.
    pub fn replace_arena_bytes(
        &mut self,
        data: Bytes,
    ) -> Result<Bytes, ReadSourceRegistrationError> {
        let range = match MemoryRange::new(data.as_ptr() as u64, data.len() as u64) {
            Ok(range) => range,
            Err(error) => {
                return Err(ReadSourceRegistrationError {
                    error: error.into(),
                    data,
                });
            }
        };
        let destination = self
            .window
            .destination
            .as_mut()
            .expect("source retains parent");
        let Some(HostBacking::ReadOnlyArena(owner)) = destination.backing.as_mut() else {
            return Err(ReadSourceRegistrationError {
                error: io::ErrorKind::Unsupported.into(),
                data,
            });
        };
        if !owner.1.regions.iter().any(|(parent, _, mr)| {
            *mr == destination.mr && parent.contains(range.address(), range.length())
        }) {
            return Err(ReadSourceRegistrationError {
                error: io::ErrorKind::InvalidInput.into(),
                data,
            });
        }
        destination.range = range;
        Ok(std::mem::replace(&mut owner.0, data))
    }

    // Only a private idle pool slot may have no payload. Checkout installs a
    // validated piece before exposing the source or allowing another BIND.
    fn release_idle_payload(&mut self) {
        let destination = self
            .window
            .destination
            .as_mut()
            .expect("source retains parent");
        let Some(HostBacking::ReadOnlyArena(owner)) = destination.backing.as_mut() else {
            unreachable!("pool only owns arena sources");
        };
        drop(std::mem::take(&mut owner.0));
    }

    pub fn range(&self) -> MemoryRange {
        self.window.range()
    }

    /// Immutable local view, independent of the source's other Bytes aliases.
    pub fn bytes(&self) -> &Bytes {
        match self
            .window
            .destination
            .as_ref()
            .unwrap()
            .backing
            .as_ref()
            .unwrap()
        {
            HostBacking::ReadOnly(data) => data,
            HostBacking::ReadOnlyArena(owner) => &owner.0,
            _ => unreachable!("typed immutable source retains its original parent"),
        }
    }

    /// Cold MW then MR retirement. Provider failure retains the backing rather
    /// than authorizing its release. Existing external Bytes aliases stay valid.
    pub fn into_bytes(self) -> io::Result<Bytes> {
        let mut destination = self.window.into_destination()?;
        destination.retire()?;
        match destination.backing.take().unwrap() {
            HostBacking::ReadOnly(data) => Ok(data),
            HostBacking::ReadOnlyArena(owner) => {
                let (data, registration) = *owner;
                drop(registration);
                Ok(data)
            }
            _ => unreachable!("typed immutable source retains its original parent"),
        }
    }
}

/// A bounded set of cold-prepared arena source windows for one device/PD.
/// Each checkout carries a non-cloneable pool ticket until retirement. A lost
/// ticket or quarantined source permanently consumes that slot; no timeout
/// authorizes replacement. All setup and final teardown are control-path work.
#[derive(Debug)]
pub struct ReadSourcePool {
    registration: Arc<super::super::super::ZcMem>,
    identity: Arc<()>,
    available: Vec<PreparedReadSource>,
    capacity: usize,
    outstanding: usize,
}

/// Unique proof of one admitted pool slot. It does not prove peer retirement.
#[derive(Debug)]
pub struct ReadSourcePoolTicket(Arc<()>, Arc<std::sync::atomic::AtomicU8>);

/// Return refusal preserves the unchanged source and ticket.
#[derive(Debug)]
pub struct ReadSourcePoolReturnError {
    pub source: PreparedReadSource,
    pub ticket: ReadSourcePoolTicket,
}

impl ReadSourcePool {
    /// Prepare all provider windows before request progress. `seed` is retained
    /// during preparation; it must lie in one parent MR. Idle slots do not
    /// retain payload bytes.
    pub fn prepare(
        registration: Arc<super::super::super::ZcMem>,
        seed: &Bytes,
        capacity: usize,
    ) -> io::Result<Self> {
        if capacity == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut available = Vec::new();
        available
            .try_reserve_exact(capacity)
            .map_err(io::Error::other)?;
        for _ in 0..capacity {
            let mut source = PreparedReadSource::from_arena(registration.clone(), seed.clone())
                .map_err(|error| error.error)?;
            source.release_idle_payload();
            available.push(source);
        }
        Ok(Self {
            registration,
            identity: Arc::new(()),
            available,
            capacity,
            outstanding: 0,
        })
    }

    /// Checkout does not allocate, register memory, or call the provider.
    /// Exhaustion or invalid data returns the original bytes unchanged.
    pub fn checkout(
        &mut self,
        data: Bytes,
    ) -> Result<(PreparedReadSource, ReadSourcePoolTicket), ReadSourceRegistrationError> {
        let Some(mut source) = self.available.pop() else {
            return Err(ReadSourceRegistrationError {
                error: io::ErrorKind::WouldBlock.into(),
                data,
            });
        };
        match source.replace_arena_bytes(data) {
            Ok(previous) => drop(previous),
            Err(error) => {
                self.available.push(source);
                return Err(error);
            }
        }
        let marker = source.window.completion().clone();
        self.outstanding += 1;
        Ok((source, ReadSourcePoolTicket(self.identity.clone(), marker)))
    }

    /// A source can be returned only after its normal peer proof and successful
    /// LOCAL_INV have produced `PreparedReadSource` again. Rejection keeps both
    /// owners, including a ticket from another pool.
    #[cfg_attr(
        test,
        expect(
            clippy::result_large_err,
            reason = "test-only injected provider fields enlarge the exact returned source and ticket; boxing would allocate on refusal"
        )
    )]
    pub fn put(
        &mut self,
        source: PreparedReadSource,
        ticket: ReadSourcePoolTicket,
    ) -> Result<(), ReadSourcePoolReturnError> {
        let parent_matches = matches!(
            source.window.destination.as_ref().and_then(|d| d.backing.as_ref()),
            Some(HostBacking::ReadOnlyArena(owner)) if Arc::ptr_eq(&owner.1, &self.registration)
        );
        if !Arc::ptr_eq(&ticket.0, &self.identity)
            || !Arc::ptr_eq(&ticket.1, source.window.completion())
            || !parent_matches
            || self.outstanding == 0
            || self.available.len() >= self.capacity
        {
            return Err(ReadSourcePoolReturnError { source, ticket });
        }
        let mut source = source;
        source.release_idle_payload();
        self.outstanding -= 1;
        self.available.push(source);
        Ok(())
    }

    pub fn available(&self) -> usize {
        self.available.len()
    }
    pub fn outstanding(&self) -> usize {
        self.outstanding
    }
}

#[derive(Debug)]
pub struct SharedReadSourceBindError {
    pub error: io::Error,
    pub source: PreparedReadSource,
}

/// Unadvertised shared source. Recovery requires successful local invalidation.
#[derive(Debug)]
pub struct LocalSharedReadSource {
    local: LocalReadSource,
}

impl LocalSharedReadSource {
    pub fn state(&self) -> WindowState {
        self.local.state()
    }
    pub fn range(&self) -> MemoryRange {
        self.local.range()
    }
    pub fn qpn(&self) -> u32 {
        self.local.qpn()
    }
    pub fn invalidate(&mut self, core: &mut Core) -> io::Result<()> {
        self.local.invalidate(core)
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve original owner without allocation"
    )]
    pub fn advertise(
        self,
        core: &Core,
        attempt: WindowAttempt,
    ) -> Result<AdvertisedSharedReadSource, Self> {
        self.local
            .advertise(core, attempt)
            .map(|source| AdvertisedSharedReadSource { source })
            .map_err(|local| Self { local })
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve original owner without allocation"
    )]
    pub fn try_recover(self) -> Result<PreparedReadSource, Self> {
        self.local
            .into_unbound()
            .map(|window| PreparedReadSource { window })
            .map_err(|local| Self { local })
    }
}

/// READ-only immutable source advertised on one exact QP/attempt. Shared CPU
/// readers are allowed, but the registration/window stay retained until peer
/// retirement and successful LOCAL_INV. No object/durability result is implied.
#[derive(Debug)]
pub struct AdvertisedSharedReadSource {
    source: AdvertisedReadSource,
}

impl AdvertisedSharedReadSource {
    pub fn state(&self) -> WindowState {
        self.source.state()
    }
    pub fn descriptor(&self) -> ReadSourceDescriptor {
        self.source.descriptor()
    }
    pub fn qpn(&self) -> u32 {
        self.source.qpn()
    }

    /// # Safety
    /// No descriptor copy may have escaped, been queued or sent to any peer.
    /// The returned local source still requires successful LOCAL_INV.
    pub unsafe fn retract_unpublished(self) -> LocalSharedReadSource {
        // SAFETY: caller establishes no descriptor escaped.
        LocalSharedReadSource {
            local: unsafe { self.source.retract_unpublished() },
        }
    }

    /// # Safety
    /// Authenticate this exact attempt on the same live RC QP, stop all future
    /// peer READ admission and prove every accepted READ retired, or retire both
    /// endpoints. Numeric identity and timeouts do not supply that proof.
    pub unsafe fn confirm_peer_retired_unchecked(
        &mut self,
        attempt: WindowAttempt,
        rkey: u32,
    ) -> bool {
        // SAFETY: caller supplies the existing peer retirement contract.
        unsafe { self.source.confirm_peer_retired_unchecked(attempt, rkey) }
    }

    pub fn invalidate(&mut self, core: &mut Core) -> io::Result<()> {
        self.source.invalidate(core)
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve original owner without allocation"
    )]
    pub fn try_recover(self) -> Result<PreparedReadSource, Self> {
        self.source
            .into_unbound()
            .map(|window| PreparedReadSource { window })
            .map_err(|source| Self { source })
    }
}

impl Core {
    /// Bind one immutable parent subrange without copying or allocating. The
    /// typed source never exposes its private writable-destination machinery.
    pub fn bind_shared_read_source(
        &mut self,
        qpn: u32,
        source: PreparedReadSource,
        range: MemoryRange,
    ) -> Result<LocalSharedReadSource, SharedReadSourceBindError> {
        self.bind_read_source(qpn, source.window, range)
            .map(|local| LocalSharedReadSource { local })
            .map_err(|error| SharedReadSourceBindError {
                error: error.error,
                source: PreparedReadSource {
                    window: error.window,
                },
            })
    }
}

#[cfg(all(test, feature = "fault-inject"))]
mod tests;
