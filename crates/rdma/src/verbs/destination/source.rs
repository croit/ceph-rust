// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! READ-only source grants using the existing type-2 window retirement owner.
//! Exclusive host backing stays inaccessible from BIND through safe retirement.
//! No parent MR key, wire codec, GPU import or durable operation is supplied.
use super::super::{Core, RemoteReadSource};
use super::{
    AdvertisedWindow, LocalWindow, MemoryRange, UnboundWindow, WindowAttempt, WindowBindError,
    WindowState,
};

mod immutable;
pub use immutable::{
    AdvertisedSharedReadSource, LocalSharedReadSource, PreparedReadSource, ReadSourcePool,
    ReadSourcePoolReturnError, ReadSourcePoolTicket, ReadSourceRegistrationError,
    SharedReadSourceBindError,
};

/// Numeric source grant for one attempt. This is a distinct type from a placed
/// READ destination; no existing destination wire record is reused or encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadSourceDescriptor {
    pub attempt: WindowAttempt,
    pub range: MemoryRange,
    pub rkey: u32,
}

impl ReadSourceDescriptor {
    /// # Safety
    /// Authenticate the descriptor on this READ's live RC connection and exact
    /// attempt; keep the source grant immutable and live until all accepted READs
    /// retire, and stop future admission before acknowledging peer retirement.
    /// Numeric fields and possession of a copied descriptor do not prove that.
    pub unsafe fn remote_source(self) -> std::io::Result<RemoteReadSource> {
        // SAFETY: the caller supplies the authenticated live-grant contract.
        unsafe {
            RemoteReadSource::from_raw_parts(self.range.address(), self.range.length(), self.rkey)
        }
    }
}

/// Unadvertised READ-only binding. It owns exclusive host storage, so producer
/// mutation cannot race peer READs. No source key is exposed before advertisement.
#[derive(Debug)]
pub struct LocalReadSource {
    local: LocalWindow,
}

impl LocalReadSource {
    pub fn state(&self) -> WindowState {
        self.local.state()
    }
    pub fn range(&self) -> MemoryRange {
        self.local.range()
    }
    pub fn qpn(&self) -> u32 {
        self.local.qpn()
    }

    /// Publish only after successful BIND on the original live QP. Consumes the
    /// local owner; subsequent invalidation additionally requires peer retirement.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns the exact window owner without allocation"
    )]
    pub fn advertise(
        self,
        core: &Core,
        attempt: WindowAttempt,
    ) -> Result<AdvertisedReadSource, Self> {
        match self.local.advertise(core, attempt) {
            Ok(window) => Ok(AdvertisedReadSource { window }),
            Err(local) => Err(Self { local }),
        }
    }

    /// No descriptor has escaped; retire the never-advertised binding locally.
    pub fn invalidate(&mut self, core: &mut Core) -> std::io::Result<()> {
        self.local.invalidate(core)
    }

    #[expect(
        clippy::result_large_err,
        reason = "unfinished retirement preserves the exact source owner"
    )]
    pub fn into_unbound(self) -> Result<UnboundWindow, Self> {
        self.local.into_unbound().map_err(|local| Self { local })
    }
}

/// Published READ-only MW. Backing may not be reused until both peer retirement
/// and successful LOCAL_INV. Neither a local CQE nor a timeout proves peer stop.
#[derive(Debug)]
pub struct AdvertisedReadSource {
    window: AdvertisedWindow,
}

impl AdvertisedReadSource {
    /// # Safety
    /// No copy of the descriptor may ever have been queued, sent or otherwise
    /// exposed to the peer. A failed send alone does not establish this if another
    /// copy escaped. The returned local owner still needs successful LOCAL_INV.
    pub unsafe fn retract_unpublished(self) -> LocalReadSource {
        // SAFETY: the caller proves no peer has ever received the source key.
        LocalReadSource {
            local: unsafe { self.window.retract_unpublished() },
        }
    }

    pub fn descriptor(&self) -> ReadSourceDescriptor {
        let descriptor = self.window.descriptor();
        ReadSourceDescriptor {
            attempt: descriptor.attempt,
            range: descriptor.range,
            rkey: descriptor.rkey,
        }
    }
    pub fn state(&self) -> WindowState {
        self.window.state()
    }
    pub fn qpn(&self) -> u32 {
        self.window.qpn()
    }

    /// # Safety
    /// The authenticated peer on this exact attempt/QP must have stopped all
    /// source READ admission and proved retirement of every accepted READ, or
    /// both endpoints must have been retired. A numeric key match is insufficient.
    /// This proof is independent of object success and durable acknowledgement.
    pub unsafe fn confirm_peer_retired_unchecked(
        &mut self,
        attempt: WindowAttempt,
        rkey: u32,
    ) -> bool {
        // SAFETY: the caller establishes the same peer/attempt retirement proof
        // as the shared window owner; this wrapper grants only remote READ access.
        unsafe { self.window.confirm_peer_retired_unchecked(attempt, rkey) }
    }

    pub fn invalidate(&mut self, core: &mut Core) -> std::io::Result<()> {
        self.window.invalidate(core)
    }

    #[expect(
        clippy::result_large_err,
        reason = "unfinished retirement preserves the exact source owner"
    )]
    pub fn into_unbound(self) -> Result<UnboundWindow, Self> {
        self.window.into_unbound().map_err(|window| Self { window })
    }
}

impl Core {
    /// Give up an unpublished source without LOCAL_INV ([`Core::abandon_window`]).
    pub fn abandon_read_source(&mut self, source: LocalReadSource) {
        self.abandon_window(source.local);
    }

    /// Give up a published source without the peer's retirement proof ([`Core::abandon_window`]): the QP's
    /// teardown (ERR, then MW deallocation, then destroy) is the proof.
    pub fn abandon_published_read_source(&mut self, source: AdvertisedReadSource) {
        self.abandon_window(source.window.into_abandoned());
    }

    /// Bind one exclusive initialized host range as a READ-only source. The
    /// existing local window/QP ownership, failure retention and LOCAL_INV path
    /// are shared with WRITE destinations. Uses a prepared MW without allocation
    /// or payload copy, consumes no SEND credit, and never exports the parent key.
    pub fn bind_read_source(
        &mut self,
        qpn: u32,
        window: UnboundWindow,
        range: MemoryRange,
    ) -> Result<LocalReadSource, WindowBindError> {
        self.bind_window_inner(qpn, window, range, true)
            .map(|local| LocalReadSource { local })
    }
}

#[cfg(test)]
mod tests;
