// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::gcm::{ConnSecret, Gcm, Role};
use crate::segbuf::{SegBuf, SegWatch};
use crate::{
    Error, INLINE_LEN, LATE_ABORTED, LATE_COMPLETE, Limits, PREAMBLE_LEN, Preamble, Revision,
    TAG_LEN, pad16,
};
use core::ops::Range;
use crc::crc32c;
use denc::le::rd_u32;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

/// Result of accepting a prefix of one owned frame's input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxFeed {
    /// Bytes accepted from the supplied slice; reoffer its suffix later.
    pub consumed: usize,
    /// Why this call stopped.
    pub state: RxFeedState,
}

/// Nonfatal owned receive progress and dispatch backpressure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxFeedState {
    /// More wire bytes are needed.
    NeedInput,
    /// One verified owned frame is ready to poll.
    FrameReady,
    /// Checked preamble is retained; no body window is exposed until credit returns.
    DispatchBlocked {
        /// Snapshot taken before the failed grant; use with DispatchBudget::arm.
        generation: u64,
    },
}

#[derive(Debug)]
struct RxDispatch {
    owner: Rc<RefCell<crate::DispatchBudget>>,
    guard: crate::DispatchGuard,
    granted: bool,
    blocked: Option<u64>,
}

impl RxDispatch {
    /// `room`: memory the frame takes beyond its segment bytes (a placed data segment's pad, [`place_room`]).
    fn admit(&mut self, p: Preamble, room: usize) -> Result<bool, Error> {
        if self.granted {
            return Ok(true);
        }
        if p.tag != crate::Tag::Message as u8 {
            self.granted = true;
            return Ok(true);
        }
        if p.len[0] as usize != crate::payload::HEADER2_LEN {
            return Err(Error::BadMessageHeaderLength(p.len[0]));
        }
        let charge = p.len[1..p.n].iter().try_fold(room as u64, |n, &len| {
            n.checked_add(u64::from(len))
                .ok_or(Error::FrameTooLarge(u64::MAX))
        })?;
        let mut owner = self.owner.borrow_mut();
        let generation = owner.generation();
        match owner.try_acquire(charge) {
            Ok(guard) => {
                self.guard = guard;
                self.granted = true;
                self.blocked = None;
                Ok(true)
            }
            Err(crate::DispatchError::NoCredit) => {
                self.blocked = Some(generation);
                Ok(false)
            }
            Err(error) => Err(Error::Dispatch(error)),
        }
    }

    fn take_guard(&mut self) -> crate::DispatchGuard {
        self.granted = false;
        self.blocked = None;
        core::mem::take(&mut self.guard)
    }
}

/// Placement alignment of a data segment hint ([`Decoder::set_rx_place`]): the largest power of two <= the hint,
/// at most 4 KiB; `None` below 2 (no placement wanted).
pub(crate) fn place_align(hint: u16) -> Option<usize> {
    let h = usize::from(hint).min(crc::blocks::BLK);
    (h >= 2).then(|| 1 << h.ilog2())
}

/// Placement of the data segment of a frame with preamble `p` and header2 segment `header` ([`Decoder::set_rx_place`]):
/// `(alignment, in-page offset of segment byte 0)`; `None` = not placed (off, no MESSAGE frame with a data segment,
/// hint below 2).
fn data_place(place: bool, p: &Preamble, header: &[u8]) -> Option<(usize, usize)> {
    if !place
        || p.tag != crate::Tag::Message as u8
        || p.n != 4
        || p.len[3] == 0
        || header.len() < crate::payload::HEADER2_LEN
    {
        return None;
    }
    let a = place_align(p.align[3])?;
    let data_off = denc::le::rd_u16(header, 26);
    Some((a, usize::from(data_off) % a))
}

/// An empty buffer with room for `len` bytes and a leading pad such that byte `at` of what follows the pad lies at
/// in-page offset `off` modulo `a`: `(buffer holding the pad, pad)`.
fn placed_buf(
    shelf: Option<&crate::rxpool::Shelf>,
    len: usize,
    at: usize,
    (a, off): (usize, usize),
) -> Result<(SegBuf, usize), Error> {
    let mut b = SegBuf::default();
    let capacity = len
        .checked_add(crate::rxpool::PAD_ROOM)
        .ok_or(Error::SegmentTooLarge(len as u32))?;
    reserve(shelf, &mut b, capacity)?;
    let pad = (off + a - (b.as_ptr() as usize + at) % a) % a;
    b.resize_zero(pad);
    Ok((b, pad))
}

/// Block grid start of a segment at `addr`: bytes before its first 4 KiB boundary.
fn grid_head(addr: usize) -> usize {
    (crc::blocks::BLK - addr % crc::blocks::BLK) % crc::blocks::BLK
}

/// Memory a placed frame takes beyond its segment bytes (charged to the ingress gate and the dispatch domain, adr
/// 0175): the leading pad room of its data segment.
fn place_room(place: bool, p: &Preamble) -> usize {
    if place
        && p.tag == crate::Tag::Message as u8
        && p.n == 4
        && p.len[3] > 0
        && place_align(p.align[3]).is_some()
    {
        crate::rxpool::PAD_ROOM
    } else {
        0
    }
}

/// Minimum bytes per crc call while assembling (L1/L2-hot, long 3-way crc path).
pub(crate) const CRC_RUN: usize = 32 * 1024;

/// Conservative per-frame framing charge of the ingress gate, in bytes: preamble (32), the seg0 trailer crc (4) and
/// the longest epilogue (13) stay below it for every revision and mode.
const FRAME_CHARGE_MIN: usize = 64;

/// Data segments at least this long are checksummed per 4 KiB block (`crc::BlockCrcs`, adr 0061 am. 4): the block crcs
/// travel with the payload (store, replica fan-out), the segment crc is joined from them.
pub const BLOCKS_MIN: usize = 64 * 1024;

/// Existing minimum wire frame size for retaining shared Secure receive storage.
const OWNED_FRAME_MIN: usize = 8192;

#[derive(Debug)]
enum Rx {
    Crc,
    Secure(Gcm),
}

#[derive(Debug, Clone, Copy)]
struct Parsed {
    p: Preamble,
    /// total wire length of the frame
    total: usize,
}

struct Done {
    r: [Range<usize>; 4],
    p: Preamble,
    total: usize,
    aborted: bool,
    /// Segments 1.. of a placed secure frame, decrypted out of place ([`Decoder::set_rx_place`]): `r[1..n]` index this
    /// buffer (not the rx buffer); its data segment lies at the wanted in-page offset.
    placed: Option<SegBuf>,
    /// Declared length of a data segment the probe refused (0 = none): `r[3]` is empty then.
    refused: u32,
}

/// A complete, verified (and decrypted) frame; segments borrow the decoder's rx buffer.
#[derive(Debug)]
pub struct Frame<'a> {
    /// Raw tag byte (see [`crate::Tag::from_u8`]).
    pub tag: u8,
    /// Preamble flags (bit0 = compressed).
    pub flags: u8,
    /// Number of segments (1..=4).
    pub num_segments: usize,
    /// Segment alignment hints from the preamble.
    pub align: [u16; 4],
    /// Declared length of a data segment the receive probe refused ([`Decoder::set_data_probe`]), 0 = none: segment 3
    /// is empty then, as on [`OwnedFrame::data_refused`]. Only the streaming path (msgr2.1 crc mode) probes here; the
    /// buffered path (secure mode, msgr2.0) probes in [`Decoder::poll_owned`] only and keeps every segment here.
    pub data_refused: u32,
    segs: [&'a [u8]; 4],
}

impl<'a> Frame<'a> {
    /// Segment `i` (empty slice for i >= num_segments).
    pub fn segment(&self, i: usize) -> &'a [u8] {
        self.segs.get(i).copied().unwrap_or(&[])
    }

    /// The `num_segments` present segments.
    pub fn segments(&self) -> &[&'a [u8]] {
        &self.segs[..self.num_segments]
    }
}

/// The MESSAGE frame whose data segment is lent to a transport ([`Decoder::lent_message`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LentMessage {
    /// Transaction id of the message (header2).
    pub tid: u64,
    /// Message type (header2).
    pub msg_type: u16,
    /// Leading bytes of the lent buffer that are not part of the segment.
    pub pad: usize,
    /// Length of the data segment.
    pub len: usize,
}

/// A complete verified frame whose segments the caller owns (no copy out of the decoder).
#[derive(Debug, Default)]
pub struct OwnedFrame {
    /// Optional logical dispatch lifetime; independent of all segment storage owners.
    pub dispatch: crate::DispatchGuard,
    /// Raw tag byte.
    pub tag: u8,
    /// Preamble flags.
    pub flags: u8,
    /// Alignment hints from the preamble.
    pub align: [u16; 4],
    /// The present segments (1..=4).
    pub segs: Vec<bytes::Bytes>,
    /// Verified `crc32c(!0, segs[3])` of the data segment when the assembler computed it (CRC mode rev 2.1).
    pub data_crc: Option<u32>,
    /// `crc32c(0, block)` of every whole 4 KiB block of `segs[3]` (data segments >= [`BLOCKS_MIN`], CRC mode rev 2.1).
    pub data_blocks: Option<std::sync::Arc<[u32]>>,
    /// Where the block grid starts in `segs[3]`: 0, or the bytes before its first 4 KiB boundary in memory when placed
    /// ([`Decoder::set_rx_place`]).
    pub data_head: usize,
    /// Declared length of a data segment the receive probe refused ([`Decoder::set_data_probe`]): it was consumed and
    /// verified but is not part of `segs` (which then holds 4 segments, the last empty). 0 = not refused.
    pub data_refused: u32,
    /// The frame's header-time reservation in the ingress pool (empty without a gate): keeps the frame's bytes
    /// counted until the message is done.
    pub credit: ingress::InputGuard,
}

/// The data segment of the frame being assembled is shared while it arrives ([`Decoder::early`], adr 0477).
#[derive(Debug)]
pub struct RxEarly<'a> {
    /// Header2 segment (verified by its inline crc).
    pub header: &'a [u8],
    /// Front segment (complete; its crc is checked with the frame's epilogue, like the data).
    pub front: &'a [u8],
    /// Reader handle of the data segment's buffer.
    pub data: &'a SegWatch,
    /// Leading pad of the buffer: segment byte `i` is buffer byte `pad + i`.
    pub pad: usize,
    /// Block grid start in the segment ([`OwnedFrame::data_head`]).
    pub head: usize,
    /// Segment length.
    pub len: usize,
}

/// A known secure frame's receive allocation, temporarily owned by a transport.
/// Keep this value alive and unchanged while the kernel holds a pointer from [`Self::recv_buf`].
/// Commit only bytes actually received; return a complete loan before decoding/authentication.
#[derive(Debug)]
pub struct SecureRxBuffer {
    buf: bytes::BytesMut,
    filled: usize,
    end: usize,
}

impl SecureRxBuffer {
    pub fn remaining(&self) -> usize {
        self.end - self.filled
    }

    pub fn recv_buf(&mut self) -> &mut [u8] {
        // Capacity is reserved before lending, so this cannot relocate a server's live I/O pointer.
        self.buf.resize(self.end, 0);
        &mut self.buf[self.filled..self.end]
    }

    pub fn commit(&mut self, n: usize) {
        assert!(n <= self.remaining());
        assert!(n <= self.buf.len() - self.filled);
        self.filled += n;
    }

    /// Uninitialized receive space, bounded by the parsed frame end.
    /// Complete writes with [`Self::commit_initialized`], never with safe `commit`.
    pub fn spare_capacity_mut(&mut self) -> &mut [core::mem::MaybeUninit<u8>] {
        self.buf.truncate(self.filled);
        let remaining = self.remaining();
        &mut self.buf.spare_capacity_mut()[..remaining]
    }

    /// Commit the next `n` bytes written through the spare-capacity interface.
    ///
    /// # Safety
    /// The next `n` bytes starting at the received prefix must have been initialized.
    /// No socket or other writer may retain access to them after this call.
    pub unsafe fn commit_initialized(&mut self, n: usize) {
        assert!(n <= self.remaining());
        let filled = self.filled + n;
        assert!(filled <= self.buf.capacity());
        if n != 0 {
            // SAFETY: caller initialized this exact prefix; bounds checked above.
            unsafe { self.buf.set_len(filled) };
            self.filled = filled;
        }
    }
}

/// Header-time admission of MESSAGE frames (doc/design/memory-envelope.md, G1): once a message frame's preamble is
/// parsed its length is reserved in the process ingress pool BEFORE any body byte is assembled or allocated. A full
/// pool leaves the decoder waiting at the header (no byte consumed, nothing allocated); the connection reports it
/// ([`Decoder::awaiting_credit`]) and the transport stops reading until a retry succeeds. The reservation travels with
/// the frame ([`OwnedFrame::credit`]) and is released when the message is done. One atomic per frame; no lock.
///
/// A frame above its pool's capacity or above [`Gate::cap`] is not refused: it waits until it is all the pool holds
/// and then takes the pool as its single oversized reservation ([`ingress::FrameGate::admit`]). One admission decision
/// per frame, at its preamble, reserving the whole declared size. The probe returns the data charge if it refuses the
/// segment; accepted data never waits for a second admission (spec msgr2.md 8.2).
#[derive(Debug, Default)]
struct Gate {
    fg: Option<ingress::FrameGate>,
    credit: Option<ingress::IngressLease>,
    wait: Option<ingress::Waiter>,
    /// Largest received MESSAGE, in segment bytes (`osd_client_message_size_cap`): above it a frame is admitted alone.
    cap: u64,
    /// Bytes the frame reserves at its preamble, including its declared data segment.
    bytes: usize,
    /// The frame is above its pool capacity or `cap`: it takes the pool alone.
    alone: bool,
    /// The data segment is decided by the probe after the front (see [`Gate::begin`]).
    split: bool,
    /// The frame in progress needs admission (gated tag) ...
    gated: bool,
    /// ... and is admitted.
    admitted: bool,
}

impl Gate {
    /// A frame with preamble `p` starts. True when it needs admission (the caller then waits in its gate state).
    /// `wire` = the frame's whole declared size; `split` = the caller assembles the data segment on demand, so the probe
    /// can return its charge after the front without allocating it.
    fn begin(
        &mut self,
        p: &Preamble,
        wire: usize,
        probe: Option<crate::DataProbe>,
        split: bool,
    ) -> bool {
        self.credit = None;
        self.admitted = false;
        self.gated = self.fg.is_some() && p.tag == crate::Tag::Message as u8;
        self.split = false;
        self.alone = false;
        self.bytes = wire;
        if p.tag == crate::Tag::Message as u8 {
            // the per-link cap counts the segments after the header2 (spec 8.2: sum(seg1..3), the bytes Ceph's
            // throttler takes); the pool cap counts the reservation (segment bytes + framing)
            let sum = p.len[1..p.n].iter().map(|&l| u64::from(l)).sum::<u64>();
            self.alone = self.gated
                && (sum > self.cap
                    || self
                        .fg
                        .as_ref()
                        .is_some_and(|fg| wire as u64 > fg.capacity()));
            // A compressed frame's segment lengths are the compressed ones: the data length is only known after
            // decompression, so its payload is always admitted (spec 8.2).
            // the probe runs with or without an ingress gate: it is what keeps a refused segment out of memory
            self.split = split
                && p.n == 4
                && p.flags & crate::FLAG_COMPRESSED == 0
                && probe.is_some_and(|pr| u64::from(p.len[3]) >= pr.threshold);
        }
        self.gated
    }

    /// The frame begun last still waits for admission.
    fn pending(&self) -> bool {
        self.gated && !self.admitted
    }

    /// Would the waiting frame be admitted now?
    fn ready(&self) -> bool {
        match &self.fg {
            None => true,
            Some(fg) => self.admitted || fg.ready(self.bytes, self.alone, self.wait.as_ref()),
        }
    }

    /// Try to admit the frame begun last (idempotent once admitted).
    fn admit(&mut self) -> bool {
        if !self.pending() {
            return true;
        }
        let Some(fg) = &self.fg else {
            return true;
        };
        match fg.admit(self.bytes, self.alone, &mut self.wait) {
            Some(l) => {
                self.credit = Some(l);
                self.admitted = true;
                true
            }
            None => false,
        }
    }

    /// The frame at its front asks the probe before its data segment is assembled.
    fn probe_split(&self) -> bool {
        self.split
    }

    /// The frame is complete: its reservation goes with it.
    fn take(&mut self) -> ingress::InputGuard {
        self.gated = false;
        self.admitted = false;
        self.split = false;
        ingress::InputGuard(self.credit.take())
    }

    /// The frame is gone (aborted, failed): give its reservation back.
    fn release(&mut self) {
        self.gated = false;
        self.admitted = false;
        self.split = false;
        self.credit = None;
    }

    /// Give back the data segment's charge when the probe refused it (spec msgr2.md 8.2).
    fn shrink(&mut self, bytes: usize) {
        if let (Some(fg), Some(l)) = (&self.fg, &self.credit) {
            fg.shrink(l, bytes);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsmSt {
    Pre,
    Admit,
    Probe,
    Seg,
    Crc0,
    Late,
}

/// Direct frame assembler (CRC mode, rev 2.1): copies received bytes straight into per-segment buffers and runs the
/// crc over each piece right after it was copied (L1-hot), so a frame is touched once instead of three times (ring
/// copy, crc pass over a cold multi-MiB buffer, copy out into owned segments).
#[derive(Debug)]
struct Asm {
    dispatch: Option<RxDispatch>,
    /// Recycles large segment buffers (the dispatch domain's shelf, or one set by [`Decoder::attach_shelf`]).
    shelf: Option<Arc<crate::rxpool::Shelf>>,
    st: AsmSt,
    /// Partial preamble (32) / inline crc (4) / epilogue (13) bytes.
    small: [u8; PREAMBLE_LEN],
    nsmall: usize,
    p: Preamble,
    seg: usize,
    segs: [SegBuf; 4],
    crc: [u32; 4],
    /// Bytes of each segment already covered by `crc`.
    crcd: [usize; 4],
    /// Compute the segment crcs of CRC-mode frames (`ms_crc_data`, spec 4.3). False: the received values are read and
    /// discarded, no comparison; the computed crc is still kept where downstream uses it as a checksum of the bytes
    /// ([`OwnedFrame::data_crc`], block crcs). The preamble crc and `late_status` are always checked.
    crc_data: bool,
    /// Wire bytes of the current frame consumed so far.
    wire: usize,
    /// Declared wire length of the frame being assembled (preamble parsed).
    total: usize,
    /// The segment buffer is lent out ([`Asm::direct_take`]): bytes it held then. Nothing may be consumed meanwhile.
    lent: Option<usize>,
    /// seg0 verified against its inline crc.
    seg0_ok: bool,
    aborted: u64,
    /// Block crcs of the data segment being assembled (>= [`BLOCKS_MIN`]).
    blk: Option<crc::BlockCrcs>,
    /// Whether downstream consumers use per-block CRC metadata.
    collect_blocks: bool,
    /// Data segments of MESSAGE frames are placed by their alignment hint and `data_off` (see
    /// [`Decoder::set_rx_place`]).
    place: bool,
    /// Grid offset of the data segment being assembled (bytes before its first 4 KiB boundary in memory when placed),
    /// and the leading pad of its buffer (the bytes of the segment start at `segs[3][pad..]`).
    head: usize,
    pad: usize,
    /// Data segments of MESSAGE frames with at least this many bytes are shared while they arrive (0 = off, see
    /// [`Decoder::set_prewrite`]).
    prewrite: usize,
    /// Reader handle of the current frame's shared data segment.
    watch: Option<SegWatch>,
    /// Decides whether the data segment of the frame being assembled is consumed unadmitted ([`Decoder::set_data_probe`]).
    probe: Option<crate::DataProbe>,
    /// The probe ran for the frame being assembled.
    probed: bool,
    /// The probe refused the data segment: it is consumed into no buffer (`skipped` = bytes so far).
    refused: bool,
    skipped: usize,
}

/// Make room for `len` bytes in the empty segment buffer `seg`: a recycled buffer of the dispatch domain's shelf when
/// there is one, else a fresh exact allocation. A buffer already holding a prefix grows in place (a shared one never
/// grows: its capacity was reserved before it was shared).
fn reserve(
    shelf: Option<&crate::rxpool::Shelf>,
    seg: &mut SegBuf,
    len: usize,
) -> Result<(), Error> {
    match shelf {
        Some(shelf) if seg.capacity() == 0 => {
            *seg = SegBuf::from(shelf.take(len).map_err(|_| Error::AllocationFailed(len))?);
            Ok(())
        }
        _ => seg.reserve_exact(len),
    }
}

impl Asm {
    fn new() -> Asm {
        Asm {
            dispatch: None,
            shelf: None,
            st: AsmSt::Pre,
            small: [0; PREAMBLE_LEN],
            nsmall: 0,
            p: Preamble {
                tag: 0,
                n: 1,
                len: [0; 4],
                align: [0; 4],
                flags: 0,
            },
            seg: 0,
            segs: Default::default(),
            crc: [!0; 4],
            crcd: [0; 4],
            crc_data: true,
            wire: 0,
            total: 0,
            lent: None,
            seg0_ok: false,
            aborted: 0,
            blk: None,
            collect_blocks: true,
            place: false,
            head: 0,
            pad: 0,
            prewrite: 0,
            watch: None,
            probe: None,
            probed: false,
            refused: false,
            skipped: 0,
        }
    }

    /// Bytes of segment `i` received so far (without the leading pad of a block-mode data segment).
    fn have(&self, i: usize) -> usize {
        self.segs[i].len() - self.pad(i)
    }

    /// Leading pad of segment `i`'s buffer: only a placed data segment (segment 3) has one ([`Asm::begin_data`]).
    fn pad(&self, i: usize) -> usize {
        if i == 3 { self.pad } else { 0 }
    }

    /// Placement of the data segment of the frame being assembled ([`Decoder::set_rx_place`]): `(alignment, in-page
    /// offset of segment byte 0)`, or `None` (not placed: placement off, no MESSAGE frame, hint below 2).
    fn data_place(&self) -> Option<(usize, usize)> {
        data_place(self.place, &self.p, &self.segs[0])
    }

    /// Start the data segment of `l` bytes (nothing received yet). Placed ([`Asm::data_place`]): the buffer gets a
    /// leading pad such that segment byte 0 lies at the wanted in-page offset (the store can DMA a payload from it in
    /// place); the block crc grid then starts at the segment's first 4 KiB boundary in memory. Segments of at least
    /// [`BLOCKS_MIN`] bytes (block crcs on) go into block mode. Wire bytes and the segment are unchanged: `finish` cuts
    /// the pad off.
    fn begin_data(&mut self, l: usize) -> Result<(), Error> {
        let place = self.data_place();
        let seg = &mut self.segs[3];
        let shelf = self.shelf.as_deref();
        let mut head = 0;
        match place {
            None => reserve(shelf, seg, l)?,
            Some(place) => {
                let (b, pad) = placed_buf(shelf, l, 0, place)?;
                *seg = b;
                self.pad = pad;
                // the 4 KiB grid of memory, seen from segment byte 0
                head = grid_head(seg.as_ptr() as usize + pad);
            }
        }
        self.head = head;
        if !(self.collect_blocks && l >= BLOCKS_MIN) {
            return Ok(());
        }
        self.blk = Some(crc::BlockCrcs::with_head(l, head));
        // pre-write (adr 0477): a large message payload is readable while it arrives (whole capacity reserved above)
        if self.prewrite > 0 && l >= self.prewrite && self.p.tag == crate::Tag::Message as u8 {
            self.watch = Some(self.segs[3].share(self.shelf.clone()));
        }
        Ok(())
    }

    fn reset(&mut self) {
        if let Some(dispatch) = &mut self.dispatch {
            dispatch.take_guard();
        }
        self.st = AsmSt::Pre;
        self.lent = None;
        self.nsmall = 0;
        self.wire = 0;
        self.seg0_ok = false;
        self.segs = Default::default();
        self.blk = None;
        self.head = 0;
        self.pad = 0;
        self.watch = None;
        self.probed = false;
        self.refused = false;
        self.skipped = 0;
    }

    /// Fill `small[..want]` from `data`; true when complete.
    #[inline]
    fn gather(&mut self, data: &[u8], used: &mut usize, want: usize) -> bool {
        let take = (want - self.nsmall).min(data.len() - *used);
        self.small[self.nsmall..self.nsmall + take].copy_from_slice(&data[*used..*used + take]);
        self.nsmall += take;
        self.wire += take;
        *used += take;
        self.nsmall == want
    }

    /// Consume bytes of exactly one frame. Returns bytes used and the frame once complete (aborted frames are
    /// counted and skipped; consumption then continues with the next frame).
    fn consume(
        &mut self,
        data: &[u8],
        limits: &Limits,
        gate: &mut Gate,
        frames: &mut u64,
    ) -> Result<(usize, Option<OwnedFrame>), Error> {
        if self.lent.is_some() {
            // bytes while the segment buffer is out: the transport broke the direct-receive contract (never append
            // to the placeholder, never panic on the crc bookkeeping)
            return Err(Error::Busy);
        }
        let mut used = 0usize;
        loop {
            match self.st {
                AsmSt::Pre => {
                    if !self.gather(data, &mut used, PREAMBLE_LEN) {
                        return Ok((used, None));
                    }
                    self.p = Preamble::parse(&self.small, limits)?;
                    self.nsmall = 0;
                    self.crc = [!0; 4];
                    self.crcd = [0; 4];
                    self.seg = 0;
                    self.seg0_ok = false;
                    self.total = self.p.wire_len(Revision::V21, false)?;
                    *frames += 1;
                    // Preserve the ingress gate's existing conservative framing charge.
                    let wire = self
                        .p
                        .len
                        .iter()
                        .try_fold(
                            FRAME_CHARGE_MIN + place_room(self.place, &self.p),
                            |n, &len| n.checked_add(usize::try_from(len).ok()?),
                        )
                        .ok_or(Error::FrameTooLarge(u64::MAX))?;
                    let gated = gate.begin(&self.p, wire, self.probe, true);
                    self.st = if self.dispatch.is_some() || gated {
                        AsmSt::Admit
                    } else {
                        AsmSt::Seg
                    };
                }
                AsmSt::Admit => {
                    if !gate.admit() {
                        return Ok((used, None));
                    }
                    if let Some(dispatch) = &mut self.dispatch
                        && !dispatch.admit(self.p, place_room(self.place, &self.p))?
                    {
                        return Ok((used, None));
                    }
                    self.st = AsmSt::Seg;
                }
                AsmSt::Probe => {
                    if !self.probed {
                        self.probed = true;
                        // header2 and the front are complete: the probe decides whether the data segment is wanted
                        let refuse = self.probe.is_some_and(|pr| {
                            (pr.refuse)(
                                &self.segs[0],
                                &self.segs[1],
                                self.p.len[2] as usize,
                                self.p.len[3] as usize,
                            )
                        });
                        self.refused = refuse;
                        if refuse {
                            // No data buffer will be allocated. Accepted data is already charged from the preamble.
                            gate.shrink(self.p.len[3] as usize);
                        }
                    }
                    self.st = AsmSt::Seg;
                }
                AsmSt::Seg => {
                    let i = self.seg;
                    let l = self.p.len[i] as usize;
                    // a refused data segment is consumed into no buffer: `skipped` counts its bytes
                    let have = if self.refused && i == 3 {
                        self.skipped
                    } else {
                        self.have(i)
                    };
                    if have < l {
                        let take = (l - have).min(data.len() - used);
                        // Offer an untouched segment to the transport before allocating its
                        // body. Ordinary direct loans still reserve the full fallback below.
                        if take == 0 {
                            return Ok((used, None));
                        }
                        if self.refused && i == 3 {
                            self.crc[3] = crc32c(self.crc[3], &data[used..used + take]);
                            self.skipped = have + take;
                            used += take;
                            self.wire += take;
                            if have + take < l {
                                return Ok((used, None));
                            }
                        } else {
                            if have == 0 && i == 3 {
                                self.begin_data(l)?;
                            } else if have == 0 {
                                reserve(self.shelf.as_deref(), &mut self.segs[i], l)?;
                            }
                            if i == 3
                                && let Some(b) = self.blk.as_mut()
                            {
                                // block mode: crc per 4 KiB block of the segment while it is cache-hot (adr 0061 am. 4)
                                block_append(
                                    b,
                                    &mut self.segs[3],
                                    self.pad,
                                    &data[used..used + take],
                                    l,
                                );
                                used += take;
                                self.wire += take;
                                self.crcd[3] = b.pos();
                                if have + take < l {
                                    return Ok((used, None));
                                }
                                self.crc[3] = b.crc(!0);
                            } else {
                                // a placed data segment below block size: its buffer starts with the pad (`begin_data`)
                                let pad = self.pad(i);
                                if cfg!(target_arch = "x86_64") && take >= CRC_RUN {
                                    // Cover a preceding short fragment before fusing this large append. Keep small
                                    // fragments batched so packet-sized feeds do not defeat the long CRC kernels.
                                    if self.crcd[i] < have {
                                        self.crc[i] = crc32c(
                                            self.crc[i],
                                            &self.segs[i][pad + self.crcd[i]..],
                                        );
                                    }
                                    self.crc[i] = self.segs[i]
                                        .extend_crc(self.crc[i], &data[used..used + take]);
                                    self.crcd[i] = have + take;
                                } else {
                                    self.segs[i].extend_from_slice(&data[used..used + take]);
                                }
                                used += take;
                                self.wire += take;
                                // crc in runs of >= CRC_RUN (the long 3-way path of the crc), while the data is still hot
                                let len = have + take;
                                if self.crcd[i] < len && (len - self.crcd[i] >= CRC_RUN || len == l)
                                {
                                    self.crc[i] =
                                        crc32c(self.crc[i], &self.segs[i][pad + self.crcd[i]..]);
                                    self.crcd[i] = len;
                                }
                                if len < l {
                                    return Ok((used, None));
                                }
                            }
                        }
                    }
                    // segment complete
                    if i == 0 && l > 0 {
                        self.nsmall = 0;
                        self.st = AsmSt::Crc0;
                    } else if i == 1 && gate.probe_split() {
                        // header2 and front complete: the probe may refuse the data segment before it is assembled
                        self.seg = i + 1;
                        self.st = AsmSt::Probe;
                    } else if i + 1 < self.p.n {
                        self.seg = i + 1;
                    } else if self.p.n > 1 {
                        self.nsmall = 0;
                        self.st = AsmSt::Late;
                    } else {
                        return Ok((used, Some(self.finish())));
                    }
                }
                AsmSt::Crc0 => {
                    if !self.gather(data, &mut used, 4) {
                        return Ok((used, None));
                    }
                    if self.crc_data && self.crc[0] != rd_u32(&self.small, 0) {
                        return Err(Error::BadSegmentCrc(0));
                    }
                    self.seg0_ok = true;
                    self.nsmall = 0;
                    if self.p.n > 1 {
                        self.seg = 1;
                        self.st = AsmSt::Seg;
                    } else {
                        return Ok((used, Some(self.finish())));
                    }
                }
                AsmSt::Late => {
                    if !self.gather(data, &mut used, 13) {
                        return Ok((used, None));
                    }
                    let aborted = late_ok(Revision::V21, self.small[0])?;
                    if aborted {
                        self.aborted += 1;
                        self.reset();
                        gate.release();
                        if self.dispatch.is_some() {
                            return Ok((used, None));
                        }
                        continue;
                    }
                    for i in 1..self.p.n {
                        if self.crc_data && self.crc[i] != rd_u32(&self.small, 1 + 4 * (i - 1)) {
                            return Err(Error::BadSegmentCrc(i));
                        }
                    }
                    return Ok((used, Some(self.finish())));
                }
            }
        }
    }

    /// While the data segment of a MESSAGE frame is lent ([`Asm::direct_take`]): the frame's header2 segment and the
    /// leading pad of the lent buffer (segment bytes start at `pad`).
    fn lent_message(&self) -> Option<(&[u8], usize, usize)> {
        (self.st == AsmSt::Seg
            && self.seg == 3
            && self.lent.is_some()
            && self.p.tag == crate::Tag::Message as u8
            && self.p.n == 4)
            .then(|| (&self.segs[0][..], self.pad, self.p.len[3] as usize))
    }

    /// Bytes still missing of the segment being received (0 unless a segment body is being assembled).
    fn direct_want(&self) -> usize {
        if self.st != AsmSt::Seg || self.lent.is_some() || (self.refused && self.seg == 3) {
            return 0;
        }
        let i = self.seg;
        (self.p.len[i] as usize).saturating_sub(self.have(i))
    }

    /// Hand the partially filled segment buffer (capacity for the whole segment, block crcs covering what it holds) to
    /// a transport that fills the rest straight from the socket; give it back with [`Asm::direct_put`]. A block-mode
    /// data segment's buffer starts with `pad` bytes that are not part of the segment (see [`Asm::begin_data`]): the
    /// transport only appends after `len()`, the block crcs count the segment's bytes only.
    fn direct_take(&mut self, reserve_body: bool) -> Result<(SegBuf, crc::BlockCrcs), Error> {
        let i = self.seg;
        let l = self.p.len[i] as usize;
        if reserve_body && i == 3 && self.segs[3].is_empty() {
            self.begin_data(l)?;
        }
        let pad = self.pad(i);
        let have = self.have(i);
        if reserve_body && self.segs[i].capacity() < pad + l {
            reserve(self.shelf.as_deref(), &mut self.segs[i], l - have)?;
        }
        let b = match self.blk.take() {
            Some(mut b) if i == 3 => {
                b.advance(&self.segs[i][pad..], true);
                b
            }
            _ if self.collect_blocks && i == 3 && l >= BLOCKS_MIN => {
                // not in block mode yet: account the (short) prefix once
                let mut b = crc::BlockCrcs::with_len(l);
                b.update(&self.segs[i][pad..]);
                b
            }
            _ => {
                // Only large data segments export block hints. For other segments the grid starts after the segment:
                // its entire CRC is accumulated in the prefix, no block table. The prefix was checksummed while it
                // was appended (`crc[i]`, seed !0, up to
                // `crcd[i]`): finish that running crc and carry it over (seed 0) instead of a second pass.
                if self.crcd[i] < have {
                    self.crc[i] = crc32c(self.crc[i], &self.segs[i][pad + self.crcd[i]..]);
                }
                let mut b = crc::BlockCrcs::with_head(l, l);
                b.push_piece(self.crc[i] ^ crc::crc32c_shift(!0, have as u64), have);
                b
            }
        };
        self.crcd[i] = have;
        self.lent = Some(have);
        Ok((core::mem::take(&mut self.segs[i]), b))
    }

    /// The buffer is back and complete (`len == pad + segment length`), `crcs` cover all of the segment.
    fn direct_put(
        &mut self,
        v: SegBuf,
        crcs: crc::BlockCrcs,
        limits: &Limits,
        gate: &mut Gate,
    ) -> Result<Option<OwnedFrame>, Error> {
        let i = self.seg;
        let Some(taken) = self.lent.take() else {
            return Err(Error::Busy); // nothing was lent
        };
        let pad = self.pad(i);
        if self.st != AsmSt::Seg
            || v.len() != pad + self.p.len[i] as usize
            || v.len() < pad + taken
            || crcs.pos() != v.len() - pad
        {
            return Err(Error::BadSegmentCrc(i));
        }
        self.wire += v.len() - pad - taken;
        self.crcd[i] = v.len() - pad;
        self.crc[i] = crcs.crc(!0);
        self.blk = (self.collect_blocks && i == 3 && v.len() - pad >= BLOCKS_MIN).then_some(crcs);
        self.segs[i] = v;
        // no new bytes are parsed here, but the returned segment may be the front: the data probe runs on the frame's
        // own gate state
        Ok(self.consume(&[], limits, gate, &mut 0)?.1)
    }

    fn finish(&mut self) -> OwnedFrame {
        let n = self.p.n;
        let refused = if self.refused { self.p.len[3] } else { 0 };
        let mut segs = Vec::with_capacity(n);
        let shelf = self.shelf.clone();
        for (i, s) in self.segs[..n].iter_mut().enumerate() {
            // the data segment of a block-mode frame starts after its leading pad (`begin_data`)
            let from = if i == 3 { self.pad } else { 0 };
            segs.push(core::mem::take(s).into_bytes(shelf.as_ref(), from));
        }
        let f = OwnedFrame {
            dispatch: self
                .dispatch
                .as_mut()
                .map_or_else(Default::default, RxDispatch::take_guard),
            tag: self.p.tag,
            flags: self.p.flags,
            align: self.p.align,
            data_crc: (n == 4 && !self.refused).then_some(self.crc[3]),
            data_blocks: if self.refused {
                None
            } else if n == 4 {
                self.blk.take().map(|b| b.into_blocks().into())
            } else {
                None
            },
            data_head: if self.refused { 0 } else { self.head },
            data_refused: refused,
            segs,
            credit: Default::default(),
        };
        self.reset();
        f
    }
}

/// Append `src` to the data segment `seg` (final length `l`) and keep its block crcs `b` current: small pieces are
/// copied and checksummed per whole block (one crc call per 4 KiB while the block is cache-hot); a large piece is
/// copied and checksummed in the same pass, grid piece by grid piece.
fn block_append(b: &mut crc::BlockCrcs, seg: &mut SegBuf, pad: usize, src: &[u8], l: usize) {
    if cfg!(target_arch = "x86_64") && src.len() >= CRC_RUN {
        b.advance(&seg[pad..], true);
        let (h, w, t) = crc::blocks::grid_split(seg.len() - pad, src.len(), b.head());
        let mut at = 0;
        for n in core::iter::once(h)
            .chain(core::iter::repeat_n(crc::blocks::BLK, w))
            .chain(core::iter::once(t))
        {
            if n > 0 {
                let c = seg.extend_crc(0, &src[at..at + n]);
                b.push_piece(c, n);
                at += n;
            }
        }
        return;
    }
    seg.extend_from_slice(src);
    b.advance(&seg[pad..], seg.len() - pad == l);
}

/// Incremental frame decoder. Owns the rx buffer; secure frames are decrypted in place, or into a placed buffer with
/// [`Decoder::set_rx_place`] (then only the ciphertext uses the rx buffer).
///
/// Usage: fill via [`recv_buf`](Self::recv_buf)+[`commit`](Self::commit) (or [`feed`](Self::feed)),
/// then call [`poll`](Self::poll) until `Ok(None)`. Any `Err` poisons the decoder.
#[derive(Debug)]
pub struct Decoder {
    buf: bytes::BytesMut,
    /// Original allocation range, retained across splits to avoid pinning a huge allocation for a small frame.
    backing: Option<(usize, usize)>,
    /// Initialized bytes in that allocation, including portions temporarily lent to owned frames.
    initialized: Option<(usize, usize)>,
    start: usize,
    filled: usize,
    rev: Revision,
    rx: Rx,
    limits: Limits,
    pre: Option<Parsed>,
    yielded: Option<usize>,
    failed: bool,
    want: usize,
    aborted: u64,
    /// Direct assembler (CRC mode, rev 2.1).
    asm: Asm,
    /// Completed direct frame waiting for `poll` (wire length kept for `buffered`).
    ready: Option<(OwnedFrame, usize)>,
    /// Direct frame lent out by `poll`.
    held: Option<OwnedFrame>,
    err: Option<Error>,
    /// Allocation identity, original filled offset and frame end of a transport-owned secure buffer.
    secure_lent: Option<(usize, usize, usize)>,
    /// Header-time admission of message frames.
    gate: Gate,
    /// Probe of MESSAGE data segments ([`Decoder::set_data_probe`]).
    probe: Option<crate::DataProbe>,
    /// Preambles parsed since construction: identifies the frame in progress ([`Decoder::frame_in_progress`]).
    frames: u64,
}

fn late_ok(rev: Revision, b: u8) -> Result<bool, Error> {
    match rev {
        Revision::V20 => Ok(b & 1 != 0),
        Revision::V21 => match b & 0x0F {
            LATE_COMPLETE => Ok(false),
            LATE_ABORTED => Ok(true),
            _ => Err(Error::BadLateStatus(b)),
        },
    }
}

/// Receive settings a connection keeps across decoder resets: applied to every fresh decoder ([`Decoder::with_cfg`]).
#[derive(Clone, Debug)]
pub(crate) struct DecoderCfg {
    /// [`Decoder::set_rx_block_crcs`].
    pub rx_block_crcs: bool,
    /// [`Decoder::set_crc_data`].
    pub crc_data: bool,
    /// [`Decoder::set_limits`].
    pub limits: Limits,
    /// [`Decoder::set_gate`].
    pub gate: Option<ingress::FrameGate>,
    /// [`Decoder::set_rx_place`].
    pub rx_place: bool,
    /// [`Decoder::set_prewrite`].
    pub prewrite: usize,
    /// [`Decoder::set_frame_cap`].
    pub frame_cap: u64,
    /// [`Decoder::set_data_probe`].
    pub data_probe: Option<crate::DataProbe>,
}

impl Default for DecoderCfg {
    /// The settings of a decoder from [`Decoder::new`].
    fn default() -> Self {
        Self {
            rx_block_crcs: true,
            crc_data: true,
            limits: Limits::default(),
            gate: None,
            rx_place: false,
            prewrite: 0,
            frame_cap: u64::MAX,
            data_probe: None,
        }
    }
}

impl Decoder {
    /// New decoder in CRC mode.
    pub fn new(rev: Revision) -> Self {
        Self::with_cfg(rev, &DecoderCfg::default())
    }

    /// New decoder in CRC mode with the settings of `cfg`.
    pub(crate) fn with_cfg(rev: Revision, cfg: &DecoderCfg) -> Self {
        let mut d = Self {
            buf: bytes::BytesMut::new(),
            backing: None,
            initialized: None,
            start: 0,
            filled: 0,
            rev,
            rx: Rx::Crc,
            limits: Limits::default(),
            pre: None,
            yielded: None,
            failed: false,
            want: PREAMBLE_LEN,
            aborted: 0,
            asm: Asm::new(),
            ready: None,
            held: None,
            err: None,
            secure_lent: None,
            gate: Gate::default(),
            probe: None,
            frames: 0,
        };
        d.set_rx_block_crcs(cfg.rx_block_crcs);
        d.set_crc_data(cfg.crc_data);
        d.set_limits(cfg.limits);
        d.set_gate(cfg.gate.clone());
        d.set_rx_place(cfg.rx_place);
        d.set_prewrite(cfg.prewrite);
        d.set_frame_cap(cfg.frame_cap);
        d.set_data_probe(cfg.data_probe);
        d
    }

    /// Attach a reactor-local logical receive domain before any frame/loan starts.
    /// The permit itself is Send; this admission owner never enters frame payloads.
    pub fn attach_dispatch(
        &mut self,
        owner: Rc<RefCell<crate::DispatchBudget>>,
    ) -> Result<(), Error> {
        if self.failed
            || self.err.is_some()
            || self.buffered() != 0
            || self.pre.is_some()
            || self.yielded.is_some()
            || self.secure_lent.is_some()
            || self.ready.is_some()
            || self.held.is_some()
            || self.asm.dispatch.is_some()
            || self.asm.st != AsmSt::Pre
            || self.asm.lent.is_some()
        {
            return Err(Error::Busy);
        }
        self.asm.shelf = Some(owner.borrow().shelf());
        self.asm.dispatch = Some(RxDispatch {
            owner,
            guard: Default::default(),
            granted: false,
            blocked: None,
        });
        Ok(())
    }

    /// Recycle this decoder's large segment buffers through `shelf` (shared by the caller across connections).
    /// Without a dispatch domain (which brings its own shelf) a decoder recycles nothing. Fails while a frame is in progress.
    pub fn attach_shelf(&mut self, shelf: Arc<crate::RxShelf>) -> Result<(), Error> {
        if self.asm.st != AsmSt::Pre || self.asm.lent.is_some() {
            return Err(Error::Busy);
        }
        self.asm.shelf = Some(shelf);
        Ok(())
    }

    fn poison(&mut self, error: Error) {
        self.failed = true;
        self.err = Some(error);
        self.ready = None;
        self.held = None;
        if let Some(dispatch) = &mut self.asm.dispatch {
            dispatch.take_guard();
        }
    }

    fn dispatch_blocked(&self) -> Option<u64> {
        self.asm.dispatch.as_ref().and_then(|d| d.blocked)
    }

    fn dispatch_guard(&mut self) -> crate::DispatchGuard {
        self.asm
            .dispatch
            .as_mut()
            .map_or_else(Default::default, RxDispatch::take_guard)
    }

    /// Override size limits.
    pub fn set_limits(&mut self, l: Limits) {
        self.limits = l;
    }

    /// Switch to secure mode for the next frame (call right after polling the frame that
    /// announced it; bytes already buffered for the next frame are fine).
    pub fn set_secure(&mut self, secret: &ConnSecret, role: Role) -> Result<(), Error> {
        if self.secure_lent.is_some()
            || self.pre.is_some()
            || self.asm.wire > 0
            || self.ready.is_some()
        {
            return Err(Error::Busy);
        }
        self.rx = Rx::Secure(secret.rx(role, self.rev)?);
        Ok(())
    }

    /// Configure optional downstream per-block CRC hints before receiving frames.
    /// False retains complete wire CRC verification and the verified segment CRC.
    /// Secure and revision 2.0 framing are unaffected. Default true.
    pub fn set_rx_block_crcs(&mut self, enabled: bool) {
        self.asm.collect_blocks = enabled;
    }

    /// `ms_crc_data` (spec 4.3): compare the received segment crcs of CRC-mode frames (default). False reads and
    /// discards them (0 or real) without comparing, for every segment including control frames; the preamble crc and
    /// `late_status` checks still run, and secure mode is unaffected (GCM tags, no crc fields).
    pub fn set_crc_data(&mut self, enabled: bool) {
        self.asm.crc_data = enabled;
    }

    /// Place the data segment of every MESSAGE frame (CRC mode rev 2.1, and secure mode through
    /// [`Decoder::poll_owned`]) in memory by the sender's hints: segment byte 0 lies at in-page offset `data_off mod A`,
    /// `A` = the preamble's data segment alignment hint as a power of two, at most 4 KiB (Ceph senders: 4096; Ceph
    /// receivers allocate the segment `A`-aligned and ignore `data_off`, which msgr1 receivers use for the same
    /// placement). A sender that knows where its payload lies in the segment states it in `data_off` (a replica's v9
    /// blob: payload at byte 14, `data_off` = -14), so the payload is 4 KiB aligned and the store writes it to the
    /// device by reference; its block crcs ([`OwnedFrame::data_blocks`]) lie on the 4 KiB grid of memory
    /// ([`OwnedFrame::data_head`]). Costs a leading pad of less than `A` bytes per data segment, never a copy. Spec
    /// msgr2.md s3.1. Default off (segment buffers as allocated).
    pub fn set_rx_place(&mut self, place: bool) {
        self.asm.place = place;
    }

    /// Receiver-side pre-write (adr 0477): the block-mode data segment of a MESSAGE frame with at least `min` bytes
    /// (CRC mode rev 2.1, block crcs on) is a shared [`SegBuf`]: while it arrives, [`Decoder::early`] gives its headers
    /// and a [`SegWatch`] to take views of the received prefix. Frame delivery, crc checks, `in_seq` and fault rules are
    /// unchanged; nothing is delivered earlier. 0 = off (plain buffers). Transports lend through
    /// [`Decoder::direct_take_seg`].
    pub fn set_prewrite(&mut self, min: usize) {
        self.asm.prewrite = min;
    }

    /// The frame being assembled has a shared data segment ([`Decoder::set_prewrite`]): its header2 (verified) and
    /// front (complete, verified only with the epilogue: a reader treats it as a hint), the watch and its layout.
    /// `None` otherwise.
    pub fn early(&self) -> Option<RxEarly<'_>> {
        let w = self.asm.watch.as_ref()?;
        Some(RxEarly {
            header: &self.asm.segs[0],
            front: &self.asm.segs[1],
            data: w,
            pad: self.asm.pad,
            head: self.asm.head,
            len: self.asm.p.len[3] as usize,
        })
    }

    /// Number of aborted frames silently dropped so far.
    pub fn aborted_frames(&self) -> u64 {
        self.aborted + self.asm.aborted
    }

    /// Bytes buffered but not yet consumed.
    pub fn buffered(&self) -> usize {
        self.filled - self.start - self.yielded.unwrap_or(0)
            + self.asm.wire
            + self.ready.as_ref().map_or(0, |r| r.1)
    }

    /// Writable space (at least `min` bytes) for reading from a socket directly into the buffer;
    /// pair with [`commit`](Self::commit).
    pub fn recv_buf(&mut self, min: usize) -> &mut [u8] {
        assert!(
            self.asm.dispatch.is_none(),
            "gated Decoder requires feed_admitted or an admitted owned loan"
        );
        self.recv_buf_inner::<true>(min)
    }

    fn recv_buf_inner<const WHOLE_FRAME: bool>(&mut self, min: usize) -> &mut [u8] {
        assert!(
            self.secure_lent.is_none(),
            "secure receive buffer is lent to the transport"
        );
        if let Some(n) = self.yielded.take() {
            self.start += n;
        }
        if self.start == self.filled {
            self.start = 0;
            self.filled = 0;
        }
        let min = min.max(1);
        if self.buf.len() - self.filled < min
            || (WHOLE_FRAME
                && matches!(self.rx, Rx::Secure(_))
                && self.start.saturating_add(self.want) > self.buf.len())
        {
            if self.start > 0 {
                self.buf.copy_within(self.start..self.filled, 0);
                self.filled -= self.start;
                self.start = 0;
            }
            // Gated fallback copies only newly accepted input. Whole-frame want is a loan/
            // progress plan, not permission to zero a body before a spare-capacity socket read.
            let want_len = if WHOLE_FRAME {
                (self.filled + min).max(self.want).max(crc::blocks::BLK)
            } else {
                (self.filled + min).max(crc::blocks::BLK)
            };
            if self.buf.len() < want_len {
                let want_len = if WHOLE_FRAME {
                    want_len.max(self.buf.len() * 2)
                } else {
                    want_len
                };
                let reclaimed = self.buf.try_reclaim(want_len - self.buf.len());
                let low = self.buf.as_ptr() as usize;
                if reclaimed
                    && self
                        .initialized
                        .is_some_and(|(a, b)| low >= a && low + want_len <= b)
                {
                    // SAFETY: try_reclaim cannot allocate/deallocate storage (bytes 1.12.1). It only moves
                    // initialized live bytes within it. Every byte in this tracked range was initialized by a
                    // previous resize/feed/authentication; unused values need not be preserved for receive.
                    // Only the mutable view is exposed, and try_reclaim guarantees sufficient capacity.
                    unsafe { self.buf.set_len(want_len) };
                } else {
                    self.buf.resize(want_len, 0);
                }
                let low = self.buf.as_ptr() as usize;
                let high = low + self.buf.capacity();
                if !reclaimed || self.backing.is_none_or(|(a, b)| low < a || high > b) {
                    self.backing = Some((low, high));
                    self.initialized = Some((low, low + self.buf.len()));
                } else {
                    let (a, b) = self.initialized.unwrap();
                    self.initialized = Some((a, b.max(low + self.buf.len())));
                }
            }
        }
        &mut self.buf[self.filled..]
    }

    /// Mark `n` bytes of the slice returned by `recv_buf` as filled.
    pub fn commit(&mut self, n: usize) {
        if self.asm.dispatch.is_some() {
            self.poison(Error::Busy);
            return;
        }
        self.commit_inner(n);
    }

    fn commit_inner(&mut self, n: usize) {
        assert!(self.filled + n <= self.buf.len());
        self.filled += n;
    }

    /// Copy `data` into the rx buffer.
    pub fn feed(&mut self, data: &[u8]) {
        if self.asm.dispatch.is_some() {
            self.poison(Error::Busy);
            return;
        }
        if self.secure_lent.is_some() {
            // No access to transport-owned storage. Poison the stream on contract violation rather
            // than parsing an empty placeholder or reusing the already-consumed preamble nonce.
            self.failed = true;
            return;
        }
        if self.direct()
            && self.start == self.filled
            && self.yielded.is_none()
            && self.ready.is_none()
        {
            return self.feed_direct(data);
        }
        self.recv_buf(data.len())[..data.len()].copy_from_slice(data);
        self.commit(data.len());
    }

    /// Accept a prefix of at most one frame, preserving a checked preamble on logical pressure.
    /// An empty slice retries existing buffered parsing/admission without physical RX activity.
    pub fn feed_admitted(&mut self, data: &[u8]) -> Result<RxFeed, Error> {
        if self.asm.dispatch.is_none() {
            return Err(Error::Busy);
        }
        if let Some(error) = self.err {
            self.poison(error);
            return Err(error);
        }
        if self.secure_lent.is_some() || self.asm.lent.is_some() {
            self.poison(Error::Busy);
            return Err(Error::Busy);
        }
        if self.failed {
            return Err(self.err.unwrap_or(Error::Failed));
        }
        if self.ready.is_some() {
            return Ok(RxFeed {
                consumed: 0,
                state: RxFeedState::FrameReady,
            });
        }
        let result = self.feed_admitted_inner(data);
        if let Err(error) = result {
            self.poison(error);
        }
        result
    }

    fn feed_admitted_inner(&mut self, data: &[u8]) -> Result<RxFeed, Error> {
        if self.direct() {
            let (consumed, frame) =
                self.asm
                    .consume(data, &self.limits, &mut self.gate, &mut self.frames)?;
            let state = if let Some(frame) = frame {
                let wire = frame_wire_len(&frame);
                self.ready = Some((frame, wire));
                RxFeedState::FrameReady
            } else {
                self.dispatch_blocked()
                    .map_or(RxFeedState::NeedInput, |generation| {
                        RxFeedState::DispatchBlocked { generation }
                    })
            };
            return Ok(RxFeed { consumed, state });
        }
        let mut consumed = 0;
        let aborted = self.aborted;
        loop {
            // This only stages the frame. Transfer ingress credit once, when
            // poll_owned exports it to the caller, just like the direct path.
            if let Some(frame) = self.poll_owned_inner()? {
                let wire = self.frame_wire_len(&frame);
                self.ready = Some((frame, wire));
                return Ok(RxFeed {
                    consumed,
                    state: RxFeedState::FrameReady,
                });
            }
            if self.aborted != aborted {
                return Ok(RxFeed {
                    consumed,
                    state: RxFeedState::NeedInput,
                });
            }
            if let Some(generation) = self.dispatch_blocked() {
                return Ok(RxFeed {
                    consumed,
                    state: RxFeedState::DispatchBlocked { generation },
                });
            }
            let available = self.filled - self.start;
            let n = self
                .want
                .saturating_sub(available)
                .min(data.len() - consumed);
            if n == 0 {
                return Ok(RxFeed {
                    consumed,
                    state: RxFeedState::NeedInput,
                });
            }
            self.recv_buf_inner::<false>(n)[..n].copy_from_slice(&data[consumed..consumed + n]);
            self.commit_inner(n);
            consumed += n;
        }
    }

    fn frame_wire_len(&self, frame: &OwnedFrame) -> usize {
        let l0 = frame.segs[0].len();
        let tail = &frame.segs[1..];
        // a refused data segment is not in `segs` but was on the wire
        let refused = frame.data_refused as usize;
        match (&self.rx, self.rev) {
            (Rx::Crc, Revision::V21) => frame_wire_len(frame),
            (Rx::Crc, Revision::V20) => {
                PREAMBLE_LEN + l0 + tail.iter().map(bytes::Bytes::len).sum::<usize>() + refused + 17
            }
            (Rx::Secure(_), Revision::V20) => {
                PREAMBLE_LEN
                    + pad16(l0)
                    + tail.iter().map(|b| pad16(b.len())).sum::<usize>()
                    + pad16(refused)
                    + 32
            }
            (Rx::Secure(_), Revision::V21) => {
                96 + pad16(l0).saturating_sub(INLINE_LEN)
                    + if pad16(l0) > INLINE_LEN { TAG_LEN } else { 0 }
                    + if tail.is_empty() && refused == 0 {
                        0
                    } else {
                        tail.iter().map(|b| pad16(b.len())).sum::<usize>() + pad16(refused) + 32
                    }
            }
        }
    }

    /// CRC-mode rev1 only: seg0 of the frame currently being received, verified against its inline
    /// CRC, as soon as it is fully buffered (before the rest of the frame). `Ok(None)` if not yet
    /// available or not applicable. Does not consume anything.
    pub fn peek_seg0(&self) -> Result<Option<&[u8]>, Error> {
        if self.direct() {
            return Ok(
                (self.asm.seg0_ok && self.asm.st != AsmSt::Pre).then(|| &self.asm.segs[0][..])
            );
        }
        let (Some(pr), Rx::Crc, Revision::V21) = (&self.pre, &self.rx, self.rev) else {
            return Ok(None);
        };
        let l0 = pr.p.len[0] as usize;
        let b = self.start + self.yielded.unwrap_or(0);
        if l0 == 0 || self.filled < b + PREAMBLE_LEN + l0 + 4 {
            return Ok(None);
        }
        let s = &self.buf[b + PREAMBLE_LEN..b + PREAMBLE_LEN + l0];
        if self.asm.crc_data && crc32c(!0, s) != rd_u32(&self.buf, b + PREAMBLE_LEN + l0) {
            return Err(Error::BadSegmentCrc(0));
        }
        Ok(Some(s))
    }

    /// Next complete frame with owned segments; a gated MESSAGE frame carries its reservation ([`OwnedFrame::credit`]).
    /// Same release / abort / error semantics as [`poll`](Self::poll).
    pub fn poll_owned(&mut self) -> Result<Option<OwnedFrame>, Error> {
        let mut result = self.poll_owned_inner();
        if self.asm.dispatch.is_some()
            && let Err(error) = result
        {
            self.poison(error);
        }
        if let Ok(Some(f)) = &mut result {
            f.credit = self.gate.take();
        }
        result
    }

    /// Admission of message frames (`None` = off, the default): see [`ingress::FrameGate`].
    pub fn set_gate(&mut self, gate: Option<ingress::FrameGate>) {
        self.gate.fg = gate;
    }

    /// Largest received MESSAGE in segment bytes (`osd_client_message_size_cap`): above it a MESSAGE is admitted alone
    /// (never refused for its size, spec msgr2.md 8.2). `u64::MAX` = no cap beyond [`Limits::max_frame`].
    pub fn set_frame_cap(&mut self, cap: u64) {
        self.gate.cap = cap;
    }

    /// Receive probe of MESSAGE data segments ([`crate::DataProbe`]): a frame whose data segment the probe refuses is
    /// consumed and verified without being buffered; its preamble reservation returns the data charge at refusal.
    /// Delivery sets [`OwnedFrame::data_refused`] / [`Frame::data_refused`]. The buffered path (secure mode, msgr2.0) holds the
    /// whole frame for authentication: it reserves it at the preamble and gives the refused segment back after the
    /// probe ([`Self::poll_owned`] only). `None` (the default) assembles every data segment.
    pub fn set_data_probe(&mut self, probe: Option<crate::DataProbe>) {
        self.probe = probe;
        self.asm.probe = probe;
    }

    /// A message frame's header is parsed but the pool has no space: no more input is wanted until
    /// [`retry_gate`](Self::retry_gate) succeeds (the transport leaves the socket unread).
    pub fn awaiting_credit(&self) -> bool {
        self.gate.wait.is_some()
    }

    /// The frame whose preamble is parsed and that is not complete yet: its identity (preambles parsed since
    /// construction, so a completed frame and its successor are told apart) and its declared wire length. `None` when
    /// the decoder waits for a preamble. The connection arms its frame-completion deadline from this.
    pub fn frame_in_progress(&self) -> Option<(u64, usize)> {
        // a frame waiting for local admission (dispatch credit) has not started to arrive in a way the link can
        // control: its completion deadline starts only once it may read
        if self.dispatch_blocked().is_some() {
            return None;
        }
        if self.direct() {
            return (self.asm.st != AsmSt::Pre).then_some((self.frames, self.asm.total));
        }
        self.pre.as_ref().map(|p| (self.frames, p.total))
    }

    /// Would the frame that waits for credit be admitted now (the owner core's re-check before it sleeps)?
    pub fn credit_ready(&self) -> bool {
        self.gate.ready()
    }

    /// Drop a waiting or admitted frame reservation (the connection ended).
    pub fn cancel_gate(&mut self) {
        self.gate.release();
        self.gate.wait = None;
    }

    /// Try to admit the waiting frame (see [`awaiting_credit`](Self::awaiting_credit)).
    pub fn retry_gate(&mut self) -> bool {
        self.gate.admit()
    }

    fn poll_owned_inner(&mut self) -> Result<Option<OwnedFrame>, Error> {
        let _profile = crate::profile::span("messenger.decode", 0);
        if self.failed {
            return Err(self.err.unwrap_or(Error::Failed));
        }
        if self.secure_lent.is_some() {
            return Err(Error::Busy);
        }
        if let Some((frame, _)) = self.ready.take() {
            return Ok(Some(frame));
        }
        if self.direct() {
            self.held = None;
            return self.poll_direct();
        }
        let Some(mut done) = self.next_buffered(true)? else {
            return Ok(None);
        };
        if let Some(placed) = done.placed.take() {
            // decrypted out of place: the rx buffer only held ciphertext, it is reused for the next frame
            self.yielded = Some(done.total);
            let out = placed.into_bytes(self.asm.shelf.as_ref(), 0);
            let n = done.p.n;
            let mut segs = Vec::with_capacity(n);
            segs.push(bytes::Bytes::copy_from_slice(&self.buf[done.r[0].clone()]));
            segs.extend(done.r[1..n].iter().map(|r| out.slice(r.clone())));
            let data_head = grid_head(segs[3].as_ptr() as usize);
            return Ok(Some(self.buffered_frame(
                done.p,
                segs,
                data_head,
                done.refused,
            )));
        }
        let backing = self.backing.map_or(self.buf.capacity(), |(a, b)| b - a);
        if done.refused == 0
            && matches!(self.rx, Rx::Secure(_))
            && done.total >= OWNED_FRAME_MIN
            && backing <= done.total.saturating_mul(4)
        {
            let consumed = self.start + done.total;
            let bytes = self.buf.split_to(consumed).freeze();
            self.filled -= consumed;
            self.start = 0;
            self.yielded = None;
            self.want = PREAMBLE_LEN;
            let segs = done.r[..done.p.n]
                .iter()
                .map(|r| bytes.slice(r.clone()))
                .collect();
            return Ok(Some(self.buffered_frame(done.p, segs, 0, done.refused)));
        }
        // Small frames copy only their segments; retaining a disproportionate backing would inflate RSS. A placed data
        // segment is copied into a placed buffer (the same one copy).
        self.yielded = Some(done.total);
        let place = if self.probe_eligible(&done.p) {
            None
        } else {
            data_place(self.asm.place, &done.p, &self.buf[done.r[0].clone()])
        };
        let mut segs = Vec::with_capacity(done.p.n);
        for (i, r) in done.r[..done.p.n].iter().enumerate() {
            let src = &self.buf[r.clone()];
            segs.push(match place {
                Some(place) if i == 3 => {
                    let (mut b, pad) = placed_buf(self.asm.shelf.as_deref(), src.len(), 0, place)?;
                    b.extend_from_slice(src);
                    b.into_bytes(self.asm.shelf.as_ref(), pad)
                }
                _ => bytes::Bytes::copy_from_slice(src),
            });
        }
        let data_head = match place {
            Some(_) => grid_head(segs[3].as_ptr() as usize),
            None => 0,
        };
        Ok(Some(self.buffered_frame(
            done.p,
            segs,
            data_head,
            done.refused,
        )))
    }

    /// An owned frame of the buffered path (secure / rev 2.0): verified in place, no block crcs; `data_head` is where
    /// the 4 KiB grid starts in the data segment ([`OwnedFrame::data_head`]).
    fn buffered_frame(
        &mut self,
        p: Preamble,
        segs: Vec<bytes::Bytes>,
        data_head: usize,
        data_refused: u32,
    ) -> OwnedFrame {
        OwnedFrame {
            dispatch: self.dispatch_guard(),
            tag: p.tag,
            flags: p.flags,
            align: p.align,
            data_crc: None,
            data_blocks: None,
            data_head,
            data_refused,
            segs,
            credit: Default::default(),
        }
    }

    #[inline]
    fn direct(&self) -> bool {
        matches!(self.rx, Rx::Crc) && self.rev == Revision::V21
    }

    /// Relinquish only idle Secure receive reuse storage sharing this owned result.
    /// This is a best-effort cache release, never a uniqueness guarantee.
    pub fn release_empty_secure_reply(&mut self, data: &bytes::Bytes) -> bool {
        // Only the zero-capacity subset: other tails may contain wire bytes or
        // initialized spare storage. Even zero-capacity tails can later reclaim
        // their original allocation, so callers must explicitly opt into release.
        if data.is_empty()
            || self.failed
            || self.err.is_some()
            || !matches!(self.rx, Rx::Secure(_))
            || self.start != 0
            || self.filled != 0
            || !self.buf.is_empty()
            || self.buf.capacity() != 0
            || self.yielded.is_some()
            || self.pre.is_some()
            || self.secure_lent.is_some()
            || self.ready.is_some()
            || self.held.is_some()
            || self.asm.st != AsmSt::Pre
            || self.asm.nsmall != 0
            || self.asm.wire != 0
            || self.asm.lent.is_some()
            || self.asm.blk.is_some()
            || self.asm.segs.iter().any(|segment| !segment.is_empty())
        {
            return false;
        }
        let (Some((low, high)), Some((initialized_low, initialized_high))) =
            (self.backing, self.initialized)
        else {
            return false;
        };
        let pointer = self.buf.as_ptr() as usize;
        let result = data.as_ptr() as usize;
        let (Some(capacity_end), Some(initialized_end), Some(result_end)) = (
            pointer.checked_add(self.buf.capacity()),
            pointer.checked_add(self.buf.len()),
            result.checked_add(data.len()),
        ) else {
            return false;
        };
        // A live result prevents allocation-address reuse. The current suffix must
        // still own this exact tracked backing, including a zero-capacity end suffix.
        if low >= high
            || initialized_low < low
            || initialized_high > high
            || initialized_low > initialized_high
            || pointer != high
            || capacity_end > high
            || pointer < initialized_low
            || initialized_end > initialized_high
            || result < initialized_low
            || result_end > initialized_high
        {
            return false;
        }
        self.buf = bytes::BytesMut::new();
        self.backing = None;
        self.initialized = None;
        true
    }

    /// Remaining bytes of an already parsed secure frame that can be received into its allocation.
    /// The preamble is authenticated once in v2.1; body authentication still precedes any delivery.
    pub fn secure_want(&self) -> usize {
        if self.failed
            || self.dispatch_blocked().is_some()
            || self.secure_lent.is_some()
            || self.yielded.is_some()
            || self.gate.pending()
            || !matches!(self.rx, Rx::Secure(_))
        {
            return 0;
        }
        self.pre
            .map_or(0, |p| p.total.saturating_sub(self.filled - self.start))
    }

    pub fn secure_take(&mut self) -> Option<SecureRxBuffer> {
        if self.secure_want() == 0 {
            return None;
        }
        // Keep only initialized received bytes before reserve/reclaim moves storage. Do not
        // zero the known frame body: a transport may initialize it directly through spare capacity.
        if self.start > 0 {
            self.buf.copy_within(self.start..self.filled, 0);
            self.filled -= self.start;
            self.start = 0;
        }
        self.buf.truncate(self.filled);
        let end = self.pre.expect("parsed secure frame").total;
        self.buf.reserve(end - self.filled);
        let low = self.buf.as_ptr() as usize;
        self.backing = Some((low, low + self.buf.capacity()));
        self.initialized = Some((low, low + self.buf.len()));
        let buf = core::mem::take(&mut self.buf);
        self.secure_lent = Some((buf.as_ptr() as usize, self.filled, end));
        Some(SecureRxBuffer {
            buf,
            filled: self.filled,
            end,
        })
    }

    pub fn secure_put(&mut self, loan: SecureRxBuffer) -> Result<(), Error> {
        if self.failed {
            return Err(if self.asm.dispatch.is_some() {
                self.err.unwrap_or(Error::Failed)
            } else {
                Error::Failed
            });
        }
        let Some((ptr, filled, end)) = self.secure_lent else {
            if self.asm.dispatch.is_some() {
                self.poison(Error::Busy);
            }
            return Err(Error::Busy);
        };
        // Fields are private and the loan cannot resize its allocation. A stale loan still owns its
        // memory, so a replacement decoder/loan cannot have that same live allocation address.
        if loan.buf.as_ptr() as usize != ptr
            || loan.end != end
            || loan.filled < filled
            || loan.filled != end
        {
            if self.asm.dispatch.is_some() {
                self.poison(Error::Busy);
            } else {
                self.failed = true;
            }
            return Err(Error::Busy);
        }
        self.buf = loan.buf;
        self.filled = loan.filled;
        let low = self.buf.as_ptr() as usize;
        self.initialized = Some((low, low + self.buf.len()));
        self.secure_lent = None;
        Ok(())
    }

    /// While the data segment of a MESSAGE frame is lent to a transport ([`Decoder::direct_take`]): the message's tid
    /// and type (from its header2 segment) and the leading pad of the lent buffer (segment bytes start there).
    pub fn lent_message(&self) -> Option<LentMessage> {
        let (header, pad, len) = self.asm.lent_message()?;
        if header.len() < 18 {
            return None; // tid at 8..16, type at 16..18
        }
        let tid = denc::le::rd_u64(header, 8);
        let msg_type = denc::le::rd_u16(header, 16);
        Some(LentMessage {
            tid,
            msg_type,
            pad,
            len,
        })
    }

    /// Bytes of the current segment still to come when a transport may fill them straight into the segment buffer
    /// (`Asm::direct_take`): only in the direct (CRC, rev 2.1) mode with nothing buffered or pending; 0 otherwise.
    pub fn direct_want(&self) -> usize {
        if !self.loan_ok() {
            return 0;
        }
        self.asm.direct_want()
    }

    /// A transport may own the rest of the frame being assembled: direct (CRC, rev 2.1) mode, nothing buffered,
    /// pending or failed.
    fn loan_ok(&self) -> bool {
        self.direct()
            && self.err.is_none()
            && !self.failed
            && self.ready.is_none()
            && self.held.is_none()
            && self.start >= self.filled
    }

    /// Lend the segment buffer (partially filled, capacity for the rest, block crcs of what it holds; the transport
    /// keeps them current with `BlockCrcs::update`). Only after [`Decoder::direct_want`] said > 0; bytes must not be
    /// fed until [`Decoder::direct_put`]. A decoder with pre-write on ([`Decoder::set_prewrite`]) lends through
    /// [`Decoder::direct_take_seg`] only (its data segment may be shared): `None` here.
    pub fn direct_take(&mut self) -> Option<(Vec<u8>, crc::BlockCrcs)> {
        // pre-write is switched at runtime: a segment that began shared stays shared whatever the setting is now
        if self.asm.prewrite > 0
            || self
                .asm
                .segs
                .get(self.asm.seg)
                .is_some_and(SegBuf::is_shared)
        {
            return None;
        }
        let (s, b) = self.direct_take_seg()?;
        Some((s.into_vec().expect("a segment that is not shared"), b))
    }

    /// [`Decoder::direct_take`] as a [`SegBuf`] (possibly shared: the transport appends through its raw spare capacity
    /// and `set_len`, which publishes the new bytes to the segment's readers).
    pub fn direct_take_seg(&mut self) -> Option<(SegBuf, crc::BlockCrcs)> {
        if self.direct_want() == 0 {
            return None;
        }
        match self.asm.direct_take(true) {
            Ok(x) => Some(x),
            Err(e) => {
                if self.asm.dispatch.is_some() {
                    self.poison(e);
                } else {
                    self.err = Some(e);
                }
                None
            }
        }
    }

    /// Lend an untouched MESSAGE data segment without allocating its body.
    ///
    /// Only CRC v2.1, with block hints and pre-write disabled, at the exact data
    /// boundary with no buffered input or existing storage. A carried-stream
    /// transport must bind caller memory before filling this loan, or reserve
    /// the complete ordinary buffer before offering it to an I/O operation.
    /// Socket transports should use [`Self::direct_take`] instead. A partially
    /// received segment retains its existing allocation and uses that path too.
    pub fn direct_take_empty_data(&mut self) -> Option<(Vec<u8>, crc::BlockCrcs)> {
        if self.direct_want() == 0
            || self.asm.collect_blocks
            || self.asm.prewrite != 0
            || self.asm.seg != 3
            || self.asm.p.tag != crate::Tag::Message as u8
            || self.asm.p.n != 4
            || self.asm.segs[3].capacity() != 0
        {
            return None;
        }
        // No block buffer can be started under these guards; taking an empty
        // owned segment without reserving is infallible.
        let (segment, crcs) = self.asm.direct_take(false).ok()?;
        Some((segment.into_vec().expect("empty owned segment"), crcs))
    }

    /// Return the buffer, now holding the whole segment, with the block crcs over all of it.
    pub fn direct_put(&mut self, v: Vec<u8>, crcs: crc::BlockCrcs) {
        self.direct_put_seg(SegBuf::from(v), crcs);
    }

    /// [`Decoder::direct_put`] of a buffer lent by [`Decoder::direct_take_seg`].
    pub fn direct_put_seg(&mut self, v: SegBuf, crcs: crc::BlockCrcs) {
        match self.asm.direct_put(v, crcs, &self.limits, &mut self.gate) {
            Err(e) => {
                if self.asm.dispatch.is_some() {
                    self.poison(e);
                } else {
                    self.err = Some(e);
                }
            }
            Ok(Some(f)) => {
                let w = frame_wire_len(&f);
                self.ready = Some((f, w));
            }
            Ok(None) => {}
        }
    }

    fn feed_direct(&mut self, data: &[u8]) {
        if self.err.is_some() || self.failed {
            return;
        }
        match self
            .asm
            .consume(data, &self.limits, &mut self.gate, &mut self.frames)
        {
            Err(e) => self.err = Some(e),
            Ok((used, f)) => {
                if let Some(f) = f {
                    let w = frame_wire_len(&f);
                    self.ready = Some((f, w));
                }
                if used < data.len() {
                    // leftover belongs to the next frame; keep it until this one was polled (mode switch)
                    let rest = &data[used..];
                    self.recv_buf(rest.len())[..rest.len()].copy_from_slice(rest);
                    self.commit(rest.len());
                }
            }
        }
    }

    fn poll_direct(&mut self) -> Result<Option<OwnedFrame>, Error> {
        loop {
            if let Some((f, _)) = self.ready.take() {
                return Ok(Some(f));
            }
            if let Some(e) = self.err.take() {
                self.failed = true;
                return Err(e);
            }
            if self.start >= self.filled {
                return Ok(None);
            }
            match self.asm.consume(
                &self.buf[self.start..self.filled],
                &self.limits,
                &mut self.gate,
                &mut self.frames,
            ) {
                Err(e) => {
                    self.failed = true;
                    return Err(e);
                }
                Ok((used, f)) => {
                    self.start += used;
                    if let Some(f) = f {
                        return Ok(Some(f));
                    }
                    if used == 0 {
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// Next complete frame, `Ok(None)` if more bytes are needed. The previous frame is released.
    /// Aborted frames are skipped (counted in [`aborted_frames`](Self::aborted_frames)).
    pub fn poll(&mut self) -> Result<Option<Frame<'_>>, Error> {
        if self.asm.dispatch.is_some() {
            self.poison(Error::Busy);
            return Err(Error::Busy);
        }
        if self.failed {
            return Err(Error::Failed);
        }
        if self.secure_lent.is_some() {
            return Err(Error::Busy);
        }
        if self.direct() {
            self.held = None;
            return Ok(match self.poll_direct()? {
                None => None,
                Some(f) => {
                    let h = self.held.insert(f);
                    let mut segs: [&[u8]; 4] = [&[]; 4];
                    for (s, v) in segs.iter_mut().zip(&h.segs) {
                        *s = v;
                    }
                    Some(Frame {
                        tag: h.tag,
                        flags: h.flags,
                        num_segments: h.segs.len(),
                        align: h.align,
                        data_refused: h.data_refused,
                        segs,
                    })
                }
            });
        }
        let Some(done) = self.next_buffered(false)? else {
            return Ok(None);
        };
        self.yielded = Some(done.total);
        let b: &[u8] = &self.buf;
        let mut segs: [&[u8]; 4] = [&[]; 4];
        for i in 0..done.p.n {
            segs[i] = &b[done.r[i].clone()];
        }
        Ok(Some(Frame {
            tag: done.p.tag,
            flags: done.p.flags,
            num_segments: done.p.n,
            align: done.p.align,
            // the buffered path consults the probe for owned delivery only: it keeps every segment here
            data_refused: 0,
            segs,
        }))
    }

    /// Verify every authentication tag before either borrowed or owned delivery.
    /// `owned`: the frame goes out as an [`OwnedFrame`] (may be decrypted out of place, [`Decoder::set_rx_place`]).
    fn next_buffered(&mut self, owned: bool) -> Result<Option<Done>, Error> {
        if let Some(n) = self.yielded.take() {
            self.start += n;
        }
        let done = loop {
            match self.step(owned) {
                Err(e) => {
                    self.failed = true;
                    return Err(e);
                }
                Ok(None) => return Ok(None),
                Ok(Some(d)) => {
                    self.pre = None;
                    if d.aborted {
                        self.start += d.total;
                        self.aborted += 1;
                        self.dispatch_guard();
                        self.gate.release();
                        continue;
                    }
                    break d;
                }
            }
        };
        Ok(Some(done))
    }

    fn step(&mut self, owned: bool) -> Result<Option<Done>, Error> {
        let b = self.start;
        let avail = self.filled - b;
        let rev = self.rev;
        if self.pre.is_none() {
            let need = match (&self.rx, rev) {
                (Rx::Secure(_), Revision::V21) => PREAMBLE_LEN + INLINE_LEN + TAG_LEN,
                _ => PREAMBLE_LEN,
            };
            if avail < need {
                self.want = need;
                return Ok(None);
            }
            let (limits, buf) = (self.limits, &mut self.buf);
            let p = match &mut self.rx {
                Rx::Crc => Preamble::parse(&buf[b..b + PREAMBLE_LEN], &limits)?,
                Rx::Secure(g) if rev == Revision::V21 => {
                    g.open(&mut buf[b..b + need])?;
                    Preamble::parse(&buf[b..b + PREAMBLE_LEN], &limits)?
                }
                Rx::Secure(g) => {
                    let ks = g.keystream32()?;
                    let mut pb = [0u8; PREAMBLE_LEN];
                    for i in 0..PREAMBLE_LEN {
                        pb[i] = buf[b + i] ^ ks[i];
                    }
                    Preamble::parse(&pb, &limits)?
                }
            };
            let total = p.wire_len(rev, matches!(self.rx, Rx::Secure(_)))?;
            self.frames += 1;
            self.pre = Some(Parsed { p, total });
            // the buffered path reserves the whole frame: its data segment is decrypted into the rx buffer, so the
            // probe decides after authentication and gives the bytes back on a refusal (`Gate::shrink`)
            let wire = total + place_room(self.asm.place, &p);
            self.gate.begin(&p, wire, None, false);
        }
        let Parsed { p, total } = self.pre.unwrap();
        if self.gate.pending() && !self.gate.admit() {
            // wait at the header: nothing of the body is awaited or allocated (`want` stays small)
            self.want = PREAMBLE_LEN;
            return Ok(None);
        }
        if let Some(dispatch) = &mut self.asm.dispatch
            && !dispatch.admit(p, place_room(self.asm.place, &p))?
        {
            return Ok(None);
        }
        if avail < total {
            self.want = total;
            return Ok(None);
        }
        let mut done = self.finish(p, total, owned)?;
        if owned
            && self.probe_eligible(&done.p)
            && let Some(pr) = self.probe
            && (pr.refuse)(
                &self.buf[done.r[0].clone()],
                &self.buf[done.r[1].clone()],
                done.p.len[2] as usize,
                done.p.len[3] as usize,
            )
        {
            // the data segment was decrypted and authenticated with the frame and is dropped now: its pool bytes are
            // held by nobody (spec msgr2.md 8.2)
            self.gate.shrink(done.p.len[3] as usize);
            done.refused = done.p.len[3];
            done.r[3] = 0..0;
        }
        Ok(Some(done))
    }

    /// The frame's data segment may be refused by the probe (spec msgr2.md 8.2): uncompressed, four segments, at or
    /// above the probe's threshold.
    fn probe_eligible(&self, p: &Preamble) -> bool {
        p.n == 4
            && p.flags & crate::FLAG_COMPRESSED == 0
            && self
                .probe
                .is_some_and(|pr| u64::from(p.len[3]) >= pr.threshold)
    }

    fn finish(&mut self, p: Preamble, total: usize, owned: bool) -> Result<Done, Error> {
        let b = self.start;
        let rev = self.rev;
        let crc_data = self.asm.crc_data;
        // a frame whose data segment the probe may refuse is never decrypted into a placed payload: the decision
        // comes after authentication, the plaintext is dropped then
        let place_ok = owned && self.asm.place && !self.probe_eligible(&p);
        let l = p.len.map(|x| x as usize);
        let n = p.n;
        let buf = &mut self.buf;
        let mut r: [Range<usize>; 4] = [0..0, 0..0, 0..0, 0..0];
        let aborted;
        let mut placed = None;
        match (&mut self.rx, rev) {
            (Rx::Crc, Revision::V21) => {
                let mut off = b + PREAMBLE_LEN;
                if l[0] > 0 {
                    r[0] = off..off + l[0];
                    if crc_data && crc32c(!0, &buf[r[0].clone()]) != rd_u32(buf, off + l[0]) {
                        return Err(Error::BadSegmentCrc(0));
                    }
                    off += l[0] + 4;
                } else {
                    r[0] = off..off;
                }
                for i in 1..n {
                    r[i] = off..off + l[i];
                    off += l[i];
                }
                if n > 1 {
                    aborted = late_ok(rev, buf[off])?;
                    if !aborted && crc_data {
                        for i in 1..n {
                            if crc32c(!0, &buf[r[i].clone()]) != rd_u32(buf, off + 1 + 4 * (i - 1))
                            {
                                return Err(Error::BadSegmentCrc(i));
                            }
                        }
                    }
                } else {
                    aborted = false;
                }
            }
            (Rx::Crc, Revision::V20) => {
                let mut off = b + PREAMBLE_LEN;
                for i in 0..n {
                    r[i] = off..off + l[i];
                    off += l[i];
                }
                aborted = late_ok(rev, buf[off])?;
                if !aborted && crc_data {
                    for i in 0..n {
                        if crc32c(!0, &buf[r[i].clone()]) != rd_u32(buf, off + 1 + 4 * i) {
                            return Err(Error::BadSegmentCrc(i));
                        }
                    }
                }
            }
            (Rx::Secure(g), Revision::V21) => {
                let p0 = pad16(l[0]);
                let mut off = b + 96;
                if p0 > INLINE_LEN {
                    let len = p0 - INLINE_LEN + TAG_LEN;
                    g.open(&mut buf[off..off + len])?;
                    // make seg0 contiguous: move the (already verified) inline bytes over the op1 tag
                    buf.copy_within(b + 32..b + 80, b + 48);
                    r[0] = b + 48..b + 48 + l[0];
                    off += len;
                } else {
                    r[0] = b + 32..b + 32 + l[0];
                }
                if n > 1 {
                    let len: usize = (1..n).map(|i| pad16(l[i])).sum::<usize>() + 32;
                    let place = data_place(place_ok, &p, &buf[r[0].clone()]);
                    if let Some(place) = place {
                        // decrypt segments 1.. straight into a buffer that places the data segment (same pass as in
                        // place, no copy afterwards)
                        let plain = len - TAG_LEN;
                        let o3 = pad16(l[1]) + pad16(l[2]);
                        let (mut out, pad) =
                            placed_buf(self.asm.shelf.as_deref(), plain, o3, place)?;
                        // SAFETY: `out` has room for `pad + plain` bytes (placed_buf reserved len + PAD_ROOM, pad <
                        // PAD_ROOM); `open_to` initializes exactly `plain` bytes after the pad, or fails (then the
                        // buffer is dropped with its length unchanged).
                        unsafe {
                            g.open_to(&buf[off..off + len], out.as_mut_ptr().add(pad))?;
                            out.set_len(pad + plain);
                        }
                        let mut o = pad;
                        for i in 1..n {
                            r[i] = o..o + l[i];
                            o += pad16(l[i]);
                        }
                        aborted = late_ok(rev, out[o])?;
                        placed = Some(out);
                    } else {
                        g.open(&mut buf[off..off + len])?;
                        let mut o = off;
                        for i in 1..n {
                            r[i] = o..o + l[i];
                            o += pad16(l[i]);
                        }
                        aborted = late_ok(rev, buf[o])?;
                    }
                } else {
                    aborted = false;
                }
            }
            (Rx::Secure(g), Revision::V20) => {
                g.open(&mut buf[b..b + total])?;
                let mut off = b + PREAMBLE_LEN;
                for i in 0..n {
                    r[i] = off..off + l[i];
                    off += pad16(l[i]);
                }
                aborted = late_ok(rev, buf[off])?;
            }
        }
        Ok(Done {
            r,
            p,
            total,
            aborted,
            placed,
            refused: 0,
        })
    }
}

/// Wire length of a CRC-mode rev 2.1 frame (a refused data segment counts its declared bytes).
fn frame_wire_len(f: &OwnedFrame) -> usize {
    let l0 = f.segs[0].len();
    PREAMBLE_LEN
        + if l0 > 0 { l0 + 4 } else { 0 }
        + f.segs[1..].iter().map(bytes::Bytes::len).sum::<usize>()
        + f.data_refused as usize
        + if f.segs.len() > 1 { 13 } else { 0 }
}

#[cfg(test)]
#[path = "decode_spare_tests.rs"]
mod spare_tests;

#[cfg(test)]
mod empty_reply_release_tests {
    use super::*;
    fn secret() -> ConnSecret {
        ConnSecret::new(&(0..64u8).collect::<Vec<_>>()).unwrap()
    }
    fn wire(encoder: &mut crate::Encoder, value: u8) -> Vec<u8> {
        let mut wire = Vec::new();
        encoder
            .encode_message(
                &[1; 41],
                &[2; 17],
                &[3; 7],
                &vec![value; 2 * OWNED_FRAME_MIN],
                &mut wire,
            )
            .unwrap();
        wire
    }
    fn fixture(revision: Revision) -> (crate::Encoder, Decoder, bytes::Bytes) {
        let mut encoder = crate::Encoder::new(revision);
        let mut decoder = Decoder::new(revision);
        encoder.set_secure(&secret(), Role::Client).unwrap();
        decoder.set_secure(&secret(), Role::Server).unwrap();
        let wire = wire(&mut encoder, 7);
        // A test-owned split gives an exact bounded view without relying on allocator
        // rounding. Receive the real authenticated frame through the current loan path.
        let mut storage = bytes::BytesMut::with_capacity(wire.len() + 17);
        storage.resize(wire.len(), 0);
        decoder.buf = storage.split_to(wire.len());
        drop(storage);
        decoder.feed(&wire[..211]);
        assert!(decoder.poll_owned().unwrap().is_none());
        let mut loan = decoder.secure_take().unwrap();
        for (slot, byte) in loan.spare_capacity_mut().iter_mut().zip(&wire[211..]) {
            slot.write(*byte);
        }
        // SAFETY: exact remaining frame prefix initialized above; no writer retained.
        unsafe { loan.commit_initialized(wire.len() - 211) };
        decoder.secure_put(loan).unwrap();
        let mut frame = decoder.poll_owned().unwrap().unwrap();
        let data = frame.segs.pop().unwrap();
        drop(frame);
        assert!(decoder.poll_owned().unwrap().is_none());
        assert_eq!(decoder.filled, 0);
        assert_eq!(decoder.buf.len(), 0);
        assert_eq!(decoder.buf.capacity(), 0);
        assert!(!data.is_unique());
        (encoder, decoder, data)
    }
    #[test]
    fn exact_idle_release_permits_adoption_and_preserves_both_revision_nonces() {
        for revision in [Revision::V20, Revision::V21] {
            let (mut encoder, mut decoder, data) = fixture(revision);
            let pointer = data.as_ptr();
            let want = decoder.want;
            assert!(decoder.release_empty_secure_reply(&data));
            assert_eq!(decoder.want, want);
            assert_eq!(decoder.backing, None);
            assert_eq!(decoder.initialized, None);
            let mut adopted = data.try_into_mut().unwrap();
            assert_eq!(adopted.as_ptr(), pointer);
            assert!(adopted.iter().all(|byte| *byte == 7));
            adopted[0] = 33;
            assert!(decoder.recv_buf(31)[..31].iter().all(|byte| *byte == 0));
            decoder.feed(&wire(&mut encoder, 9));
            let next = decoder.poll_owned().unwrap().unwrap();
            assert!(next.segs[3].iter().all(|byte| *byte == 9));
            assert_eq!(adopted[0], 33);
            assert!(decoder.poll_owned().unwrap().is_none());
        }
    }
    #[test]
    fn a_real_alias_survives_release_and_still_prevents_mutable_adoption() {
        let (_, mut decoder, data) = fixture(Revision::V21);
        let alias = data.clone();
        assert!(decoder.release_empty_secure_reply(&data));
        let data = data.try_into_mut().unwrap_err();
        assert!(alias.iter().all(|byte| *byte == 7));
        drop(alias);
        assert!(data.try_into_mut().is_ok());
    }
    #[test]
    fn next_frame_prefix_and_secure_loan_refuse_release_without_losing_bytes() {
        for revision in [Revision::V20, Revision::V21] {
            let (mut encoder, mut decoder, data) = fixture(revision);
            let next = wire(&mut encoder, 9);
            decoder.feed(&next[..11]);
            let backing = decoder.backing;
            assert!(!decoder.release_empty_secure_reply(&data));
            assert_eq!(decoder.backing, backing);
            assert!(decoder.poll_owned().unwrap().is_none());
            decoder.feed(&next[11..211]);
            assert!(decoder.poll_owned().unwrap().is_none());
            let mut loan = decoder.secure_take().unwrap();
            assert!(!decoder.release_empty_secure_reply(&data));
            loan.recv_buf().copy_from_slice(&next[211..]);
            loan.commit(next.len() - 211);
            decoder.secure_put(loan).unwrap();
            let result = decoder.poll_owned().unwrap().unwrap();
            assert!(result.segs[3].iter().all(|byte| *byte == 9));
            assert!(data.iter().all(|byte| *byte == 7));
        }
    }
    #[test]
    fn unrelated_empty_and_partial_overlapping_views_do_not_release_storage() {
        let (_, mut decoder, data) = fixture(Revision::V21);
        let before = decoder.backing;
        assert!(!decoder.release_empty_secure_reply(&bytes::Bytes::from(vec![0; data.len()])));
        assert!(!decoder.release_empty_secure_reply(&bytes::Bytes::new()));
        // The initialized bound is checked for the entire view, not only its start.
        // Use an explicit bound inside the payload; it simulates inconsistent metadata safely.
        decoder.initialized = Some((
            data.as_ptr() as usize,
            data.as_ptr() as usize + data.len() - 1,
        ));
        assert!(!decoder.release_empty_secure_reply(&data));
        assert_eq!(decoder.backing, before);
    }
    #[test]
    fn default_zero_tail_retains_original_reclaim_value_after_result_drop() {
        for revision in [Revision::V20, Revision::V21] {
            let (_, mut decoder, data) = fixture(revision);
            let original = decoder.backing.unwrap().0;
            assert_eq!(decoder.buf.capacity(), 0);
            drop(data);
            assert!(decoder.buf.try_reclaim(OWNED_FRAME_MIN));
            assert_eq!(decoder.buf.as_ptr() as usize, original);
            assert!(decoder.buf.capacity() >= OWNED_FRAME_MIN);
        }
    }
    #[test]
    fn ordinary_small_secure_frame_has_no_releasable_shared_tail() {
        for revision in [Revision::V20, Revision::V21] {
            let mut encoder = crate::Encoder::new(revision);
            let mut decoder = Decoder::new(revision);
            encoder.set_secure(&secret(), Role::Client).unwrap();
            decoder.set_secure(&secret(), Role::Server).unwrap();
            let mut wire = Vec::new();
            encoder
                .encode_message(&[1; 41], &[], &[], &[7; 13], &mut wire)
                .unwrap();
            decoder.feed(&wire);
            let mut frame = decoder.poll_owned().unwrap().unwrap();
            let data = frame.segs.pop().unwrap();
            drop(frame);
            assert!(decoder.poll_owned().unwrap().is_none());
            let pointer = decoder.buf.as_ptr();
            let backing = decoder.backing;
            assert!(!decoder.release_empty_secure_reply(&data));
            assert_eq!(decoder.buf.as_ptr(), pointer);
            assert_eq!(decoder.backing, backing);
            assert_eq!(data.as_ref(), &[7; 13]);
        }
    }
    #[test]
    fn partial_parser_and_stale_metadata_guards_are_nonmutating() {
        let states: &[fn(&mut Decoder)] = &[
            |d| d.failed = true,
            |d| d.err = Some(Error::Busy),
            |d| d.start = 1,
            |d| d.filled = 1,
            |d| d.yielded = Some(0),
            |d| d.ready = Some((OwnedFrame::default(), 1)),
            |d| d.held = Some(OwnedFrame::default()),
            |d| d.secure_lent = Some((0, 0, 0)),
            |d| d.asm.st = AsmSt::Seg,
            |d| d.asm.nsmall = 1,
            |d| d.asm.wire = 1,
            |d| d.asm.lent = Some(0),
            |d| d.asm.segs[0].extend_from_slice(&[1]),
            |d| d.asm.blk = Some(crc::BlockCrcs::with_len(1)),
            |d| d.buf.reserve(1),
            |d| d.buf.resize(1, 0),
            |d| {
                let (low, high) = d.backing.unwrap();
                d.backing = Some((low, high + 1));
            },
            |d| d.backing = None,
            |d| d.initialized = None,
            |d| d.backing = Some((usize::MAX - 1, usize::MAX)),
            |d| d.initialized = Some((0, usize::MAX)),
            |d| d.rx = Rx::Crc,
        ];
        for state in states {
            let (_, mut decoder, data) = fixture(Revision::V21);
            state(&mut decoder);
            let pointer = decoder.buf.as_ptr();
            let backing = decoder.backing;
            assert!(!decoder.release_empty_secure_reply(&data));
            assert_eq!(decoder.buf.as_ptr(), pointer);
            assert_eq!(decoder.backing, backing);
            assert!(data.iter().all(|byte| *byte == 7));
        }
    }
}

#[cfg(test)]
#[path = "decode_dispatch_tests.rs"]
mod dispatch_tests;

#[cfg(test)]
#[path = "decode_capacity_tests.rs"]
mod capacity_tests;
