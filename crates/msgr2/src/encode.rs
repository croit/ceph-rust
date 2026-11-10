// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::gcm::{ConnSecret, Gcm, Role};
use crate::{
    ALIGN_CTRL, ALIGN_MESSAGE, Error, INLINE_LEN, LATE_ABORTED, LATE_COMPLETE, Limits,
    MAX_SEGMENTS, PREAMBLE_LEN, Preamble, Revision, TAG_LEN, pad16,
};
use bytes::Bytes;
use crc::{crc32c, crc32c_extend};

/// Data segments at least this long are sent by reference ([`Encoder::encode_message_zc`]).
pub const ZC_MIN: usize = 8192;

/// Append `piece` to `out` and extend the running crc; with segment crcs off (`ms_crc_data=false`) only append (the
/// slot is written as 0, so the crc is never needed).
#[inline]
fn extend_crc(enabled: bool, c: u32, piece: &[u8], out: &mut Vec<u8>) -> u32 {
    if enabled {
        crc32c_extend(c, piece, out)
    } else {
        out.extend_from_slice(piece);
        c
    }
}

/// The value written into a segment crc slot.
#[inline]
fn wire_crc(enabled: bool, c: u32) -> u32 {
    if enabled { c } else { 0 }
}

/// One input segment: bytes + alignment hint (written to the preamble, byte-identical to Ceph senders).
#[derive(Clone, Copy, Debug)]
pub struct Seg<'a> {
    /// Segment payload.
    pub data: &'a [u8],
    /// Receiver alignment hint.
    pub align: u16,
}

#[derive(Debug)]
enum Tx {
    Crc,
    Secure(Gcm),
}

/// Frame encoder (one per connection direction). Mode switch applies from the next frame.
#[derive(Debug)]
pub struct Encoder {
    rev: Revision,
    tx: Tx,
    limits: Limits,
    crc_data: bool,
}

impl Encoder {
    /// New encoder in CRC mode.
    pub fn new(rev: Revision) -> Self {
        Self {
            rev,
            tx: Tx::Crc,
            limits: Limits::default(),
            crc_data: true,
        }
    }

    /// Override size limits.
    pub fn set_limits(&mut self, l: Limits) {
        self.limits = l;
    }

    /// `ms_crc_data` (spec 4.3): compute the segment crcs (default). False writes 0 into every segment crc slot of a
    /// CRC-mode frame (also the empty-segment slots) and skips their computation; positions, the frame length and
    /// `late_status` are unchanged. Secure mode has no crc slots, so it ignores the switch.
    pub fn set_crc_data(&mut self, enabled: bool) {
        self.crc_data = enabled;
    }

    /// Switch to secure mode for all following frames.
    pub fn set_secure(&mut self, secret: &ConnSecret, role: Role) -> Result<(), Error> {
        self.tx = Tx::Secure(secret.tx(role, self.rev)?);
        Ok(())
    }

    /// Frame revision.
    pub fn revision(&self) -> Revision {
        self.rev
    }

    /// Encode a single-segment control frame (alignment 8).
    pub fn encode_control(
        &mut self,
        tag: u8,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        self.encode(
            tag,
            &[Seg {
                data: payload,
                align: ALIGN_CTRL,
            }],
            out,
        )
    }

    /// Encode a MESSAGE frame (tag 17) with Ceph's segment alignments (8, 8, 8, 4096).
    pub fn encode_message(
        &mut self,
        header: &[u8],
        front: &[u8],
        middle: &[u8],
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let a = ALIGN_MESSAGE;
        let segs = [
            Seg {
                data: header,
                align: a[0],
            },
            Seg {
                data: front,
                align: a[1],
            },
            Seg {
                data: middle,
                align: a[2],
            },
            Seg { data, align: a[3] },
        ];
        self.encode(crate::Tag::Message as u8, &segs, out)
    }

    /// Like [`encode_message`](Self::encode_message), but a large `data` segment is not copied: in CRC mode rev 2.1 the
    /// frame is appended as the byte run `out` (flushed into `chunks`), the shared `data` (crc only, no copy) and
    /// the epilogue (left in `out`). Output order = `chunks` then `out`. Otherwise (small data, secure mode, rev 2.0)
    /// it is a plain `encode_message` into `out`. On error both are restored.
    #[expect(clippy::too_many_arguments)]
    pub fn encode_message_zc(
        &mut self,
        header: &[u8],
        front: &[u8],
        middle: &[u8],
        data: &Bytes,
        data_crc: &crc::CrcHint,
        out: &mut Vec<u8>,
        chunks: &mut Vec<Bytes>,
    ) -> Result<(), Error> {
        let _profile = crate::profile::span("messenger.encode.zc", data.len());
        self.encode_message_rope(
            header,
            front,
            &[],
            &Default::default(),
            middle,
            data,
            data_crc,
            out,
            chunks,
        )
    }

    /// Frames of this encoder can carry shared runs by reference (CRC mode, rev 2.1); otherwise
    /// [`encode_message_rope`](Self::encode_message_rope) copies them into the frame.
    pub fn zero_copy(&self) -> bool {
        matches!(self.tx, Tx::Crc) && self.rev == Revision::V21
    }

    /// [`encode_message_zc`](Self::encode_message_zc) with shared runs spliced into the front (`front_zc`, their known
    /// crcs in `front_hints`:
    /// `(offset in front, run)`, ascending; logical front = `front` with each run inserted at its offset): runs of at
    /// least [`ZC_MIN`] bytes go out by reference like a large data segment (crc only, no copy). Without
    /// [`zero_copy`](Self::zero_copy) the pieces are copied directly into the frame.
    #[expect(clippy::too_many_arguments)]
    pub fn encode_message_rope(
        &mut self,
        header: &[u8],
        front: &[u8],
        front_zc: &[(usize, Bytes)],
        front_hints: &crc::CrcHints,
        middle: &[u8],
        data: &Bytes,
        data_crc: &crc::CrcHint,
        out: &mut Vec<u8>,
        chunks: &mut Vec<Bytes>,
    ) -> Result<(), Error> {
        let _profile = crate::profile::span("messenger.encode.rope", data.len());
        check_rope(front, front_zc)?;
        let front_len = front_zc
            .iter()
            .try_fold(front.len(), |n, (_, run)| n.checked_add(run.len()))
            .ok_or(Error::FrameTooLarge(u64::MAX))?;
        let a = ALIGN_MESSAGE;
        let (p, _) = self.layout_lens(
            crate::Tag::Message as u8,
            0,
            &[
                (header.len(), a[0]),
                (front_len, a[1]),
                (middle.len(), a[2]),
                (data.len(), a[3]),
            ],
        )?;
        // the frame is validated against the limits before any fallback flattens the shared runs
        let shared = front_zc.iter().any(|(_, r)| r.len() >= ZC_MIN);
        if !self.zero_copy() || (data.len() < ZC_MIN && !shared) {
            if front_zc.is_empty() {
                return self.encode_message(header, front, middle, data, out);
            }
            // The emitter accepts segmented input: copy each run into its final frame
            // position, without a payload-sized plaintext temporary.
            let mut pieces = Vec::new();
            let mut pos = 0;
            for (at, run) in front_zc {
                pieces.push(&front[pos..*at]);
                pieces.push(run.as_ref());
                pos = *at;
            }
            pieces.push(&front[pos..]);
            let start = out.len();
            let result = self.emit(p, [&[header], &pieces, &[middle], &[data]], false, out);
            if result.is_err() {
                out.truncate(start);
            }
            return result;
        }
        let n = p.n;
        // Only copied bytes are reserved; shared runs never cause a body-sized allocation.
        reserve_output(out, copied_len(header.len(), front.len(), middle.len())?)?;
        p.write(out);
        let crc = self.crc_data;
        let c = extend_crc(crc, !0, header, out);
        out.extend_from_slice(&wire_crc(crc, c).to_le_bytes());
        // a shared run: crc only, the bytes so far become a chunk, the run follows by reference
        let mut by_ref = |out: &mut Vec<u8>, run: &Bytes| {
            if !out.is_empty() {
                chunks.push(Bytes::from(core::mem::take(out)));
            }
            chunks.push(run.clone());
        };
        let mut crcs = [0u32; 4];
        if n > 1 {
            let (mut c, mut pos) = (!0u32, 0usize);
            for (at, run) in front_zc {
                c = extend_crc(crc, c, &front[pos..*at], out);
                if run.len() >= ZC_MIN {
                    // a hint made for exactly this run: its crc is joined, the bytes are not read again
                    if crc {
                        c = match front_hints.of(run) {
                            Some(h) => {
                                debug_assert_eq!(h, crc32c(!0, run), "wrong front crc hint");
                                crc::crc32c_append_ones(c, h, run.len() as u64)
                            }
                            None => crc32c(c, run),
                        };
                    }
                    by_ref(out, run);
                } else {
                    c = extend_crc(crc, c, run, out);
                }
                pos = *at;
            }
            crcs[1] = extend_crc(crc, c, &front[pos..], out);
        }
        if n > 2 {
            crcs[2] = extend_crc(crc, !0, middle, out);
        }
        if n > 3 {
            if data.len() >= ZC_MIN {
                if crc {
                    // the hint holds the very bytes it was made for: trusted only if this segment IS that range, else
                    // computed
                    let known = data_crc.of(data);
                    debug_assert!(
                        known.is_none_or(|c| c == crc32c(!0, data)),
                        "wrong data crc hint"
                    );
                    crcs[3] = known.unwrap_or_else(|| crc32c(!0, data));
                }
                by_ref(out, data);
            } else {
                crcs[3] = extend_crc(crc, !0, data, out);
            }
        }
        out.push(LATE_COMPLETE);
        for c in &crcs[1..] {
            out.extend_from_slice(&wire_crc(crc, *c).to_le_bytes());
        }
        Ok(())
    }

    /// [`encode_message_zc`](Self::encode_message_zc) for a data segment made of parts: `data ++ more[0].0 ++ ...`
    /// (a large payload shared with another buffer between small encoded pieces: no copy into one blob). CRC mode rev
    /// 2.1: every part goes out by reference, the segment crc is joined from the parts (`crc32c_combine`; a part's hint
    /// is used when it views exactly that part, else its crc is computed). Otherwise the parts are concatenated (copy)
    /// and encoded as one segment. `data_crc` hints `data` only.
    #[expect(clippy::too_many_arguments)]
    pub fn encode_message_parts(
        &mut self,
        header: &[u8],
        front: &[u8],
        middle: &[u8],
        data: &Bytes,
        data_crc: &crc::CrcHint,
        more: &[(Bytes, crc::CrcHint)],
        out: &mut Vec<u8>,
        chunks: &mut Vec<Bytes>,
    ) -> Result<(), Error> {
        if more.is_empty() {
            return self.encode_message_zc(header, front, middle, data, data_crc, out, chunks);
        }
        let total = more
            .iter()
            .try_fold(data.len(), |n, (b, _)| n.checked_add(b.len()))
            .ok_or(Error::FrameTooLarge(u64::MAX))?;
        if total < ZC_MIN || !self.zero_copy() {
            // copied into the frame piece by piece (the one copy every such frame makes; no flattened blob first)
            let pieces: Vec<&[u8]> = std::iter::once(&data[..])
                .chain(more.iter().map(|(b, _)| &b[..]))
                .collect();
            let a = ALIGN_MESSAGE;
            let lens = [
                (header.len(), a[0]),
                (front.len(), a[1]),
                (middle.len(), a[2]),
                (total, a[3]),
            ];
            let (p, _) = self.layout_lens(crate::Tag::Message as u8, 0, &lens)?;
            let start = out.len();
            let r = self.emit(p, [&[header], &[front], &[middle], &pieces], false, out);
            if r.is_err() {
                out.truncate(start);
            }
            return r;
        }
        if total > self.limits.max_segment as usize {
            return Err(Error::SegmentTooLarge(total.min(u32::MAX as usize) as u32));
        }
        let a = ALIGN_MESSAGE;
        let segs = [
            Seg {
                data: header,
                align: a[0],
            },
            Seg {
                data: front,
                align: a[1],
            },
            Seg {
                data: middle,
                align: a[2],
            },
            Seg {
                data: &[],
                align: a[3],
            },
        ];
        let (mut p, d, sum) = self.layout(crate::Tag::Message as u8, 0, &segs)?;
        let sum = sum
            .checked_add(u64::try_from(total).map_err(|_| Error::FrameTooLarge(u64::MAX))?)
            .ok_or(Error::FrameTooLarge(u64::MAX))?;
        if sum > self.limits.max_frame {
            return Err(Error::FrameTooLarge(sum));
        }
        // the data segment (empty in `layout`) is present: length, alignment, segment count
        p.len[3] = u32::try_from(total).map_err(|_| Error::FrameTooLarge(u64::MAX))?;
        p.align = a;
        p.n = 4;
        p.wire_len(self.rev, false)?;
        let copied = copied_len(header.len(), front.len(), middle.len())?;
        reserve_output(out, copied)?;
        p.write(out);
        let crc = self.crc_data;
        let c = extend_crc(crc, !0, d[0], out);
        out.extend_from_slice(&wire_crc(crc, c).to_le_bytes());
        let mut crcs = [0u32; 4];
        for i in 1..3 {
            crcs[i] = extend_crc(crc, !0, d[i], out);
        }
        if crc {
            let part_crc = |b: &Bytes, h: &crc::CrcHint| {
                let known = h.of(b);
                debug_assert!(
                    known.is_none_or(|c| c == crc32c(!0, b)),
                    "wrong data crc hint"
                );
                known
            };
            let mut r = match part_crc(data, data_crc) {
                Some(c) => c,
                None => crc32c(!0, data),
            };
            for (b, h) in more {
                r = match part_crc(b, h) {
                    // `c` is hashed from seed !0: its seed-0 form joins the running crc
                    Some(c) => crc::crc32c_combine(
                        r,
                        c ^ crc::crc32c_shift(!0, b.len() as u64),
                        b.len() as u64,
                    ),
                    None => crc32c(r, b),
                };
            }
            crcs[3] = r;
        }
        chunks.push(Bytes::from(core::mem::take(out)));
        if !data.is_empty() {
            chunks.push(data.clone());
        }
        for (b, _) in more {
            if !b.is_empty() {
                chunks.push(b.clone());
            }
        }
        out.push(LATE_COMPLETE);
        for c in &crcs[1..] {
            out.extend_from_slice(&wire_crc(crc, *c).to_le_bytes());
        }
        Ok(())
    }
    /// Consume a disposable message's body. Owned secure buffers are encrypted in place;
    /// shared data gets a private ciphertext buffer. Never use for lossless replay storage.
    pub fn encode_message_owned(
        &mut self,
        header: &[u8],
        mut front: Vec<u8>,
        mut middle: Vec<u8>,
        data: Bytes,
        out: &mut Vec<u8>,
        chunks: &mut Vec<Bytes>,
    ) -> Result<(), Error> {
        let _profile = crate::profile::span("messenger.encode.owned", data.len());
        let body_len = front
            .len()
            .checked_add(middle.len())
            .and_then(|n| n.checked_add(data.len()))
            .ok_or(Error::FrameTooLarge(u64::MAX))?;
        if body_len < ZC_MIN || !matches!(self.tx, Tx::Secure(_)) {
            return self.encode_message_zc(
                header,
                &front,
                &middle,
                &data,
                &Default::default(),
                out,
                chunks,
            );
        }
        let a = ALIGN_MESSAGE;
        let segs = [
            Seg {
                data: header,
                align: a[0],
            },
            Seg {
                data: &front,
                align: a[1],
            },
            Seg {
                data: &middle,
                align: a[2],
            },
            Seg {
                data: &data,
                align: a[3],
            },
        ];
        let (p, _, _) = self.layout(crate::Tag::Message as u8, 0, &segs)?;
        let Tx::Secure(g) = &mut self.tx else {
            unreachable!()
        };
        let p0 = pad16(header.len());
        let head_cap = if self.rev == Revision::V20 {
            PREAMBLE_LEN + p0
        } else {
            PREAMBLE_LEN
                + INLINE_LEN
                + TAG_LEN
                + p0.saturating_sub(INLINE_LEN)
                + if p0 > INLINE_LEN { TAG_LEN } else { 0 }
        };
        let mut head = Vec::with_capacity(head_cap);
        p.write(&mut head);
        if self.rev == Revision::V20 {
            head.extend_from_slice(header);
            head.resize(PREAMBLE_LEN + p0, 0);
        } else {
            let k = header.len().min(INLINE_LEN);
            head.extend_from_slice(&header[..k]);
            head.resize(PREAMBLE_LEN + INLINE_LEN, 0);
            let tag = g.seal(&mut head)?;
            head.extend_from_slice(&tag);
            if p0 > INLINE_LEN {
                let start = head.len();
                head.extend_from_slice(&header[INLINE_LEN..]);
                head.resize(start + p0 - INLINE_LEN, 0);
                let tag = g.seal(&mut head[start..])?;
                head.extend_from_slice(&tag);
            }
        }
        let mut front_pad = [0u8; 15];
        let mut middle_pad = [0u8; 15];
        let nf = pad16(front.len()) - front.len();
        let nm = pad16(middle.len()) - middle.len();
        let nd = pad16(data.len()) - data.len();
        let mut tail = Vec::with_capacity(nd + 16 + TAG_LEN);
        tail.resize(nd + 16, 0);
        tail[nd] = if self.rev == Revision::V21 {
            LATE_COMPLETE
        } else {
            0
        };
        // Rev2.0 authenticates the head with the body; rev2.1 already sealed it.
        // Empty runs perform no EVP update and do not create a new nonce region.
        let head_region = if self.rev == Revision::V20 {
            head.as_mut_slice()
        } else {
            &mut []
        };
        let (data, tag) = match data.try_into_mut() {
            Ok(mut data) => {
                let tag = g.seal_chunks(&mut [
                    head_region,
                    &mut front,
                    &mut front_pad[..nf],
                    &mut middle,
                    &mut middle_pad[..nm],
                    &mut data,
                    &mut tail,
                ])?;
                (data, tag)
            }
            Err(shared) => g.seal_chunks_copy(
                &mut [
                    head_region,
                    &mut front,
                    &mut front_pad[..nf],
                    &mut middle,
                    &mut middle_pad[..nm],
                ],
                &shared,
                &mut [&mut tail],
            )?,
        };
        tail.extend_from_slice(&tag);
        // Commit only after every region was sealed; shared plaintext stays immutable.
        if !out.is_empty() {
            chunks.push(Bytes::from(core::mem::take(out)));
        }
        chunks.push(Bytes::from(head));
        if !front.is_empty() {
            chunks.push(Bytes::from(front));
        }
        if nf != 0 {
            chunks.push(Bytes::copy_from_slice(&front_pad[..nf]));
        }
        if !middle.is_empty() {
            chunks.push(Bytes::from(middle));
        }
        if nm != 0 {
            chunks.push(Bytes::copy_from_slice(&middle_pad[..nm]));
        }
        if !data.is_empty() {
            chunks.push(data.freeze());
        }
        out.extend_from_slice(&tail);
        Ok(())
    }

    /// Append one frame to `out` (appended bytes are encrypted in place in secure mode).
    /// On error `out` is restored to its original length.
    pub fn encode(&mut self, tag: u8, segs: &[Seg<'_>], out: &mut Vec<u8>) -> Result<(), Error> {
        self.encode_ex(tag, 0, false, segs, out)
    }

    /// Like [`encode`](Self::encode) with explicit preamble flags and optional abort marker
    /// (rev0: late_flags bit0; rev1: late_status 0x01, requires >1 segment).
    pub fn encode_ex(
        &mut self,
        tag: u8,
        flags: u8,
        aborted: bool,
        segs: &[Seg<'_>],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let start = out.len();
        let r = self.encode_inner(tag, flags, aborted, segs, out);
        if r.is_err() {
            out.truncate(start);
        }
        r
    }

    fn encode_inner(
        &mut self,
        tag: u8,
        flags: u8,
        aborted: bool,
        segs: &[Seg<'_>],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let (p, d, _) = self.layout(tag, flags, segs)?;
        if aborted && self.rev == Revision::V21 && p.n == 1 {
            return Err(Error::CannotAbort);
        }
        let one = d.map(|s| [s]);
        self.emit(p, [&one[0], &one[1], &one[2], &one[3]], aborted, out)
    }

    /// Validate `segs` and build the preamble.
    fn layout<'a>(
        &self,
        tag: u8,
        flags: u8,
        segs: &[Seg<'a>],
    ) -> Result<(Preamble, [&'a [u8]; 4], u64), Error> {
        if segs.len() > MAX_SEGMENTS {
            return Err(Error::TooManySegments);
        }
        let mut d: [&[u8]; 4] = [&[]; 4];
        let mut lens = [(0usize, 0u16); 4];
        for (i, s) in segs.iter().enumerate() {
            d[i] = s.data;
            lens[i] = (s.data.len(), s.align);
        }
        let (p, sum) = self.layout_lens(tag, flags, &lens[..segs.len()])?;
        Ok((p, d, sum))
    }

    /// [`layout`](Self::layout) from `(length, align)` per segment.
    fn layout_lens(
        &self,
        tag: u8,
        flags: u8,
        segs: &[(usize, u16)],
    ) -> Result<(Preamble, u64), Error> {
        if segs.len() > MAX_SEGMENTS {
            return Err(Error::TooManySegments);
        }
        let mut p = Preamble {
            tag,
            n: 1,
            len: [0; 4],
            align: [0; 4],
            flags,
        };
        let mut sum = 0u64;
        for (i, &(len, align)) in segs.iter().enumerate() {
            if len > self.limits.max_segment as usize {
                return Err(Error::SegmentTooLarge(len.min(u32::MAX as usize) as u32));
            }
            p.len[i] = u32::try_from(len).map_err(|_| Error::FrameTooLarge(u64::MAX))?;
            p.align[i] = align;
            sum = sum
                .checked_add(u64::from(p.len[i]))
                .ok_or(Error::FrameTooLarge(u64::MAX))?;
            if len != 0 {
                p.n = i + 1;
            }
        }
        if sum > self.limits.max_frame {
            return Err(Error::FrameTooLarge(sum));
        }
        // same rule the receiving preamble parse applies (spec 16 C7): only MESSAGE frames are exempt from the ceiling
        if tag != crate::Tag::Message as u8 && self.limits.max_control.is_some_and(|c| sum > c) {
            return Err(Error::FrameTooLarge(sum));
        }
        // trailing empty segments dropped: alignment slots of dropped segments are zero
        for i in p.n..4 {
            p.align[i] = 0;
        }
        p.wire_len(self.rev, matches!(self.tx, Tx::Secure(_)))?;
        Ok((p, sum))
    }

    /// Write the frame of preamble `p`; segment `i` is the concatenation of the pieces `d[i]` (the header one piece).
    fn emit(
        &mut self,
        p: Preamble,
        d: [&[&[u8]]; 4],
        aborted: bool,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let n = p.n;
        let l = p.len.map(|x| x as usize);
        let crc = self.crc_data;
        let crc_extend = |s: &[&[u8]], out: &mut Vec<u8>| {
            s.iter().fold(!0, |c, piece| extend_crc(crc, c, piece, out))
        };
        debug_assert!(d[0].len() <= 1, "header in one piece");
        let head = d[0].first().copied().unwrap_or(&[]);
        // Validate destination growth before any offset arithmetic or body copy.
        reserve_output(out, p.wire_len(self.rev, matches!(self.tx, Tx::Secure(_)))?)?;
        match (&mut self.tx, self.rev) {
            (Tx::Crc, Revision::V21) => {
                p.write(out);
                // copy + crc fused per 16 KiB block (cache-blocked), crc of segments 1.. goes to the epilogue
                if l[0] > 0 {
                    let c = extend_crc(crc, !0, head, out);
                    out.extend_from_slice(&wire_crc(crc, c).to_le_bytes());
                }
                let mut crcs = [0u32; 4];
                for i in 1..n {
                    crcs[i] = crc_extend(d[i], out);
                }
                if n > 1 {
                    out.push(if aborted { LATE_ABORTED } else { LATE_COMPLETE });
                    for c in &crcs[1..] {
                        out.extend_from_slice(&wire_crc(crc, *c).to_le_bytes());
                    }
                }
            }
            (Tx::Crc, Revision::V20) => {
                p.write(out);
                let mut crcs = [0u32; 4];
                for i in 0..n {
                    crcs[i] = crc_extend(d[i], out);
                }
                out.push(aborted as u8);
                for c in &crcs {
                    out.extend_from_slice(&wire_crc(crc, *c).to_le_bytes());
                }
            }
            (Tx::Secure(g), Revision::V21) => {
                let s0 = out.len();
                let p0 = pad16(l[0]);
                p.write(out);
                let k = l[0].min(INLINE_LEN);
                out.extend_from_slice(&head[..k]);
                out.resize(s0 + PREAMBLE_LEN + INLINE_LEN, 0);
                let t = g.seal(&mut out[s0..])?;
                out.extend_from_slice(&t);
                if p0 > INLINE_LEN {
                    let s = out.len();
                    out.extend_from_slice(&head[INLINE_LEN..]);
                    out.resize(s + p0 - INLINE_LEN, 0);
                    let t = g.seal(&mut out[s..])?;
                    out.extend_from_slice(&t);
                }
                if n > 1 {
                    // segments 1.., their padding and the epilogue: one region, encrypted from the sources into the
                    // frame (no plaintext copy that is then read and rewritten in place)
                    let mut epilogue = [0u8; 16];
                    epilogue[0] = if aborted { LATE_ABORTED } else { LATE_COMPLETE };
                    let s = out.len();
                    let t = g.seal_append(out, s, padded(&d[1..n], &l[1..n], &epilogue))?;
                    out.extend_from_slice(&t);
                }
            }
            (Tx::Secure(g), Revision::V20) => {
                // one region from the preamble on: the preamble is sealed in place, the segments from their sources
                let s0 = out.len();
                p.write(out);
                let mut epilogue = [0u8; 16];
                epilogue[0] = aborted as u8;
                let t = g.seal_append(out, s0, padded(&d[..n], &l[..n], &epilogue))?;
                out.extend_from_slice(&t);
            }
        }
        Ok(())
    }
}

/// The plaintext of a secure region in wire order: each segment's pieces, its zero padding to 16 bytes, then `tail`
/// (the epilogue). Empty pieces are skipped.
fn padded<'a>(
    segs: &'a [&'a [&'a [u8]]],
    lens: &'a [usize],
    tail: &'a [u8],
) -> impl Iterator<Item = &'a [u8]> {
    const ZERO: [u8; 16] = [0; 16];
    segs.iter()
        .zip(lens)
        .flat_map(|(pieces, &l)| pieces.iter().copied().chain([&ZERO[..pad16(l) - l]]))
        .chain([tail])
        .filter(|piece| !piece.is_empty())
}

/// Bytes a zero-copy frame copies into `out` besides the shared runs: preamble, header, the inline front and middle,
/// the seg0 trailer crc and the epilogue.
fn copied_len(header: usize, front: usize, middle: usize) -> Result<usize, Error> {
    [PREAMBLE_LEN, header, front, middle, 17]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or(Error::FrameTooLarge(u64::MAX))
}

fn reserve_output(out: &mut Vec<u8>, additional: usize) -> Result<(), Error> {
    let total = out
        .len()
        .checked_add(additional)
        .ok_or(Error::FrameTooLarge(u64::MAX))?;
    if total > isize::MAX as usize {
        return Err(Error::FrameTooLarge(
            u64::try_from(total).unwrap_or(u64::MAX),
        ));
    }
    out.try_reserve(additional)
        .map_err(|_| Error::AllocationFailed(total))
}

/// Reject front-rope offsets that do not ascend inside `front`: every slice below indexes `front[pos..at]`.
pub(crate) fn check_rope(front: &[u8], zc: &[(usize, Bytes)]) -> Result<(), Error> {
    let mut pos = 0;
    for (at, _) in zc {
        if *at < pos || *at > front.len() {
            return Err(Error::BadFrontRope);
        }
        pos = *at;
    }
    Ok(())
}

/// `front` with the runs `zc` (`(offset in front, run)`, ascending) inserted. A broken rope is an error, never an
/// out-of-bounds slice.
pub fn flatten(front: &[u8], zc: &[(usize, Bytes)]) -> Result<Vec<u8>, Error> {
    check_rope(front, zc)?;
    let total = zc
        .iter()
        .try_fold(front.len(), |n, (_, r)| n.checked_add(r.len()))
        .ok_or(Error::FrameTooLarge(u64::MAX))?;
    let mut v = Vec::with_capacity(total);
    let mut pos = 0;
    for (at, r) in zc {
        v.extend_from_slice(&front[pos..*at]);
        v.extend_from_slice(r);
        pos = *at;
    }
    v.extend_from_slice(&front[pos..]);
    Ok(v)
}

/// The data segment of [`Encoder::encode_message_parts`] as one buffer (copy; non-zero-copy paths only).
pub fn flatten_data(data: &Bytes, more: &[(Bytes, crc::CrcHint)]) -> Bytes {
    if more.is_empty() {
        return data.clone();
    }
    let mut v = Vec::with_capacity(more.iter().fold(data.len(), |n, (b, _)| n + b.len()));
    v.extend_from_slice(data);
    for (b, _) in more {
        v.extend_from_slice(b);
    }
    v.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcm::{FaultPoint, inject_fault};

    #[test]
    fn an_oversized_rope_is_refused_before_the_front_is_flattened() {
        // rev 2.0 has no zero-copy path, so a rope front would be flattened: the limit check must come first
        let run = Bytes::from(vec![0u8; ZC_MIN]);
        let front_zc: Vec<(usize, Bytes)> = (0..4).map(|_| (0, run.clone())).collect();
        let mut encoder = Encoder::new(Revision::V20);
        encoder.set_limits(Limits {
            max_segment: u32::try_from(ZC_MIN).unwrap(),
            ..Limits::default()
        });
        let (mut out, mut chunks) = (Vec::new(), Vec::new());
        let r = encoder.encode_message_rope(
            &[0; 41],
            &[],
            &front_zc,
            &Default::default(),
            &[],
            &Bytes::new(),
            &Default::default(),
            &mut out,
            &mut chunks,
        );
        assert!(
            matches!(r, Err(Error::SegmentTooLarge(_) | Error::FrameTooLarge(_))),
            "{r:?}"
        );
        assert!(out.is_empty() && chunks.is_empty());
    }

    #[test]
    fn control_frames_are_bounded_by_max_control_on_send() {
        const MAX: u64 = crate::MAX_CONTROL_FRAME;
        let big = vec![0u8; MAX as usize + 1];
        let mut out = Vec::new();
        let mut encoder = Encoder::new(Revision::V21);
        assert_eq!(
            encoder.encode_control(crate::Tag::Ack as u8, &big, &mut out),
            Err(Error::FrameTooLarge(MAX + 1))
        );
        assert!(out.is_empty(), "a refused frame leaves no bytes behind");
        // a MESSAGE of the same size is not a control frame
        encoder
            .encode_message(&[0; 41], &[], &[], &big, &mut out)
            .unwrap();
        // the compatible wire shape declares no ceiling of its own
        out.clear();
        encoder.set_limits(Limits::wire_shape());
        encoder
            .encode_control(crate::Tag::Ack as u8, &big, &mut out)
            .unwrap();
    }

    #[test]
    fn checked_wire_size_matches_emission_at_inline_and_padding_boundaries() {
        for rev in [Revision::V20, Revision::V21] {
            for secure in [false, true] {
                for length in [0, 1, 15, 16, 17, 47, 48, 49, 64, 65] {
                    for count in 1..=MAX_SEGMENTS {
                        let mut encoder = Encoder::new(rev);
                        if secure {
                            encoder
                                .set_secure(&ConnSecret::new(&[7; 64]).unwrap(), Role::Client)
                                .unwrap();
                        }
                        let body = vec![7; length];
                        let segs = vec![
                            Seg {
                                data: &body,
                                align: 8
                            };
                            count
                        ];
                        let (p, _, _) = encoder.layout(17, 0, &segs).unwrap();
                        let mut out = vec![1, 2, 3];
                        encoder.encode(17, &segs, &mut out).unwrap();
                        assert_eq!(out.len() - 3, p.wire_len(rev, secure).unwrap());
                        assert_eq!(&out[..3], &[1, 2, 3]);
                    }
                }
            }
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn metadata_layout_checks_wire_fields_aggregate_and_all_secure_padding() {
        for rev in [Revision::V20, Revision::V21] {
            for secure in [false, true] {
                let mut encoder = Encoder::new(rev);
                if secure {
                    encoder
                        .set_secure(&ConnSecret::new(&[7; 64]).unwrap(), Role::Client)
                        .unwrap();
                }
                let max = u32::MAX as usize;
                let lengths = [(max, 8); MAX_SEGMENTS];
                assert!(matches!(
                    encoder.layout_lens(crate::Tag::Message as u8, 0, &lengths),
                    Err(Error::SegmentTooLarge(_))
                ));
                encoder.set_limits(Limits::wire_shape());
                let (p, sum) = encoder
                    .layout_lens(crate::Tag::Message as u8, 0, &lengths)
                    .unwrap();
                assert_eq!(sum, Limits::wire_shape().max_frame);
                assert_eq!(p.len, [u32::MAX; MAX_SEGMENTS]);
                assert!(p.wire_len(rev, secure).unwrap() > sum as usize);
                assert!(encoder.layout_lens(17, 0, &[(max + 1, 8)]).is_err());
                assert!(encoder.layout_lens(17, 0, &[(usize::MAX, 8)]).is_err());
                assert_eq!(
                    encoder.layout_lens(17, 0, &[(1, 8); MAX_SEGMENTS + 1]),
                    Err(Error::TooManySegments)
                );
                encoder.set_limits(Limits {
                    max_frame: sum - 1,
                    ..Limits::wire_shape()
                });
                assert_eq!(
                    encoder.layout_lens(17, 0, &lengths),
                    Err(Error::FrameTooLarge(sum))
                );
            }
        }
    }

    #[test]
    fn failed_shared_secure_regions_preserve_output_prefixes_and_input_aliases() {
        let secret = ConnSecret::new(&[7; 64]).unwrap();
        for rev in [Revision::V20, Revision::V21] {
            for point in [
                FaultPoint::Begin,
                FaultPoint::Update,
                FaultPoint::ShortWrite,
                FaultPoint::Final,
                FaultPoint::Tag,
            ] {
                let mut encoder = Encoder::new(rev);
                encoder.set_secure(&secret, Role::Client).unwrap();
                let source = Bytes::from(vec![0x6a; 8193]);
                let mut out = vec![4, 5];
                let mut chunks = vec![Bytes::from_static(b"existing")];
                inject_fault(point);
                assert!(matches!(
                    encoder.encode_message_owned(
                        &[1; 65],
                        vec![2; 17],
                        vec![3; 7],
                        source.clone(),
                        &mut out,
                        &mut chunks,
                    ),
                    Err(Error::Crypto)
                ));
                assert_eq!(out, [4, 5]);
                assert_eq!(chunks, [Bytes::from_static(b"existing")]);
                assert!(source.iter().all(|&byte| byte == 0x6a));
            }
        }
    }
}
