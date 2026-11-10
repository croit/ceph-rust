// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Request-owned output/cursor, independent of the opportunistic DB page cache.
//! Uses the existing session/object invalidation, cancellation and TTL lifecycle.
use super::super::shardio::RocksScanMemo;
use super::*;
use crate::rocks_omap::ScanAdmission;

#[derive(Debug, PartialEq, Eq)]
enum Consumed {
    NeedPage,
    Complete,
    Quantum,
}

fn writable_output(m: &mut RocksScanMemo) -> (Vec<u8>, usize, Option<Vec<u8>>) {
    let mut enc = Vec::with_capacity(m.enc.len().saturating_add(1));
    enc.extend_from_slice(&m.enc);
    (enc, m.n, m.walked.clone().flatten())
}

/// Consume only already-owned entries. The restricted permit cannot query,
/// poll, wait, yield or publish. The outer Stage drops it before doing any of
/// those, even for list_whole. A large first entry may exceed the byte quantum.
fn consume_page(
    m: &mut RocksScanMemo,
    mode: OmapScanMode,
    others: usize,
    quantum: (usize, usize),
    admission: &mut ScanAdmission<'_>,
) -> crate::error::Result<Consumed> {
    let n0 = m.n;
    let bytes0 = m.bytes;
    loop {
        let Some(page) = m.engine_page.as_ref() else {
            return Ok(Consumed::NeedPage);
        };
        let Some((k, v)) = page.peek() else {
            if !matches!(page.end, crate::rocks_omap::PageEnd::End) {
                return Err(StoreError::Invalid("empty nonterminal RocksDB batch"));
            }
            m.engine_page = None;
            m.walked = Some(None);
            return Ok(Consumed::Complete);
        };
        let end = page.last().then(|| page.end.clone());
        let cost = if mode == OmapScanMode::Keys {
            k.len().saturating_add(4)
        } else {
            k.len().saturating_add(v.len())
        };
        let full = match mode {
            OmapScanMode::Values => m.n > 0 && m.bytes >= m.max_bytes,
            OmapScanMode::Keys => m.bytes >= m.max_bytes,
            OmapScanMode::Recovery => m.n > 0 && cost >= m.max_bytes.saturating_sub(m.bytes),
        };
        if m.n >= m.max || full {
            m.scan.walked = Some(Some(k.to_vec()));
            m.engine_cursor = Some((Bytes::copy_from_slice(k), true));
            m.engine_page = None;
            return Ok(Consumed::Complete);
        }
        let growth = cost.saturating_add(8).saturating_mul(8).saturating_add(128);
        admission.charge(
            others
                .saturating_add(m.engine_charge())
                .saturating_add(growth),
        )?;
        // Preserve every projected/growth/post-entry check and capacity multiple.
        let need = m.enc.len().saturating_add(cost).saturating_add(8);
        if need > m.enc.capacity() {
            let target = need.saturating_add((64 << 10) - 1) & !((64 << 10) - 1);
            let projected = m
                .engine_charge()
                .saturating_sub(m.enc.capacity().saturating_mul(4))
                .saturating_add(target.saturating_mul(4))
                .saturating_add(128);
            admission.charge(others.saturating_add(projected))?;
            let extra = target.saturating_sub(m.enc.len());
            m.scan.enc.reserve_exact(extra);
        }
        m.scan
            .enc
            .extend_from_slice(&(k.len() as u32).to_le_bytes());
        m.scan.enc.extend_from_slice(k);
        if mode != OmapScanMode::Keys {
            m.scan
                .enc
                .extend_from_slice(&(v.len() as u32).to_le_bytes());
            m.scan.enc.extend_from_slice(v);
        }
        m.scan.n += 1;
        m.scan.bytes = m.scan.bytes.saturating_add(cost);
        // A partial batch resumes from its offset; it does not need an owned
        // per-entry cursor. Copy only when the envelope will be released. The
        // next worker query then starts after this detached boundary key.
        if end.is_some() {
            m.engine_cursor = Some((Bytes::copy_from_slice(k), true));
            m.engine_page = None;
        } else {
            m.engine_page.as_mut().expect("owned batch").advance();
        }
        if let Some(end) = &end {
            match end {
                crate::rocks_omap::PageEnd::End => m.walked = Some(None),
                crate::rocks_omap::PageEnd::Next(next)
                    if m.n >= m.max || m.bytes >= m.max_bytes =>
                {
                    m.walked = Some(Some(next.to_vec()));
                }
                _ => {}
            }
        }
        admission.charge(others.saturating_add(m.engine_charge()))?;
        // Quantum precedes Complete: the final entry must still yield in sliced
        // mode, exactly as before. list_whole just starts another bounded permit.
        if m.n - n0 >= quantum.0 || m.bytes - bytes0 >= quantum.1 {
            return Ok(Consumed::Quantum);
        }
        if m.walked.is_some() {
            return Ok(Consumed::Complete);
        }
    }
}

impl<D: BlockDev, C: Clock> Stage<'_, '_, D, C> {
    pub(super) fn rocks_list_memo(
        &mut self,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        max: usize,
    ) -> Result<(Vec<(Bytes, Bytes)>, bool)> {
        let (enc, n, next) = self.rocks_memo(
            id,
            from,
            excl,
            prefix,
            (max, usize::MAX, 0),
            (OmapScanMode::Values, if excl { 255 } else { 254 }),
            writable_output,
        )?;
        Ok((
            enc_decode(&enc, n, true)
                .into_iter()
                .map(|(k, v)| (Bytes::from(k), Bytes::from(v)))
                .collect(),
            next.is_some(),
        ))
    }

    pub(super) fn rocks_scan_memo(
        &mut self,
        id: u64,
        from: &[u8],
        prefix: &[u8],
        limits: (usize, usize),
        mode: OmapScanMode,
        head: usize,
    ) -> Result<(Vec<u8>, usize, Option<Vec<u8>>)> {
        self.rocks_memo(
            id,
            from,
            false,
            prefix,
            (limits.0, limits.1, head),
            (mode, mode as u8),
            writable_output,
        )
    }

    pub(super) fn rocks_scan_reply(
        &mut self,
        id: u64,
        from: &[u8],
        prefix: &[u8],
        limits: (usize, usize),
        mode: OmapScanMode,
    ) -> Result<Bytes> {
        self.rocks_memo(
            id,
            from,
            false,
            prefix,
            (limits.0, limits.1, 4),
            // Distinct from writable encodings with the same head/budget.
            // Values/Keys are 0/1; legacy pair listings use 254/255.
            (mode, 128 + mode as u8),
            |m| {
                if let Some(reply) = &m.reply {
                    return reply.clone();
                }
                let n = m.n as u32;
                let more = m.walked.as_ref().expect("completed listing").is_some();
                m.enc[..4].copy_from_slice(&n.to_le_bytes());
                // Existing growth/return reservations cover this byte and a
                // possible shrink copy. The full frozen allocation, not a slice
                // of rounded spare capacity, can then outlive the Store memo.
                m.enc.reserve_exact(1);
                m.enc.push(u8::from(more));
                let reply = Bytes::from(std::mem::take(&mut m.enc).into_boxed_slice());
                m.reply = Some(reply.clone());
                reply
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn rocks_memo<T>(
        &mut self,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        limits: (usize, usize, usize),
        mode: (OmapScanMode, u8),
        finish: impl FnOnce(&mut RocksScanMemo) -> T,
    ) -> Result<T> {
        let (max, max_bytes, head) = limits;
        let (mode, mode_id) = mode;
        let session = self.s.memo_session().expect("request-scoped listing");
        let revision = self
            .rocks_omem
            .as_ref()
            .expect("RocksDB staging")
            .obj(id)
            .map_or(0, |o| o.revision.1);
        let same = |m: &RocksScanMemo| {
            m.mode == mode_id
                && m.head == head
                && m.max == max
                && m.max_bytes == max_bytes
                && m.from == from
                && m.prefix == prefix
                && m.engine_revision == revision
        };
        let mut m = self
            .s
            .rocks_memo_take(session, id, same)
            .unwrap_or_else(|| RocksScanMemo {
                scan: ScanMemo {
                    session,
                    id,
                    from: from.to_vec(),
                    prefix: prefix.to_vec(),
                    max,
                    max_bytes,
                    mode: mode_id,
                    head,
                    cur: ScanCursor::new(&[0], &[255]),
                    lsm: None,
                    enc: vec![0; head],
                    n: 0,
                    holes: Vec::new(),
                    hole_vals: Vec::new(),
                    bytes: 0,
                    walked: None,
                    touched: 0,
                },
                engine_cursor: Some((Bytes::copy_from_slice(from), excl)),
                engine_page: None,
                engine_revision: revision,
                reply: None,
            });
        let n0 = m.n;
        let bytes0 = m.bytes;
        let result = (|| {
            self.rocks_memo_admit(session, &m)?;
            loop {
                if m.walked.is_some() {
                    return Ok(());
                }
                if m.engine_page.is_none() {
                    let (cursor, ex) = m.engine_cursor.as_ref().expect("engine cursor");
                    let entries = if max == usize::MAX {
                        SCAN_SLICE_ENTRIES
                    } else {
                        max.saturating_sub(m.n)
                            .clamp(1, crate::rocks_omap::SCAN_BATCH)
                    };
                    let (page, end) = match self.s.sh.rocks_scan_batch(
                        self.rocks_omem.as_ref(),
                        id,
                        cursor,
                        *ex,
                        prefix,
                        entries,
                    ) {
                        Err(StoreError::Miss) => {
                            self.s.miss_wait(self.clk)?;
                            continue;
                        }
                        r => r?,
                    };
                    m.engine_page = Some(super::super::shardio::EnginePage::new(page, end));
                }
                // Other memos cannot change while this owner-side slice borrows
                // the shard's Client. Cache their charge only for this slice.
                let others = self
                    .s
                    .rocks_memos
                    .iter()
                    .map(RocksScanMemo::engine_charge)
                    .sum::<usize>();
                let sliced = self.s.list_sliced();
                let quantum = if sliced {
                    (
                        SCAN_SLICE_ENTRIES.saturating_sub(m.n - n0),
                        SCAN_SLICE_BYTES.saturating_sub(m.bytes - bytes0),
                    )
                } else {
                    (SCAN_SLICE_ENTRIES, SCAN_SLICE_BYTES)
                };
                let consumed = self
                    .s
                    .sh
                    .rocks_scan_admission(session)
                    .and_then(|mut a| consume_page(&mut m, mode, others, quantum, &mut a)); // admission ends before any query, wait, yield or publication
                match consumed {
                    Err(StoreError::Miss) => {
                        self.s.miss_wait(self.clk)?;
                        return Err(ObjError::WouldBlock);
                    }
                    Err(e) => return Err(e.into()),
                    Ok(Consumed::Complete) => return Ok(()),
                    Ok(Consumed::Quantum) if sliced => {
                        self.s.scan_slice();
                        return Err(ObjError::WouldBlock);
                    }
                    Ok(Consumed::Quantum | Consumed::NeedPage) => {}
                }
            }
        })();
        self.s.rm_progress |= m.n > n0;
        let out = result.and_then(|()| {
            let output = finish(&mut m);
            if m.reply.is_some() {
                // Freezing usually lowers the charge, but an encoding exactly
                // filling its allocation gains the trailer byte. Re-admit the
                // final owned shape before publication, even in that boundary
                // case. The existing growth/return multiple covers the bounded
                // temporary shrink allocation; writable outputs are unchanged.
                self.rocks_memo_admit(session, &m)?;
            }
            Ok(output)
        });
        if (out.is_ok() || matches!(out, Err(ObjError::WouldBlock)))
            && self.s.sh.rocks_session_admitted(session)
        {
            self.s.rocks_memo_put(m);
        }
        out
    }

    fn rocks_memo_admit(&mut self, session: (u64, u64), m: &RocksScanMemo) -> Result<()> {
        let bytes = self
            .s
            .rocks_memos
            .iter()
            .map(RocksScanMemo::engine_charge)
            .sum::<usize>()
            .saturating_add(m.engine_charge());
        match self.s.sh.rocks_scan_admit(session, bytes) {
            Err(StoreError::Miss) => {
                self.s.miss_wait(self.clk)?;
                Err(ObjError::WouldBlock)
            }
            r => Ok(r?),
        }
    }
}
