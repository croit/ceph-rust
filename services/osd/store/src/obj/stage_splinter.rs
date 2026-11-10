// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
//! Request-scoped bounded scan accumulation over the foreign base.
use super::super::shardio::SplinterScanMemo;
use super::*;
impl<D: BlockDev, C: Clock> Stage<'_, '_, D, C> {
    pub(super) fn splinter_list_memo(
        &mut self,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        max: usize,
    ) -> Result<(Vec<(Bytes, Bytes)>, bool)> {
        let (enc, n, next) = self.splinter_memo(
            id,
            from,
            excl,
            prefix,
            (max, usize::MAX, 0),
            (OmapScanMode::Values, if excl { 255 } else { 254 }),
        )?;
        Ok((
            enc_decode(&enc, n, true)
                .into_iter()
                .map(|(k, v)| (Bytes::from(k), Bytes::from(v)))
                .collect(),
            next.is_some(),
        ))
    }
    pub(super) fn splinter_scan_memo(
        &mut self,
        id: u64,
        from: &[u8],
        prefix: &[u8],
        limits: (usize, usize),
        mode: OmapScanMode,
        head: usize,
    ) -> Result<(Vec<u8>, usize, Option<Vec<u8>>)> {
        self.splinter_memo(
            id,
            from,
            false,
            prefix,
            (limits.0, limits.1, head),
            (mode, mode as u8),
        )
    }
    fn splinter_memo(
        &mut self,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        limits: (usize, usize, usize),
        mode: (OmapScanMode, u8),
    ) -> Result<(Vec<u8>, usize, Option<Vec<u8>>)> {
        let (max, max_bytes, head) = limits;
        let (mode, mode_id) = mode;
        let session = self.s.memo_session().expect("request scoped listing");
        let revision = self
            .splinter_omem
            .as_ref()
            .expect("SplinterDB staging")
            .obj(id)
            .map_or(0, |o| o.revision.1);
        let same = |m: &SplinterScanMemo| {
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
            .splinter_memo_take(session, id, same)
            .unwrap_or_else(|| SplinterScanMemo {
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
                engine_revision: revision,
            });
        let (n0, bytes0) = (m.n, m.bytes);
        let result = (|| {
            self.splinter_memo_admit(session, &m)?;
            if m.walked.is_some() {
                return Ok(());
            }
            loop {
                let (cursor, ex) = m.engine_cursor.as_ref().expect("engine cursor");
                // A sliced pass consumes at most the rest of its slice plus the one
                // row that ends a full page: copy no more than that.
                let take = if self.s.list_sliced() {
                    SCAN_SLICE_ENTRIES
                        .saturating_sub(m.n - n0)
                        .saturating_add(1)
                } else {
                    usize::MAX
                };
                let (page, more) = match self.s.sh.splinter_list_mode(
                    self.splinter_omem.as_ref(),
                    id,
                    cursor,
                    *ex,
                    prefix,
                    (
                        max.saturating_sub(m.n)
                            .saturating_add(1)
                            .min(crate::splinter_omap::MAX_SCAN_ROWS),
                        mode == OmapScanMode::Keys,
                        take,
                    ),
                ) {
                    Err(StoreError::Miss) => {
                        self.s.omap_miss_wait(self.clk)?;
                        // A blocking wait polled the store: re-check the credit before
                        // the cheap per-entry charges resume.
                        self.splinter_memo_admit(session, &m)?;
                        continue;
                    }
                    r => r?,
                };
                for (k, v) in page {
                    let cost = if mode == OmapScanMode::Keys {
                        k.len().saturating_add(4)
                    } else {
                        k.len().saturating_add(v.len())
                    };
                    let full = match mode {
                        OmapScanMode::Values => m.n > 0 && m.bytes >= max_bytes,
                        OmapScanMode::Keys => m.bytes >= max_bytes,
                        OmapScanMode::Recovery => {
                            m.n > 0 && cost >= max_bytes.saturating_sub(m.bytes)
                        }
                    };
                    if (m.n >= max && (mode != OmapScanMode::Recovery || m.n > 0)) || full {
                        m.walked = Some(Some(k.to_vec()));
                        return Ok(());
                    }
                    let others = self
                        .s
                        .splinter_memos
                        .iter()
                        .map(SplinterScanMemo::engine_charge)
                        .sum::<usize>();
                    let growth = cost.saturating_add(8).saturating_mul(8).saturating_add(128);
                    // The credit was admitted at this pass's start and nothing else runs
                    // on the owner during it: per-entry growth only updates the charge.
                    self.s.sh.splinter_scan_charge(
                        others
                            .saturating_add(m.engine_charge())
                            .saturating_add(growth),
                    );
                    let need = m.enc.len().saturating_add(cost).saturating_add(8);
                    if need > m.enc.capacity() {
                        let target = need.saturating_add((64 << 10) - 1) & !((64 << 10) - 1);
                        let projected = m
                            .engine_charge()
                            .saturating_sub(m.enc.capacity().saturating_mul(4))
                            .saturating_add(target.saturating_mul(4))
                            .saturating_add(128);
                        self.s
                            .sh
                            .splinter_scan_admit(session, others.saturating_add(projected))?;
                        let additional = target.saturating_sub(m.enc.len());
                        m.enc.reserve_exact(additional);
                    }
                    m.enc.extend_from_slice(&(k.len() as u32).to_le_bytes());
                    m.enc.extend_from_slice(&k);
                    if mode != OmapScanMode::Keys {
                        m.enc.extend_from_slice(&(v.len() as u32).to_le_bytes());
                        m.enc.extend_from_slice(&v);
                    }
                    m.n += 1;
                    m.bytes = m.bytes.saturating_add(cost);
                    m.engine_cursor = Some((k, true));
                    self.splinter_memo_charge(&m);
                    if self.s.list_sliced()
                        && (m.n - n0 >= SCAN_SLICE_ENTRIES || m.bytes - bytes0 >= SCAN_SLICE_BYTES)
                    {
                        self.s.scan_slice();
                        return Err(ObjError::WouldBlock);
                    }
                }
                if !more {
                    m.walked = Some(None);
                    return Ok(());
                }
            }
        })();
        self.s.rm_progress |= m.n > n0;
        let out = match result {
            Ok(()) => Ok((m.enc.clone(), m.n, m.walked.clone().flatten())),
            Err(e) => Err(e),
        };
        if (out.is_ok() || matches!(out, Err(ObjError::WouldBlock)))
            && self.s.sh.splinter_session_admitted(session)
        {
            self.s.splinter_memo_put(m);
        }
        out
    }
    /// Charge-only form of [`splinter_memo_admit`](Self::splinter_memo_admit) inside a
    /// pass that already holds the credit.
    fn splinter_memo_charge(&mut self, m: &SplinterScanMemo) {
        let bytes = self
            .s
            .splinter_memos
            .iter()
            .map(SplinterScanMemo::engine_charge)
            .sum::<usize>()
            .saturating_add(m.engine_charge());
        self.s.sh.splinter_scan_charge(bytes);
    }
    fn splinter_memo_admit(&mut self, s: (u64, u64), m: &SplinterScanMemo) -> Result<()> {
        let bytes = self
            .s
            .splinter_memos
            .iter()
            .map(SplinterScanMemo::engine_charge)
            .sum::<usize>()
            .saturating_add(m.engine_charge());
        match self.s.sh.splinter_scan_admit(s, bytes) {
            Err(StoreError::Miss) => {
                self.s.omap_miss_wait(self.clk)?;
                Err(ObjError::WouldBlock)
            }
            r => Ok(r?),
        }
    }
}
