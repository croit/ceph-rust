// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! LAB ONLY (feature `cut-probe`, adr 0477): measurement of the chunk arrival profile of large frames,
//! to bound what cut-through could gain (doc/perf/cut-through-20261021.md). Per connection: (rx) when each 256 KiB piece of a
//! direct data segment completed, relative to the segment start; (tx) how long the output queue needed to go from the first
//! submit to idle for a burst of >= 1 MiB. One stderr line per large frame (`CUTPROBE ...`); nothing else changes. Needs the
//! receive spread off (`NV_KNET_SPREAD=0`, read only in this feature's build): a spread segment is received by a helper core and is not stamped.
use std::sync::OnceLock;
use std::time::Instant;

/// Frames below this size are not reported.
const MIN: usize = 1 << 20;

fn origin() -> Instant {
    static T0: OnceLock<Instant> = OnceLock::new();
    *T0.get_or_init(Instant::now)
}

fn us(t: Instant) -> u64 {
    t.saturating_duration_since(origin()).as_micros() as u64
}

#[derive(Debug)]
struct Rx {
    t0: Instant,
    total: usize,
    got: usize,
    pieces: Vec<(usize, u64)>,
}

#[derive(Debug)]
struct Tx {
    t0: Instant,
    bytes: usize,
    sends: u32,
}

/// Probe state of one connection.
#[derive(Debug, Default)]
pub struct ConnProbe {
    rx: Option<Rx>,
    tx: Option<Tx>,
}

impl ConnProbe {
    /// A direct receive of `total` segment bytes starts.
    pub fn rx_start(&mut self, total: usize) {
        self.rx = (total >= MIN).then(|| Rx {
            t0: Instant::now(),
            total,
            got: 0,
            pieces: Vec::with_capacity(total.div_ceil(256 << 10)),
        });
    }

    /// `n` more bytes of the segment landed.
    pub fn rx_piece(&mut self, n: usize) {
        if let Some(r) = &mut self.rx {
            r.got += n;
            r.pieces.push((r.got, r.t0.elapsed().as_micros() as u64));
        }
    }

    /// The segment is complete: report it.
    pub fn rx_end(&mut self, conn: u64) {
        let Some(r) = self.rx.take() else { return };
        let list: Vec<String> = r
            .pieces
            .iter()
            .map(|(b, t)| format!("{}@{t}", b >> 10))
            .collect();
        eprintln!(
            "CUTPROBE rx conn={conn} t_us={} total={} fill_us={} pieces={}",
            us(r.t0),
            r.total,
            r.pieces.last().map_or(0, |p| p.1),
            list.join(",")
        );
    }

    /// A send of the output queue is queued.
    pub fn tx_submit(&mut self) {
        let t = self.tx.get_or_insert_with(|| Tx {
            t0: Instant::now(),
            bytes: 0,
            sends: 0,
        });
        t.sends += 1;
    }

    /// The kernel took `n` bytes of the current send.
    pub fn tx_sent(&mut self, n: usize) {
        if let Some(t) = &mut self.tx {
            t.bytes += n;
        }
    }

    /// The output queue is empty and nothing is in flight: report a burst of >= 1 MiB.
    pub fn tx_idle(&mut self, conn: u64) {
        let Some(t) = self.tx.take() else { return };
        if t.bytes >= MIN {
            eprintln!(
                "CUTPROBE tx conn={conn} t_us={} bytes={} drain_us={} sends={}",
                us(t.t0),
                t.bytes,
                t.t0.elapsed().as_micros(),
                t.sends
            );
        }
    }
}
