// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `bench` / `crash` subcommands: engine benchmarks and crash-consistency runs on a REAL device (or a file).
//!
//!   croit-flashstore-tool bench --dev spdk:PCI [--format-lba4k] [--shards auto|N] [--qdepth 256] [--pgs 32] [--objs 16] [--secs 5]
//!                      [--modes rw4k:1,rw4k:32,rw64k:32,seq4m:16,meta:32,rw4k+:32] [--cpu N] [--cores N] [--wal-coalesce K] [--wal-mib N] [--ckpt-delta-leaves N] [--ckpt-slice N]
//!     `--cores N` (N <= shards; `--shards auto` = N): one thread per core on cpus `--cpu`..`--cpu`+N-1, each owns the shards
//!     s%N==t; QD of a mode is per core, results summed. Mode `rw128k` = 128 KiB random-offset overwrite.
//!     DESTROYS the device (fresh mkfs). Modes `NAME:QD`: rw4k / rw64k = random overwrite inside pre-filled 4 MiB
//!     objects, seq4m = sequential 4 MiB object writes, meta = attr + omap-only txns, `+` suffix = OSD-like extra
//!     metadata (object_info attr + pg-log omap key + trim) in the same txn. `omap4k` = rados bench --omap (new object, 4 KiB omap value). `mix4k` = rw4k where every
//!     `--mix-every N`-th (default 16) txn instead writes a whole 4 MiB object (sequential): IOPS/MB/s count both,
//!     latency columns are the 4 KiB txns only (head-of-line cost of big txns sharing a shard / WAL, adr 0160).
//!   croit-flashstore-tool bench --dev spdk:PCI --cold [--nobj 600000] [--cache-pages 512] [--qds 1,16] [--park] [--new] [--secs 8]
//!     Cold tree cache (ADR 0021 am. 8): small objects, tiny page cache, random (or `--new` fresh-name) 4 KiB OSD-like
//!     txns; `--park` = probe with `Store::warm` and park per PG instead of spinning on a miss. `--loop-us N` (any mode)
//!     spins N us per iteration between queue and poll to emulate the OSD core loop.
//!   croit-flashstore-tool crash write  --dev SPEC --ledger FILE [--mkfs [--format-lba4k]] [--qd 32]   (runs until killed)
//!   croit-flashstore-tool crash verify --dev SPEC --ledger FILE            (mount, fsck, every acked txn intact, atomicity)
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use nvme::any::{AnyBuf, AnyCtrl, AnyDev, DevSpec};
use nvme::{BlockDev, Completion, Geometry, Nanos, Submit};
use osd::nvmestore;
use std::cell::Cell;
use std::io::Write;
use std::rc::Rc;
use std::time::Instant;
use store::dev::MonoClock;
use store::obj::{OTxn, Store, StoreCfg, TOp};
use store::rng::Rng;

pub(crate) type St = Store<CountDev, MonoClock>;
/// The other lab benches take their argument helpers from this module.
pub(crate) use crate::{arg, flag, fnum, mib, num, num_opt};

// ------------------------------------------------------------------ counting device wrapper

#[derive(Default)]
pub(crate) struct Counters {
    pub(crate) wr: Cell<u64>,
    pub(crate) wr_lbas: Cell<u64>,
    pub(crate) rd: Cell<u64>,
    pub(crate) rd_lbas: Cell<u64>,
    pub(crate) other: Cell<u64>,
    pub(crate) done: Cell<u64>,
}

/// Delegating `BlockDev` that counts device commands (bench only; the production path has no counters).
pub(crate) struct CountDev {
    d: AnyDev,
    c: Rc<Counters>,
}

impl BlockDev for CountDev {
    type Buf = AnyBuf;
    fn submits_at_flush(&self) -> bool {
        self.d.submits_at_flush()
    }
    fn issue(&mut self) {
        self.d.issue()
    }
    fn wait_hint(&mut self) -> Option<std::time::Duration> {
        self.d.wait_hint()
    }
    fn geometry(&self) -> Geometry {
        self.d.geometry()
    }
    fn alloc_buf(&mut self, len: usize) -> AnyBuf {
        self.d.alloc_buf(len)
    }
    fn alloc_buf_uninit(&mut self, len: usize) -> AnyBuf {
        self.d.alloc_buf_uninit(len)
    }
    fn try_alloc_buf_uninit(&mut self, len: usize) -> Option<AnyBuf> {
        self.d.try_alloc_buf_uninit(len)
    }
    fn try_alloc_io_uninit(&mut self, len: usize) -> Option<AnyBuf> {
        self.d.try_alloc_io_uninit(len)
    }
    fn release_pooled(&mut self) {
        self.d.release_pooled()
    }
    fn ram_reads(&self) -> bool {
        self.d.ram_reads()
    }
    fn alloc_buf_ram_uninit(&mut self, len: usize) -> AnyBuf {
        self.d.alloc_buf_ram_uninit(len)
    }
    fn queue_space(&self) -> usize {
        self.d.queue_space()
    }
    fn queue_depth(&self) -> usize {
        self.d.queue_depth()
    }
    fn submit_write(&mut self, lba: u64, buf: AnyBuf, tag: u64) -> Submit<AnyBuf> {
        use nvme::IoBuf;
        let n = (buf.len() / self.d.geometry().lba_size as usize) as u64;
        let r = self.d.submit_write(lba, buf, tag);
        if r.is_ok() {
            self.c.wr.set(self.c.wr.get() + 1);
            self.c.wr_lbas.set(self.c.wr_lbas.get() + n);
        }
        r
    }
    fn submit_read(&mut self, lba: u64, buf: AnyBuf, tag: u64) -> Submit<AnyBuf> {
        use nvme::IoBuf;
        let n = (buf.len() / self.d.geometry().lba_size as usize) as u64;
        let r = self.d.submit_read(lba, buf, tag);
        if r.is_ok() {
            self.c.rd.set(self.c.rd.get() + 1);
            self.c.rd_lbas.set(self.c.rd_lbas.get() + n);
        }
        r
    }
    fn dealloc_limits(&self) -> nvme::DeallocLimits {
        self.d.dealloc_limits()
    }
    fn submit_deallocate(&mut self, ranges: &[(u64, u32)], tag: u64) -> Submit<AnyBuf> {
        self.c.other.set(self.c.other.get() + 1);
        self.d.submit_deallocate(ranges, tag)
    }
    fn submit_write_zeroes(&mut self, lba: u64, nlba: u32, tag: u64) -> Submit<AnyBuf> {
        self.c.other.set(self.c.other.get() + 1);
        self.d.submit_write_zeroes(lba, nlba, tag)
    }
    fn poll(&mut self, now: Nanos, out: &mut Vec<Completion<AnyBuf>>) -> usize {
        let n = self.d.poll(now, out);
        if n > 0 {
            self.c.done.set(self.c.done.get() + n as u64);
        }
        n
    }
    fn next_deadline(&self) -> Option<Nanos> {
        self.d.next_deadline()
    }
    fn is_dead(&self) -> bool {
        self.d.is_dead()
    }
}

// ------------------------------------------------------------------ setup

pub(crate) fn open_ctrl(a: &[String], create: bool) -> Result<AnyCtrl, String> {
    let spec = DevSpec::parse(&arg(a, "--dev").ok_or("--dev required")?)?;
    crate::devopen::open(&spec, create, 0)
}

pub(crate) fn make_store(
    a: &[String],
    mut ctrl: AnyCtrl,
    c: &Rc<Counters>,
) -> Result<(AnyCtrl, St), String> {
    if ctrl.geometry().vwc && !flag(a, "--allow-vwc") {
        return Err(
            "device has a volatile write cache: refused (adr 0008), --allow-vwc = lab".into(),
        );
    }
    if let Some(cur) = ctrl.needs_4k_format() {
        if !flag(a, "--format-lba4k") {
            return Err(format!(
                "format is {cur}: pass --format-lba4k (DESTROYS data)"
            ));
        }
        let t = Instant::now();
        ctrl = ctrl.ensure_4k()?.0;
        eprintln!("bench: Format NVM {} ms", t.elapsed().as_millis());
    }
    let g = ctrl.geometry();
    // `--shards auto|N` (default auto = `--cores`, adr 0160)
    let shards =
        store::layout::StoreShards::parse(&arg(a, "--shards").unwrap_or_else(|| "auto".into()))?
            .resolve(num(a, "--cores", 1)? as usize);
    let mut p = nvmestore::mkfs_params_for(g.capacity_bytes(), shards);
    p.allow_volatile_cache = flag(a, "--allow-vwc");
    let wm = WAL_MIB.load(std::sync::atomic::Ordering::Relaxed);
    if wm > 0 {
        p.wal_blocks = (wm << 20) / store::BLK as u64;
    }
    // `--elastic [--base-pct N] [--chunk-blocks N]`: chunk-table store (adr 0021 am. 47; build with --features elastic)
    if flag(a, "--elastic") {
        p.chunked = true;
        p.base_pct = num(a, "--base-pct", u64::from(p.base_pct))? as u32;
        p.chunk_blocks = num(a, "--chunk-blocks", p.chunk_blocks)?;
        eprintln!(
            "bench: elastic base {} % chunk {} blocks",
            p.base_pct, p.chunk_blocks
        );
    }
    let t = Instant::now();
    nvmestore::mkfs_dev(&ctrl, &p)?;
    eprintln!(
        "bench: mkfs {} shards (WAL ring {} MiB, qpair depth {}) in {} ms (lba {} B, {} GiB)",
        p.shards,
        (p.wal_blocks * store::BLK as u64) >> 20,
        nvme::any::queue_depth(),
        t.elapsed().as_millis(),
        g.lba_size,
        g.capacity_bytes() >> 30
    );
    let st = mount(&ctrl, c)?;
    Ok((ctrl, st))
}

fn mount(ctrl: &AnyCtrl, c: &Rc<Counters>) -> Result<St, String> {
    mount_cfg(ctrl, c, Sizing::Default)
}

/// Cache sizing of a bench mount: the bench default, a tree cache of N pages per shard (with the run budget the daemon
/// gives a shard of that cache), or the daemon's sizing from a store memory budget (`StoreCfg::for_memory`: cache, dirty marks, point cache, run budget).
#[derive(Clone, Copy)]
pub(crate) enum Sizing {
    Default,
    Pages(usize),
    Mem(u64),
}

fn mount_cfg(ctrl: &AnyCtrl, c: &Rc<Counters>, sizing: Sizing) -> Result<St, String> {
    let t = Instant::now();
    // open every queue up front so a failure is reported, not panicked inside the mount closure
    let mut d0 = ctrl.open_queue()?;
    let (sb, _) = store::layout::read_super(&mut d0, &mut MonoClock::default())
        .map_err(|e| format!("superblock: {e:?}"))?;
    let mut qs = vec![CountDev {
        d: d0,
        c: c.clone(),
    }];
    // the elastic pool owner takes one queue more (its lending table writes, adr 0021 am. 52)
    #[cfg(feature = "elastic")]
    let extra = (sb.features & store::layout::FEAT_CHUNKED != 0) as u32;
    #[cfg(not(feature = "elastic"))]
    let extra = 0;
    for _ in 1..sb.shards + extra {
        qs.push(CountDev {
            d: ctrl.open_queue()?,
            c: c.clone(),
        });
    }
    let mut cfg = bench_cfg();
    match sizing {
        Sizing::Default => {}
        Sizing::Pages(n) => {
            cfg.shard.cache_pages = n;
            cfg.shard.run_soft_bytes = store::obj::run_soft_for_pages(n);
        }
        Sizing::Mem(b) => {
            let m = StoreCfg::for_memory(b, sb.shards).map_err(|e| format!("--store-mem: {e}"))?;
            let (d, s) = (&mut cfg.shard, &m.shard);
            d.cache_pages = s.cache_pages;
            d.dirty_soft_pages = s.dirty_soft_pages;
            d.dirty_hard_pages = s.dirty_hard_pages;
            d.point_cache = s.point_cache;
            d.delta_cap_bytes = s.delta_cap_bytes;
            d.run_soft_bytes = s.run_soft_bytes;
        }
    }
    let (st, stats) = Store::mount(
        move || qs.pop().expect("one queue per shard prepared"),
        MonoClock::default(),
        cfg,
    )
    .map_err(|e| format!("mount: {e}"))?;
    let n: u64 = stats.iter().map(|s| s.txns).sum();
    eprintln!(
        "mount: {} shards, replayed {n} txns, {} ms",
        st.nshards(),
        t.elapsed().as_millis()
    );
    Ok(st)
}

pub(crate) fn pgc(seed: u32) -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, seed),
        shard: ShardId::NO_SHARD,
    })
}

pub(crate) fn obj(name: &str, seed: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(name.as_bytes(), SnapId(0), seed, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

pub(crate) fn pgmeta(seed: u32) -> Ghobject {
    Ghobject::pgmeta(1, seed, ShardId::NO_SHARD)
}

pub(crate) fn fill_pattern(buf: &mut [u8], seed: u64) {
    let mut r = Rng::new(seed);
    for c in buf.chunks_mut(8) {
        let v = r.next_u64().to_le_bytes();
        c.copy_from_slice(&v[..c.len()]);
    }
}

// ------------------------------------------------------------------ bench

#[derive(Clone, Copy)]
enum Kind {
    Rw(usize),
    Seq4m,
    Meta,
    /// rw4k with every `MIX_EVERY`-th txn a whole 4 MiB object write; latency of the 4 KiB txns only.
    Mix,
    /// `rados bench --omap`: a new object per txn with one 4 KiB omap value (+ `_`/snapset attrs, pg-log key with `+`).
    Omap,
}

/// `--mix-every N` for mode `mix4k`.
static MIX_EVERY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(16);

struct Mode {
    name: String,
    kind: Kind,
    qd: usize,
    extra_meta: bool,
}

fn parse_mode(s: &str) -> Option<Mode> {
    let (n, qd) = s.split_once(':')?;
    let (n, plus) = n.strip_suffix('+').map_or((n, false), |x| (x, true));
    let kind = match n {
        "rw4k" => Kind::Rw(4096),
        "rw64k" => Kind::Rw(65536),
        "rw128k" => Kind::Rw(131072),
        "rw1m" => Kind::Rw(1 << 20),
        "seq4m" => Kind::Seq4m,
        "meta" => Kind::Meta,
        "mix4k" => Kind::Mix,
        "omap4k" => Kind::Omap,
        _ => return None,
    };
    Some(Mode {
        name: s.to_owned(),
        kind,
        qd: qd.parse().ok().filter(|&q| q >= 1)?,
        extra_meta: plus,
    })
}

struct Env {
    pgs: u32,
    /// Seed of logical PG k (multi-core bench: the PGs whose shard the thread owns).
    seeds: Vec<u32>,
    objs: u32,
    data: Vec<u8>,
    log_seq: Vec<u64>,
    /// Pre-built object names (index `oi * pgs + pg`) and pgmeta objects: keeps the harness off the profile.
    names: Vec<Ghobject>,
    pgm: Vec<Ghobject>,
    /// Objects created by `omap4k` so far (fresh names).
    omap_next: u64,
}

/// `"pglog.0." + 16 decimal digits` without formatting machinery.
pub(crate) fn log_key(buf: &mut [u8; 24], n: u64) {
    buf[..8].copy_from_slice(b"pglog.0.");
    let mut v = n;
    for i in (8..24).rev() {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
}

pub(crate) const OBJ_BYTES: usize = 4 << 20;

fn oname(pg: u32, i: u32) -> String {
    format!("rbd_data.{pg:04}.{i:06}")
}

#[derive(Default)]
struct Res {
    ops: u64,
    secs: f64,
    bytes: u64,
    lat: Vec<u32>, // us
    wr: u64,
    wr_lbas: u64,
    rd: u64,
    other: u64,
    busy_ns: u64,
    queue_ns: u64,
    /// WAL units, unit blocks, unit header + record bytes (shard stats).
    units: u64,
    wal_blocks: u64,
    wal_payload: u64,
    /// Checkpoints, sync start ns (sum, max of one start), max pages of one checkpoint (shard stats; tail sources).
    ck: (u64, u64, u64, u64, u64),
    /// Tree dirty pages at the end of the mode (sum over shards; a drift grows it run over run: adr 0021 am. 42).
    dirty: u64,
    /// Acks per 100 ms (stop-go detector), `Shard::validate` dirty-hard refusals, parked txns, checkpoint wall ns (adr 0021 am. 43).
    buckets: Vec<u32>,
    busy_hard: u64,
    parks: u64,
    ck_ns: u64,
    /// WAL ring high-water (percent, max over shards), ring-full refusals, forced checkpoints during the mode (adr 0160 am. 4).
    wal_hw: u64,
    ring_full: u64,
    forced: u64,
    /// Tree pages written by checkpoints during the mode (checkpoint write cost).
    ck_pages: u64,
}

fn drive(
    st: &mut St,
    cn: &Counters,
    env: &mut Env,
    m: &Mode,
    secs: f64,
    rng: &mut Rng,
    fill: bool,
) -> Result<Res, String> {
    let io = match m.kind {
        Kind::Rw(n) => n,
        Kind::Seq4m => OBJ_BYTES,
        Kind::Meta => 0,
        Kind::Mix => 4096,
        Kind::Omap => 0,
    };
    let mix_every = MIX_EVERY.load(std::sync::atomic::Ordering::Relaxed).max(1);
    let total_objs = env.pgs * env.objs;
    let cap = 4096usize;
    let mut issue: Vec<u64> = vec![0; cap];
    // mix4k: tokens of whole-object writes (latency not recorded) and their count
    let mut big: Vec<bool> = vec![false; cap];
    let mut big_done = 0u64;
    let (mut inflight, mut issued, mut done) = (0usize, 0u64, 0u64);
    let mut lat: Vec<u32> = Vec::with_capacity(1 << 20);
    let mut acked: Vec<u64> = Vec::new();
    let (w0, wl0, r0, o0) = (cn.wr.get(), cn.wr_lbas.get(), cn.rd.get(), cn.other.get());
    let u0 = wal_stats(st);
    let c0 = ck_stats(st, true);
    let x0 = store_x(st);
    for s in st.shards.iter_mut() {
        s.sh.stats.wal_hw_blocks = 0;
    }
    let rf0 = ring_stats(st);
    let mut buckets: Vec<u32> = Vec::new();
    #[cfg(feature = "alloc-count")]
    let (mut qa, mut pa) = (0u64, 0u64);
    let t0 = Instant::now();
    let limit = if fill { u64::MAX } else { (secs * 1e9) as u64 };
    let fill_total = total_objs as u64;
    let mut busy: u64 = 0;
    let mut qns: u64 = 0;
    let mut seqpos: u64 = 0;
    // `NV_TRACE=ms`: a line per interval (acks, dirty pages, checkpoint begins, dirty-hard refusals, parked txns)
    let trace_ns = std::env::var("NV_TRACE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|ms| ms * 1_000_000);
    let (mut tr_next, mut tr_done) = (trace_ns.unwrap_or(0), 0u64);
    let mut tr0 = trace_snap(st);
    loop {
        let now = t0.elapsed().as_nanos() as u64;
        let stop = if fill {
            issued >= fill_total
        } else {
            now >= limit
        };
        // issue
        while !stop && inflight < m.qd && inflight < cap && (!fill || issued < fill_total) {
            let is_big = !fill && matches!(m.kind, Kind::Mix) && issued % mix_every == 0;
            let (pg, oi, off) = if fill {
                let i = issued as u32;
                (i % env.pgs, i / env.pgs, 0u64)
            } else {
                match m.kind {
                    _ if is_big => {
                        let i = (seqpos % total_objs as u64) as u32;
                        seqpos += 1;
                        (i % env.pgs, i / env.pgs, 0)
                    }
                    Kind::Seq4m => {
                        let i = (seqpos % total_objs as u64) as u32;
                        seqpos += 1;
                        (i % env.pgs, i / env.pgs, 0)
                    }
                    _ => {
                        let i = rng.below(total_objs as u64) as u32;
                        let slots = ((OBJ_BYTES - io.min(OBJ_BYTES)) / io.max(4096)) as u64 + 1;
                        (
                            i % env.pgs,
                            i / env.pgs,
                            rng.below(slots) * io.max(4096) as u64,
                        )
                    }
                }
            };
            let sd = env.seeds[pg as usize];
            let o = if matches!(m.kind, Kind::Omap) && !fill {
                env.omap_next += 1;
                let h = crate::bench_purge::mix(env.omap_next ^ (u64::from(sd) << 40));
                obj(&format!("om.{h:016x}"), sd)
            } else {
                env.names[(oi * env.pgs + pg) as usize].clone()
            };
            let shift = (rng.next_u64() as usize & 0xffff) & !7usize;
            let mut t = OTxn::new();
            if matches!(m.kind, Kind::Omap) && !fill {
                t.push(TOp::Touch {
                    cid: pgc(sd),
                    oid: o.clone(),
                });
                t.push(TOp::OmapSetKeys {
                    cid: pgc(sd),
                    oid: o.clone(),
                    pairs: vec![(
                        b"bench-omap-key-0".as_slice().into(),
                        env.data[..4096].into(),
                    )],
                });
            }
            let wlen = if fill || is_big { OBJ_BYTES } else { io };
            if wlen > 0 {
                t.write(pgc(sd), &o, off, &env.data[shift..shift + wlen]);
            }
            let mut keys = [[0u8; 24]; 2];
            if (m.extra_meta || matches!(m.kind, Kind::Meta)) && !fill {
                let seq = &mut env.log_seq[pg as usize];
                *seq += 1;
                let (n, old) = (*seq, seq.saturating_sub(300));
                log_key(&mut keys[0], n);
                log_key(&mut keys[1], old);
                t.push(TOp::SetAttrs {
                    cid: pgc(sd),
                    oid: o.clone(),
                    attrs: vec![
                        (b"_".as_slice().into(), env.data[..250].into()),
                        (b"snapset".as_slice().into(), env.data[250..282].into()),
                    ],
                });
                t.push(TOp::OmapSetKeys {
                    cid: pgc(sd),
                    oid: env.pgm[pg as usize].clone(),
                    pairs: vec![(keys[0].as_slice().into(), env.data[256..436].into())],
                });
                t.push(TOp::OmapRmKeys {
                    cid: pgc(sd),
                    oid: env.pgm[pg as usize].clone(),
                    keys: vec![keys[1].as_slice().into()],
                });
            }
            let tok = issued + 1;
            let tq = Instant::now();
            #[cfg(feature = "alloc-count")]
            let ac = crate::alloc_count::count();
            let q = st.queue(&t, tok);
            let e = tq.elapsed().as_nanos() as u64;
            busy += e;
            qns += e;
            match q {
                // shard FIFO full (admission): issue again after the next poll
                Err(store::obj::ObjError::WouldBlock) => break,
                r => {
                    r.map_err(|e| format!("queue: {e}"))?;
                }
            }
            #[cfg(feature = "alloc-count")]
            {
                qa += crate::alloc_count::count() - ac;
            }
            issue[(tok as usize) % cap] = t0.elapsed().as_nanos() as u64;
            big[(tok as usize) % cap] = is_big;
            issued += 1;
            inflight += 1;
        }
        if let Some(iv) = trace_ns {
            let now = t0.elapsed().as_nanos() as u64;
            if now >= tr_next {
                tr_next = now + iv;
                let s = trace_snap(st);
                println!(
                    "trace {} t={}ms acks={} dirty={} dirty_max={} fz_left={} begins={} ends={} busy={} parked={} why={:?} busy_by={:?} rq={:?} q_att={}",
                    m.name,
                    now / 1_000_000,
                    done - tr_done,
                    s.0,
                    s.1,
                    s.2,
                    s.3 - tr0.3,
                    s.4 - tr0.4,
                    s.5 - tr0.5,
                    s.6,
                    store::dbg::PARK_WHY
                        .iter()
                        .map(|x| x.swap(0, std::sync::atomic::Ordering::Relaxed))
                        .collect::<Vec<_>>(),
                    store::dbg::BUSY
                        .iter()
                        .map(|x| x.swap(0, std::sync::atomic::Ordering::Relaxed))
                        .collect::<Vec<_>>(),
                    store::dbg::RQ
                        .iter()
                        .map(|x| x.swap(0, std::sync::atomic::Ordering::Relaxed))
                        .collect::<Vec<_>>(),
                    st.queue_attempts,
                );
                tr_done = done;
                tr0 = s;
            }
        }
        // poll
        loop_pause();
        let d0 = cn.done.get();
        let tp = Instant::now();
        #[cfg(feature = "alloc-count")]
        let ac = crate::alloc_count::count();
        acked.clear();
        st.poll(&mut acked).map_err(|e| format!("poll: {e}"))?;
        #[cfg(feature = "alloc-count")]
        {
            pa += crate::alloc_count::count() - ac;
        }
        if !acked.is_empty() || cn.done.get() != d0 {
            busy += tp.elapsed().as_nanos() as u64;
        }
        if !acked.is_empty() {
            let now = t0.elapsed().as_nanos() as u64;
            for &tk in &acked {
                if big[(tk as usize) % cap] {
                    big_done += 1;
                } else {
                    lat.push(((now - issue[(tk as usize) % cap]) / 1000) as u32);
                }
                let b = (now / 100_000_000) as usize;
                if b >= buckets.len() {
                    buckets.resize(b + 1, 0);
                }
                buckets[b] += 1;
                done += 1;
                inflight -= 1;
            }
        }
        if stop && inflight == 0 {
            break;
        }
    }
    #[cfg(feature = "alloc-count")]
    if !fill {
        println!(
            "  engine allocs/txn: queue {:.1} poll {:.1}",
            qa as f64 / done.max(1) as f64,
            pa as f64 / done.max(1) as f64
        );
    }
    let secs = t0.elapsed().as_secs_f64();
    let per = if fill { OBJ_BYTES } else { io } as u64;
    if std::env::var_os("NV_DIAG").is_some() {
        println!("diag {}: {}", m.name, store::diag::take_all());
    }
    // one read pass per counter group (each walks every shard)
    let (wal, sx, ring) = (wal_stats(st), store_x(st), ring_stats(st));
    Ok(Res {
        ops: done,
        secs,
        bytes: (done - big_done) * per + big_done * OBJ_BYTES as u64,
        lat,
        wr: cn.wr.get() - w0,
        wr_lbas: cn.wr_lbas.get() - wl0,
        rd: cn.rd.get() - r0,
        other: cn.other.get() - o0,
        busy_ns: busy,
        queue_ns: qns,
        units: wal.0 - u0.0,
        wal_blocks: wal.1 - u0.1,
        wal_payload: wal.2 - u0.2,
        ck: {
            let c = ck_stats(st, false);
            (c.0 - c0.0, c.1 - c0.1, c.2, c.3, c.4 - c0.4)
        },
        dirty: st
            .shards
            .iter()
            .map(|s| s.sh.state().tree.dirty_pages() as u64)
            .sum(),
        buckets,
        busy_hard: sx.0 - x0.0,
        parks: sx.1 - x0.1,
        ck_ns: sx.2 - x0.2,
        wal_hw: ring.0,
        ring_full: ring.1 - rf0.1,
        forced: ring.2 - rf0.2,
        ck_pages: ring.3 - rf0.3,
    })
}

/// (WAL ring high-water percent max over shards, ring-full refusals, forced checkpoints).
fn ring_stats(st: &St) -> (u64, u64, u64, u64) {
    let mut r = (0, 0, 0, 0);
    for s in &st.shards {
        let x = &s.sh.stats;
        r.0 =
            r.0.max(x.wal_hw_blocks * 100 / s.sh.gauges().wal_blocks.max(1));
        r.1 += x.busy[7] + x.busy[9];
        r.2 += x.forced_ckpts;
        r.3 += x.ckpt_pages;
    }
    r
}

/// (dirty-hard Busy refusals, parked txns, checkpoint wall ns) of the store (adr 0021 am. 43).
fn store_x(st: &St) -> (u64, u64, u64) {
    let (mut b, mut ns) = (0, 0);
    for s in &st.shards {
        b += s.sh.stats.busy[2];
        ns += s.sh.stats.ckpt_ns;
    }
    (b, st.parks, ns)
}

/// Stop-go summary of acks per 100 ms: (median, min, buckets < 25 % of median, longest zero run ms). The last bucket
/// (partial) is left out.
pub(crate) fn stop_go(b: &[u32]) -> (u32, u32, usize, usize) {
    let b = &b[..b.len().saturating_sub(1)];
    if b.is_empty() {
        return (0, 0, 0, 0);
    }
    let mut s = b.to_vec();
    s.sort_unstable();
    let med = s[s.len() / 2];
    let slow = b.iter().filter(|&&x| x * 4 < med).count();
    let (mut run, mut best) = (0, 0);
    for &x in b {
        run = if x == 0 { run + 1 } else { 0 };
        best = best.max(run);
    }
    (med, s[0], slow, best * 100)
}

/// Summed shard WAL stats: (units, unit blocks, unit header + record bytes).
fn wal_stats(st: &St) -> (u64, u64, u64) {
    st.shards.iter().fold((0, 0, 0), |a, s| {
        let x = &s.sh.stats;
        (a.0 + x.units, a.1 + x.wal_bytes / 4096, a.2 + x.wal_payload)
    })
}

/// Summed shard checkpoint stats: (checkpoints, sync start ns, longest piece (begin, slice) ns, most pages, freeze slices); `reset` zeroes the maxima
/// first (they are lifetime values in the store).
fn ck_stats(st: &mut St, reset: bool) -> (u64, u64, u64, u64, u64) {
    st.shards.iter_mut().fold((0, 0, 0, 0, 0), |a, s| {
        let x = &mut s.sh.stats;
        if reset {
            x.ckpt_sync_max_ns = 0;
            x.ckpt_max_pages = 0;
        }
        (
            a.0 + x.checkpoints,
            a.1 + x.ckpt_sync_ns,
            a.2.max(x.ckpt_sync_max_ns),
            a.3.max(x.ckpt_max_pages),
            a.4 + x.ckpt_slices,
        )
    })
}

/// `--wal-coalesce K` (adr 0021 am. 37) for every bench mount; `usize::MAX` = store default.
/// `--wal-mib N`: per-shard WAL ring MiB at the bench mkfs (0 = `layout::wal_blocks_for`).
static WAL_MIB: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static WAL_COALESCE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// `--ckpt-delta-leaves N` (adr 0021 am. 39); `usize::MAX` = store default.
static CKPT_DELTA_LEAVES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// `--ckpt-slice N` (adr 0021 am. 40); `usize::MAX` = store default.
static CKPT_SLICE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);
/// `--park-lookahead N` (adr 0021 am. 44); `usize::MAX` = store default.
/// `--helpers`: the store dispatches run compactions as helper jobs (adr 0534; the omapfill bench steps them).
static RUN_HELPERS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static PARK_LOOKAHEAD: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// `--val-ext-min N` (adr 0021 am. 46); `usize::MAX` = store default.
static VAL_EXT_MIN: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

/// `--lend-auto`: elastic pool requests on (adr 0021 am. 52; build with --features elastic).
#[cfg(feature = "elastic")]
static LEND_AUTO: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// `--lend-wm N`: pool request watermark in percent of a chunk (default: store default).
#[cfg(feature = "elastic")]
static LEND_WM: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

/// `--reclaim-mbps N`: evacuation rate of the elastic reclaim (adr 0021 am. 57; reclaim runs with `--lend-auto`); 0 = store
/// default.
#[cfg(feature = "elastic")]
static RECLAIM_MBPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn bench_cfg() -> StoreCfg {
    let mut c = StoreCfg::default();
    #[cfg(feature = "elastic")]
    match RECLAIM_MBPS.load(std::sync::atomic::Ordering::Relaxed) {
        0 => {}
        n => c.shard.reclaim_mbps = n.min(u32::MAX as usize) as u32,
    }
    #[cfg(feature = "elastic")]
    {
        c.shard.lend_auto = LEND_AUTO.load(std::sync::atomic::Ordering::Relaxed);
        let w = LEND_WM.load(std::sync::atomic::Ordering::Relaxed);
        if w != usize::MAX {
            c.shard.lend_wm_pct = w as u32;
        }
    }
    c.shard.run_helpers = RUN_HELPERS.load(std::sync::atomic::Ordering::Relaxed);
    let k = WAL_COALESCE.load(std::sync::atomic::Ordering::Relaxed);
    if k != usize::MAX {
        c.shard.wal_coalesce = k;
    }
    let n = CKPT_DELTA_LEAVES.load(std::sync::atomic::Ordering::Relaxed);
    if n != usize::MAX {
        c.shard.ckpt_delta_leaves = n;
    }
    let n = CKPT_SLICE.load(std::sync::atomic::Ordering::Relaxed);
    if n != usize::MAX {
        c.shard.ckpt_slice = n;
    }
    let n = PARK_LOOKAHEAD.load(std::sync::atomic::Ordering::Relaxed);
    if n != usize::MAX {
        c.shard.park_lookahead = n;
    }
    let n = VAL_EXT_MIN.load(std::sync::atomic::Ordering::Relaxed);
    if n != usize::MAX {
        c.shard.val_ext_min = n as u32;
    }
    c
}

pub(crate) fn pct(v: &[u32], p: f64) -> u32 {
    if v.is_empty() {
        return 0;
    }
    v[(((v.len() - 1) as f64) * p) as usize]
}

fn report(name: &str, mut r: Res, lba: u64) {
    r.lat.sort_unstable();
    let sg = stop_go(&r.buckets);
    let ops = r.ops.max(1) as f64;
    println!(
        "{:<10} ops={:<8} {:>9.0} IOPS {:>8.1} MB/s  p50={:>5}us p99={:>6}us p99.9={:>6}us p99.99={:>6}us max={:>6}us  wr_cmd/txn={:.2} wr_KiB/cmd={:.1} rd_cmd/txn={:.2} other/txn={:.2} cpu={:.2}us/op (queue {:.2}) busy={:.0}% txn/unit={:.2} wal_blk/txn={:.2} wal_B/txn={:.0} ckpts={} ckpt_sync avg={:.0}us max={}us ckpt_pages max={} slices/ckpt={:.1} dirty_end={} ckpt_ms={:.1} busy_hard={} parks={} stopgo(med/min/slow/zero_ms)={}/{}/{}/{} wal_hw_pct={} ring_full={} forced_ckpts={} ckpt_pages_total={}",
        name,
        r.ops,
        r.ops as f64 / r.secs,
        r.bytes as f64 / r.secs / 1e6,
        pct(&r.lat, 0.5),
        pct(&r.lat, 0.99),
        pct(&r.lat, 0.999),
        pct(&r.lat, 0.9999),
        r.lat.last().copied().unwrap_or(0),
        r.wr as f64 / ops,
        r.wr_lbas as f64 * lba as f64 / 1024.0 / r.wr.max(1) as f64,
        r.rd as f64 / ops,
        r.other as f64 / ops,
        r.busy_ns as f64 / 1000.0 / ops,
        r.queue_ns as f64 / 1000.0 / ops,
        r.busy_ns as f64 / (r.secs * 1e9) * 100.0,
        r.ops as f64 / r.units.max(1) as f64,
        r.wal_blocks as f64 / ops,
        r.wal_payload as f64 / ops,
        r.ck.0,
        r.ck.1 as f64 / 1000.0 / r.ck.0.max(1) as f64,
        r.ck.2 / 1000,
        r.ck.3,
        r.ck.4 as f64 / r.ck.0.max(1) as f64,
        r.dirty,
        r.ck_ns as f64 / 1e6 / r.ck.0.max(1) as f64,
        r.busy_hard,
        r.parks,
        sg.0,
        sg.1,
        sg.2,
        sg.3,
        r.wal_hw,
        r.ring_full,
        r.forced,
        r.ck_pages,
    );
}

pub fn bench(a: &[String]) -> i32 {
    match bench_inner(a) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("bench: {e}");
            crate::devopen::exit_code(&e)
        }
    }
}

fn bench_inner(a: &[String]) -> Result<(), String> {
    if std::env::var_os("NV_DIAG").is_some() {
        store::diag::enable();
    }
    if let Some(c) = num_opt(a, "--cpu")? {
        pin(c as usize)?;
    }
    if let Some(n) = num_opt(a, "--ckpt-delta-leaves")? {
        CKPT_DELTA_LEAVES.store(n as usize, std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(n) = num_opt(a, "--ckpt-slice")? {
        CKPT_SLICE.store(n as usize, std::sync::atomic::Ordering::Relaxed);
    }
    RUN_HELPERS.store(flag(a, "--helpers"), std::sync::atomic::Ordering::Relaxed);
    if let Some(n) = num_opt(a, "--park-lookahead")? {
        PARK_LOOKAHEAD.store(n as usize, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(feature = "elastic")]
    LEND_AUTO.store(flag(a, "--lend-auto"), std::sync::atomic::Ordering::Relaxed);
    #[cfg(feature = "elastic")]
    RECLAIM_MBPS.store(
        num(a, "--reclaim-mbps", 0)? as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    #[cfg(feature = "elastic")]
    if let Some(n) = num_opt(a, "--lend-wm")? {
        LEND_WM.store(n as usize, std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(n) = num_opt(a, "--val-ext-min")? {
        VAL_EXT_MIN.store(n as usize, std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(n) = num_opt(a, "--wal-mib")? {
        WAL_MIB.store(n, std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(k) = num_opt(a, "--wal-coalesce")? {
        WAL_COALESCE.store(k as usize, std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(d) = num_opt(a, "--qdepth")? {
        nvme::any::set_queue_depth(d.min(u64::from(u32::MAX)) as u32);
    }
    if let Some(n) = num_opt(a, "--mix-every")? {
        MIX_EVERY.store(n.max(1), std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(us) = num_opt(a, "--loop-us")? {
        LOOP_NS.store(us * 1000, std::sync::atomic::Ordering::Relaxed);
    }
    if flag(a, "--cold") {
        return bench_cold(a);
    }
    if let Some(m) = arg(a, "--fs") {
        return crate::bench_fs::run(a, &m);
    }
    let ctrl = open_ctrl(a, true)?;
    let cn = Rc::new(Counters::default());
    let (ctrl, mut st) = make_store(a, ctrl, &cn)?;
    if arg(a, "--omapfill").is_some()
        || arg(a, "--omapchurn").is_some()
        || arg(a, "--omapmix").is_some()
    {
        // `--cache-pages N`: remount with that tree cache per shard; `--store-mem MiB`: with the daemon's sizing from that
        // store budget (the cluster derives it from osd_memory_target)
        let sizing = match (num_opt(a, "--store-mem")?, num_opt(a, "--cache-pages")?) {
            (Some(m), _) => Some(Sizing::Mem(mib("--store-mem", m)?)),
            (None, Some(n)) => Some(Sizing::Pages(n as usize)),
            _ => None,
        };
        if let Some(z) = sizing {
            drop(st);
            st = mount_cfg(&ctrl, &cn, z)?;
        }
        if arg(a, "--omapchurn").is_some() {
            return crate::bench_omaprm::run(&mut st, a);
        }
        if arg(a, "--omapmix").is_some() {
            return crate::bench_omapmix::run(&mut st, a);
        }
        crate::bench_omapfill::run(&mut st, &cn, a)?;
        if flag(a, "--omap-reads") {
            // cold start: remount, the read phases begin with an empty tree cache of `--read-cache-pages`
            drop(st);
            let mut st = mount_cfg(
                &ctrl,
                &cn,
                num_opt(a, "--read-cache-pages")?
                    .map_or(Sizing::Default, |n| Sizing::Pages(n as usize)),
            )?;
            crate::bench_omapfill::reads(&mut st, &cn, a)?;
        }
        return Ok(());
    }
    let pgs = pgs_arg(a)?;
    let objs = num(a, "--objs", 16)?.min(u64::from(u32::MAX)) as u32;
    let secs = fnum(a, "--secs", 5.0)?;
    let cores = num(a, "--cores", 1)? as usize;
    let modes: Vec<Mode> = arg(a, "--modes")
        .unwrap_or_else(|| "rw4k:1,rw4k:32,rw4k:64,rw64k:1,rw64k:32,seq4m:1,seq4m:16,meta:1,meta:32,rw4k+:1,rw4k+:32".into())
        .split(',')
        .map(|m| parse_mode(m).ok_or_else(|| format!("bad mode {m}")))
        .collect::<Result<_, _>>()?;
    if cores > 1 {
        let shards = st.sb.shards;
        let lba = st.sb.lba_size as u64;
        st.sync().map_err(|e| e.to_string())?;
        drop(st);
        let base = num(a, "--cpu", 2)? as usize;
        return bench_mc(&ctrl, cores, base, shards, lba, pgs, objs, secs, &modes);
    }
    let mut env = make_env((0..pgs).collect(), objs);
    prep_pgs(&mut st, &env)?;
    let lba = st.sb.lba_size as u64;
    let mut rng = Rng::new(7);
    let fm = Mode {
        name: "fill".into(),
        kind: Kind::Seq4m,
        qd: 16,
        extra_meta: false,
    };
    let r = drive(&mut st, &cn, &mut env, &fm, 0.0, &mut rng, true)?;
    report(
        &format!("fill{}GiB", (pgs * objs) as u64 * 4 / 1024),
        r,
        lba,
    );
    st.sync().map_err(|e| e.to_string())?;
    #[cfg(feature = "elastic")]
    if let Some(mib) = num_opt(a, "--reclaim-prep")? {
        reclaim_prep(&mut st, &env, mib)?;
    }
    for m in &modes {
        let r = drive(&mut st, &cn, &mut env, m, secs, &mut rng, false)?;
        report(&m.name, r, lba);
    }
    #[cfg(feature = "elastic")]
    if arg(a, "--reclaim-prep").is_some() {
        let s = st
            .shards
            .iter()
            .map(|s| s.defrag_stats())
            .fold((0, 0, 0), |a, d| {
                (a.0 + d.evacs, a.1 + d.evac_blocks, a.2 + d.chunks_returned)
            });
        println!(
            "reclaim evacs={} moved_blocks={} returned={} lent0={}",
            s.0,
            s.1,
            s.2,
            lent_of(&st, 0)
        );
    }
    let rep = st.check(true).map_err(|e| e.to_string())?;
    println!(
        "fsck after bench: errors={} {:?}",
        rep.errors.len(),
        st.statfs()
    );
    Ok(())
}

/// Env for the PGs `seeds` (logical PG k = seed `seeds[k]`).
fn make_env(seeds: Vec<u32>, objs: u32) -> Env {
    let pgs = seeds.len() as u32;
    let sd = |k: u32| seeds[k as usize];
    let mut data = vec![0u8; OBJ_BYTES + 65536 + 8];
    fill_pattern(&mut data, 42 + seeds.first().copied().unwrap_or(0) as u64);
    Env {
        pgs,
        objs,
        data,
        log_seq: vec![0; pgs as usize],
        names: (0..pgs * objs)
            .map(|i| obj(&oname(sd(i % pgs), i / pgs), sd(i % pgs)))
            .collect(),
        pgm: (0..pgs).map(|k| pgmeta(sd(k))).collect(),
        seeds,
        omap_next: 0,
    }
}

fn prep_pgs(st: &mut St, env: &Env) -> Result<(), String> {
    for k in 0..env.pgs {
        let pg = env.seeds[k as usize];
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: pgc(pg),
            bits: 0,
            exist_ok: true,
        });
        t.touch(pgc(pg), &pgmeta(pg));
        st.commit(&t).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// `--cores N`: one thread per core pinned to `base + t`, each mounts the shards `s % N == t` with its own device
/// queues (adr 0031 layout) and drives the PGs of its shards (shard % N == t). `QD` of a mode is PER CORE.
/// Fill and every mode start behind a barrier; results are summed (busy% = summed over cores).
#[expect(clippy::too_many_arguments)]
fn bench_mc(
    ctrl: &AnyCtrl,
    n: usize,
    base: usize,
    shards: u32,
    lba: u64,
    pgs: u32,
    objs: u32,
    secs: f64,
    modes: &[Mode],
) -> Result<(), String> {
    if n > shards as usize {
        return Err("--cores must not exceed the store shards".into());
    }
    // one CPU per core from `base`: a wrong `--cpu` fails before the threads start (and not in one of them)
    for t in 0..n {
        let cpu = base
            .checked_add(t)
            .ok_or_else(|| format!("--cpu {base}: +{t} overflows"))?;
        check_cpu(cpu)?;
    }
    // PGs 0..pgs of pool 1 (shard (1 + seed) % S, adr 0021) go to the core owning their shard (shard % n)
    let seeds_of = |t: usize| -> Vec<u32> {
        (0..pgs)
            .filter(|s| store::obj::shard_of_spg(1, *s, shards) % n == t)
            .collect()
    };
    if (0..n).any(|t| seeds_of(t).is_empty()) {
        return Err("--pgs too small: a core owns no PG".into());
    }
    let mut qs: Vec<Vec<AnyDev>> = Vec::new();
    for t in 0..n {
        let owned = (0..shards).filter(|s| *s as usize % n == t).count();
        qs.push(
            (0..owned)
                .map(|_| ctrl.open_queue())
                .collect::<Result<_, _>>()?,
        );
    }
    let bar = std::sync::Barrier::new(n);
    let all: Vec<Vec<Res>> = std::thread::scope(|sc| {
        let hs: Vec<_> = qs
            .into_iter()
            .enumerate()
            .map(|(t, q)| {
                let (bar, modes) = (&bar, modes);
                sc.spawn(move || {
                    let r = (|| -> Result<Vec<Res>, String> {
                        pin(base + t)?;
                        let cn = Rc::new(Counters::default());
                        let mut q: Vec<CountDev> = q
                            .into_iter()
                            .map(|d| CountDev { d, c: cn.clone() })
                            .collect();
                        let (mut st, _) = Store::mount_shards(
                            move || q.pop().expect("queue per owned shard"),
                            MonoClock::default(),
                            bench_cfg(),
                            move |s| s as usize % n == t,
                        )
                        .map_err(|e| format!("mount core {t}: {e}"))?;
                        let mut env = make_env(seeds_of(t), objs);
                        prep_pgs(&mut st, &env)?;
                        let mut rng = Rng::new(7 + t as u64);
                        let fm = Mode {
                            name: "fill".into(),
                            kind: Kind::Seq4m,
                            qd: 16,
                            extra_meta: false,
                        };
                        bar.wait();
                        drive(&mut st, &cn, &mut env, &fm, 0.0, &mut rng, true)?;
                        st.sync().map_err(|e| e.to_string())?;
                        let mut out = Vec::new();
                        for m in modes {
                            bar.wait();
                            out.push(drive(&mut st, &cn, &mut env, m, secs, &mut rng, false)?);
                        }
                        Ok(out)
                    })();
                    r.unwrap_or_else(|e| {
                        eprintln!("bench core {t}: {e}");
                        std::process::exit(1)
                    })
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (i, m) in modes.iter().enumerate() {
        let mut tot = Res {
            ops: 0,
            secs: 0.0,
            bytes: 0,
            lat: Vec::new(),
            wr: 0,
            wr_lbas: 0,
            rd: 0,
            other: 0,
            busy_ns: 0,
            queue_ns: 0,
            units: 0,
            wal_blocks: 0,
            ..Default::default()
        };
        for core in &all {
            let r = &core[i];
            tot.ops += r.ops;
            tot.secs = tot.secs.max(r.secs);
            tot.bytes += r.bytes;
            tot.lat.extend_from_slice(&r.lat);
            tot.wr += r.wr;
            tot.wr_lbas += r.wr_lbas;
            tot.rd += r.rd;
            tot.other += r.other;
            tot.busy_ns += r.busy_ns;
            tot.queue_ns += r.queue_ns;
            tot.units += r.units;
            tot.wal_blocks += r.wal_blocks;
            tot.wal_payload += r.wal_payload;
            tot.ck = (
                tot.ck.0 + r.ck.0,
                tot.ck.1 + r.ck.1,
                tot.ck.2.max(r.ck.2),
                tot.ck.3.max(r.ck.3),
                tot.ck.4 + r.ck.4,
            );
            tot.dirty += r.dirty;
            tot.busy_hard += r.busy_hard;
            tot.parks += r.parks;
            tot.ck_ns += r.ck_ns;
            tot.wal_hw = tot.wal_hw.max(r.wal_hw);
            tot.ring_full += r.ring_full;
            tot.forced += r.forced;
            tot.ck_pages += r.ck_pages;
            if tot.buckets.len() < r.buckets.len() {
                tot.buckets.resize(r.buckets.len(), 0);
            }
            for (a, b) in tot.buckets.iter_mut().zip(&r.buckets) {
                *a += b;
            }
        }
        report(&format!("{}x{n}", m.name), tot, lba);
    }
    Ok(())
}

/// CPUs this host may have (`_SC_NPROCESSORS_CONF`, glibc/musl `confname.h`): an upper bound for a CPU id, and the width
/// of the affinity mask handed to the kernel.
#[cfg(target_os = "linux")]
fn configured_cpus() -> Result<usize, String> {
    const SC_NPROCESSORS_CONF: i32 = 83;
    unsafe extern "C" {
        fn sysconf(name: i32) -> i64;
    }
    // SAFETY: plain sysconf query, no pointers.
    let n = unsafe { sysconf(SC_NPROCESSORS_CONF) };
    if n <= 0 {
        return Err(format!(
            "cannot read the CPU count (sysconf {SC_NPROCESSORS_CONF})"
        ));
    }
    Ok(n as usize)
}

/// One-hot affinity mask for `cpu` on a host with `cpus` configured CPUs: words covering `cpu`, nothing beyond it set.
#[cfg(any(target_os = "linux", test))]
fn cpu_mask(cpu: usize, cpus: usize) -> Result<Vec<u64>, String> {
    if cpu >= cpus {
        return Err(format!("--cpu {cpu}: this host has {cpus} CPUs"));
    }
    let mut m = vec![0u64; cpu / 64 + 1];
    m[cpu / 64] = 1 << (cpu % 64);
    Ok(m)
}

/// Check that `cpu` exists (no pin): `--cpu`/`--cores` fail before the per-core threads start, not once per core inside
/// a thread. A pin that does not happen is an error: the run would report numbers of another core.
pub(crate) fn check_cpu(cpu: usize) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        cpu_mask(cpu, configured_cpus()?)?;
    }
    let _ = cpu;
    Ok(())
}

/// Pin the calling thread to `cpu` (Linux; a no-op elsewhere). Fails when the CPU does not exist or is not in the
/// process' affinity set (cpuset/cgroup, an outer `taskset`): an unpinned benchmark measures the wrong core.
pub(crate) fn pin(cpu: usize) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        unsafe extern "C" {
            fn sched_setaffinity(pid: i32, sz: usize, mask: *const u64) -> i32;
        }
        let m = cpu_mask(cpu, configured_cpus()?)?;
        // SAFETY: the mask is sized for the highest CPU id and outlives the call.
        let rc = unsafe { sched_setaffinity(0, m.len() * 8, m.as_ptr()) };
        if rc != 0 {
            return Err(format!(
                "--cpu {cpu}: pin failed ({})",
                std::io::Error::last_os_error()
            ));
        }
    }
    let _ = cpu;
    Ok(())
}

/// `--pgs N`: at least one PG (the PG index is a modulus of it).
pub(crate) fn pgs_arg(a: &[String]) -> Result<u32, String> {
    let n = num(a, "--pgs", 32)?;
    if n == 0 || n > u64::from(u32::MAX) {
        return Err(format!("--pgs {n}: must be 1..={}", u32::MAX));
    }
    Ok(n as u32)
}

// ------------------------------------------------------------------ crash test

const CRASH_PGS: u32 = 32;
const CRASH_OBJS: u32 = 16; // 4 MiB each = 1024 blocks
const BLOCKS_PER_PG: u64 = CRASH_OBJS as u64 * 1024;
const CRASH_TXNS: u64 = CRASH_PGS as u64 * BLOCKS_PER_PG / 2; // two blocks per txn, never overwritten

fn pattern_block(i: u64, which: u64) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    fill_pattern(&mut b, i * 2 + which + 1000);
    b
}

/// Txn `i`: two data blocks (+ a pg-log style omap key) in ONE object-store txn on one PG.
fn crash_loc(i: u64) -> (u32, [(u32, u64); 2]) {
    let pg = (i % CRASH_PGS as u64) as u32;
    let q = i / CRASH_PGS as u64; // index inside the PG
    let b0 = q * 2;
    let loc = |b: u64| ((b / 1024) as u32, (b % 1024) * 4096);
    let (o0, f0) = loc(b0);
    let (o1, f1) = loc(b0 + 1);
    (pg, [(o0, f0), (o1, f1)])
}

pub fn crash(a: &[String]) -> i32 {
    let r = match a.first().map(String::as_str) {
        Some("write") => crash_write(&a[1..]),
        Some("verify") => crash_verify(&a[1..]),
        _ => Err("crash write|verify ...".into()),
    };
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("crash: {e}");
            crate::devopen::exit_code(&e)
        }
    }
}

fn crash_write(a: &[String]) -> Result<(), String> {
    let ctrl = open_ctrl(a, true)?;
    let cn = Rc::new(Counters::default());
    let (_ctrl, mut st) = if flag(a, "--mkfs") {
        make_store(a, ctrl, &cn)?
    } else {
        let st = mount(&ctrl, &cn)?;
        (ctrl, st)
    };
    let ledger = arg(a, "--ledger").ok_or("--ledger required")?;
    let mut lf = std::fs::File::create(&ledger).map_err(|e| e.to_string())?;
    let qd = num(a, "--qd", 32)? as usize;
    if qd == 0 {
        return Err("--qd 0: no txn is ever in flight (nothing to measure)".into());
    }
    for pg in 0..CRASH_PGS {
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: pgc(pg),
            bits: 0,
            exist_ok: true,
        });
        t.touch(pgc(pg), &pgmeta(pg));
        st.commit(&t).map_err(|e| e.to_string())?;
    }
    println!("crash write: ready");
    let _ = std::io::stdout().flush();
    let (mut next, mut inflight) = (0u64, 0usize);
    let mut acked = Vec::new();
    loop {
        while inflight < qd && next < CRASH_TXNS {
            let (pg, locs) = crash_loc(next);
            let bufs = [pattern_block(next, 0), pattern_block(next, 1)];
            let mut t = OTxn::new();
            for (k, (oi, off)) in locs.iter().enumerate() {
                t.write(pgc(pg), &obj(&oname(pg, *oi), pg), *off, &bufs[k]);
            }
            t.push(TOp::OmapSetKeys {
                cid: pgc(pg),
                oid: pgmeta(pg),
                pairs: vec![(
                    format!("pglog.{next:016}").into_bytes().into(),
                    bufs[0][..100].to_vec().into(),
                )],
            });
            st.queue(&t, next + 1).map_err(|e| format!("queue: {e}"))?;
            next += 1;
            inflight += 1;
        }
        acked.clear();
        st.poll(&mut acked).map_err(|e| format!("poll: {e}"))?;
        if !acked.is_empty() {
            let mut buf = Vec::with_capacity(acked.len() * 8);
            for t in &acked {
                buf.extend_from_slice(&(t - 1).to_le_bytes());
            }
            inflight -= acked.len();
            // ack seen -> ledger (one write(2) per batch; survives kill -9 of this process)
            lf.write_all(&buf).map_err(|e| e.to_string())?;
        }
        if next >= CRASH_TXNS && inflight == 0 {
            println!("crash write: finished all {CRASH_TXNS} txns");
            return Ok(());
        }
    }
}

fn crash_verify(a: &[String]) -> Result<(), String> {
    let ctrl = open_ctrl(a, false)?;
    let cn = Rc::new(Counters::default());
    let mut st = mount(&ctrl, &cn)?;
    let rep = st.check(true).map_err(|e| format!("fsck: {e}"))?;
    if !rep.errors.is_empty() {
        return Err(format!(
            "fsck errors: {:?}",
            &rep.errors[..rep.errors.len().min(10)]
        ));
    }
    let ledger =
        std::fs::read(arg(a, "--ledger").ok_or("--ledger required")?).map_err(|e| e.to_string())?;
    let mut acked = vec![false; CRASH_TXNS as usize];
    let mut max_acked = 0u64;
    for (n, c) in ledger.as_chunks::<8>().0.iter().enumerate() {
        let i = u64::from_le_bytes(*c);
        let idx = usize::try_from(i)
            .ok()
            .filter(|&x| x < CRASH_TXNS as usize)
            .ok_or_else(|| {
                format!(
                    "--ledger: record {n} (offset {}) names txn {i}, the run has {CRASH_TXNS}",
                    n * 8
                )
            })?;
        acked[idx] = true;
        max_acked = max_acked.max(i);
    }
    if ledger.len() % 8 != 0 {
        return Err(format!(
            "--ledger: {} trailing byte(s) (not a whole txn id)",
            ledger.len() % 8
        ));
    }
    let n_acked = acked.iter().filter(|x| **x).count();
    let (mut present_unacked, mut absent_unacked, mut bad) = (0u64, 0u64, 0u64);
    // every txn up to max_acked + window: acked -> fully present; unacked -> all-or-nothing
    let upto = (max_acked + 2000).min(CRASH_TXNS - 1);
    for i in 0..=upto {
        let (pg, locs) = crash_loc(i);
        let mut have = [false; 2];
        for (k, (oi, off)) in locs.iter().enumerate() {
            let o = obj(&oname(pg, *oi), pg);
            let got = match st.read(&pgc(pg), &o, *off, 4096) {
                Ok(b) => b,
                Err(store::obj::ObjError::NoEnt) => vec![],
                Err(e) => return Err(format!("read txn {i}: {e}")),
            };
            have[k] = got == pattern_block(i, k as u64);
            if !have[k] && !(got.is_empty() || got.iter().all(|b| *b == 0)) {
                eprintln!("txn {i} block {k}: foreign content");
                bad += 1;
            }
        }
        let key = format!("pglog.{i:016}").into_bytes();
        let kv = st
            .omap_get(&pgc(pg), &pgmeta(pg), &[key.as_slice()])
            .map_err(|e| e.to_string())?;
        let has_key = kv.contains_key(&key);
        let all = have[0] && have[1] && has_key;
        let none = !have[0] && !have[1] && !has_key;
        if acked[i as usize] {
            if !all {
                eprintln!("ACKED txn {i} lost/partial: blocks {have:?} key {has_key}");
                bad += 1;
            }
        } else if all {
            present_unacked += 1;
        } else if none {
            absent_unacked += 1;
        } else {
            eprintln!("txn {i} TORN (unacked): blocks {have:?} key {has_key}");
            bad += 1;
        }
    }
    println!(
        "crash verify: acked={n_acked} max_acked={max_acked} unacked_present={present_unacked} unacked_absent={absent_unacked} bad={bad}"
    );
    if bad > 0 {
        return Err(format!("{bad} violations"));
    }
    Ok(())
}

// ------------------------------------------------------------------ cold tree cache (ADR 0021 am. 8)

struct Pend<'a> {
    t: OTxn<'a>,
    pg: u32,
    o: Ghobject,
    t0: u64,
}

/// `bench --cold`: `--nobj N` small objects (4 KiB + object_info/snapset attrs) are written, checkpointed, the store is
/// re-mounted with a tiny tree cache (`--cache-pages`, per shard) and 4 KiB OSD-like txns (data + attrs + pg-log omap
/// key + trim) hit random existing objects (`--new`: fresh names). Every access walks cold tree pages. `--park`:
/// like the OSD engine, probe with `Store::warm` first and park the op per PG until the pages arrive (the core never
/// waits); without it `Store::queue` spins on each miss. `--qds 1,16`.
fn bench_cold(a: &[String]) -> Result<(), String> {
    let ctrl = open_ctrl(a, true)?;
    let cn = Rc::new(Counters::default());
    let (ctrl, st) = make_store(a, ctrl, &cn)?;
    drop(st);
    let pgs = pgs_arg(a)?;
    let nobj = num(a, "--nobj", 1_000_000)?;
    let cache = num(a, "--cache-pages", 256)? as usize;
    let secs = fnum(a, "--secs", 8.0)?;
    let (park, newm) = (flag(a, "--park"), flag(a, "--new"));
    let qds: Vec<usize> = arg(a, "--qds")
        .unwrap_or_else(|| "1,16".into())
        .split(',')
        .map(|s| {
            s.parse::<usize>()
                .ok()
                .filter(|&q| q >= 1)
                .ok_or_else(|| format!("--qds {s}: bad queue depth (1..)"))
        })
        .collect::<Result<_, _>>()?;
    let mut st = mount_cfg(&ctrl, &cn, Sizing::Default)?;
    let mut data = vec![0u8; 4096 + 512];
    fill_pattern(&mut data, 5);
    let mut env = Env {
        pgs,
        seeds: (0..pgs).collect(),
        objs: 0,
        data,
        log_seq: vec![0; pgs as usize],
        names: Vec::new(),
        pgm: (0..pgs).map(pgmeta).collect(),
        omap_next: 0,
    };
    for pg in 0..pgs {
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: pgc(pg),
            bits: 0,
            exist_ok: true,
        });
        t.touch(pgc(pg), &pgmeta(pg));
        st.commit(&t).map_err(|e| e.to_string())?;
    }
    // random-looking names (rados bench style): neighbours in time are far apart in key order
    let cname = |i: u64| {
        let h = i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        format!("cold.{:016x}", h ^ (h >> 29))
    };
    // populate (random key order is irrelevant: hobject order is by hash)
    let t0 = Instant::now();
    let (mut next, mut inflight, mut acked) = (0u64, 0usize, Vec::new());
    while next < nobj || inflight > 0 {
        while next < nobj && inflight < 32 {
            let pg = (next % pgs as u64) as u32;
            let o = obj(&cname(next), pg);
            let mut t = OTxn::new();
            t.write(pgc(pg), &o, 0, &env.data[..4096]);
            t.push(TOp::SetAttrs {
                cid: pgc(pg),
                oid: o,
                attrs: vec![
                    (b"_".as_slice().into(), env.data[..250].into()),
                    (b"snapset".as_slice().into(), env.data[250..282].into()),
                ],
            });
            st.queue(&t, next + 1).map_err(|e| format!("queue: {e}"))?;
            next += 1;
            inflight += 1;
        }
        acked.clear();
        st.poll(&mut acked).map_err(|e| format!("poll: {e}"))?;
        inflight -= acked.len();
    }
    st.checkpoint().map_err(|e| e.to_string())?;
    println!(
        "cold: populated {nobj} objects in {:.1} s",
        t0.elapsed().as_secs_f64()
    );
    drop(st);
    let lba = ctrl.geometry().lba_size as u64;
    let mut rng = Rng::new(11);
    let mut fresh = 0u64;
    for &qd in &qds {
        let mut st = mount_cfg(&ctrl, &cn, Sizing::Pages(cache))?;
        let tag = format!(
            "cold4k{}{}:{qd}",
            if newm { "-new" } else { "" },
            if park { "-park" } else { "" }
        );
        let mc0 = store::dbg::MISS_CALLS.load(std::sync::atomic::Ordering::Relaxed);
        let mn0 = store::dbg::MISS_NS.load(std::sync::atomic::Ordering::Relaxed);
        let mt0: Vec<u64> = store::dbg::MISS_TAG
            .iter()
            .map(|x| x.load(std::sync::atomic::Ordering::Relaxed))
            .collect();
        let (res, loads) = drive_cold(
            &mut st, &cn, &mut env, qd, secs, park, newm, nobj, &mut fresh, &mut rng, &cname,
        )?;
        println!(
            "  tree page loads/op = {:.2} (cache {cache} pages/shard)",
            loads as f64 / res.ops.max(1) as f64
        );
        {
            use std::sync::atomic::Ordering::Relaxed;
            let mc = store::dbg::MISS_CALLS.load(Relaxed) - mc0;
            let mn = store::dbg::MISS_NS.load(Relaxed) - mn0;
            let tags: Vec<String> = store::dbg::MISS_TAG
                .iter()
                .enumerate()
                .filter_map(|(i, x)| {
                    let d = x.load(Relaxed) - mt0[i];
                    (d > 0).then(|| format!("{i:#04x}:{d}"))
                })
                .collect();
            println!(
                "  blocking miss waits/op = {:.3} ({:.2} us/op spun) by tag [{}]",
                mc as f64 / res.ops.max(1) as f64,
                mn as f64 / 1000.0 / res.ops.max(1) as f64,
                tags.join(" ")
            );
        }
        report(&tag, res, lba);
        st.checkpoint().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[expect(clippy::too_many_arguments)]
fn drive_cold(
    st: &mut St,
    cn: &Counters,
    env: &mut Env,
    qd: usize,
    secs: f64,
    park: bool,
    newm: bool,
    nobj: u64,
    fresh: &mut u64,
    rng: &mut Rng,
    cname: &dyn Fn(u64) -> String,
) -> Result<(Res, u64), String> {
    use std::collections::VecDeque;
    let pgs = env.pgs;
    let mut gates: Vec<VecDeque<Pend>> = (0..pgs).map(|_| VecDeque::new()).collect();
    let mut gated = 0usize;
    let mut t0v: Vec<u64> = vec![0; qd * 4 + 64];
    let (mut inflight, mut tok, mut done) = (0usize, 0u64, 0u64);
    let mut lat: Vec<u32> = Vec::with_capacity(1 << 20);
    let mut acked: Vec<u64> = Vec::new();
    let (w0, wl0, r0, o0) = (cn.wr.get(), cn.wr_lbas.get(), cn.rd.get(), cn.other.get());
    let loads0: u64 = st.shards.iter().map(|s| s.sh.tree_stats().loads).sum();
    let t0 = Instant::now();
    let limit = (secs * 1e9) as u64;
    let (mut busy, mut woke) = (0u64, false);
    let cap = t0v.len();
    let queue = |st: &mut St, p: Pend, tok: u64, t0v: &mut Vec<u64>| -> Result<(), String> {
        st.queue(&p.t, tok).map_err(|e| format!("queue: {e}"))?;
        t0v[(tok as usize) % cap] = p.t0;
        Ok(())
    };
    loop {
        let now = t0.elapsed().as_nanos() as u64;
        let stop = now >= limit;
        if !stop {
            while inflight < qd {
                let i = if newm {
                    *fresh += 1;
                    nobj + *fresh
                } else {
                    rng.below(nobj)
                };
                let pg = (i % pgs as u64) as u32;
                let o = obj(&cname(i), pg);
                let mut t = OTxn::new();
                t.write(pgc(pg), &o, 0, &env.data[..4096]);
                let seq = &mut env.log_seq[pg as usize];
                *seq += 1;
                let (mut k1, mut k2) = ([0u8; 24], [0u8; 24]);
                log_key(&mut k1, *seq);
                log_key(&mut k2, seq.saturating_sub(300));
                t.push(TOp::SetAttrs {
                    cid: pgc(pg),
                    oid: o.clone(),
                    attrs: vec![
                        (b"_".as_slice().into(), env.data[..250].into()),
                        (b"snapset".as_slice().into(), env.data[250..282].into()),
                    ],
                });
                t.push(TOp::OmapSetKeys {
                    cid: pgc(pg),
                    oid: env.pgm[pg as usize].clone(),
                    pairs: vec![(k1.to_vec().into(), env.data[256..436].into())],
                });
                t.push(TOp::OmapRmKeys {
                    cid: pgc(pg),
                    oid: env.pgm[pg as usize].clone(),
                    keys: vec![k2.to_vec().into()],
                });
                let p = Pend {
                    t,
                    pg,
                    o,
                    t0: t0.elapsed().as_nanos() as u64,
                };
                inflight += 1;
                tok += 1;
                if park {
                    let cold = !st
                        .warm(&pgc(pg), &p.o, 0, 4096)
                        .map_err(|e| format!("warm: {e}"))?;
                    if cold || !gates[pg as usize].is_empty() {
                        gates[pg as usize].push_back(p);
                        gated += 1;
                        continue;
                    }
                }
                let tq = Instant::now();
                queue(st, p, tok, &mut t0v)?;
                busy += tq.elapsed().as_nanos() as u64;
            }
        }
        if gated > 0 && woke {
            woke = false;
            for gate in gates.iter_mut() {
                while let Some(f) = gate.front() {
                    if !st
                        .warm(&pgc(f.pg), &f.o, 0, 4096)
                        .map_err(|e| format!("warm: {e}"))?
                    {
                        break;
                    }
                    let p = gate.pop_front().unwrap();
                    gated -= 1;
                    tok += 1;
                    queue(st, p, tok, &mut t0v)?;
                }
            }
        }
        loop_pause();
        acked.clear();
        let tp = Instant::now();
        st.poll(&mut acked).map_err(|e| format!("poll: {e}"))?;
        busy += tp.elapsed().as_nanos() as u64;
        woke |= st.take_wake();
        if !acked.is_empty() {
            let now = t0.elapsed().as_nanos() as u64;
            for &tk in &acked {
                lat.push(((now - t0v[(tk as usize) % cap]) / 1000) as u32);
                done += 1;
                inflight -= 1;
            }
        }
        if stop && inflight == 0 {
            break;
        }
    }
    let loads: u64 = st
        .shards
        .iter()
        .map(|s| s.sh.tree_stats().loads)
        .sum::<u64>()
        - loads0;
    let secs = t0.elapsed().as_secs_f64();
    Ok((
        Res {
            ops: done,
            secs,
            bytes: done * 4096,
            lat,
            wr: cn.wr.get() - w0,
            wr_lbas: cn.wr_lbas.get() - wl0,
            rd: cn.rd.get() - r0,
            other: cn.other.get() - o0,
            busy_ns: busy,
            queue_ns: 0,
            ..Default::default()
        },
        loads,
    ))
}

/// `--loop-us N`: spin N us per loop iteration, emulating the OSD core loop (NIC poll syscall, other work) between
/// two store polls: shows what the poll cadence costs a lone txn.
static LOOP_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn loop_pause() {
    let ns = LOOP_NS.load(std::sync::atomic::Ordering::Relaxed);
    if ns > 0 {
        let t = Instant::now();
        while (t.elapsed().as_nanos() as u64) < ns {
            std::hint::spin_loop();
        }
    }
}

/// `NV_TRACE` snapshot: (dirty sum, dirty max, freeze pages left, ckpt begins, ckpt ends, dirty-hard refusals, parked).
fn trace_snap(st: &St) -> (u64, u64, u64, u64, u64, u64, u64) {
    let mut r = (0, 0, 0, 0, 0, 0, st.queued_count() as u64);
    for s in &st.shards {
        let g = s.sh.gauges();
        let x = &s.sh.stats;
        r.0 += g.dirty_pages;
        r.1 = r.1.max(g.dirty_pages);
        r.2 += g.freeze_left;
        r.3 += x.ckpt_begins;
        r.4 += x.checkpoints;
        r.5 += x.busy.iter().sum::<u64>();
    }
    r
}

/// Borrowed (non-hole) chunks of shard `s`.
#[cfg(feature = "elastic")]
fn lent_of(st: &St, s: u32) -> usize {
    st.lent_chunks(s).map_or(0, |v| {
        v.iter().filter(|e| e.0 != store::alloc::HOLE).count()
    })
}

/// `--reclaim-prep MiB` (adr 0021 am. 57 perf gate): after the fill, one extra PG on shard 0 grows by `MiB` of 4 MiB
/// objects (past its base: borrowed chunks), then 7 of 8 go. The borrowed chunks are sparse: the modes run while
/// they are evacuated and returned.
#[cfg(feature = "elastic")]
fn reclaim_prep(st: &mut St, env: &Env, mib: u64) -> Result<(), String> {
    let seed = (1000u32..2000)
        .find(|s| st.shard_of(&pgc(*s)) == 0)
        .ok_or("no PG on shard 0")?;
    let c = pgc(seed);
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid: c,
        bits: 0,
        exist_ok: true,
    });
    st.commit(&t).map_err(|e| e.to_string())?;
    let n = mib.div_ceil(4) as u32;
    for i in 0..n {
        let mut t = OTxn::new();
        t.write(c, &obj(&oname(seed, i), seed), 0, &env.data[..OBJ_BYTES]);
        st.commit(&t)
            .map_err(|e| format!("reclaim prep write {i}: {e}"))?;
    }
    let lent = lent_of(st, 0);
    for i in (0..n).filter(|i| i % 8 != 0) {
        let mut t = OTxn::new();
        t.remove(c, &obj(&oname(seed, i), seed));
        st.commit(&t)
            .map_err(|e| format!("reclaim prep remove {i}: {e}"))?;
    }
    st.sync().map_err(|e| e.to_string())?;
    println!(
        "reclaim prep: {n} x 4 MiB on shard 0, lent {lent}, kept {}",
        n.div_ceil(8)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    /// A CPU id the kernel cannot accept (the old mask was a fixed 16 words: `--cpu 1024` indexed past it and
    /// panicked) is an error naming the CPU.
    #[test]
    fn cpu_above_the_host_is_an_error_not_a_panic() {
        assert!(cpu_mask(1024, 1024).is_err());
        assert!(cpu_mask(2000, 64).is_err());
        assert_eq!(
            cpu_mask(2000, 64).unwrap_err(),
            "--cpu 2000: this host has 64 CPUs"
        );
        assert_eq!(cpu_mask(1023, 1024).unwrap(), {
            let mut m = vec![0u64; 16];
            m[15] = 1 << 63;
            m
        });
        // the mask covers the CPU and nothing above it
        assert_eq!(cpu_mask(64, 128).unwrap(), vec![0, 1]);
        assert_eq!(cpu_mask(0, 1).unwrap(), vec![1]);
    }

    /// `--pgs 0` divided by zero in the PG mapping (`i % pgs`).
    #[test]
    fn zero_pgs_is_rejected() {
        assert_eq!(pgs_arg(&s(&[])).unwrap(), 32);
        assert_eq!(pgs_arg(&s(&["--pgs", "4"])).unwrap(), 4);
        assert_eq!(
            pgs_arg(&s(&["--pgs", "0"])).unwrap_err(),
            "--pgs 0: must be 1..=4294967295"
        );
        assert_eq!(
            pgs_arg(&s(&["--pgs", "x"])).unwrap_err(),
            "--pgs: not a number: \"x\""
        );
    }
}
