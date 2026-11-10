// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `mkfs`: generate osd uuid + cephx secret, `osd new` via the mon, write identity + superblock
//! (spec osd-lifecycle.md 1, 1.2).
use crate::{arg, num_opt};
use cephx::keyring::Keyring;
use cephx::{CryptoKey, KeyType, UTime};
use denc::types::Uuid;
use messages::{CompatSet, OsdSuperblock};
use monc::{Config, MonClient, MonEvent, parse_mon_host};
use nvme::any::{AnyCtrl, DevSpec};
#[cfg(feature = "lab")]
use osd::FileMetaStore;
use osd::nvmestore;
use osd::{Identity, MetaStore};
use std::time::Duration;

/// Parse before opening/discarding any native device. Existing-store selection
/// remains persistent; these flags never convert an engine in place.
pub(crate) fn engine_options(a: &[String]) -> Result<Option<&'static str>, String> {
    let legacy = a.iter().any(|x| x == "--omap-lsm");
    let engine = arg(a, "--omap-engine");
    if a.iter().any(|x| x == "--omap-engine") && engine.is_none() {
        return Err("--omap-engine needs btree|lsm|rocksdb|splinterdb".into());
    }
    if legacy && engine.as_deref().is_some_and(|engine| engine != "lsm") {
        return Err("--omap-lsm conflicts with --omap-engine".into());
    }
    let selected = match engine.as_deref() {
        None if legacy => Some("lsm"),
        None => None,
        Some("btree") => Some("btree"),
        Some("lsm") => Some("lsm"),
        Some("rocksdb") => Some("rocksdb"),
        Some("splinterdb") => Some("splinterdb"),
        Some(e) => return Err(format!("unknown OMAP engine {e:?}")),
    };
    if selected == Some("rocksdb") && !cfg!(feature = "rocksdb") {
        return Err("RocksDB requires a build with --features rocksdb".into());
    }
    if selected == Some("splinterdb") {
        if !cfg!(feature = "splinterdb") {
            return Err("SplinterDB requires a build with --features splinterdb".into());
        }
        let capacity = arg(a, "--splinterdb-capacity")
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v >= 128 << 20 && v.is_multiple_of(128 << 10));
        if capacity.is_none() {
            return Err(
                "--splinterdb-capacity requires bytes per shard, >=128MiB and 128KiB aligned"
                    .into(),
            );
        }
        if arg(a, "--splinterdb-dir").is_none() {
            return Err("SplinterDB requires --splinterdb-dir".into());
        }
    }
    // Backing settings can be inherited for a different engine. Only selecting
    // SplinterDB requires its feature; an existing unsupported SDB header is
    // still refused by the persistent-format gate before mount/mutation.
    Ok(selected)
}

#[cfg(feature = "splinterdb")]
pub(crate) fn splinter_config(
    a: &[String],
) -> Result<Option<store::splinter_omap::Config>, String> {
    let Some(root) = arg(a, "--splinterdb-dir") else {
        return Ok(None);
    };
    let capacity = arg(a, "--splinterdb-capacity")
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| "invalid --splinterdb-capacity")
        })
        .transpose()?
        .unwrap_or(0);
    let mut cfg = store::splinter_omap::Config::new(root.into(), capacity);
    cfg.io = arg(a, "--splinterdb-io")
        .as_deref()
        .unwrap_or("buffered")
        .parse()
        .map_err(str::to_owned)?;
    cfg.prefetch_bytes = arg(a, "--splinterdb-prefetch-bytes")
        .as_deref()
        .unwrap_or("1048576")
        .parse()
        .map_err(|_| "invalid --splinterdb-prefetch-bytes")?;
    cfg.scan_readahead_pages = arg(a, "--splinterdb-scan-readahead-pages")
        .as_deref()
        .unwrap_or("4")
        .parse()
        .map_err(|_| "invalid --splinterdb-scan-readahead-pages")?;
    cfg.cache_stats = a.iter().any(|s| s == "--splinterdb-cache-stats");
    // Creation-only image mode: no library log; barriers checkpoint (native WAL only).
    cfg.no_log = a.iter().any(|s| s == "--splinterdb-no-log");
    #[cfg(feature = "lab")]
    let cfg = {
        let mut cfg = cfg;
        cfg.allow_non_nvme = a.iter().any(|v| v == "--splinterdb-lab-filesystem");
        cfg
    };
    Ok(Some(cfg))
}
pub(crate) fn configure_splinter(a: &[String]) -> Result<(), String> {
    #[cfg(feature = "splinterdb")]
    {
        let cfg = splinter_config(a);
        if engine_options(a)? == Some("splinterdb") {
            let shards = store_shards(a)?;
            cfg.as_ref()
                .map_err(Clone::clone)?
                .as_ref()
                .ok_or("SplinterDB requires root")?
                .validate_provision(shards, 64 << 20)
                .map_err(|e| e.to_string())?;
        }
        nvmestore::set_splinterdb_config_result(cfg);
    }
    #[cfg(not(feature = "splinterdb"))]
    let _ = engine_options(a)?;
    Ok(())
}

fn kv(t: &str) -> std::collections::BTreeMap<String, String> {
    t.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

pub fn run(a: &[String]) -> i32 {
    if let Err(e) = requested_id(a) {
        return crate::usage_err(&e);
    }
    match run_inner(a) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("mkfs: {e}");
            crate::devopen::exit_code(&e)
        }
    }
}

/// An explicit identity must never silently become automatic OSD allocation.
pub(crate) fn requested_id(a: &[String]) -> Result<Option<i64>, String> {
    let Some(i) = a.iter().position(|s| s == "--id") else {
        return Ok(None);
    };
    let value = a.get(i + 1).ok_or("--id: missing value")?;
    value
        .parse::<i32>()
        .ok()
        .filter(|id| *id >= 0)
        .map(|id| Some(i64::from(id)))
        .ok_or_else(|| {
            format!(
                "--id: expected an OSD id in 0..={}, got {value:?}",
                i32::MAX
            )
        })
}

/// Fresh osd uuid + cephx secret.
/// `keyed` = the cluster uses cephx; without a bootstrap keyring (auth none) the OSD gets no key.
fn new_secrets(a: &[String], keyed: bool) -> Result<(Uuid, String), String> {
    let uuid = match arg(a, "--osd-uuid") {
        Some(u) => Uuid::parse(&u).map_err(|e| format!("--osd-uuid: {e}"))?,
        None => cephx::challenge::random_uuid_v4().map_err(|e| format!("random uuid: {e:?}"))?,
    };
    if !keyed {
        return Ok((uuid, String::new()));
    }
    let k = CryptoKey::generate(
        KeyType::Aes256Krb5,
        UTime::new(osd::monboot::unix_now() as u32, 0),
    )
    .map_err(|e| format!("key generation: {e:?}"))?;
    Ok((
        uuid,
        k.to_base64().map_err(|e| format!("key encoding: {e:?}"))?,
    ))
}

/// Cores `store_shards = auto` assumes when the OSD's core count is not given (the 8-core-per-OSD budget, adr 0160).
pub(crate) const AUTO_CORES_DEFAULT: usize = 8;

/// `--store-shards auto|N` (alias `--shards`; default auto) resolved with `--cores N` (adr 0160).
pub(crate) fn store_shards(a: &[String]) -> Result<u32, String> {
    let v = arg(a, "--store-shards")
        .or_else(|| arg(a, "--shards"))
        .unwrap_or_else(|| "auto".into());
    let s = store::layout::StoreShards::parse(&v)?;
    let cores = match arg(a, "--cores") {
        Some(c) => c
            .parse::<usize>()
            .ok()
            .filter(|&c| c >= 1)
            .ok_or_else(|| format!("bad --cores {c:?}"))?,
        None => {
            if s == store::layout::StoreShards::Auto {
                eprintln!(
                    "mkfs: store_shards auto without a core count (--cores / flashstore_cores / flashstore_lcores): assuming {AUTO_CORES_DEFAULT}"
                );
            }
            AUTO_CORES_DEFAULT
        }
    };
    Ok(s.resolve(cores))
}

/// Result of opening the device store.
struct Opened {
    meta: Box<dyn MetaStore>,
    desc: String,
    ident: Option<nvme::health::Ident>,
    size: u64,
}

/// Windows probed after the first 8 KiB: btrfs keeps its primary superblock at 64 KiB and the first backup at 256 KiB,
/// with the first 64 KiB of such a device all zero.
const LATE_PROBES: [u64; 2] = [64 << 10, 256 << 10];
/// Bytes read from each late window (one page).
const PROBE_WINDOW: u64 = 4096;
/// `btrfs_super_block.s_magic` inside the superblock.
const BTRFS_MAGIC_OFF: usize = 0x40;

/// Reason the window at absolute byte `base` shows a foreign filesystem, `None` = empty. Pure: the tests feed windows.
fn window_reason(b: &[u8], base: u64, ss: usize) -> Option<String> {
    let has = |off: usize, m: &[u8]| b.len() >= off + m.len() && &b[off..off + m.len()] == m;
    let why = if base == 0 {
        if has(ss.max(512), b"EFI PART") {
            "GPT partition table"
        } else if has(0, b"bluestore block device") {
            "bluestore label"
        } else if has(0, b"XFSB") {
            "XFS filesystem"
        } else if has(0, b"LUKS\xba\xbe") {
            "LUKS header"
        } else if has(1080, &[0x53, 0xEF]) {
            "ext2/3/4 filesystem"
        } else if has(510, &[0x55, 0xAA]) {
            "MBR/boot sector"
        } else {
            return b
                .iter()
                .any(|&x| x != 0)
                .then(|| format!("non-zero data in the first {} bytes", base + b.len() as u64));
        }
    } else if has(BTRFS_MAGIC_OFF, b"_BHRfS_M") {
        "btrfs filesystem"
    } else {
        return b
            .iter()
            .any(|&x| x != 0)
            .then(|| format!("non-zero data at {base} bytes"));
    };
    Some(why.to_owned())
}

/// Read `n` LBAs at `lba` (one queue, bounded by the loud probe timeout).
fn read_window(ctrl: &AnyCtrl, lba: u64, n: usize) -> Result<Vec<u8>, String> {
    use nvme::BlockDev;
    let mut dev = ctrl.open_queue()?;
    let ss = dev.geometry().lba_size as usize;
    let buf = dev.alloc_buf(n * ss);
    dev.submit_read(lba, buf, 1)
        .map_err(|e| format!("probe read: {:?}", e.err))?;
    let mut out = Vec::new();
    let t0 = std::time::Instant::now();
    while out.is_empty() {
        dev.poll(0, &mut out);
        if t0.elapsed() > Duration::from_secs(10) {
            eprintln!("WARNING TIMEOUT device probe read exceeded 10s (used-device check)");
            return Err("probe read timed out".into());
        }
    }
    let c = out.pop().ok_or("probe read")?;
    c.result.map_err(|e| format!("probe read: {e:?}"))?;
    let b = c.buf.as_ref().ok_or("probe read: no buffer")?;
    Ok(nvme::IoBuf::as_slice(b).to_vec())
}

/// Raw read of the first 8 KiB and the btrfs superblock windows (partition table, filesystem / bluestore labels): why
/// the device is NOT empty and not ours, if so. Reads only; never touches a device it cannot attribute, fail closed.
fn looks_used(ctrl: &AnyCtrl) -> Result<Option<String>, String> {
    let ss = ctrl.geometry().lba_size as u64;
    let first = (8192u64 / ss).max(1);
    if let Some(why) = window_reason(&read_window(ctrl, 0, first as usize)?, 0, ss as usize) {
        return Ok(Some(why));
    }
    for base in LATE_PROBES {
        // a window is only probed when the offset is a whole LBA (64 KiB and 256 KiB are multiples of 4 KiB and 512 B)
        if base % ss != 0 {
            continue;
        }
        let n = (PROBE_WINDOW / ss).max(1);
        let b = read_window(ctrl, base / ss, n as usize)?;
        if let Some(why) = window_reason(&b, base, ss as usize) {
            return Ok(Some(why));
        }
    }
    Ok(None)
}

/// Conf key `bluestore_discard_on_mkfs` (Ceph's own name and default true) from an effective option map.
pub(crate) fn conf_discard_on_mkfs(opts: &std::collections::BTreeMap<String, String>) -> bool {
    !opts
        .get("bluestore_discard_on_mkfs")
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "false" | "0" | "no"))
}

/// Deallocate on (re)create unless `--no-discard` or `--conf` says `bluestore_discard_on_mkfs = false`.
fn discard_on_mkfs(a: &[String]) -> Result<bool, String> {
    if a.iter().any(|x| x == "--no-discard") {
        return Ok(false);
    }
    Ok(match arg(a, "--conf") {
        Some(p) => conf_discard_on_mkfs(&osddir::Conf::load(std::path::Path::new(&p))?.for_osd(-1)),
        None => true,
    })
}

/// mkfs probes passthrough DSM (adr 0169 am. 8) and then deallocates the WHOLE namespace (also with `--store-size`: the
/// namespace belongs to the OSD) before the store format writes anything. After a Format NVM it still runs (not known
/// whether the format already deallocated). Returns the DSM probe verdict for the superblock. The probe always runs, also
/// with `--no-discard` / `bluestore_discard_on_mkfs = false`: it only deallocates LBA 0..8, which the store format of this
/// fresh store overwrites anyway, and without a verdict the OSD would run without runtime deallocate for the life of the
/// store. Skipping the whole-device deallocate does not change that.
fn discard_namespace(a: &[String], ctrl: &AnyCtrl) -> Result<Option<bool>, String> {
    let (verdict, discard) = dsm_probe_and_discard_choice(a, || ctrl.probe_dsm_at_mkfs())?;
    if !discard {
        eprintln!("mkfs: whole-device deallocate skipped (--no-discard)");
        return Ok(verdict);
    }
    let mut dev = ctrl.open_queue()?;
    let lba_size = u64::from(nvme::BlockDev::geometry(&dev).lba_size);
    let t0 = std::time::Instant::now();
    let n = nvme::BlockDev::deallocate_all(&mut dev)
        .map_err(|e| format!("{e} (--no-discard skips it)"))?;
    eprintln!(
        "mkfs: deallocated {n} LBAs ({} GiB) in {} ms",
        (n * lba_size) >> 30,
        t0.elapsed().as_millis()
    );
    Ok(verdict)
}

/// The mkfs DSM probe (always runs, see [`discard_namespace`]; an error of the probe is a warning, never fatal) and whether the whole-device deallocate follows.
fn dsm_probe_and_discard_choice(
    a: &[String],
    probe: impl FnOnce() -> Result<Option<bool>, String>,
) -> Result<(Option<bool>, bool), String> {
    // a probe ERROR (e.g. EINVAL on a host whose passthrough rejects the probe buffers) never fails prepare: the verdict
    // stays unknown, so the OSD runs without runtime deallocate (BLKDISCARD at mkfs only), loudly
    let verdict = probe().unwrap_or_else(|e| {
        eprintln!(
            "mkfs: WARNING DSM probe failed ({e}): verdict stored as unknown, runtime deallocate off for this store; \
             re-prepare the OSD to retry"
        );
        None
    });
    if let Some(ok) = verdict {
        eprintln!(
            "mkfs: passthrough DSM probe: {}",
            if ok { "accepted" } else { "rejected" }
        );
    }
    Ok((verdict, discard_on_mkfs(a)?))
}

/// Open (formatting if needed) the NVMe store on `--dev` and return it as the OSD meta store. The pending
/// uuid/secret are persisted inside the store before the mon is contacted (crash after `osd new` must not leave
/// an orphan OSD). Refuse a foreign non-blank device unless `--wipe`.
fn open_dev_store(a: &[String], spec: &str, admit: Admit) -> Result<Opened, String> {
    let requested_engine = engine_options(a)?;
    let engine = requested_engine.unwrap_or("btree");
    configure_splinter(a)?;
    #[cfg(feature = "rocksdb")]
    let rocks = if engine == "rocksdb" {
        let root = arg(a, "--rocksdb-dir")
            .ok_or("RocksDB requires --rocksdb-dir on an admitted filesystem")?;
        let cfg = store::rocks_omap::Config::new(root.clone().into());
        cfg.admit().map_err(|e| e.to_string())?;
        osd::nvmestore::set_store_options(&[("flashstore_rocksdb_dir".into(), root)])?;
        Some(cfg)
    } else {
        None
    };
    let spec = DevSpec::parse(spec)?;
    if spec.is_dev_only() {
        eprintln!("mkfs: NOTE file: devices are DEV/LAB ONLY (production = spdk:PCI)");
    }
    let mut ctrl = crate::devopen::open(&spec, true, 0)?;
    let wipe = a.iter().any(|x| x == "--wipe"); // re-create the store even if one exists (DESTROYS it)
    let g = ctrl.geometry();
    eprintln!(
        "mkfs: device lba {} B x {} ({} B), awupf {} lba, vwc {}, max_xfer {} lba",
        g.lba_size,
        g.lba_count,
        g.capacity_bytes(),
        g.awupf_lbas,
        g.vwc,
        g.max_xfer_lbas
    );
    // one probe, fail closed (an error is never "not formatted": that would discard an existing store)
    let fresh = wipe || !nvmestore::is_formatted(&ctrl)?;
    if !fresh {
        let mut d = ctrl.open_queue()?;
        let (sb, _) = store::layout::read_super(&mut d, &mut store::dev::MonoClock::default())
            .map_err(|e| e.to_string())?;
        if let Some(wanted) = requested_engine {
            let actual = if sb.features & store::layout::FEAT_OMAP_ROCKSDB != 0 {
                "rocksdb"
            } else if sb.features & store::layout::FEAT_OMAP_SPLINTERDB != 0 {
                "splinterdb"
            } else if sb.features & store::layout::FEAT_OMAP_LSM != 0 {
                "lsm"
            } else {
                "btree"
            };
            if actual != wanted {
                return Err(format!(
                    "existing OMAP engine is {actual}, not {wanted}; no implicit conversion"
                ));
            }
        }
        #[cfg(feature = "splinterdb")]
        if sb.features & store::layout::FEAT_OMAP_SPLINTERDB != 0 {
            let cfg =
                splinter_config(a)?.ok_or("existing SplinterDB store requires --splinterdb-dir")?;
            for s in 0..sb.shards {
                store::splinter_omap::validate_binding(&cfg, &sb, s).map_err(|e| e.to_string())?;
            }
        }
    }
    if fresh
        && !wipe
        && let Some(why) = looks_used(&ctrl)?
    {
        return Err(format!(
            "refused: device is not empty ({why}); --wipe destroys it"
        ));
    }
    // the identity a fresh store will get; the target OSD dir is admitted before the device is touched
    let fresh_secrets = if fresh {
        let (uuid, secret) = new_secrets(a, true)?;
        admit_plan(a, admit, &uuid, &secret)?;
        Some((uuid, secret))
    } else {
        None
    };
    // passthrough DSM verdict of the probe at this mkfs (adr 0169 am. 8), stored in the superblock
    #[cfg(feature = "splinterdb")]
    if engine == "splinterdb"
        && let Some((uuid, _)) = &fresh_secrets
    {
        let cfg = splinter_config(a)?.expect("required root validated");
        if cfg
            .directory(&uuid.0)
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            return Err("SplinterDB identity directory already exists; refusing before native discard/format".into());
        }
    }
    if fresh {
        // ADR 0008: PLP only (no volatile write cache); lab override is explicit
        if g.vwc && !a.iter().any(|x| x == "--allow-vwc") {
            return Err(
                "refused: device has a volatile write cache (no PLP, adr 0008); --allow-vwc = lab only"
                    .into(),
            );
        }
        // the store wants 4096 B LBAs without metadata: Format NVM (destroys the namespace) only on request
        if let Some(cur) = ctrl.needs_4k_format() {
            if !a.iter().any(|x| x == "--format-lba4k") {
                return Err(format!(
                    "refused: namespace format is {cur}, store needs 4096+0: pass --format-lba4k to run NVMe Format NVM (DESTROYS all data)"
                ));
            }
            let t0 = std::time::Instant::now();
            let (c2, old) = ctrl.ensure_4k()?;
            ctrl = c2;
            eprintln!(
                "mkfs: Format NVM done in {} ms (was {}); now lba {} B",
                t0.elapsed().as_millis(),
                old.unwrap_or_default(),
                ctrl.geometry().lba_size
            );
        }
    }
    // lab: `--store-size BYTES` formats only the first BYTES of the device (short fill tests on a big drive)
    let max_bytes = num_opt(a, "--store-size")?.unwrap_or(u64::MAX);
    let bytes = ctrl.geometry().capacity_bytes().min(max_bytes);
    let mut pending = None;
    if let Some((uuid, secret)) = fresh_secrets {
        let mut p = nvmestore::mkfs_params_for(bytes, store_shards(a)?);
        eprintln!(
            "mkfs: {} store shards, WAL ring {} MiB each",
            p.shards,
            (p.wal_blocks * store::BLK as u64) >> 20
        );
        // `--wal-mib N`: WAL ring MiB per shard instead of the formula (lab A/B of adr 0160 am. 4)
        if let Some(m) = arg(a, "--wal-mib") {
            let m: u64 = m.parse().map_err(|_| format!("bad --wal-mib {m:?}"))?;
            p.wal_blocks = crate::mib("--wal-mib", m)? / store::BLK as u64;
        }
        // elastic shard capacity (adr 0021 am. 53): `--base-pct N` (conf `flashstore_store_base_pct`) makes a chunked store
        // (default on production devices of an elastic build, `store::layout::PROD_BASE_PCT`); `--base-pct 100` = plain static layout
        if let Some(b) = arg(a, "--base-pct") {
            if !cfg!(feature = "elastic") {
                return Err("--base-pct needs a build with the elastic feature".into());
            }
            let v: u32 = b
                .parse()
                .map_err(|_| format!("bad --base-pct {b:?} (10..=90, 100 = plain)"))?;
            p.chunked = v != 100;
            if v != 100 {
                p.base_pct = v;
            }
        }
        // `--omap-lsm` (conf `flashstore_omap_lsm`): omap keys in the LSM engine (adr 0610, default off until qualified)
        p.omap_lsm = engine == "lsm";
        p.omap_rocksdb = engine == "rocksdb";
        p.omap_splinterdb = engine == "splinterdb";
        p.max_bytes = max_bytes;
        p.osd_fsid = uuid.0;
        p.osd_id = -1;
        p.allow_volatile_cache = a.iter().any(|x| x == "--allow-vwc");
        p.mkfs_time = osd::monboot::unix_now();
        #[cfg(feature = "rocksdb")]
        if let Some(cfg) = &rocks {
            let (sb, _) =
                store::layout::plan(bytes / store::BLK as u64, &p).map_err(|e| e.to_string())?;
            store::rocks_omap::create(cfg, &sb, 16 << 20).map_err(|e| e.to_string())?;
        }
        p.dsm_verdict = discard_namespace(a, &ctrl)?;
        nvmestore::mkfs_dev(&ctrl, &p)?;
        pending = Some((uuid, secret));
    }
    let (st, stats) = nvmestore::mount_dev(&ctrl)?;
    let replayed: u64 = stats.iter().map(|s| s.txns).sum();
    if replayed > 0 {
        eprintln!("mkfs: replayed {replayed} records on mount");
    }
    let parts = nvmestore::open_nvme(st).map_err(|e| e.to_string())?;
    let mut meta: Box<dyn MetaStore> = Box::new(parts.meta);
    if let Some((uuid, secret)) = pending {
        meta.set_meta("mkfs-pending", &format!("uuid={uuid}\nkey={secret}\n"))
            .map_err(|e| e.to_string())?;
    }
    Ok(Opened {
        meta,
        desc: format!("{spec:?}"),
        ident: ctrl.health_probe().map(|p| p.ident()),
        size: bytes,
    })
}

/// What `prepare` knows about the OSD it is about to create, for [`Admit`].
pub struct Plan<'a> {
    /// `None` = the mon will allocate the id: only id-independent targets can be checked.
    pub id: Option<i64>,
    pub osd_uuid: &'a str,
    /// Cluster fsid when known (configured, or answered by the mon).
    pub cluster_fsid: Option<&'a str>,
    /// Cephx secret; empty for an auth-none cluster.
    pub key: &'a str,
}

/// Admission of the target (the OSD dir) by the caller: called with everything known at that moment, before the
/// device is formatted, before the mon is contacted, and once more with the mon-allocated id (a refusal there
/// rolls the registration back). `Err` is a refusal message.
pub type Admit<'a> = &'a dyn Fn(&Plan) -> Result<(), String>;

/// No target to admit (`mkfs`).
pub const NO_ADMIT: Admit = &|_| Ok(());

fn admit_plan(a: &[String], admit: Admit, uuid: &Uuid, secret: &str) -> Result<(), String> {
    let conf = crate::devopen::optional_conf(a, &osddir::cluster_from_args(a)?)?;
    let want_id = requested_id(a)?;
    let fsid = conf.for_osd(want_id.unwrap_or(-1)).get("fsid").cloned();
    admit(&Plan {
        id: want_id,
        osd_uuid: &uuid.to_string(),
        cluster_fsid: fsid.as_deref(),
        key: secret,
    })
    .map_err(|e| format!("refused: {e}"))
}

/// What `provision` produced (or found).
pub struct Prov {
    pub id: i64,
    pub osd_uuid: String,
    pub cluster_fsid: String,
    pub key: String,
    pub class: String,
    pub desc: String,
    pub ident: Option<nvme::health::Ident>,
    pub size: u64,
    /// The store already carried an identity (nothing was changed).
    pub already: bool,
}

fn run_inner(a: &[String]) -> Result<(), String> {
    let p = provision(a, NO_ADMIT)?;
    if p.already {
        println!(
            "osd.{} already provisioned in {} (osd_fsid {})",
            p.id, p.desc, p.osd_uuid
        );
    } else {
        println!(
            "provisioned osd.{} (osd_fsid {}, cluster {}, class {}) in {}",
            p.id, p.osd_uuid, p.cluster_fsid, p.class, p.desc
        );
    }
    Ok(())
}

/// Resolve the requested cluster before any device creation or format.
fn configured_fsid(conf: &osddir::Conf, id: Option<i64>) -> Result<Uuid, String> {
    match conf.for_osd(id.unwrap_or(-1)).get("fsid") {
        Some(fsid) => Uuid::parse(fsid).map_err(|e| format!("configured fsid: {e}")),
        None => Ok(Uuid::default()),
    }
}

/// Reusing a device must satisfy every identity the caller actually supplied.
fn validate_existing_identity(
    a: &[String],
    conf: &osddir::Conf,
    id: &Identity,
) -> Result<(), String> {
    if let Some(want) = requested_id(a)?
        && want != i64::from(id.whoami)
    {
        return Err(format!(
            "refused: device belongs to osd.{}, requested osd.{want}: drop --id / pass --id {} to reuse it, or --wipe to destroy it",
            id.whoami, id.whoami
        ));
    }
    if let Some(want) = arg(a, "--osd-uuid") {
        let want = Uuid::parse(&want).map_err(|e| format!("--osd-uuid: {e}"))?;
        if want != id.osd_fsid {
            return Err(format!(
                "refused: device holds OSD UUID {}, not --osd-uuid {want}: wrong device, or --wipe to destroy it",
                id.osd_fsid
            ));
        }
    }
    if let Some(want) = conf.for_osd(i64::from(id.whoami)).get("fsid") {
        let want = Uuid::parse(want).map_err(|e| format!("configured fsid: {e}"))?;
        if want != id.cluster_fsid {
            return Err(format!(
                "refused: device belongs to cluster {}, configured fsid is {want}: wrong device or --conf, or --wipe to destroy it",
                id.cluster_fsid
            ));
        }
    }
    Ok(())
}

/// The on-disk identity must still be registered in the mon with the same uuid. After `ceph osd destroy`,
/// `ceph osd purge` or a re-create with a fresh uuid the mon no longer knows it, and an OSD booted from the device
/// would exit (`identity_gone`): reusing the identity must be refused, not reported as success. Mirrors the
/// OSD's own boot check. `Err` = refuse (precondition failure, prepare exit 3).
fn identity_still_in_mon(map: &osdmap::OsdMap, id: &Identity) -> Result<(), String> {
    let me = id.whoami;
    if !map.exists(me) {
        return Err(format!(
            "refused: device holds osd.{me}'s old store, but the mon has no osd.{me} (purged): re-run with --wipe to prepare it fresh"
        ));
    }
    // `ceph osd destroy` keeps the id and its uuid but removes the OSD's key: the old store cannot authenticate
    if map.raw_state(me) & osdmap::consts::osd_state::DESTROYED != 0 {
        return Err(format!(
            "refused: device holds osd.{me}'s old store, but the mon has osd.{me} destroyed: re-run with --wipe to prepare it fresh"
        ));
    }
    if let Some(u) = map.osd_uuid.get(me as usize)
        && *u != Uuid::default()
        && *u != id.osd_fsid
    {
        return Err(format!(
            "refused: device holds osd.{me}'s old store, but the mon has osd.{me} re-created with uuid {u} (device uuid {}): re-run with --wipe to prepare it fresh",
            id.osd_fsid
        ));
    }
    Ok(())
}

/// Fetch the mon's OSD map and check the reused on-disk identity against it (the local constraints of
/// [`validate_existing_identity`] do not see that the mon destroyed or re-created the OSD).
fn verify_identity_in_mon(mc: &mut MonClient, id: &Identity) -> Result<(), String> {
    mc.subscribe("osdmap", 0, 0);
    let mut map: Option<std::sync::Arc<osdmap::OsdMap>> = None;
    let finished = osd::monboot::run_mon(mc, Duration::from_secs(60), |_, ev| {
        if let MonEvent::OsdMap { map: m, .. } = ev {
            map = Some(m);
            true
        } else {
            false
        }
    });
    if !finished {
        eprintln!(
            "WARNING TIMEOUT osd map fetch exceeded 60s (prepare reuse check of osd.{})",
            id.whoami
        );
        return Err("timed out fetching the mon's osd map".into());
    }
    let map = map.ok_or("no osd map from the mon")?;
    identity_still_in_mon(&map, id)
}

/// The mon session (re)registration and the reuse verification run on: the bootstrap-osd key (an absent
/// keyring file = an auth-none cluster: method NONE, the OSD gets no key) and the mon host.
fn mon_session(
    a: &[String],
    conf: &osddir::Conf,
    want_id: Option<i64>,
    cluster_fsid: Uuid,
) -> Result<(MonClient, bool), String> {
    let entity = arg(a, "--entity").unwrap_or_else(|| "client.bootstrap-osd".into());
    let keyring =
        arg(a, "--keyring").unwrap_or_else(|| "/etc/ceph/ceph.client.bootstrap-osd.keyring".into());
    // no bootstrap keyring file = an auth-none cluster: the mon session runs method NONE and the OSD gets no key
    let bkey = match std::fs::read_to_string(&keyring) {
        Ok(kr_text) => {
            let kr = Keyring::parse(&kr_text).map_err(|e| format!("keyring parse: {e:?}"))?;
            Some(
                kr.get(&entity)
                    .and_then(|e| e.key.clone())
                    .ok_or_else(|| format!("no key for {entity} in {keyring}"))?,
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("keyring {keyring}: {e}")),
    };
    // `--conf FILE` (default /etc/ceph/ceph.conf), [global] < [osd] < [osd.N], any key spelling
    let mon_host = arg(a, "--mon-host")
        .or_else(|| conf.mon_host(want_id))
        .ok_or("--mon-host required")?;
    let keyed = bkey.is_some();
    let wall = osd::monboot::unix_now();
    let mut cfg = Config::new(&entity, bkey);
    // classic client default `auth_client_required = cephx, none`: without a key only NONE remains
    cfg.methods = vec![cephx::modes::AUTH_CEPHX, cephx::modes::AUTH_NONE];
    cfg.fsid = cluster_fsid;
    cfg.mon_host = parse_mon_host(&mon_host).map_err(|e| format!("mon_host: {e}"))?;
    cfg.wall_origin = Duration::from_secs(wall);
    cfg.seed = wall ^ u64::from(std::process::id()) << 20;
    cfg.hostname = osd::sysinfo::short_hostname();
    Ok((MonClient::new(cfg), keyed))
}

/// Format (if needed) the device / dev dir, `osd new` via the mon, persist identity + superblock. Idempotent.
/// Errors starting with `refused:` are precondition failures (prepare exit 3).
pub fn provision(a: &[String], admit: Admit) -> Result<Prov, String> {
    let engine = engine_options(a)?;
    if arg(a, "--dev").is_none() && engine == Some("splinterdb") {
        return Err(
            "SplinterDB requires a native --dev store, not the lab --data metadata backend".into(),
        );
    }
    let want_id = requested_id(a)?;
    let conf = crate::devopen::optional_conf(a, &osddir::cluster_from_args(a)?)?;
    let cluster_fsid = configured_fsid(&conf, want_id)?;
    type Opened4 = (Box<dyn MetaStore>, String, Option<nvme::health::Ident>, u64);
    let (mut store, data, ident0, size): Opened4 = if let Some(spec) = arg(a, "--dev") {
        let o = open_dev_store(a, &spec, admit)?;
        (o.meta, o.desc, o.ident, o.size)
    } else {
        #[cfg(feature = "lab")]
        {
            let data = arg(a, "--data").ok_or("--dev SPEC or --data DIR required")?;
            let size = crate::num(a, "--size", FileMetaStore::DEFAULT_SIZE)?;
            (
                Box::new(FileMetaStore::open(&data, size).map_err(|e| e.to_string())?),
                data,
                None,
                size,
            )
        }
        #[cfg(not(feature = "lab"))]
        return Err("--dev SPEC required (--data is lab only)".into());
    };
    if let Some(id) = store.load_identity().map_err(|e| e.to_string())? {
        validate_existing_identity(a, &conf, &id)?;
        // the local constraints above do not see that the mon destroyed or re-created the OSD: verify the
        // on-disk identity against the mon before reusing it (never silently reuse a stale identity)
        let (mut mc, _) = mon_session(a, &conf, want_id, cluster_fsid)?;
        verify_identity_in_mon(&mut mc, &id)?;
        admit(&Plan {
            id: Some(i64::from(id.whoami)),
            osd_uuid: &id.osd_fsid.to_string(),
            cluster_fsid: Some(&id.cluster_fsid.to_string()),
            key: &id.key,
        })
        .map_err(|e| format!("refused: {e}"))?;
        return Ok(Prov {
            id: i64::from(id.whoami),
            osd_uuid: id.osd_fsid.to_string(),
            cluster_fsid: id.cluster_fsid.to_string(),
            key: id.key,
            class: id.crush_device_class,
            desc: data,
            ident: ident0,
            size,
            already: true,
        });
    }
    let (mut mc, keyed) = mon_session(a, &conf, want_id, cluster_fsid)?;
    let class = arg(a, "--crush-device-class").unwrap_or_else(|| "nvme".into());

    // A crash after `osd new` must not leave an orphan: persist uuid + secret first and reuse them.
    let (uuid, secret) = match store.get_meta("mkfs-pending").map(|t| kv(&t)) {
        Some(m) if m.contains_key("uuid") && m.contains_key("key") => (
            Uuid::parse(&m["uuid"]).map_err(|e| e.to_string())?,
            m["key"].clone(),
        ),
        _ => {
            let (uuid, secret) = new_secrets(a, keyed)?;
            store
                .set_meta("mkfs-pending", &format!("uuid={uuid}\nkey={secret}\n"))
                .map_err(|e| e.to_string())?;
            (uuid, secret)
        }
    };

    // keyless cluster: a key the device-level mkfs pre-generated is dropped
    let secret = if keyed { secret } else { String::new() };
    // a resumed or fresh registration: the target is admitted again with the (possibly pending) identity
    admit_plan(a, admit, &uuid, &secret)?;
    let mut cmd = format!(r#"{{"prefix":"osd new","uuid":"{uuid}""#);
    if let Some(id) = want_id {
        cmd.push_str(&format!(r#","id":{id}"#));
    }
    cmd.push('}');
    let mut secrets = serde_json::json!({"crush_device_class": class});
    if !secret.is_empty() {
        secrets["cephx_secret"] = secret.clone().into();
    }
    let mut tid = None;
    let mut purge_tid = None;
    let mut refusal: Option<String> = None;
    let mut purge_r: Option<(i32, String)> = None;
    let mut result: Option<Result<i64, String>> = None;
    let finished = osd::monboot::run_mon(&mut mc, Duration::from_secs(60), |mc, ev| {
        match ev {
            MonEvent::Authenticated { .. } if tid.is_none() => {
                tid = Some(mc.send_command(&cmd, secrets.to_string().into_bytes()));
            }
            MonEvent::CommandReply {
                tid: t,
                r,
                rs,
                data,
            } if Some(t) == tid => {
                let txt = String::from_utf8_lossy(&data).trim().to_owned();
                result = Some(if r == 0 {
                    txt.parse::<i64>()
                        .or_else(|_| {
                            serde_json::from_str::<serde_json::Value>(&txt)
                                .ok()
                                .and_then(|v| v["osdid"].as_i64())
                                .ok_or(())
                        })
                        .map_err(|()| format!("osd new: unparsable reply {txt:?}"))
                } else {
                    Err(format!("osd new failed: r={r} {rs}"))
                });
                // The id is known now: admit the target dir. A refusal withdraws the registration (`osd purge-new`
                // is what a bootstrap-osd key may do) before any identity is committed to the device.
                if let Some(Ok(id)) = result {
                    let fsid = mc.fsid().to_string();
                    let known = (mc.fsid() != Uuid::default()).then_some(fsid.as_str());
                    if let Err(why) = admit(&Plan {
                        id: Some(id),
                        osd_uuid: &uuid.to_string(),
                        cluster_fsid: known,
                        key: &secret,
                    }) {
                        refusal = Some(why);
                        purge_tid = Some(mc.send_command(
                            format!(r#"{{"prefix":"osd purge-new","id":"osd.{id}","yes_i_really_mean_it":true}}"#)
                                .as_str(),
                            Vec::new(),
                        ));
                        return false;
                    }
                }
                return true;
            }
            MonEvent::CommandReply { tid: t, r, rs, .. } if Some(t) == purge_tid => {
                purge_r = Some((r, rs));
                return true;
            }
            MonEvent::AuthFailed(w) => eprintln!("auth failed: {w}"),
            _ => {}
        }
        false
    });
    if let (Some(why), Some(Ok(id))) = (&refusal, &result) {
        return Err(format!(
            "refused: {why}; {}",
            rollback_note(*id, purge_r.as_ref())
        ));
    }
    if !finished {
        return Err("timed out talking to the mon".into());
    }
    let id = result.ok_or("no reply")??;
    let fsid = mc.fsid();
    if fsid == Uuid::default() {
        return Err("cluster fsid unknown".into());
    }
    let wall = osd::monboot::unix_now();
    let ident = Identity {
        whoami: id as i32,
        cluster_fsid: fsid,
        osd_fsid: uuid,
        key: secret,
        crush_device_class: class,
        created_at: chrono_now(wall),
        ceph_version_when_created: osd::version::ceph_version_pretty(),
    };
    commit_osd(store.as_mut(), &ident)?;
    Ok(Prov {
        id,
        osd_uuid: uuid.to_string(),
        cluster_fsid: fsid.to_string(),
        key: ident.key.clone(),
        class: ident.crush_device_class.clone(),
        desc: data,
        ident: ident0,
        size,
        already: false,
    })
}

/// What happened to the mon registration of a refused `prepare` (`purge_r` = reply of `osd purge-new`, `None` =
/// none arrived). The device keeps only the resumable `mkfs-pending` record (no identity committed).
fn rollback_note(id: i64, purge_r: Option<&(i32, String)>) -> String {
    match purge_r {
        Some((0, _)) => format!("the registration of osd.{id} was withdrawn (osd purge-new)"),
        _ => format!(
            "the registration of osd.{id} is still in the mon: run `ceph osd purge-new osd.{id} --yes-i-really-mean-it` (or `ceph osd purge osd.{id} --yes-i-really-mean-it`)"
        ),
    }
}

/// Persist the initial superblock, then the identity. The identity marks a complete store (`provision` returns
/// `already` and activate passes on it), so it goes last: an error or crash in between leaves no identity and a
/// re-run redoes both (`osd new` with the persisted `mkfs-pending` uuid is idempotent).
fn commit_osd(store: &mut dyn MetaStore, ident: &Identity) -> Result<(), String> {
    let sb = OsdSuperblock {
        cluster_fsid: ident.cluster_fsid,
        whoami: ident.whoami,
        osd_fsid: ident.osd_fsid,
        compat_features: CompatSet::osd_initial(),
        ..Default::default()
    };
    store.store_superblock(&sb).map_err(|e| e.to_string())?;
    store.store_identity(ident).map_err(|e| e.to_string())
}

/// RFC 3339 UTC like classic `created_at` (second resolution).
fn chrono_now(unix: u64) -> String {
    let (y, m, d, h, mi, s) = osddir::civil_from_secs(unix);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.000000Z")
}

#[cfg(all(test, feature = "lab"))]
mod tests {
    use super::*;

    /// A refused `prepare` states whether the mon registration was withdrawn; if not, the exact command to do it.
    #[test]
    fn refusal_reports_the_registration_rollback() {
        assert!(rollback_note(5, Some(&(0, String::new()))).contains("withdrawn"));
        for r in [None, Some(&(-1, "EPERM".to_string()))] {
            let n = rollback_note(5, r);
            assert!(
                n.contains("ceph osd purge-new osd.5 --yes-i-really-mean-it"),
                "{n}"
            );
        }
    }

    /// Records the commit order; `fail_identity` makes the identity write fail (crash stand-in).
    #[derive(Default)]
    struct Rec {
        ident: Option<Identity>,
        sb: Option<OsdSuperblock>,
        fail_identity: bool,
    }
    impl MetaStore for Rec {
        fn load_identity(&self) -> osd::meta::Result<Option<Identity>> {
            Ok(self.ident.clone())
        }
        fn store_identity(&mut self, id: &Identity) -> osd::meta::Result<()> {
            if self.fail_identity {
                return Err(osd::meta::MetaError("io error".into()));
            }
            self.ident = Some(id.clone());
            Ok(())
        }
        fn load_superblock(&self) -> osd::meta::Result<Option<OsdSuperblock>> {
            Ok(self.sb.clone())
        }
        fn store_superblock(&mut self, sb: &OsdSuperblock) -> osd::meta::Result<()> {
            self.sb = Some(sb.clone());
            Ok(())
        }
        fn commit_maps(
            &mut self,
            _: &[(u32, osd::MapKind, Vec<u8>)],
            _: &OsdSuperblock,
        ) -> osd::meta::Result<()> {
            Ok(())
        }
        fn get_map(&self, _: u32, _: osd::MapKind) -> osd::meta::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn map_epochs(&self, _: u32) -> osd::meta::Result<Vec<u32>> {
            Ok(Vec::new())
        }
        fn statfs(&self) -> messages::StoreStatfs {
            messages::StoreStatfs::default()
        }
        fn get_meta(&self, _: &str) -> Option<String> {
            None
        }
        fn set_meta(&mut self, _: &str, _: &str) -> osd::meta::Result<()> {
            Ok(())
        }
    }

    fn ident() -> Identity {
        Identity {
            whoami: 3,
            cluster_fsid: Uuid([1; 16]),
            osd_fsid: Uuid([2; 16]),
            key: "k".into(),
            crush_device_class: "nvme".into(),
            created_at: String::new(),
            ceph_version_when_created: String::new(),
        }
    }

    /// T7: a failed identity write leaves no identity (re-run redoes the commit, never "already prepared" without a
    /// superblock); a complete commit has both.
    #[test]
    fn identity_is_written_last() {
        let mut r = Rec {
            fail_identity: true,
            ..Rec::default()
        };
        assert!(commit_osd(&mut r, &ident()).is_err());
        assert!(r.ident.is_none() && r.sb.is_some());
        let mut r = Rec::default();
        commit_osd(&mut r, &ident()).unwrap();
        let sb = r.sb.unwrap();
        assert_eq!((sb.whoami, sb.osd_fsid), (3, Uuid([2; 16])));
        assert!(r.ident.is_some());
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn other_engine_selection_ignores_dormant_splinter_backing_options() {
        for engine in ["btree", "lsm", "rocksdb"] {
            if engine == "rocksdb" && !cfg!(feature = "rocksdb") {
                continue;
            }
            let a = args(&[
                "--omap-engine",
                engine,
                "--splinterdb-dir",
                "/unused/foreign/root",
                "--splinterdb-capacity",
                "invalid",
                "--splinterdb-io",
                "invalid",
            ]);
            assert_eq!(engine_options(&a).unwrap(), Some(engine));
        }
        let inherited = args(&[
            "--splinterdb-dir",
            "/unused/foreign/root",
            "--splinterdb-io",
            "invalid",
        ]);
        assert_eq!(engine_options(&inherited).unwrap(), None);
        #[cfg(not(feature = "splinterdb"))]
        assert!(
            engine_options(&args(&["--omap-engine", "splinterdb"]))
                .unwrap_err()
                .contains("build with --features splinterdb")
        );
    }

    #[cfg(feature = "splinterdb")]
    #[test]
    fn parsing_unused_splinter_backing_never_admits_a_filesystem() {
        // A relative root is always unadmitted, independently of host filesystems.
        let a = args(&["--splinterdb-dir", "relative-unused-root"]);
        let cfg = splinter_config(&a).unwrap().unwrap();
        assert_eq!(cfg.root, std::path::PathBuf::from("relative-unused-root"));
        assert!(cfg.validate_provision(1, 64 << 20).is_err());
        let mut invalid = a;
        invalid.extend(args(&["--splinterdb-io", "invalid"]));
        assert!(
            splinter_config(&invalid).is_err(),
            "parse errors remain available for selected SDB"
        );
    }

    #[test]
    fn conf_key_defaults_true_and_honours_false() {
        let c = |t: &str| conf_discard_on_mkfs(&osddir::Conf::parse(t).for_osd(-1));
        assert!(c(""));
        assert!(c("[global]\nbluestore_discard_on_mkfs = true\n"));
        assert!(!c("[global]\nbluestore_discard_on_mkfs = false\n"));
        assert!(!c("[osd]\nbluestore discard on mkfs = false\n"));
    }

    #[test]
    fn no_discard_flag_and_conf_skip() {
        assert_eq!(discard_on_mkfs(&args(&[])), Ok(true));
        assert_eq!(discard_on_mkfs(&args(&["--no-discard"])), Ok(false));
        let p = std::env::temp_dir().join(format!("mkfs-discard-conf-{}", std::process::id()));
        std::fs::write(&p, "[global]\nbluestore_discard_on_mkfs = false\n").unwrap();
        let conf = p.to_str().unwrap();
        assert_eq!(discard_on_mkfs(&args(&["--conf", conf])), Ok(false));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn no_discard_still_probes_dsm_and_keeps_the_verdict() {
        for (verdict, a, discard) in [
            (Some(true), &["--no-discard"][..], false),
            (Some(false), &["--no-discard"][..], false),
            (None, &["--no-discard"][..], false),
            (Some(true), &[][..], true),
        ] {
            let mut probed = 0;
            let got = dsm_probe_and_discard_choice(&args(a), || {
                probed += 1;
                Ok(verdict)
            });
            assert_eq!(got, Ok((verdict, discard)), "{a:?}");
            assert_eq!(probed, 1, "the probe runs once, also without discard");
        }
        // a probe error is not fatal: unknown verdict, the discard choice still follows the flags
        for (a, discard) in [(&["--no-discard"][..], false), (&[][..], true)] {
            assert_eq!(
                dsm_probe_and_discard_choice(&args(a), || Err("EINVAL".into())),
                Ok((None, discard))
            );
        }
    }

    #[test]
    fn direct_mkfs_refuses_foreign_data_without_prepare_flag() {
        use std::io::{Seek, SeekFrom, Write};
        let p = std::env::temp_dir().join(format!("mkfs-direct-used-{}", std::process::id()));
        let f = std::fs::File::create(&p).unwrap();
        f.set_len(8 << 20).unwrap();
        drop(f);
        let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(b"XFSBvaluable filesystem").unwrap();
        f.sync_all().unwrap();
        drop(f);
        let before = std::fs::read(&p).unwrap();
        let spec = format!("file:{}", p.display());
        let e = open_dev_store(&args(&["--dev", &spec]), &spec, NO_ADMIT)
            .err()
            .expect("foreign device accepted");
        assert!(e.starts_with("refused: device is not empty"), "{e}");
        assert_eq!(std::fs::read(&p).unwrap(), before);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn configured_cluster_is_resolved_before_device_creation() {
        let root = std::env::temp_dir().join(format!("mkfs-cluster-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let conf = root.join("ceph.conf");
        let device = root.join("must-not-exist.img");
        let spec = format!("file:{},size=8M", device.display());
        std::fs::write(&conf, "[global]\nfsid = invalid\n").unwrap();
        let e = provision(
            &args(&["--dev", &spec, "--conf", conf.to_str().unwrap()]),
            NO_ADMIT,
        )
        .err()
        .expect("bad fsid accepted");
        assert!(e.starts_with("configured fsid:"), "{e}");
        assert!(!device.exists());
        // conf precedence [global] < [osd.N] (Ceph option `fsid` = cluster fsid in any section)
        let (global, per_osd) = (Uuid([5; 16]), Uuid([6; 16]));
        let conf = osddir::Conf::parse(&format!(
            "[global]\nfsid = {global}\n[osd.3]\nfsid = {per_osd}\n"
        ));
        assert_eq!(configured_fsid(&conf, None).unwrap(), global);
        assert_eq!(configured_fsid(&conf, Some(3)).unwrap(), per_osd);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reused_identity_must_match_explicit_request() {
        let id = ident(); // whoami 3, osd_fsid Uuid([2; 16]), cluster_fsid Uuid([1; 16])
        let empty = osddir::Conf::parse("");
        // no explicit request: the stored identity passes the local check
        assert_eq!(validate_existing_identity(&args(&[]), &empty, &id), Ok(()));
        // an explicit request that contradicts the stored identity is refused (before the mon is contacted)
        for a in [
            args(&["--id", "4"]),
            args(&["--osd-uuid", &Uuid([3; 16]).to_string()]),
        ] {
            let e =
                validate_existing_identity(&a, &empty, &id).expect_err("wrong identity accepted");
            assert!(e.starts_with("refused:"), "{e}");
        }
        // a configured cluster fsid that contradicts the stored identity is refused
        let conf = osddir::Conf::parse(&format!("[global]\nfsid = {}\n", Uuid([3; 16])));
        let e =
            validate_existing_identity(&args(&[]), &conf, &id).expect_err("wrong cluster accepted");
        assert!(e.starts_with("refused:"), "{e}");
    }

    fn osdmap_with(max_osd: i32, states: Vec<u32>, uuids: Vec<Uuid>) -> osdmap::OsdMap {
        let mut m = osdmap::OsdMap::default();
        m.max_osd = max_osd;
        m.osd_state = states;
        m.osd_uuid = uuids;
        m
    }

    /// The reused on-disk identity is checked against the mon's OSD map (the fake mon = a hand-built map):
    /// a destroyed (purged) or re-created (fresh uuid) osd.N is refused, the same uuid stays idempotent.
    #[test]
    fn reused_identity_is_checked_against_the_mon() {
        use osdmap::consts::osd_state;
        let id = ident(); // whoami 3, osd_fsid Uuid([2; 16])
        let exists = osd_state::EXISTS;
        // the mon knows osd.3 with the same uuid: a re-run of an interrupted prepare stays idempotent
        let mut m = osdmap_with(4, vec![exists; 4], vec![Uuid::default(); 4]);
        m.osd_uuid[3] = id.osd_fsid;
        assert_eq!(identity_still_in_mon(&m, &id), Ok(()));
        // an exists slot without a uuid (default) is not a mismatch (mirrors the OSD's identity_gone)
        let m = osdmap_with(4, vec![exists; 4], vec![Uuid::default(); 4]);
        assert_eq!(identity_still_in_mon(&m, &id), Ok(()));
        // the mon purged osd.3: the id is no longer in the map
        let m = osdmap_with(3, vec![exists; 3], vec![Uuid::default(); 3]);
        let e = identity_still_in_mon(&m, &id).expect_err("stale identity accepted");
        assert!(e.starts_with("refused:") && e.contains("purged"), "{e}");
        // `ceph osd destroy`: id and uuid stay, the DESTROYED bit is set (the reported NT-devfail-01 case)
        let mut m = osdmap_with(4, vec![exists; 4], vec![Uuid::default(); 4]);
        m.osd_uuid[3] = id.osd_fsid;
        m.osd_state[3] |= osd_state::DESTROYED;
        let e = identity_still_in_mon(&m, &id).expect_err("destroyed identity accepted");
        assert!(e.starts_with("refused:") && e.contains("destroyed"), "{e}");
        // the mon re-created osd.3 with a fresh uuid
        let mut m = osdmap_with(4, vec![exists; 4], vec![Uuid::default(); 4]);
        m.osd_uuid[3] = Uuid([9; 16]);
        let e = identity_still_in_mon(&m, &id).expect_err("re-created identity accepted");
        assert!(e.starts_with("refused:") && e.contains("re-created"), "{e}");
    }

    /// A btrfs keeps its superblock at 64 KiB with the first 64 KiB zero: the used-device probe must see it.
    #[test]
    fn used_probe_reads_beyond_the_first_window() {
        use std::io::{Seek, SeekFrom, Write};
        let p = std::env::temp_dir().join(format!("mkfs-used-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let ctrl = AnyCtrl::File(nvme::filedev::FileCtrl::open_or_create(&p, 8 << 20).unwrap());
        assert_eq!(looks_used(&ctrl).unwrap(), None, "blank device");
        let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.seek(SeekFrom::Start((64 << 10) + BTRFS_MAGIC_OFF as u64))
            .unwrap();
        f.write_all(b"_BHRfS_M").unwrap();
        f.sync_all().unwrap();
        assert_eq!(
            looks_used(&ctrl).unwrap().as_deref(),
            Some("btrfs filesystem"),
            "btrfs superblock behind the first 8 KiB was missed"
        );
        drop(f);
        // a zero window at 64 KiB stays empty; stale bytes there count as used
        assert_eq!(window_reason(&vec![0u8; 4096], 64 << 10, 4096), None);
        assert_eq!(
            window_reason(&[0u8; 4096], 256 << 10, 4096),
            None,
            "zero backup window"
        );
        let mut w = vec![0u8; 4096];
        w[0] = 1;
        assert_eq!(
            window_reason(&w, 64 << 10, 4096).as_deref(),
            Some("non-zero data at 65536 bytes")
        );
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mkfs_deallocates_whole_namespace_unless_skipped() {
        use nvme::BlockDev;
        use std::os::unix::fs::MetadataExt;
        let p = std::env::temp_dir().join(format!("mkfs-discard-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let ctrl = AnyCtrl::File(nvme::filedev::FileCtrl::open_or_create(&p, 8 << 20).unwrap());
        let mut dev = ctrl.open_queue().unwrap();
        for i in 0..32 {
            let mut buf = dev.alloc_buf(256 << 10);
            nvme::IoBuf::as_mut_slice(&mut buf).fill(0xAB);
            dev.submit_write(i * 64, buf, i).unwrap();
        }
        let mut out = Vec::new();
        while out.len() < 32 {
            dev.poll(0, &mut out);
        }
        let alloc = || std::fs::metadata(&p).unwrap().blocks() * 512;
        let before = alloc();
        assert!(before >= 8 << 20, "allocated {before}");
        discard_namespace(&args(&["--no-discard"]), &ctrl).unwrap();
        assert_eq!(alloc(), before, "skipped: untouched");
        discard_namespace(&args(&[]), &ctrl).unwrap();
        assert!(alloc() < before / 2, "deallocated {before} -> {}", alloc());
        let _ = std::fs::remove_file(&p);
    }
}
