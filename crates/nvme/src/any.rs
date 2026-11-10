// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Runtime device selection for the daemon and tools: `--dev kernel:/dev/nvmeXnY` (the default tier, feature
//! `kernel`, adr 0169), `--dev spdk:0000:03:00.0[,ns=1]` (production, feature `spdk`) or
//! `--dev file:/path[,size=8G]` (DEV/LAB ONLY, feature `lab`, [`crate::filedev`]). One concrete [`AnyDev`] type so
//! the OSD code needs no generics over the backend; variants that are not compiled in do not exist (a build with one
//! backend collapses every match; adr 0024 zero-cost).

use crate::{BlockDev, Completion, Geometry, IoBuf, Nanos, Submit};
#[cfg(any(feature = "lab", feature = "kernel"))]
use std::path::PathBuf;

/// Parsed `--dev` argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DevSpec {
    /// Regular file or block device through `pread`/`pwrite` + `fdatasync` (DEV / LAB ONLY).
    #[cfg(feature = "lab")]
    File { path: PathBuf, size: Option<u64> },
    /// NVMe controller by PCI address through SPDK (production). `shared` (DEBUG/TESTING ONLY, feature `spdk-mp`): the
    /// controller is shared with other processes, one namespace each, through SPDK multi-process mode
    /// (`spdk:PCI,ns=N,shared`, adr 0463; production = one OSD per controller, adr 0103).
    Spdk {
        traddr: String,
        nsid: u32,
        shared: bool,
    },
    /// Namespace on the kernel nvme driver through io_uring (adr 0169): `/dev/nvmeXnY` = O_DIRECT, `/dev/ngXnY` = NVMe
    /// passthrough. Production backend of the kernel tier.
    #[cfg(feature = "kernel")]
    Kernel { path: PathBuf },
}

/// `8G`, `512M`, `4096`, ... (binary units).
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (n, mul) = match s.chars().last()? {
        'k' | 'K' => (&s[..s.len() - 1], 1u64 << 10),
        'm' | 'M' => (&s[..s.len() - 1], 1 << 20),
        'g' | 'G' => (&s[..s.len() - 1], 1 << 30),
        't' | 'T' => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    n.trim().parse::<u64>().ok()?.checked_mul(mul)
}

impl DevSpec {
    pub fn parse(s: &str) -> Result<DevSpec, String> {
        #[cfg(feature = "lab")]
        if let Some(rest) = s.strip_prefix("file:") {
            let mut it = rest.split(',');
            let path = it
                .next()
                .filter(|p| !p.is_empty())
                .ok_or("file: needs a path")?;
            let mut size = None;
            for o in it {
                match o.split_once('=') {
                    Some(("size", v)) => {
                        size = Some(parse_size(v).ok_or_else(|| format!("bad size {v:?}"))?)
                    }
                    _ => return Err(format!("unknown file: option {o:?}")),
                }
            }
            return Ok(DevSpec::File {
                path: path.into(),
                size,
            });
        }
        #[cfg(feature = "kernel")]
        if let Some(p) = s.strip_prefix("kernel:") {
            if !p.starts_with('/') || p.contains(',') {
                return Err(format!(
                    "bad --dev {s:?}: expected kernel:/dev/nvmeXnY (O_DIRECT) or kernel:/dev/ngXnY (NVMe passthrough)"
                ));
            }
            return Ok(DevSpec::Kernel { path: p.into() });
        }
        if let Some(rest) = s.strip_prefix("spdk:") {
            // PCI addresses contain ':' (0000:03:00.0); options follow after ','
            let mut it = rest.split(',');
            let traddr = it
                .next()
                .filter(|p| !p.is_empty())
                .ok_or("spdk: needs a PCI address")?
                .to_owned();
            let mut nsid = 1;
            let mut shared = false;
            for o in it {
                match o.split_once('=') {
                    Some(("ns", v)) => {
                        // 0 = no namespace, 0xffffffff = broadcast (all namespaces): never a store target
                        nsid = v
                            .parse()
                            .ok()
                            .filter(|n: &u32| (1..u32::MAX).contains(n))
                            .ok_or_else(|| {
                                format!("bad ns {v:?}: expected an NSID 1..4294967294")
                            })?
                    }
                    // SPDK multi-process (adr 0463): debug/testing only, never in production builds (adr 0103)
                    None if o == "shared" => {
                        if !cfg!(feature = "spdk-mp") {
                            return Err(MP_OFF.into());
                        }
                        shared = true
                    }
                    _ => return Err(format!("unknown spdk: option {o:?}")),
                }
            }
            Ok(DevSpec::Spdk {
                traddr,
                nsid,
                shared,
            })
        } else {
            Err(format!(
                "bad --dev {s:?}: expected spdk:PCI[,ns=N][,shared] or kernel:/dev/NODE (file:PATH needs a `lab` build)"
            ))
        }
    }

    /// Is this a dev/lab backend?
    pub fn is_dev_only(&self) -> bool {
        match self {
            DevSpec::Spdk { .. } => false,
            #[cfg(feature = "kernel")]
            DevSpec::Kernel { .. } => false,
            #[cfg(feature = "lab")]
            DevSpec::File { .. } => true,
        }
    }

    /// Store backend name (OSD metadata `flashstore_store_backend`, logs): `spdk`, `kernel`, `kernel-cmd`, `file`.
    pub fn backend_name(&self) -> &'static str {
        match self {
            DevSpec::Spdk { .. } => "spdk",
            #[cfg(feature = "kernel")]
            DevSpec::Kernel { path } => {
                if path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("ng"))
                {
                    "kernel-cmd"
                } else {
                    "kernel"
                }
            }
            #[cfg(feature = "lab")]
            DevSpec::File { .. } => "file",
        }
    }

    /// The `kernel:` spec of this device for `--store-backend kernel|kernel-cmd` (adr 0169): an `spdk:BDF[,ns=N]` spec
    /// resolves through sysfs to the namespace node of that controller (bound to the kernel nvme driver); other specs
    /// stay as they are.
    #[cfg(feature = "kernel")]
    pub fn to_kernel(&self, cmd: bool) -> Result<DevSpec, String> {
        match self {
            // `shared` (SPDK multi-process) does not apply: every namespace node is its own kernel device
            DevSpec::Spdk { traddr, nsid, .. } => {
                let (blk, ng) =
                    crate::kdev::nodes_of_pci(&crate::pciallow::canonical_bdf(traddr)?, *nsid)?;
                Ok(DevSpec::Kernel {
                    path: if cmd { ng } else { blk },
                })
            }
            s => Ok(s.clone()),
        }
    }

    /// `spdk:...,shared`: a secondary of the controller's `croit-flashstore-osd spdk-primary` (adr 0463).
    pub fn is_shared(&self) -> bool {
        matches!(self, DevSpec::Spdk { shared: true, .. })
    }

    /// Initialize the SPDK environment for this device (a no-op for `file:`): single-process with the PCI address as
    /// the allow-list, or as a multi-process secondary for `shared` (`core_mask` = this process's main lcore, e.g.
    /// `[5]`; `None` = SPDK's default). Call once, after [`AnyCtrl::claim_before_env`].
    pub fn spdk_env_init(
        &self,
        name: &str,
        core_mask: Option<&str>,
        mem_mb: i32,
    ) -> Result<(), String> {
        let _ = (name, core_mask, mem_mb);
        match self {
            #[cfg(feature = "spdk")]
            DevSpec::Spdk { traddr, shared, .. } => {
                if *shared {
                    #[cfg(feature = "spdk-mp")]
                    return crate::spdk::env_init_mp(
                        name,
                        core_mask,
                        mem_mb,
                        traddr,
                        crate::spdk::MpRole::Secondary,
                    );
                    #[cfg(not(feature = "spdk-mp"))]
                    return Err(MP_OFF.into());
                }
                crate::spdk::env_init(name, core_mask, mem_mb, &[traddr.as_str()])
                    .map_err(|e| format!("spdk env: {e:?}"))
            }
            #[cfg(not(feature = "spdk"))]
            DevSpec::Spdk { .. } => Err("spdk: devices need a build with --features spdk".into()),
            #[cfg(feature = "kernel")]
            DevSpec::Kernel { .. } => Ok(()),
            #[cfg(feature = "lab")]
            _ => Ok(()),
        }
    }
}

/// `spdk:..,shared` in a build without the debug/testing feature `spdk-mp` (adr 0463; production = one OSD per
/// controller, adr 0103).
const MP_OFF: &str = "spdk: `shared` (SPDK multi-process, debug/testing only, adr 0463) needs a build with feature `spdk-mp`";

/// Controller handle (hands out per-core queues).
pub enum AnyCtrl {
    #[cfg(feature = "lab")]
    File(crate::filedev::FileCtrl),
    #[cfg(feature = "spdk")]
    Spdk(crate::spdk::SpdkCtrlr),
    #[cfg(feature = "kernel")]
    Kernel(crate::kdev::KernelCtrl),
}

impl std::fmt::Debug for AnyCtrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnyCtrl")
    }
}

impl AnyCtrl {
    /// Open the device. `create` lets a `file:` spec with `size` create the (sparse) file. For `spdk:` the SPDK
    /// environment must already be initialized by the caller.
    pub fn open(spec: &DevSpec, create: bool) -> Result<AnyCtrl, String> {
        let _ = create;
        match spec {
            #[cfg(feature = "lab")]
            DevSpec::File { path, size } => {
                let c = match (create, size) {
                    (true, Some(s)) => crate::filedev::FileCtrl::open_or_create(path, *s),
                    _ => crate::filedev::FileCtrl::open(path, *size),
                };
                c.map(|c| AnyCtrl::File(c.with_path(path)))
                    .map_err(|e| format!("{}: {e}", path.display()))
            }
            #[cfg(feature = "spdk")]
            DevSpec::Spdk {
                traddr,
                nsid,
                shared,
            } => if *shared {
                #[cfg(feature = "spdk-mp")]
                {
                    crate::spdk::SpdkCtrlr::attach_pci_shared(traddr, *nsid)
                }
                #[cfg(not(feature = "spdk-mp"))]
                return Err(MP_OFF.into());
            } else {
                crate::spdk::SpdkCtrlr::attach_pci(traddr, *nsid)
            }
            .map(AnyCtrl::Spdk)
            .map_err(|e| match e {
                crate::spdk::SpdkError::InUse(m) => format!("spdk {traddr}: {m}"),
                e => format!("spdk attach {traddr}: {e:?}"),
            }),
            #[cfg(not(feature = "spdk"))]
            DevSpec::Spdk { .. } => Err("spdk: devices need a build with --features spdk".into()),
            #[cfg(feature = "kernel")]
            DevSpec::Kernel { path } => crate::kdev::KernelCtrl::open(path).map(AnyCtrl::Kernel),
        }
    }

    /// [`open`](Self::open) for a user that needs the device alone (the daemon, offline repair tools): `file:` devices
    /// are `flock`ed exclusively (a second opener fails); `spdk:` devices are exclusive through the SPDK PCI claim that
    /// [`open`](Self::open) takes before DPDK maps the device ([`crate::pcilock`], every `spdk:` open); `shared` ones
    /// through the namespace claim instead ([`crate::spdkmp`]).
    pub fn open_exclusive(spec: &DevSpec) -> Result<AnyCtrl, String> {
        Self::open_exclusive_create(spec, false)
    }

    /// [`open_exclusive`](Self::open_exclusive) that may create a missing `file:` device (`create` + `size`, mkfs/bench);
    /// the lock is taken before the file is sized.
    pub fn open_exclusive_create(spec: &DevSpec, create: bool) -> Result<AnyCtrl, String> {
        let _ = create;
        match spec {
            #[cfg(feature = "lab")]
            DevSpec::File { path, size } => {
                crate::filedev::FileCtrl::open_exclusive_create(path, *size, create)
                    .map(|c| AnyCtrl::File(c.with_path(path)))
                    .map_err(|e| format!("{}: {e}", path.display()))
            }
            _ => Self::open(spec, create),
        }
    }

    /// Take the exclusive claim of a `spdk:` device BEFORE the SPDK/DPDK environment is initialized (a no-op for
    /// `file:`, whose lock is taken by the open): a device owned by a running OSD is refused with "in use" before
    /// DPDK touches it ([`crate::pcilock`]).
    pub fn claim_before_env(spec: &DevSpec) -> Result<(), String> {
        match spec {
            DevSpec::Spdk {
                traddr,
                nsid,
                shared: true,
            } => {
                #[cfg(feature = "spdk-mp")]
                return crate::spdkmp::claim_ns(traddr, *nsid);
                #[cfg(not(feature = "spdk-mp"))]
                {
                    let _ = (traddr, nsid);
                    Err(MP_OFF.into())
                }
            }
            DevSpec::Spdk { traddr, .. } => crate::pcilock::claim(traddr),
            #[cfg(any(feature = "lab", feature = "kernel"))]
            _ => Ok(()), // file: flock / kernel: O_EXCL, both taken by the open
        }
    }

    /// mkfs helper: make sure the namespace uses 4096 B LBAs without metadata (NVMe Format NVM, DESTROYS the
    /// namespace content). `Ok(Some(desc))` = a format ran (old format described), `Ok(None)` = nothing to do (also
    /// for `file:` devices). The caller must have decided that wiping is allowed. Consumes the handle (no io queue may be open); on error the controller is gone.
    pub fn ensure_4k(self) -> Result<(AnyCtrl, Option<String>), String> {
        match self {
            #[cfg(feature = "lab")]
            AnyCtrl::File(c) => Ok((AnyCtrl::File(c), None)),
            #[cfg(feature = "spdk")]
            AnyCtrl::Spdk(c) => c.ensure_4k().map(|(c, o)| {
                (
                    AnyCtrl::Spdk(c),
                    o.map(|f| {
                        format!(
                            "{}+{} (lbaf {}, pi {})",
                            f.data_bytes, f.meta_bytes, f.index, f.pi
                        )
                    }),
                )
            }),
            #[cfg(feature = "kernel")]
            AnyCtrl::Kernel(c) => Ok((AnyCtrl::Kernel(c), None)), // a wrong format is refused at open
        }
    }

    /// Would [`AnyCtrl::ensure_4k`] have to format? (`Some(description of the current format)`)
    pub fn needs_4k_format(&self) -> Option<String> {
        match self {
            #[cfg(feature = "lab")]
            AnyCtrl::File(_) => None,
            #[cfg(feature = "spdk")]
            AnyCtrl::Spdk(c) => {
                let f = c.lba_format();
                (f.data_bytes != 4096 || f.meta_bytes != 0 || f.pi != 0).then(|| {
                    format!(
                        "{}+{} (lbaf {}, pi {})",
                        f.data_bytes, f.meta_bytes, f.index, f.pi
                    )
                })
            }
            #[cfg(feature = "kernel")]
            AnyCtrl::Kernel(_) => None,
        }
    }

    /// Format NVM scope of the controller (FNA, namespace counts; [`crate::fna`]). `None` for lab devices.
    pub fn ns_scope(&self) -> Option<crate::fna::NsScope> {
        match self {
            #[cfg(feature = "lab")]
            AnyCtrl::File(_) => None,
            #[cfg(feature = "spdk")]
            AnyCtrl::Spdk(c) => Some(c.ns_scope()),
            #[cfg(feature = "kernel")]
            AnyCtrl::Kernel(_) => None,
        }
    }

    pub fn geometry(&self) -> Geometry {
        match self {
            #[cfg(feature = "lab")]
            AnyCtrl::File(c) => c.geometry(),
            #[cfg(feature = "spdk")]
            AnyCtrl::Spdk(c) => c.geometry(),
            #[cfg(feature = "kernel")]
            AnyCtrl::Kernel(c) => c.geometry(),
        }
    }

    /// Driven by SPDK: its IO buffers come from the EAL hugepage heap, within the DMA budget (`crate::dmapool`).
    pub fn is_spdk(&self) -> bool {
        match self {
            #[cfg(feature = "lab")]
            AnyCtrl::File(_) => false,
            #[cfg(feature = "spdk")]
            AnyCtrl::Spdk(_) => true,
            #[cfg(feature = "kernel")]
            AnyCtrl::Kernel(_) => false,
        }
    }

    /// mkfs only: the passthrough DSM probe of a kernel cmd namespace before mkfs deallocates it (adr 0169 am. 8). Returns
    /// the verdict for the superblock; `None` for every other device. Opens never probe.
    pub fn probe_dsm_at_mkfs(&self) -> Result<Option<bool>, String> {
        match self {
            #[cfg(feature = "lab")]
            AnyCtrl::File(_) => Ok(None),
            #[cfg(feature = "spdk")]
            AnyCtrl::Spdk(_) => Ok(None),
            #[cfg(feature = "kernel")]
            AnyCtrl::Kernel(c) => c.probe_dsm_at_mkfs(),
        }
    }

    /// Mount: apply the superblock's DSM verdict (`None` = no verdict stored). Only kernel cmd namespaces use it.
    pub fn apply_dsm_verdict(&self, v: Option<bool>) {
        match self {
            #[cfg(feature = "lab")]
            AnyCtrl::File(_) => {
                let _ = v;
            }
            #[cfg(feature = "spdk")]
            AnyCtrl::Spdk(_) => {
                let _ = v;
            }
            #[cfg(feature = "kernel")]
            AnyCtrl::Kernel(c) => c.apply_dsm_verdict(v),
        }
    }

    /// Handle for background identity / SMART reads (admin commands only). `None` for lab devices.
    pub fn health_probe(&self) -> Option<HealthProbe> {
        match self {
            #[cfg(feature = "lab")]
            AnyCtrl::File(c) => Some(HealthProbe::Kernel(crate::kprobe::KernelProbe(
                c.path().to_owned(),
            ))),
            #[cfg(feature = "spdk")]
            AnyCtrl::Spdk(c) => Some(HealthProbe::Spdk(c.clone())),
            #[cfg(feature = "kernel")]
            AnyCtrl::Kernel(c) => Some(HealthProbe::Kernel(crate::kprobe::KernelProbe(
                c.probe_path().to_owned(),
            ))),
        }
    }

    /// New queue handle (one per owning core / shard), [`queue_depth`] deep.
    pub fn open_queue(&self) -> Result<AnyDev, String> {
        match self {
            #[cfg(feature = "lab")]
            AnyCtrl::File(c) => Ok(AnyDev::File(c.open_queue())),
            #[cfg(feature = "spdk")]
            AnyCtrl::Spdk(c) => c
                .open_queue(QUEUE_DEPTH.load(std::sync::atomic::Ordering::Relaxed))
                .map(AnyDev::Spdk)
                .map_err(|e| format!("spdk queue: {e:?}")),
            #[cfg(feature = "kernel")]
            AnyCtrl::Kernel(c) => Ok(AnyDev::Kernel(
                c.open_queue(QUEUE_DEPTH.load(std::sync::atomic::Ordering::Relaxed)),
            )),
        }
    }
}

/// IO buffer of [`AnyDev`].
#[derive(Debug)]
pub enum AnyBuf {
    #[cfg(feature = "lab")]
    Mem(Vec<u8>),
    #[cfg(feature = "spdk")]
    Dma(crate::spdk::DmaBuf),
    #[cfg(feature = "kernel")]
    K(crate::kdev::KBuf),
}

macro_rules! bufmatch {
    ($self:ident, $b:ident => $e:expr) => {
        match $self {
            #[cfg(feature = "lab")]
            AnyBuf::Mem($b) => $e,
            #[cfg(feature = "spdk")]
            AnyBuf::Dma($b) => $e,
            #[cfg(feature = "kernel")]
            AnyBuf::K($b) => $e,
        }
    };
}

impl IoBuf for AnyBuf {
    fn len(&self) -> usize {
        bufmatch!(self, b => IoBuf::len(b))
    }
    fn as_slice(&self) -> &[u8] {
        bufmatch!(self, b => IoBuf::as_slice(b))
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        bufmatch!(self, b => IoBuf::as_mut_slice(b))
    }
    fn copy_from_slice(&mut self, src: &[u8]) {
        bufmatch!(self, b => IoBuf::copy_from_slice(b, src))
    }
    fn copy_from_slices_zero_tail(&mut self, parts: &[&[u8]]) {
        bufmatch!(self, b => IoBuf::copy_from_slices_zero_tail(b, parts))
    }
    fn copy_from_slice_crc32c(&mut self, src: &[u8], block_bytes: usize, crcs: &mut [u32]) {
        bufmatch!(self, b => IoBuf::copy_from_slice_crc32c(b, src, block_bytes, crcs))
    }
    fn into_shared(self) -> bytes::Bytes {
        bufmatch!(self, b => IoBuf::into_shared(b))
    }
}

// Per-thread completion scratch of `AnyDev::poll` (thread-per-core: no sharing; keeps the capacity so a poll
// allocates nothing).
#[cfg(feature = "lab")]
thread_local! {
    static FILE_SCR: std::cell::RefCell<Vec<Completion<Vec<u8>>>> = const { std::cell::RefCell::new(Vec::new()) };
}
#[cfg(feature = "spdk")]
thread_local! {
    static SPDK_SCR: std::cell::RefCell<Vec<Completion<crate::spdk::DmaBuf>>> = const { std::cell::RefCell::new(Vec::new()) };
}
#[cfg(feature = "kernel")]
thread_local! {
    static KDEV_SCR: std::cell::RefCell<Vec<Completion<crate::kdev::KBuf>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Queue handle of any compiled-in backend.
#[derive(Debug)]
pub enum AnyDev {
    #[cfg(feature = "lab")]
    File(crate::filedev::FileDev),
    #[cfg(feature = "spdk")]
    Spdk(crate::spdk::SpdkDev),
    #[cfg(feature = "kernel")]
    Kernel(crate::kdev::KernelDev),
}

fn rej<B, A>(r: Submit<A>, w: impl Fn(A) -> B) -> Submit<B> {
    r.map_err(|e| crate::Rejected {
        err: e.err,
        buf: e.buf.map(w),
    })
}

/// A buffer of another backend handed to a queue (more than one backend compiled in).
#[cfg(any(
    all(feature = "lab", feature = "spdk"),
    all(feature = "lab", feature = "kernel"),
    all(feature = "spdk", feature = "kernel")
))]
fn wrong(buf: AnyBuf) -> Submit<AnyBuf> {
    Err(crate::Rejected {
        err: crate::SubmitError::Invalid,
        buf: Some(buf),
    })
}

macro_rules! dispatch {
    ($self:ident, $d:ident => $e:expr) => {
        match $self {
            #[cfg(feature = "lab")]
            AnyDev::File($d) => $e,
            #[cfg(feature = "spdk")]
            AnyDev::Spdk($d) => $e,
            #[cfg(feature = "kernel")]
            AnyDev::Kernel($d) => $e,
        }
    };
}

/// Run `d.poll` into the backend's thread scratch and wrap the buffers.
macro_rules! poll_into {
    ($d:ident, $now:ident, $out:ident, $scr:ident, $wrap:path) => {{
        let mut v = $scr.with(|s| std::mem::take(&mut *s.borrow_mut()));
        let n = $d.poll($now, &mut v);
        $out.extend(v.drain(..).map(|c| Completion {
            tag: c.tag,
            op: c.op,
            result: c.result,
            buf: c.buf.map($wrap),
        }));
        $scr.with(|s| *s.borrow_mut() = v);
        n
    }};
}

impl BlockDev for AnyDev {
    type Buf = AnyBuf;

    fn geometry(&self) -> Geometry {
        dispatch!(self, d => d.geometry())
    }
    fn alloc_buf(&mut self, len: usize) -> AnyBuf {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => AnyBuf::Mem(d.alloc_buf(len)),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => AnyBuf::Dma(d.alloc_buf(len)),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => AnyBuf::K(d.alloc_buf(len)),
        }
    }
    fn alloc_buf_uninit(&mut self, len: usize) -> AnyBuf {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => AnyBuf::Mem(d.alloc_buf_uninit(len)),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => AnyBuf::Dma(d.alloc_buf_uninit(len)),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => AnyBuf::K(d.alloc_buf_uninit(len)),
        }
    }
    fn try_alloc_io_uninit(&mut self, len: usize) -> Option<AnyBuf> {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => d.try_alloc_io_uninit(len).map(AnyBuf::Mem),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => d.try_alloc_io_uninit(len).map(AnyBuf::Dma),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => d.try_alloc_io_uninit(len).map(AnyBuf::K),
        }
    }
    fn try_alloc_buf_uninit(&mut self, len: usize) -> Option<AnyBuf> {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => d.try_alloc_buf_uninit(len).map(AnyBuf::Mem),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => d.try_alloc_buf_uninit(len).map(AnyBuf::Dma),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => d.try_alloc_buf_uninit(len).map(AnyBuf::K),
        }
    }
    fn release_pooled(&mut self) {
        dispatch!(self, d => d.release_pooled())
    }
    fn ram_reads(&self) -> bool {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => d.ram_reads(),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => d.ram_reads(),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => d.ram_reads(),
        }
    }
    fn alloc_buf_ram_uninit(&mut self, len: usize) -> AnyBuf {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => AnyBuf::Mem(d.alloc_buf_ram_uninit(len)),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => AnyBuf::Dma(d.alloc_buf_ram_uninit(len)),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => AnyBuf::K(d.alloc_buf_ram_uninit(len)),
        }
    }
    fn trim_ram(&mut self) {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => d.trim_ram(),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => d.trim_ram(),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => d.trim_ram(),
        }
    }
    fn view_buf(&mut self, data: &bytes::Bytes) -> Option<AnyBuf> {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(_) => {
                let _ = data;
                None
            }
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => d.view_buf(data).map(AnyBuf::Dma),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => d.view_buf(data).map(AnyBuf::K),
        }
    }
    fn queue_space(&self) -> usize {
        dispatch!(self, d => d.queue_space())
    }
    fn queue_depth(&self) -> usize {
        dispatch!(self, d => d.queue_depth())
    }
    fn submit_write(&mut self, lba: u64, buf: AnyBuf, tag: u64) -> Submit<AnyBuf> {
        match (self, buf) {
            #[cfg(feature = "lab")]
            (AnyDev::File(d), AnyBuf::Mem(b)) => rej(d.submit_write(lba, b, tag), AnyBuf::Mem),
            #[cfg(feature = "spdk")]
            (AnyDev::Spdk(d), AnyBuf::Dma(b)) => rej(d.submit_write(lba, b, tag), AnyBuf::Dma),
            #[cfg(feature = "kernel")]
            (AnyDev::Kernel(d), AnyBuf::K(b)) => rej(d.submit_write(lba, b, tag), AnyBuf::K),
            #[cfg(any(
                all(feature = "lab", feature = "spdk"),
                all(feature = "lab", feature = "kernel"),
                all(feature = "spdk", feature = "kernel")
            ))]
            (_, b) => wrong(b),
        }
    }
    fn submit_read(&mut self, lba: u64, buf: AnyBuf, tag: u64) -> Submit<AnyBuf> {
        match (self, buf) {
            #[cfg(feature = "lab")]
            (AnyDev::File(d), AnyBuf::Mem(b)) => rej(d.submit_read(lba, b, tag), AnyBuf::Mem),
            #[cfg(feature = "spdk")]
            (AnyDev::Spdk(d), AnyBuf::Dma(b)) => rej(d.submit_read(lba, b, tag), AnyBuf::Dma),
            #[cfg(feature = "kernel")]
            (AnyDev::Kernel(d), AnyBuf::K(b)) => rej(d.submit_read(lba, b, tag), AnyBuf::K),
            #[cfg(any(
                all(feature = "lab", feature = "spdk"),
                all(feature = "lab", feature = "kernel"),
                all(feature = "spdk", feature = "kernel")
            ))]
            (_, b) => wrong(b),
        }
    }
    fn submits_at_flush(&self) -> bool {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => d.submits_at_flush(),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => d.submits_at_flush(),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => d.submits_at_flush(),
        }
    }
    fn issue(&mut self) {
        dispatch!(self, d => d.issue())
    }
    fn wait_hint(&mut self) -> Option<std::time::Duration> {
        dispatch!(self, d => d.wait_hint())
    }
    fn dealloc_limits(&self) -> crate::DeallocLimits {
        dispatch!(self, d => d.dealloc_limits())
    }
    fn submit_deallocate(&mut self, ranges: &[(u64, u32)], tag: u64) -> Submit<AnyBuf> {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => rej(d.submit_deallocate(ranges, tag), AnyBuf::Mem),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => rej(d.submit_deallocate(ranges, tag), AnyBuf::Dma),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => rej(d.submit_deallocate(ranges, tag), AnyBuf::K),
        }
    }
    fn deallocate_all(&mut self) -> Result<u64, String> {
        dispatch!(self, d => d.deallocate_all())
    }
    fn submit_write_zeroes(&mut self, lba: u64, nlba: u32, tag: u64) -> Submit<AnyBuf> {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => rej(d.submit_write_zeroes(lba, nlba, tag), AnyBuf::Mem),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => rej(d.submit_write_zeroes(lba, nlba, tag), AnyBuf::Dma),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => rej(d.submit_write_zeroes(lba, nlba, tag), AnyBuf::K),
        }
    }
    fn poll(&mut self, now: Nanos, out: &mut Vec<Completion<AnyBuf>>) -> usize {
        match self {
            #[cfg(feature = "lab")]
            AnyDev::File(d) => poll_into!(d, now, out, FILE_SCR, AnyBuf::Mem),
            #[cfg(feature = "spdk")]
            AnyDev::Spdk(d) => poll_into!(d, now, out, SPDK_SCR, AnyBuf::Dma),
            #[cfg(feature = "kernel")]
            AnyDev::Kernel(d) => poll_into!(d, now, out, KDEV_SCR, AnyBuf::K),
        }
    }
    fn next_deadline(&self) -> Option<Nanos> {
        dispatch!(self, d => d.next_deadline())
    }
    fn is_dead(&self) -> bool {
        dispatch!(self, d => d.is_dead())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_specs() {
        #[cfg(feature = "lab")]
        assert_eq!(
            DevSpec::parse("file:/data/x.img,size=8G").unwrap(),
            DevSpec::File {
                path: "/data/x.img".into(),
                size: Some(8 << 30)
            }
        );
        assert_eq!(
            DevSpec::parse("spdk:0000:03:00.0").unwrap(),
            DevSpec::Spdk {
                traddr: "0000:03:00.0".into(),
                nsid: 1,
                shared: false
            }
        );
        // `shared` = SPDK multi-process, debug/testing builds only (adr 0463)
        let s = DevSpec::parse("spdk:0000:af:00.0,ns=3,shared");
        if cfg!(feature = "spdk-mp") {
            let s = s.unwrap();
            assert_eq!(
                s,
                DevSpec::Spdk {
                    traddr: "0000:af:00.0".into(),
                    nsid: 3,
                    shared: true
                }
            );
            assert!(s.is_shared() && !s.is_dev_only());
        } else {
            assert!(s.unwrap_err().contains("spdk-mp"));
        }
        assert!(DevSpec::parse("spdk:0000:af:00.0,shared=1").is_err());
        assert!(DevSpec::parse("nvme0").is_err());
        assert_eq!(
            DevSpec::parse("spdk:0000:03:00.0,ns=2").unwrap(),
            DevSpec::Spdk {
                traddr: "0000:03:00.0".into(),
                nsid: 2,
                shared: false
            }
        );
        for bad in ["0", "4294967295", "-1", "x", ""] {
            let e = DevSpec::parse(&format!("spdk:0000:03:00.0,ns={bad}")).unwrap_err();
            assert!(e.contains("bad ns"), "{bad}: {e}");
        }
        assert_eq!(parse_size("512M"), Some(512 << 20));
        assert_eq!(parse_size("x"), None);
    }
}

#[cfg(all(test, feature = "lab"))]
mod ensure_4k_tests {
    use super::*;

    #[test]
    fn file_ctrl_ensure_4k_is_a_noop_that_keeps_the_handle() {
        let p = std::env::temp_dir().join(format!("nvme-ens4k-{}.img", std::process::id()));
        let spec = DevSpec::File {
            path: p.clone(),
            size: Some(8 << 20),
        };
        let c = AnyCtrl::open(&spec, true).unwrap();
        assert!(c.needs_4k_format().is_none());
        let g = c.geometry();
        let (c, old) = c.ensure_4k().unwrap();
        assert!(old.is_none());
        assert_eq!(c.geometry(), g);
        let _ = std::fs::remove_file(p);
    }
}

/// Admin-command handle (Identify strings, SMART log); `Send`, usable from a background thread while the io queues
/// run on the cores. SPDK: admin queue of the controller (serialized by SPDK); lab `file:/dev/nvmeXnY`: kernel passthrough.
#[derive(Clone, Debug)]
pub enum HealthProbe {
    #[cfg(feature = "spdk")]
    Spdk(crate::spdk::SpdkCtrlr),
    #[cfg(any(feature = "lab", feature = "kernel"))]
    Kernel(crate::kprobe::KernelProbe),
}

impl HealthProbe {
    /// Kernel block device name (`nvme2n1`, also for a generic `ng2n1` node); empty for SPDK.
    pub fn kernel_name(&self) -> String {
        match self {
            #[cfg(feature = "spdk")]
            HealthProbe::Spdk(_) => String::new(),
            #[cfg(any(feature = "lab", feature = "kernel"))]
            HealthProbe::Kernel(k) => {
                k.0.file_name()
                    .map(|n| crate::health::block_name(&n.to_string_lossy()))
                    .unwrap_or_default()
            }
        }
    }
    pub fn ident(&self) -> crate::health::Ident {
        match self {
            #[cfg(feature = "spdk")]
            HealthProbe::Spdk(c) => c.ident(),
            #[cfg(any(feature = "lab", feature = "kernel"))]
            HealthProbe::Kernel(k) => k.ident(),
        }
    }
    pub fn smart(&self) -> Result<crate::health::Smart, crate::health::SmartError> {
        use crate::health::SmartError;
        let b = match self {
            #[cfg(feature = "spdk")]
            HealthProbe::Spdk(c) => c.smart_log().map_err(SmartError::Failed)?,
            #[cfg(any(feature = "lab", feature = "kernel"))]
            HealthProbe::Kernel(k) => k.smart_log()?,
        };
        crate::health::Smart::parse(&b)
            .ok_or_else(|| SmartError::Failed("short log page".to_owned()))
    }
}

/// Depth of the SPDK queue pairs [`AnyCtrl::open_queue`] opens (one per store shard). 256 (was 128): adr 0160 A/B, one shard
/// per core carries all of a core's data + WAL commands (1 core QD128 +15..28 %).
static QUEUE_DEPTH: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(256);

/// Current queue pair depth for new queues.
pub fn queue_depth() -> u32 {
    QUEUE_DEPTH.load(std::sync::atomic::Ordering::Relaxed)
}

/// Set the depth of queue pairs opened from now on (benchmarks; `2..=4096`).
pub fn set_queue_depth(d: u32) {
    QUEUE_DEPTH.store(d.clamp(2, 4096), std::sync::atomic::Ordering::Relaxed);
}

/// `--store-backend` (adr 0169): `spdk` keeps the spec; `kernel` / `kernel-cmd` turn an `spdk:BDF[,ns=N]` spec into the
/// kernel node of that namespace (O_DIRECT block device / NVMe passthrough char device; the controller must be bound to
/// the kernel nvme driver). Returns the spec string to open.
#[cfg(feature = "kernel")]
pub fn resolve_backend(spec: &str, backend: &str) -> Result<String, String> {
    match backend {
        "spdk" | "" => Ok(spec.to_owned()),
        "kernel" | "kernel-cmd" => {
            match DevSpec::parse(spec)?.to_kernel(backend == "kernel-cmd")? {
                DevSpec::Kernel { path } => {
                    if backend == "kernel-cmd" {
                        // A basename is not a device type: an alias may be
                        // named `ng-*`. Never silently select direct I/O here.
                        let error = "kernel-cmd requires an NVMe generic character node, not a block device";
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::FileTypeExt;
                            let md = std::fs::metadata(&path)
                                .map_err(|e| format!("{error} ({}: {e})", path.display()))?;
                            if !md.file_type().is_char_device() {
                                return Err(format!("{error} ({})", path.display()));
                            }
                        }
                        #[cfg(not(unix))]
                        return Err(error.into());
                    }
                    Ok(format!("kernel:{}", path.display()))
                }
                _ => Ok(spec.to_owned()),
            }
        }
        b => Err(format!("bad store backend {b:?} (spdk|kernel|kernel-cmd)")),
    }
}

#[cfg(all(test, feature = "kernel"))]
mod kernel_spec_tests {
    use super::*;

    #[test]
    fn block_specs_keep_direct_io_and_refuse_cmd_mode() {
        for spec in [
            "kernel:/dev/nvme0n1",
            "kernel:/dev/dm-0",
            "kernel:/dev/mapper/vg-lv",
            "kernel:/dev/vg/lv",
        ] {
            assert_eq!(resolve_backend(spec, "kernel").unwrap(), spec);
            assert!(
                resolve_backend(spec, "kernel-cmd")
                    .unwrap_err()
                    .contains("not a block device")
            );
        }
        assert!(resolve_backend("kernel:/dev/ng-data", "kernel-cmd").is_err());
        assert_eq!(
            resolve_backend("spdk:0000:03:00.0", "spdk").unwrap(),
            "spdk:0000:03:00.0"
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_resolution_checks_node_type_not_its_name() {
        let path = std::env::temp_dir().join(format!("ng-type-test-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let spec = format!("kernel:{}", path.display());
        assert!(
            resolve_backend(&spec, "kernel-cmd")
                .unwrap_err()
                .contains("not a block device")
        );
        drop(file);
        std::fs::remove_file(&path).unwrap();
        // Selection only checks the node class; KernelCtrl::open still has to
        // identify a real NVMe generic node before opening command queues.
        assert_eq!(
            resolve_backend("kernel:/dev/null", "kernel-cmd").unwrap(),
            "kernel:/dev/null"
        );
    }

    #[test]
    fn kernel_specs_parse_and_name_their_backend() {
        let s = DevSpec::parse("kernel:/dev/nvme0n1").unwrap();
        assert_eq!(
            s,
            DevSpec::Kernel {
                path: "/dev/nvme0n1".into()
            }
        );
        assert_eq!(s.backend_name(), "kernel");
        assert!(!s.is_dev_only());
        assert_eq!(
            DevSpec::parse("kernel:/dev/ng0n1").unwrap().backend_name(),
            "kernel-cmd"
        );
        assert!(
            DevSpec::parse("kernel:nvme0n1").is_err(),
            "absolute paths only"
        );
        assert!(
            DevSpec::parse("kernel:/dev/nvme0n1,ns=2").is_err(),
            "no options"
        );
        assert_eq!(
            DevSpec::parse("spdk:0000:03:00.0").unwrap().backend_name(),
            "spdk"
        );
        assert_eq!(
            resolve_backend("spdk:0000:03:00.0", "spdk").unwrap(),
            "spdk:0000:03:00.0"
        );
        assert_eq!(
            resolve_backend("kernel:/dev/nvme1n1", "kernel").unwrap(),
            "kernel:/dev/nvme1n1"
        );
        assert!(
            resolve_backend("spdk:0000:03:00.0", "bogus")
                .unwrap_err()
                .contains("bad store backend")
        );
    }
}
