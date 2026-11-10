// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Startup-only validation of single-target dm-linear LVM. Data never leaves the LV descriptor.
use super::*;
use std::os::unix::fs::MetadataExt;

const HEADER: usize = 312;
const TARGET: usize = 40;
const TABLE_STATUS: libc::c_ulong = (3 << 30) | (HEADER as u64) << 16 | (0xfd << 8) | 12;
const ACTIVE: u32 = 1 << 5;
const UNSAFE_FLAGS: u32 = 1 | (1 << 1) | (1 << 6) | (1 << 8) | (1 << 17) | (1 << 18);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Mapping {
    device: u64,
    uuid: String,
    event: u32,
    sectors: u64,
    backing: u64,
    offset: u64,
}

fn u32_at(b: &[u8], o: usize) -> Result<u32, String> {
    Ok(u32::from_ne_bytes(
        b.get(o..o + 4)
            .ok_or("short dm response")?
            .try_into()
            .unwrap(),
    ))
}
fn u64_at(b: &[u8], o: usize) -> Result<u64, String> {
    Ok(u64::from_ne_bytes(
        b.get(o..o + 8)
            .ok_or("short dm response")?
            .try_into()
            .unwrap(),
    ))
}
fn cstr(b: &[u8]) -> Result<&str, String> {
    let end = b
        .iter()
        .position(|c| *c == 0)
        .ok_or("unterminated dm string")?;
    std::str::from_utf8(&b[..end]).map_err(|_| "non-UTF8 dm string".into())
}
fn dev_number(s: &str) -> Result<u64, String> {
    let (a, b) = s.split_once(':').ok_or("bad dm backing device")?;
    let major = a.parse::<u32>().map_err(|_| "bad dm major")?;
    let minor = b.parse::<u32>().map_err(|_| "bad dm minor")?;
    if major > 4095 || minor > 1_048_575 {
        return Err("dm device number out of range".into());
    }
    Ok(libc::makedev(major, minor))
}
fn parse_table(b: &[u8], device: u64) -> Result<Mapping, String> {
    if b.len() < HEADER || u32_at(b, 0)? != 4 || u64_at(b, 40)? != device {
        return Err("dm identity/ABI mismatch".into());
    }
    let size = u32_at(b, 12)? as usize;
    let start = u32_at(b, 16)? as usize;
    let flags = u32_at(b, 28)?;
    if size > b.len() || start < HEADER || start > size || size - start < TARGET {
        return Err("bad dm response bounds".into());
    }
    if u32_at(b, 20)? != 1 || flags & ACTIVE == 0 || flags & UNSAFE_FLAGS != 0 {
        return Err("need one active writable target without pending changes".into());
    }
    let uuid = cstr(&b[176..305])?;
    if uuid.len() != 68
        || !uuid.starts_with("LVM-")
        || !uuid.as_bytes()[4..].iter().all(u8::is_ascii_alphanumeric)
    {
        return Err("mapped device is not an identified LVM LV".into());
    }
    let target = &b[start..size];
    if u64_at(target, 0)? != 0 || cstr(&target[24..40])? != "linear" {
        return Err("only a linear target starting at zero is supported".into());
    }
    let sectors = u64_at(target, 8)?;
    let next = u32_at(target, 20)? as usize;
    let padded_len = target.len().saturating_add(7) & !7;
    if sectors == 0
        || sectors.checked_mul(512).is_none()
        || (next != 0 && (next < TARGET || !next.is_multiple_of(8) || next > padded_len))
    {
        return Err("bad dm target extent".into());
    }
    let mut params = cstr(&target[TARGET..])?.split_whitespace();
    let backing = dev_number(params.next().ok_or("missing backing device")?)?;
    let offset = params
        .next()
        .ok_or("missing backing offset")?
        .parse::<u64>()
        .map_err(|_| "bad backing offset")?;
    if params.next().is_some() || offset.checked_add(sectors).is_none() {
        return Err("bad linear parameters/range".into());
    }
    Ok(Mapping {
        device,
        uuid: uuid.to_owned(),
        event: u32_at(b, 32)?,
        sectors,
        backing,
        offset,
    })
}
fn query(control: RawFd, device: u64) -> Result<Mapping, String> {
    let mut storage = [0u64; 512];
    // SAFETY: live initialized aligned storage, exclusively borrowed as its byte representation.
    let b = unsafe { std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), 4096) };
    b[0..4].copy_from_slice(&4u32.to_ne_bytes());
    b[12..16].copy_from_slice(&4096u32.to_ne_bytes());
    b[16..20].copy_from_slice(&(HEADER as u32).to_ne_bytes());
    b[28..32].copy_from_slice(&(1u32 << 4).to_ne_bytes());
    b[40..48].copy_from_slice(&device.to_ne_bytes());
    // SAFETY: TABLE_STATUS queries only the live table into a bounded aligned buffer.
    if unsafe { libc::ioctl(control, TABLE_STATUS, b.as_mut_ptr()) } != 0 {
        return Err(format!(
            "dm table query: {}",
            std::io::Error::last_os_error()
        ));
    }
    parse_table(b, device)
}
fn sysdev(device: u64) -> PathBuf {
    Path::new("/sys/dev/block").join(format!("{}:{}", libc::major(device), libc::minor(device)))
}
fn fd_device(io: &OwnedFd) -> Result<u64, String> {
    let f = std::fs::File::from(io.try_clone().map_err(|e| e.to_string())?);
    f.metadata().map(|m| m.rdev()).map_err(|e| e.to_string())
}
pub(super) fn is_mapped(io: &OwnedFd) -> Result<bool, String> {
    let sys = sysdev(fd_device(io)?)
        .canonicalize()
        .map_err(|e| format!("opened block device has no sysfs identity: {e}"))?;
    Ok(sys.join("dm").is_dir())
}
fn number(path: impl AsRef<Path>) -> Result<u64, String> {
    let p = path.as_ref();
    read_sys(p)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("{}: missing/invalid sysfs value", p.display()))
}
fn check_range(mapping: &Mapping, partition_sectors: u64, bytes: u64) -> Result<(), String> {
    if mapping.sectors.checked_mul(512) != Some(bytes)
        || mapping
            .offset
            .checked_add(mapping.sectors)
            .is_none_or(|end| end > partition_sectors)
    {
        return Err(
            "linear mapping exceeds backing partition or disagrees with LV capacity".into(),
        );
    }
    Ok(())
}
fn overlaps(a: &Mapping, b: &Mapping) -> bool {
    a.offset < b.offset.saturating_add(b.sectors) && b.offset < a.offset.saturating_add(a.sectors)
}
fn byte_range(start: u64, sectors: u64) -> Result<(u64, u64), String> {
    let end = start
        .checked_add(sectors)
        .and_then(|n| n.checked_mul(512))
        .ok_or("sector extent overflow")?;
    Ok((start.checked_mul(512).ok_or("sector offset overflow")?, end))
}
fn mapped_ident(backing: Ident, logical: u32, bytes: u64) -> Result<Ident, String> {
    if ![512, 4096].contains(&logical)
        || backing.data_bytes != logical
        || backing.meta_bytes != 0
        || backing.pi != 0
        || backing.vwc
        || bytes == 0
        || !bytes.is_multiple_of(4096)
    {
        return Err("mapped storage needs matching 512/4096-byte NVMe sectors, no metadata/PI or volatile cache".into());
    }
    Ok(Ident {
        nsze: bytes / u64::from(logical),
        awupf: 1,
        awun: 1,
        dsm: false,
        write_zeroes: false,
        ..backing
    })
}

fn identified_backing(id: Option<Ident>) -> Result<Ident, String> {
    // Configured sysfs write-through is not proof that the physical NVMe has no
    // volatile cache. Unlike a native device's DSYNC fallback, an LV is admitted
    // only when real Identify establishes the strict mapped durability contract.
    id.ok_or_else(|| "mapped storage requires read-only NVMe Identify access to establish backing format and volatile-cache state; sysfs fallback is insufficient".into())
}
fn check_holders(
    part: &Path,
    mapping: &Mapping,
    sectors: u64,
    mut query_mapping: impl FnMut(u64) -> Result<Mapping, String>,
) -> Result<(), String> {
    let mut count = 0;
    let mut seen_self = false;
    for entry in std::fs::read_dir(part.join("holders")).map_err(|e| e.to_string())? {
        count += 1;
        if count > 128 {
            return Err("too many mapped holders".into());
        }
        let entry = entry.map_err(|e| e.to_string())?;
        let device =
            dev_number(&read_sys(entry.path().join("dev")).ok_or("missing holder identity")?)?;
        let other = query_mapping(device)?;
        if other.device != device || (device == mapping.device && other != *mapping) {
            return Err("holder identity/table changed during open".into());
        }
        seen_self |= device == mapping.device;
        check_range(
            &other,
            sectors,
            other
                .sectors
                .checked_mul(512)
                .ok_or("holder size overflow")?,
        )?;
        if other.backing != mapping.backing
            || (device != mapping.device && overlaps(mapping, &other))
        {
            return Err("ambiguous or overlapping backing-partition holder".into());
        }
    }
    if !seen_self {
        return Err("mapped device has no backing-partition holder".into());
    }
    Ok(())
}
fn backing_namespace(part: &Path) -> Result<&Path, String> {
    if number(part.join("partition"))? == 0 {
        return Err("linear backing must be an NVMe partition".into());
    }
    let namespace = part.parent().ok_or("missing namespace parent")?;
    let controller = namespace.parent().ok_or("missing NVMe controller")?;
    let driver = std::fs::read_link(controller.join("device/driver")).map_err(|e| e.to_string())?;
    let name = namespace
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid namespace name")?;
    if driver.file_name().is_none_or(|n| n != "nvme")
        || !name.starts_with("nvme")
        || head_name(name) != name
    {
        return Err("backing is not a single kernel-owned NVMe namespace".into());
    }
    Ok(namespace)
}
fn check_partitions(namespace: &Path, part: &Path, start: u64, end: u64) -> Result<(), String> {
    for entry in std::fs::read_dir(namespace).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.path().join("partition").exists() || entry.path() == part {
            continue;
        }
        let (other_start, other_end) = byte_range(
            number(entry.path().join("start"))?,
            number(entry.path().join("size"))?,
        )?;
        if start < other_end && other_start < end {
            return Err("mapped range overlaps another physical partition".into());
        }
    }
    Ok(())
}
fn check_namespace_holders(namespace: &Path) -> Result<(), String> {
    if std::fs::read_dir(namespace.join("holders"))
        .map_err(|e| e.to_string())?
        .next()
        .transpose()
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("backing namespace has a conflicting whole-device holder".into());
    }
    Ok(())
}
fn check_backing_range(
    mapping: &Mapping,
    partition_start: u64,
    partition_sectors: u64,
    backing: &Ident,
) -> Result<(u64, u64), String> {
    if ![512, 4096].contains(&backing.data_bytes) {
        return Err("invalid backing logical sector size".into());
    }
    let capacity = backing
        .nsze
        .checked_mul(u64::from(backing.data_bytes))
        .ok_or("namespace capacity overflow")?;
    if byte_range(partition_start, partition_sectors)?.1 > capacity {
        return Err("backing partition exceeds namespace".into());
    }
    let start = partition_start
        .checked_add(mapping.offset)
        .ok_or("backing offset overflow")?;
    let (start, end) = byte_range(start, mapping.sectors)?;
    if !start.is_multiple_of(u64::from(backing.data_bytes)) || end > capacity {
        return Err("unaligned/out-of-namespace mapped range".into());
    }
    Ok((start, end))
}
fn queue_limits(hw: u64, dma: u64, logical: u32) -> Result<(u64, usize), String> {
    if hw < 4 || hw.checked_mul(1024).is_none() || ![512, 4096].contains(&logical) {
        return Err("invalid mapped transfer/sector limit".into());
    }
    let dma =
        usize::try_from(dma).map_err(|_| "mapped DMA alignment overflow")? | (logical as usize - 1);
    if !dma.checked_add(1).is_some_and(usize::is_power_of_two) {
        return Err("invalid mapped DMA alignment".into());
    }
    Ok((hw, dma))
}
struct Validated {
    sys: PathBuf,
    nsid: u32,
    id: Ident,
    backing_path: PathBuf,
    hw: u64,
    dma: usize,
}

// Shared cold validation. Never opens the mounted LV exclusively or writes to it.
// The raw-store caller separately owns its exclusive direct-I/O descriptor.
fn validate(io: &OwnedFd) -> Result<Validated, String> {
    let device = fd_device(io)?;
    let sys = sysdev(device);
    let control = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/mapper/control")
        .map_err(|e| format!("mapped storage needs read-only device-mapper table access: {e}"))?;
    let mapping = query(control.as_raw_fd(), device)?;
    let part = sysdev(mapping.backing)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let namespace = backing_namespace(&part)?;
    check_namespace_holders(namespace)?;
    let name = namespace
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid namespace name")?;
    let (mut logical, mut bytes) = (0u32, 0u64);
    // SAFETY: block geometry ioctls each write one integer of the specified width.
    if unsafe { libc::ioctl(io.as_raw_fd(), 0x1268, &mut logical) } != 0
        || unsafe { libc::ioctl(io.as_raw_fd(), 0x8008_1272u64, &mut bytes) } != 0
    {
        return Err(format!("LV geometry: {}", std::io::Error::last_os_error()));
    }
    let partition_sectors = number(part.join("size"))?;
    let partition_start = number(part.join("start"))?;
    check_range(&mapping, partition_sectors, bytes)?;
    let backing_path = Path::new("/dev").join(name);
    let probe = std::fs::OpenOptions::new()
        .read(true)
        .open(&backing_path)
        .map_err(|e| e.to_string())?;
    if probe.metadata().map_err(|e| e.to_string())?.rdev()
        != dev_number(&read_sys(namespace.join("dev")).ok_or("missing namespace identity")?)?
    {
        return Err("backing namespace node identity changed".into());
    }
    // SAFETY: namespace-ID ioctl has no pointer argument on the read-only backing fd.
    let nsid = unsafe { libc::ioctl(probe.as_raw_fd(), NVME_IOCTL_ID as _) };
    if nsid <= 0 {
        return Err("backing node does not identify as NVMe".into());
    }
    let nsid = nsid as u32;
    let backing = identified_backing(ident_of(probe.as_raw_fd(), nsid)?)?;
    let id = mapped_ident(backing, logical, bytes)?;
    direct_cache_ok(&backing, namespace)?;
    let (start, end) = check_backing_range(&mapping, partition_start, partition_sectors, &backing)?;
    check_partitions(namespace, &part, start, end)?;
    check_holders(&part, &mapping, partition_sectors, |dev| {
        query(control.as_raw_fd(), dev)
    })?;
    if mapping != query(control.as_raw_fd(), device)? {
        return Err("LV table changed during open".into());
    }
    let (hw, dma) = queue_limits(
        number(sys.join("queue/max_hw_sectors_kb"))?,
        number(sys.join("queue/dma_alignment"))?,
        logical,
    )?;
    Ok(Validated {
        sys,
        nsid,
        id,
        backing_path,
        hw,
        dma,
    })
}

pub(super) fn validate_filesystem(path: &Path, expected_device: u64) -> Result<(), String> {
    let io: OwnedFd = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("mounted LV read-only open: {e}"))?
        .into();
    check_filesystem_device(&io, expected_device)?;
    validate(&io)?;
    Ok(())
}

fn check_filesystem_device(io: &OwnedFd, expected_device: u64) -> Result<(), String> {
    let metadata = std::fs::File::from(io.try_clone().map_err(|e| e.to_string())?)
        .metadata()
        .map_err(|e| e.to_string())?;
    if !metadata.file_type().is_block_device() || metadata.rdev() != expected_device {
        return Err("mounted filesystem block-node identity mismatch".into());
    }
    Ok(())
}

pub(super) fn open(io: OwnedFd, path: &Path) -> Result<KernelCtrl, String> {
    let Validated {
        sys,
        nsid,
        id,
        backing_path,
        hw,
        dma,
    } = validate(&io)?;
    let mut ctrl = KernelCtrl::from_parts(io, None, Mode::Direct, nsid, id, Some(hw), dma, path);
    let inner = Arc::get_mut(&mut ctrl.c).expect("new controller is unique");
    inner.tags = blk_tags(&sys);
    Ok(finish_mapped(ctrl, backing_path))
}
fn finish_mapped(mut ctrl: KernelCtrl, backing_path: PathBuf) -> KernelCtrl {
    let inner = Arc::get_mut(&mut ctrl.c).expect("new controller is unique");
    inner.mapped = true;
    inner.probe_path = backing_path;
    inner.geo.dealloc = false;
    inner.geo.write_zeroes = false;
    ctrl
}

#[cfg(test)]
#[path = "klinear_tests.rs"]
mod tests;
