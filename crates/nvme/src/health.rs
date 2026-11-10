// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! NVMe identity + SMART/Health for `ceph device ls`, devicehealth (`smart`) and `list_devices` (doc/spec/devicehealth.md).
//! Pure parsing/rendering (no SPDK needed, unit-testable) plus a process-wide snapshot cell: the daemon fills it
//! once at start (identity) and from a slow background thread (SMART JSON); the OSD tell/boot code only reads it.

use std::fmt::Write as _;
use std::sync::Mutex;

/// Controller identity: Identify Controller strings (trimmed, for display) and the raw fixed-width model / serial fields
/// the device id is built from (doc/spec/devicehealth.md section "Device id").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ident {
    pub model: String,
    pub serial: String,
    pub firmware: String,
    /// Identify Controller MN field as the kernel exposes it: up to 40 bytes, space padding kept, cut at the first NUL.
    raw_model: String,
    /// Identify Controller SN field, same form (up to 20 bytes).
    raw_serial: String,
}

impl Ident {
    /// From the raw Identify Controller fields (MN 40 B, SN 20 B, FR 8 B).
    pub fn from_raw(model: &[u8], serial: &[u8], firmware: &[u8]) -> Ident {
        let cut = |b: &[u8]| {
            let n = b.iter().position(|&x| x == 0).unwrap_or(b.len());
            String::from_utf8_lossy(&b[..n]).into_owned()
        };
        let (rm, rs) = (cut(model), cut(serial));
        Ident {
            model: rm.trim().to_owned(),
            serial: rs.trim().to_owned(),
            firmware: cut(firmware).trim().to_owned(),
            raw_model: rm,
            raw_serial: rs,
        }
    }

    /// Device id exactly as classic Ceph derives it for an NVMe drive (udev `ID_MODEL`_`ID_SERIAL_SHORT` with the
    /// fixed-width padding kept, every space turned into `_`). Empty when model or serial is empty.
    pub fn device_id(&self) -> String {
        if self.raw_model.trim().is_empty() || self.raw_serial.trim().is_empty() {
            return String::new();
        }
        format!("{}_{}", self.raw_model, self.raw_serial).replace(' ', "_")
    }
}

/// Everything the boot metadata + tell commands say about the device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DevMeta {
    /// Device name (`devices` metadata, `ceph device ls` DEV): the kernel block name (`nvme2n1`) when the kernel owns
    /// the device, else the PCI address (no kernel name exists while SPDK owns the device).
    pub name: String,
    /// PCI address (`0000:03:00.0`), empty when unknown.
    pub pci: String,
    /// The kernel owns the device (`name` is a kernel block name).
    pub kernel: bool,
    pub ident: Ident,
    pub size_bytes: u64,
}

impl DevMeta {
    /// `by-path`-like stable path (empty without a PCI address).
    pub fn path(&self) -> String {
        if self.pci.is_empty() {
            String::new()
        } else {
            format!("pci-{}-nvme-1", self.pci)
        }
    }

    /// Device node as `list_devices` / the SMART JSON name it: `/dev/<name>` (kernel) or `spdk:<pci>`.
    pub fn node(&self) -> String {
        if self.kernel {
            format!("/dev/{}", self.name)
        } else {
            format!("spdk:{}", self.name)
        }
    }
}

/// Why a SMART read failed. `Denied` (EPERM/EACCES: the kernel passthrough needs CAP_SYS_ADMIN, adr 0056) selects the
/// classic `sudo smartctl` route; `Failed` is any other error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmartError {
    Denied(String),
    Failed(String),
}

impl SmartError {
    /// Classify an io error: permission errors (EPERM, EACCES) are `Denied`.
    pub fn from_io(msg: String, e: &std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            SmartError::Denied(msg)
        } else {
            SmartError::Failed(msg)
        }
    }
}

impl std::fmt::Display for SmartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (SmartError::Denied(m) | SmartError::Failed(m)) = self;
        f.write_str(m)
    }
}

/// Block device name of an NVMe node: the generic char node `ng2n1` belongs to the block device `nvme2n1`; block names
/// stay as they are.
pub fn block_name(node: &str) -> String {
    match node.strip_prefix("ng") {
        Some(r) if r.starts_with(|c: char| c.is_ascii_digit()) => format!("nvme{r}"),
        _ => node.to_owned(),
    }
}

/// Parsed NVMe SMART / Health Information log (log page 0x02, 512 bytes). Counters are 128-bit on the wire; u64 is
/// plenty (saturating).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Smart {
    pub critical_warning: u8,
    /// Composite temperature in Kelvin.
    pub temperature_k: u16,
    pub available_spare: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub data_units_read: u64,
    pub data_units_written: u64,
    pub host_reads: u64,
    pub host_writes: u64,
    pub controller_busy_time: u64,
    pub power_cycles: u64,
    pub power_on_hours: u64,
    pub unsafe_shutdowns: u64,
    pub media_errors: u64,
    pub num_err_log_entries: u64,
    pub warning_temp_time: u32,
    pub critical_comp_time: u32,
    /// Temperature sensors 1..8 in Kelvin (0 = not implemented).
    pub temp_sensors_k: [u16; 8],
}

fn u128_at(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 16];
    v.copy_from_slice(&b[off..off + 16]);
    u64::try_from(u128::from_le_bytes(v)).unwrap_or(u64::MAX)
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl Smart {
    /// Parse the 512-byte log page; `None` if shorter.
    pub fn parse(b: &[u8]) -> Option<Smart> {
        if b.len() < 512 {
            return None;
        }
        let mut s = [0u16; 8];
        for (i, v) in s.iter_mut().enumerate() {
            *v = u16_at(b, 200 + 2 * i);
        }
        Some(Smart {
            critical_warning: b[0],
            temperature_k: u16_at(b, 1),
            available_spare: b[3],
            available_spare_threshold: b[4],
            percentage_used: b[5],
            data_units_read: u128_at(b, 32),
            data_units_written: u128_at(b, 48),
            host_reads: u128_at(b, 64),
            host_writes: u128_at(b, 80),
            controller_busy_time: u128_at(b, 96),
            power_cycles: u128_at(b, 112),
            power_on_hours: u128_at(b, 128),
            unsafe_shutdowns: u128_at(b, 144),
            media_errors: u128_at(b, 160),
            num_err_log_entries: u128_at(b, 176),
            warning_temp_time: u32_at(b, 192),
            critical_comp_time: u32_at(b, 196),
            temp_sensors_k: s,
        })
    }
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                o.push('\\');
                o.push(c);
            }
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o
}

/// Render the subset of `smartctl -x --json` that devicehealth/croit consume for NVMe (keys as smartctl 7.x).
/// `now_unix` = timestamp for `local_time`.
pub fn render_smartctl_json(m: &DevMeta, s: &Smart, now_unix: u64) -> String {
    // smartctl omits an unavailable sensor; 0 K is what a controller without one reports (never -273 C)
    let log_temp = if s.temperature_k == 0 {
        String::new()
    } else {
        format!("\"temperature\":{},", i32::from(s.temperature_k) - 273)
    };
    let cur_temp = if s.temperature_k == 0 {
        String::new()
    } else {
        format!(
            "\"temperature\":{{\"current\":{}}},",
            i32::from(s.temperature_k) - 273
        )
    };
    let sensors: Vec<String> = s
        .temp_sensors_k
        .iter()
        .filter(|&&k| k != 0)
        .map(|&k| (i32::from(k) - 273).to_string())
        .collect();
    // smartctl: smart_status.passed = no critical warning bit set
    let passed = s.critical_warning == 0;
    format!(
        concat!(
            r#"{{"json_format_version":[1,0],"smartctl":{{"version":[7,4],"platform_info":"croit-flashstore-osd","exit_status":0}},"#,
            r#""device":{{"name":"{name}","info_name":"{name}","type":"nvme","protocol":"NVMe"}},"#,
            r#""model_name":"{model}","serial_number":"{serial}","firmware_version":"{fw}","#,
            r#""nvme_pci_vendor":{{"id":0,"subsystem_id":0}},"user_capacity":{{"blocks":{blocks},"bytes":{bytes}}},"#,
            r#""logical_block_size":4096,"#,
            r#""local_time":{{"time_t":{now}}},"#,
            r#""smart_status":{{"passed":{passed},"nvme":{{"value":{cw}}}}},"#,
            r#""nvme_smart_health_information_log":{{"critical_warning":{cw},{tc}"available_spare":{sp},"#,
            r#""available_spare_threshold":{spt},"percentage_used":{pu},"data_units_read":{dur},"data_units_written":{duw},"#,
            r#""host_reads":{hr},"host_writes":{hw},"controller_busy_time":{cb},"power_cycles":{pc},"power_on_hours":{poh},"#,
            r#""unsafe_shutdowns":{us},"media_errors":{me},"num_err_log_entries":{ne},"warning_temp_time":{wt},"#,
            r#""critical_comp_time":{ct},"temperature_sensors":[{sens}]}},"#,
            r#"{cur}"power_cycle_count":{pc},"power_on_time":{{"hours":{poh}}}}}"#
        ),
        name = esc(&m.node()),
        model = esc(&m.ident.model),
        serial = esc(&m.ident.serial),
        fw = esc(&m.ident.firmware),
        blocks = m.size_bytes / 4096,
        bytes = m.size_bytes,
        now = now_unix,
        passed = passed,
        cw = s.critical_warning,
        tc = log_temp,
        sp = s.available_spare,
        spt = s.available_spare_threshold,
        pu = s.percentage_used,
        dur = s.data_units_read,
        duw = s.data_units_written,
        hr = s.host_reads,
        hw = s.host_writes,
        cb = s.controller_busy_time,
        pc = s.power_cycles,
        poh = s.power_on_hours,
        us = s.unsafe_shutdowns,
        me = s.media_errors,
        ne = s.num_err_log_entries,
        wt = s.warning_temp_time,
        ct = s.critical_comp_time,
        sens = sensors.join(","),
        cur = cur_temp,
    )
}

struct Cell {
    meta: Option<DevMeta>,
    smart_json: Option<String>,
}
static CELL: Mutex<Cell> = Mutex::new(Cell {
    meta: None,
    smart_json: None,
});

/// Daemon start: publish the device identity (boot metadata, `list_devices`, `smart`).
pub fn set_device(m: DevMeta) {
    if let Ok(mut c) = CELL.lock() {
        c.meta = Some(m);
    }
}

/// Background refresh: latest smartctl-style JSON.
pub fn set_smart_json(j: String) {
    if let Ok(mut c) = CELL.lock() {
        c.smart_json = Some(j);
    }
}

pub fn device() -> Option<DevMeta> {
    CELL.lock().ok().and_then(|c| c.meta.clone())
}

pub fn smart_json() -> Option<String> {
    CELL.lock().ok().and_then(|c| c.smart_json.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = 0;
        b[1..3].copy_from_slice(&313u16.to_le_bytes()); // 40 C
        b[3] = 100;
        b[4] = 10;
        b[5] = 7;
        b[32..40].copy_from_slice(&1234u64.to_le_bytes());
        b[48..56].copy_from_slice(&99u64.to_le_bytes());
        b[128..136].copy_from_slice(&4321u64.to_le_bytes());
        b[160..168].copy_from_slice(&2u64.to_le_bytes());
        b[200..202].copy_from_slice(&300u16.to_le_bytes());
        b
    }

    #[test]
    fn parse_fields() {
        let s = Smart::parse(&page()).unwrap();
        assert_eq!(s.temperature_k, 313);
        assert_eq!(s.percentage_used, 7);
        assert_eq!(s.data_units_read, 1234);
        assert_eq!(s.data_units_written, 99);
        assert_eq!(s.power_on_hours, 4321);
        assert_eq!(s.media_errors, 2);
        assert_eq!(s.temp_sensors_k[0], 300);
        assert!(Smart::parse(&[0; 100]).is_none());
    }

    #[test]
    fn id_form() {
        // classic form: raw fixed-width fields (MN 40 B, SN 20 B, space padded), spaces -> `_`
        let mut mn = [b' '; 40];
        mn[..26].copy_from_slice(b"SAMSUNG MZQL27T6HBLA-00A07");
        let mut sn = [b' '; 20];
        sn[..14].copy_from_slice(b"S6CKNS0X903238");
        let i = Ident::from_raw(&mn, &sn, b"1.0     ");
        assert_eq!(
            i.device_id(),
            "SAMSUNG_MZQL27T6HBLA-00A07_______________S6CKNS0X903238______"
        );
        assert_eq!(
            (i.model.as_str(), i.serial.as_str(), i.firmware.as_str()),
            ("SAMSUNG MZQL27T6HBLA-00A07", "S6CKNS0X903238", "1.0")
        );
        // NUL padded fields end at the first NUL
        let j = Ident::from_raw(b"Dell Ent\0\0\0", b"S7ABC\0\0", b"1.0");
        assert_eq!(j.device_id(), "Dell_Ent_S7ABC");
        assert_eq!(Ident::default().device_id(), "");
        assert_eq!(Ident::from_raw(b"M", b"    ", b"").device_id(), "");
    }

    #[test]
    fn kernel_block_names() {
        assert_eq!(block_name("ng2n1"), "nvme2n1");
        assert_eq!(block_name("nvme2n1"), "nvme2n1");
        assert_eq!(block_name("ngfoo"), "ngfoo");
        let k = DevMeta {
            name: "nvme2n1".into(),
            pci: "0000:01:00.0".into(),
            kernel: true,
            ..Default::default()
        };
        assert_eq!(k.node(), "/dev/nvme2n1");
        assert_eq!(k.path(), "pci-0000:01:00.0-nvme-1");
        let s = DevMeta {
            name: "0000:01:00.0".into(),
            pci: "0000:01:00.0".into(),
            ..Default::default()
        };
        assert_eq!(s.node(), "spdk:0000:01:00.0");
    }

    #[test]
    fn smart_error_classifies_permission() {
        let e = std::io::Error::from_raw_os_error(1); // EPERM
        assert!(matches!(
            SmartError::from_io("x".into(), &e),
            SmartError::Denied(_)
        ));
        let e = std::io::Error::from_raw_os_error(13); // EACCES
        assert!(matches!(
            SmartError::from_io("x".into(), &e),
            SmartError::Denied(_)
        ));
        let e = std::io::Error::from_raw_os_error(5); // EIO
        assert!(matches!(
            SmartError::from_io("x".into(), &e),
            SmartError::Failed(_)
        ));
    }

    #[test]
    fn smartctl_json_is_valid_and_has_devicehealth_keys() {
        let m = DevMeta {
            name: "0000:03:00.0".into(),
            pci: "0000:03:00.0".into(),
            kernel: false,
            ident: Ident::from_raw(b"M \"q\"", b"S1", b"F"),
            size_bytes: 4096 * 1000,
        };
        let j = render_smartctl_json(&m, &Smart::parse(&page()).unwrap(), 1_700_000_000);
        // balanced braces/brackets, escaped quote, devicehealth wear-level key
        assert_eq!(j.matches('{').count(), j.matches('}').count());
        assert_eq!(j.matches('[').count(), j.matches(']').count());
        assert!(j.contains(r#""model_name":"M \"q\"""#));
        assert!(j.contains(
            r#""nvme_smart_health_information_log":{"critical_warning":0,"temperature":40"#
        ));
        assert!(j.contains(r#""percentage_used":7"#));
        assert!(j.contains(r#""smart_status":{"passed":true"#));
        assert!(j.contains(r#""temperature_sensors":[27]"#));
        assert!(j.contains(r#""temperature":{"current":40}"#));
    }

    #[test]
    fn smartctl_json_omits_an_unavailable_temperature_sensor() {
        let m = DevMeta {
            name: "nvme0n1".into(),
            kernel: true,
            ..Default::default()
        };
        // a controller without a temperature sensor reports 0 K: smartctl leaves the keys out, never -273 C
        let s = Smart::parse(&vec![0u8; 512]).unwrap();
        let j = render_smartctl_json(&m, &s, 1_700_000_000);
        assert!(!j.contains("-273"), "{j}");
        assert!(!j.contains(r#""temperature""#), "{j}");
        assert_eq!(j.matches('{').count(), j.matches('}').count());
    }
}
