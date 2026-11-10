// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Bounded CRC/copy cells. Build with `cargo build -p crc --example bench_crc --profile rados`.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use std::{
    ffi::{c_int, c_long},
    io,
};
use std::{hint::black_box, time::Instant};

const MAX_SIZE: usize = 4 << 20;
const MAX_TOTAL: usize = 1 << 30;
const MAX_DST_SPAN: usize = 256 << 20;
const HELP: &str = "bench_crc [--format plain|json|json-pretty|jsonl] [--total-bytes N] [--sizes N,N] [--dst-span N]\n\
          [--dst-offsets START:END:STEP [--src-offset N] [--kernel NAME]]\n\
Defaults: plain, 8388608 bytes/cell, --sizes 4096,4194304, --dst-span 0. Decimal bytes only.\n\
--dst-offsets: copy cells only, source 4096-aligned and fixed, destination at (dst - src) mod 4096 = each offset of\n\
START..END (END exclusive, <= 4096, STEP >= 1, <= 1024 offsets); probes 4K address aliasing. Excludes --dst-span.\n\
--src-offset N (sweep only, 0..4095): source starts N bytes past the 4096-aligned base (absolute misalignment).\n\
--kernel NAME (sweep only): run only that kernel label (e.g. level4_vpclmul512), for per-kernel perf counters.\n\
--dst-span N: iterations rotate over size-sized, 64-byte-aligned destination slots of an N-byte region (cold\n\
destinations, like device DMA buffers); 0 = one slot (cache-hot destination). Bound 0..268435456.\n\
Kernel dispatch_nt = the store's DMA staging copy+crc (non-temporal stores where supported).\n\
Bounds: total 1..1073741824; 1..16 distinct sizes 1..4194304, each <= total.\n\
Exit 0 success/skipped unsupported levels; exit 1 verification/clock failure; exit 2 invalid CLI.\n\
Fields: operation,kernel,size_bytes,requested_total_bytes,iterations,processed_bytes,\n\
dst_offset((dst - src) mod 4096; null outside --dst-offsets),wall_ns,cpu_ns(process CPU; null off Linux64),\n\
gb_s(decimal wall GB/s),status,verified,skip_reason.\n\
No timed work runs with --help. Run measurements only on the controlled benchmark host.";

struct Options {
    format: String,
    total: usize,
    sizes: Vec<usize>,
    span: usize,
    offsets: Vec<usize>,
    src_offset: usize,
    kernel: Option<String>,
}
fn decimal(value: &str) -> Result<usize, &'static str> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected decimal byte count");
    }
    value.parse().map_err(|_| "byte count overflow")
}
fn options() -> Result<Option<Options>, &'static str> {
    let (mut format, mut total, mut sizes, mut span) =
        ("plain".into(), 8 << 20, vec![4096, MAX_SIZE], 0);
    let mut offsets = Vec::new();
    let mut src_offset = 0;
    let mut kernel = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            return Ok(None);
        }
        let value = args.next().ok_or("missing option value")?;
        match arg.as_str() {
            "--format" => format = value,
            "--total-bytes" => total = decimal(&value)?,
            "--sizes" => sizes = value.split(',').map(decimal).collect::<Result<_, _>>()?,
            "--dst-span" => span = decimal(&value)?,
            "--src-offset" => src_offset = decimal(&value)?,
            "--kernel" => kernel = Some(value),
            "--dst-offsets" => {
                let parts = value
                    .split(':')
                    .map(decimal)
                    .collect::<Result<Vec<_>, _>>()?;
                let &[start, end, step] = &parts[..] else {
                    return Err("--dst-offsets expects START:END:STEP");
                };
                if step == 0 || start >= end || end > 4096 || (end - start).div_ceil(step) > 1024 {
                    return Err("invalid --dst-offsets; see --help");
                }
                offsets = (start..end).step_by(step).collect();
            }
            _ => return Err("unknown option"),
        }
    }
    if !["plain", "json", "json-pretty", "jsonl"].contains(&format.as_str()) {
        return Err("invalid format");
    }
    if !(1..=MAX_TOTAL).contains(&total)
        || sizes.is_empty()
        || sizes.len() > 16
        || span > MAX_DST_SPAN
        || (span != 0 && !offsets.is_empty())
        || src_offset >= 4096
        || ((src_offset != 0 || kernel.is_some()) && offsets.is_empty())
    {
        return Err("invalid work bounds; see --help");
    }
    for (i, &size) in sizes.iter().enumerate() {
        if size == 0 || size > MAX_SIZE || size > total || sizes[..i].contains(&size) {
            return Err("invalid or duplicate size; see --help");
        }
    }
    Ok(Some(Options {
        format,
        total,
        sizes,
        span,
        offsets,
        src_offset,
        kernel,
    }))
}

#[derive(Clone, Copy)]
enum Method {
    Crc(u8),
    CrcDispatch,
    CopyCrc(u8),
    CopyDispatch,
    CopyDma,
    Copy,
}
impl Method {
    fn names(self) -> (&'static str, &'static str) {
        let operation = match self {
            Self::Crc(_) | Self::CrcDispatch => "crc",
            Self::CopyCrc(_) | Self::CopyDispatch | Self::CopyDma => "copy_crc",
            Self::Copy => "copy",
        };
        let kernel = match self {
            Self::Crc(1) => "level1_fallback",
            Self::Crc(2) | Self::CopyCrc(2) => "level2_crc32",
            Self::Crc(3) | Self::CopyCrc(3) => "level3_pclmul",
            Self::Crc(4) | Self::CopyCrc(4) => "level4_vpclmul512",
            Self::CrcDispatch | Self::CopyDispatch => "dispatch",
            Self::CopyDma => "dispatch_nt",
            Self::Copy => "memcpy",
            _ => unreachable!("fixed benchmark method list"),
        };
        (operation, kernel)
    }
    fn skip(self) -> Option<&'static str> {
        if let Self::Crc(level) | Self::CopyCrc(level) = self {
            if level > 1 && !cfg!(target_arch = "x86_64") {
                return Some("unsupported_architecture");
            }
            if crc::crc32c_level(level, !0, b"runtime-probe", None).is_none() {
                return Some("unsupported_runtime_level");
            }
        }
        None
    }
    fn copies(self) -> bool {
        matches!(
            self,
            Self::CopyCrc(_) | Self::CopyDispatch | Self::CopyDma | Self::Copy
        )
    }
    fn run(self, source: &[u8], destination: &mut [u8]) -> Option<u32> {
        let source = black_box(source);
        match self {
            Self::Crc(level) => crc::crc32c_level(level, !0, source, None),
            Self::CrcDispatch => Some(crc::crc32c(!0, source)),
            Self::CopyCrc(level) => {
                crc::crc32c_level(level, !0, source, Some(black_box(destination)))
            }
            Self::CopyDispatch => Some(crc::crc32c_copy(!0, source, black_box(destination))),
            Self::CopyDma => Some(crc::crc32c_copy_dma(!0, source, black_box(destination))),
            Self::Copy => {
                black_box(destination).copy_from_slice(source);
                None
            }
        }
    }
    fn verify(self, src: &[u8], dst: &[u8], sum: Option<u32>) -> Result<(), String> {
        let expected = crc::soft(!0, src);
        let (operation, kernel) = self.names();
        let size = src.len();
        let copies = self.copies();
        if (!matches!(self, Self::Copy) && sum != Some(expected))
            || (copies && (dst != src || crc::soft(!0, dst) != expected))
            || (!copies && dst.iter().any(|&b| b != 0xa5))
        {
            return Err(format!(
                "verification failed {operation}/{kernel} size {size}"
            ));
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn cpu_ns() -> Result<Option<u128>, String> {
    #[repr(C)]
    #[derive(Default)]
    struct Timespec {
        seconds: c_long,
        nanos: c_long,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: c_int, time: *mut Timespec) -> c_int;
    }
    let mut time = Timespec::default();
    // Linux LP64 CLOCK_PROCESS_CPUTIME_ID. Includes the process, not elapsed wait.
    if unsafe { clock_gettime(2, &mut time) } != 0 {
        return Err(format!("process clock: {}", io::Error::last_os_error()));
    }
    if time.seconds < 0 || !(0..1_000_000_000).contains(&time.nanos) {
        return Err("invalid process clock".into());
    }
    let nanos = time.seconds as u128 * 1_000_000_000 + time.nanos as u128;
    Ok(Some(nanos))
}
#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn cpu_ns() -> Result<Option<u128>, String> {
    Ok(None)
}

fn record(
    method: Method,
    size: usize,
    dst_offset: Option<usize>,
    total: usize,
    iters: usize,
    (wall, cpu): (Option<u128>, Option<u128>),
    skip: Option<&str>,
) -> String {
    let (operation, kernel) = method.names();
    let processed = iters * size;
    let number = |n: Option<u128>| n.map_or_else(|| "null".into(), |n| n.to_string());
    let gb_s = wall.filter(|&n| n != 0).map_or_else(
        || "null".into(),
        |n| format!("{:.6}", processed as f64 / n as f64),
    );
    let reason = skip.map_or_else(|| "null".into(), |s| format!("\"{s}\""));
    let status = if skip.is_some() { "skipped" } else { "ok" };
    // Schema strings are closed static labels: no CLI/user text needs JSON escaping.
    format!(
        r#"{{"operation":"{operation}","kernel":"{kernel}","size_bytes":{size},"requested_total_bytes":{total},"iterations":{iters},"processed_bytes":{processed},"dst_offset":{},"wall_ns":{},"cpu_ns":{},"gb_s":{gb_s},"status":"{status}","verified":{},"skip_reason":{reason}}}"#,
        number(dst_offset.map(|o| o as u128)),
        number(wall),
        number(cpu),
        skip.is_none()
    )
}
/// One timed cell. `fixed` = `--dst-offsets` mode: the source window stays at offset 0 and the reported offset is
/// `(dst - src) mod 4096`; else the source window rotates by 64 B per iteration.
fn measure(
    method: Method,
    size: usize,
    total: usize,
    src: &[u8],
    dst: &mut [u8],
    fixed: bool,
) -> Result<String, String> {
    let dst_offset =
        fixed.then(|| (dst.as_ptr() as usize).wrapping_sub(src.as_ptr() as usize) % 4096);
    if let Some(skip) = method.skip() {
        return Ok(record(
            method,
            size,
            dst_offset,
            total,
            0,
            (None, None),
            Some(skip),
        ));
    }
    let slots = (dst.len() / size).max(1);
    let window = |i: usize| {
        if fixed {
            0
        } else {
            i.wrapping_mul(64) % (src.len() - size + 1)
        }
    };
    dst.fill(0xa5);
    let sum = method.run(&src[..size], &mut dst[..size]);
    method.verify(&src[..size], &dst[..size], sum)?;
    let iterations = total / size;
    let before_cpu = cpu_ns()?;
    let start = Instant::now();
    let mut sum = None;
    for i in 0..iterations {
        let offset = window(i);
        let d = (i % slots) * size;
        sum = black_box(method.run(
            black_box(&src[offset..offset + size]),
            &mut dst[d..d + size],
        ));
    }
    let wall = Some(start.elapsed().as_nanos());
    let cpu = cpu_ns()?
        .zip(before_cpu)
        .map(|(end, start)| end.checked_sub(start).ok_or("process clock regressed"))
        .transpose()?;
    let offset = window(iterations - 1);
    let d = ((iterations - 1) % slots) * size;
    method.verify(&src[offset..offset + size], &dst[d..d + size], sum)?;
    Ok(record(
        method,
        size,
        dst_offset,
        total,
        iterations,
        (wall, cpu),
        None,
    ))
}
fn emit(format: &str, record: String, records: &mut Vec<String>) {
    // Closed schema: labels contain no quotes, braces, commas or colons.
    let record = match format {
        "plain" => record
            .replace(&['{', '}', '"'][..], "")
            .replace(':', "=")
            .replace(',', " "),
        "json-pretty" => record
            .replace('{', "{\n    ")
            .replace(',', ",\n    ")
            .replace('}', "\n  }"),
        _ => record,
    };
    if format == "jsonl" || format == "plain" {
        println!("{record}");
    } else {
        records.push(record);
    }
}
fn run(o: Options) -> Result<(), String> {
    // 4096-aligned source (the --dst-offsets sweep fixes `(dst - src) mod 4096`); one spare page for the alignment.
    let mut src_backing = vec![0u8; MAX_SIZE + 8192];
    let sbase = src_backing.as_ptr().align_offset(4096);
    let src = &mut src_backing[sbase..sbase + MAX_SIZE + 4096];
    for (i, b) in src.iter_mut().enumerate() {
        *b = (i.wrapping_mul(131).wrapping_add(i >> 8)) as u8;
    }
    let (src, swept) = (&src[..MAX_SIZE], &*src);
    // 4096-aligned destination base (64 B aligned for the non-temporal kernels; page aligned for the sweep).
    let len = o.span.max(MAX_SIZE) + 8192;
    let mut backing = vec![0xa5u8; len + 4096];
    let base = backing.as_ptr().align_offset(4096);
    let dst = &mut backing[base..base + len];
    let mut records = Vec::new();
    use Method::*;
    for &size in &o.sizes {
        if !o.offsets.is_empty() {
            for &off in &o.offsets {
                for method in [CopyCrc(3), CopyCrc(4), CopyDma, Copy] {
                    if o.kernel.as_deref().is_some_and(|k| k != method.names().1) {
                        continue;
                    }
                    let (s, d) = (o.src_offset, o.src_offset + off);
                    let record = measure(
                        method,
                        size,
                        o.total,
                        &swept[s..s + size],
                        &mut dst[d..d + size],
                        true,
                    )?;
                    emit(&o.format, record, &mut records);
                }
            }
            continue;
        }
        let crc = [Crc(1), Crc(2), Crc(3), Crc(4), CrcDispatch];
        let copy = [
            CopyCrc(2),
            CopyCrc(3),
            CopyCrc(4),
            CopyDispatch,
            CopyDma,
            Copy,
        ];
        for method in crc.into_iter().chain(copy) {
            let span = if o.span == 0 { size } else { o.span.max(size) };
            let record = measure(method, size, o.total, src, &mut dst[..span], false)?;
            emit(&o.format, record, &mut records);
        }
    }
    match o.format.as_str() {
        "json" => println!("[{}]", records.join(",")),
        "json-pretty" => println!("[\n  {}\n]", records.join(",\n  ")),
        _ => {} // Plain/JSONL emitted after each verified cell, outside its timing.
    }
    Ok(())
}
fn main() {
    match options() {
        Ok(None) => println!("{HELP}"),
        Ok(Some(options)) => {
            if let Err(error) = run(options) {
                eprintln!("ERROR bench_crc {error}");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("ERROR bench_crc {error}");
            std::process::exit(2);
        }
    }
}
