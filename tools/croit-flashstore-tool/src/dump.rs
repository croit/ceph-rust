// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `dump --dev SPEC --out DIR`: READ-ONLY forensic copy of everything but the data area: superblock A/B, shard
//! directory, per shard root A/B + WAL ring + meta region (all-zero 1 MiB chunks skipped, file is sparse).
//! Never mounts (no replay, no writes): the device is only ever read. Files: `super.txt`, `shard<N>.img`
//! (offset = (blk - region_start) * 4096). Exit: 0 ok, 1 error, 2 usage, 3 refused (device in use).
use crate::arg;
use nvme::any::DevSpec;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use store::BLK;
use store::dev::MonoClock;
use store::layout::read_super;
use store::sio::Sio;

/// Blocks of one forensic read (1 MiB at 4 KiB blocks).
const CHUNK_BLOCKS: u64 = 256;

pub fn run(a: &[String]) -> i32 {
    let Some(spec) = arg(a, "--dev") else {
        return crate::usage_err("dump: usage: dump --dev SPEC --out DIR");
    };
    let Some(out) = arg(a, "--out") else {
        return crate::usage_err("dump: usage: dump --dev SPEC --out DIR");
    };
    let dspec = match DevSpec::parse(&spec) {
        Ok(d) => d,
        Err(e) => return crate::usage_err(&format!("dump --dev {spec}: {e}")),
    };
    match dump_dir(&dspec, &spec, &out) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("croit-flashstore-tool: dump: {e}");
            crate::devopen::exit_code(&e)
        }
    }
}

/// The read-only forensic copy: open (exclusive, but only reads are issued) and copy, never mount, never write.
fn dump_dir(dspec: &DevSpec, spec: &str, out: &str) -> Result<(), String> {
    let ctrl = crate::devopen::open(dspec, false, 0).map_err(|e| format!("{spec}: {e}"))?;
    let mut dev = ctrl.open_queue()?;
    let mut clk = MonoClock::default();
    let (sb, dir) = read_super(&mut dev, &mut clk).map_err(|e| format!("superblock: {e:?}"))?;
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    crate::fsout::write_output(
        &Path::new(out).join("super.txt"),
        format!("{sb:#?}\n{dir:#?}\n").as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    let mut io = Sio::new(&mut dev, &mut clk);
    for d in &dir {
        let mut f =
            crate::fsout::create_output(&Path::new(out).join(format!("shard{}.img", d.shard)))
                .map_err(|e| e.to_string())?;
        let end = d.data_start;
        let (mut blk, mut kept) = (d.region_start, 0u64);
        while blk < end {
            let n = CHUNK_BLOCKS.min(end - blk);
            let buf = io
                .read_one(blk, n as u32)
                .map_err(|e| format!("read blk {blk}: {e:?}"))?;
            if buf.iter().any(|&x| x != 0) {
                f.seek(SeekFrom::Start((blk - d.region_start) * BLK as u64))
                    .and_then(|_| f.write_all(&buf))
                    .map_err(|e| e.to_string())?;
                kept += n;
            }
            blk += n;
        }
        f.set_len((end - d.region_start) * BLK as u64)
            .map_err(|e| e.to_string())?;
        eprintln!(
            "dump: shard {} region {}..{} nonzero blocks {kept}",
            d.shard, d.region_start, end
        );
    }
    eprintln!("dump: done -> {out}");
    Ok(())
}
