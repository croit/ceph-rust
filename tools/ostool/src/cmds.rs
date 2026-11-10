// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Store level commands: fsck, statfs, dump-super, get/set-superblock, get/set (inc) osdmap.
use crate::{Ctx, R, fail};
use denc::{Decode, Encode};
use messages::OsdSuperblock;
use osd::meta::{MapKind, MetaStore};
use std::io::Write;
use store::dev::{BlockDev, Clock};

pub fn op_fsck<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, deep: bool) -> R {
    let rep =
        c.ad.with_store(|s| s.check(deep))
            .map_err(|e| format!("fsck failed: {e}"))?;
    writeln!(
        c.err,
        "fsck: {} collections, {} onodes, {} omap keys, {} data blocks{}",
        rep.colls,
        rep.onodes,
        rep.omap_keys,
        rep.data_blocks,
        if deep {
            " (deep: every block checksum verified)"
        } else {
            ""
        }
    )?;
    for e in rep.errors.iter().take(50) {
        writeln!(c.err, "fsck: {e}")?;
    }
    if !rep.errors.is_empty() {
        return fail(format!(
            "fsck status: {} remaining error(s) and warning(s)",
            rep.errors.len()
        ));
    }
    writeln!(c.out, "fsck success")?;
    Ok(())
}

pub fn op_statfs<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let s = c.meta.statfs();
    let v = serde_json::json!({
        "total": s.total, "available": s.available, "internally_reserved": s.internally_reserved,
        "allocated": s.allocated, "data_stored": s.data_stored, "data_compressed": s.data_compressed,
        "data_compressed_allocated": s.data_compressed_allocated,
        "data_compressed_original": s.data_compressed_original,
        "omap_allocated": s.omap_allocated, "internal_metadata": s.internal_metadata,
    });
    crate::json::emit(c.out, &c.o.format, &v)?;
    Ok(())
}

/// `(oldest, newest)` epoch of the stored map range: the superblock's `mapc` intervals (start -> length).
pub(crate) fn map_range(sb: &OsdSuperblock) -> R<(u32, u32)> {
    let oldest = sb
        .mapc
        .keys()
        .next()
        .copied()
        .unwrap_or(sb.cluster_osdmap_trim_lower_bound);
    let Some((&start, &len)) = sb.mapc.iter().next_back() else {
        return Ok((oldest, sb.current_epoch));
    };
    // a superblock can come from `set-superblock` (a file): an empty or overflowing range is corrupt, not a wrap
    let newest = start
        .checked_add(len)
        .and_then(|end| end.checked_sub(1))
        .filter(|_| len > 0);
    match newest {
        Some(newest) => Ok((oldest, newest)),
        None => fail(format!("superblock map range {start}+{len} is corrupt")),
    }
}

pub fn op_dump_super<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let sb = crate::superblock(c)?;
    let (oldest, newest) = map_range(&sb)?;
    let v = crate::json::super_json(&sb, oldest, newest);
    crate::json::emit(c.out, &c.o.format, &v)?;
    Ok(())
}

fn out_file<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, data: &[u8]) -> R {
    match c.o.file.as_deref() {
        None | Some("-") => {
            if c.o.tty {
                return fail("stdout is a tty and no --file filename specified");
            }
            c.out.write_all(data)?;
        }
        Some(f) => crate::create_output(f, true)?
            .write_all(data)
            .map_err(|e| format!("Failed to write to {f}: {e}"))?,
    }
    Ok(())
}

fn in_file<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R<Vec<u8>> {
    match c.o.file.as_deref() {
        None | Some("-") => {
            if c.o.stdin_tty {
                return fail("stdin is a tty and no --file filename specified");
            }
            match c.input.as_mut() {
                Some(i) => crate::read_capped(i, crate::MAX_INPUT, "stdin"),
                None => Ok(Vec::new()),
            }
        }
        Some(f) => crate::read_capped_file(f, crate::MAX_INPUT),
    }
}

pub fn op_get_super<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let sb = crate::superblock(c)?;
    let b = sb.encode_to_vec().map_err(|e| format!("encode: {e}"))?;
    out_file(c, &b)?;
    writeln!(c.err, "superblock exported.")?;
    Ok(())
}

pub fn op_set_super<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let b = in_file(c)?;
    let sb = OsdSuperblock::decode(&mut denc::Decoder::new(&b))
        .map_err(|e| format!("Failed to read superblock: {e}"))?;
    // the guard may only be skipped when there is no stored superblock yet: an unreadable one is an error
    match c.meta.load_superblock() {
        Ok(Some(cur)) if cur.cluster_fsid != sb.cluster_fsid && !c.o.force => {
            return fail(
                "superblock cluster_fsid differs from the stored one (--force to replace)",
            );
        }
        Ok(_) => {}
        Err(e) => return fail(format!("Failure to read OSD superblock: {e}")),
    }
    if !c.o.dry_run {
        c.meta
            .store_superblock(&sb)
            .map_err(|e| format!("Error setting superblock: {e}"))?;
        crate::checkpoint(c)?;
    }
    writeln!(c.out, "Superblock was set")?;
    Ok(())
}

pub fn op_get_map<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, inc: bool) -> R {
    let e = match c.o.epoch {
        Some(e) if e != 0 => e,
        _ => crate::superblock(c)?.current_epoch,
    };
    let blob = if inc {
        c.meta
            .get_map(e, MapKind::Inc)
            .map_err(|x| x.to_string())?
            .ok_or_else(|| {
                format!("Failed to get incremental osdmap# {e}: No such file or directory")
            })?
    } else {
        crate::pg::map_blob(c, e).map_err(|x| format!("Failed to get osdmap#{e}: {}", x.msg))?
    };
    out_file(c, &blob)?;
    writeln!(
        c.err,
        "{}osdmap#{e} exported.",
        if inc { "inc-" } else { "" }
    )?;
    Ok(())
}

pub fn op_set_map<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, inc: bool) -> R {
    let b = in_file(c)?;
    let got = if inc {
        osdmap::Incremental::decode_from(&b).map(|i| i.epoch)
    } else {
        osdmap::OsdMap::decode_from(&b).map(|m| m.epoch)
    }
    .map_err(|e| format!("Failed to decode the map: {e}"))?;
    let e = match c.o.epoch {
        Some(e) if e != 0 && e != got => {
            writeln!(c.err, "epoch mismatch: {got} != {e}")?;
            if !c.o.force {
                return fail("epoch of the file differs from --epoch");
            }
            writeln!(c.err, "But will continue anyway.")?;
            e
        }
        _ => got,
    };
    let kind = if inc { MapKind::Inc } else { MapKind::Full };
    let exists = c
        .meta
        .get_map(e, kind)
        .map_err(|x| x.to_string())?
        .is_some();
    if !exists {
        writeln!(
            c.err,
            "{}osdmap ({e}) does not exist.",
            if inc { "inc-" } else { "" }
        )?;
        if !c.o.force {
            return fail("map does not exist (--force creates a new epoch)");
        }
        writeln!(c.out, "Creating a new epoch.")?;
    }
    if c.o.dry_run {
        return Ok(());
    }
    let sb = crate::superblock(c)?;
    c.meta
        .commit_maps(&[(e, kind, b)], &sb)
        .map_err(|x| x.to_string())?;
    crate::checkpoint(c)
}
