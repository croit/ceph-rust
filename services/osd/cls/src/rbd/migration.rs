// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Image migration methods (cls_rbd.md B.9).

use super::types::*;
use super::types_group::MigrationSpec;
use super::*;
use crate::ctx::ClsCtx;
use crate::errno::*;

pub const HEADER_TEXT: &[u8; 34] = b"<<< Rados Block Device Image >>>\n\0";
pub const MIGRATE_TEXT: &[u8; 34] = b"<<< Migrating RBD Image      >>>\n\0";

/// v1 header probe: classification of the first 34 data bytes.
enum Text {
    Header,
    Migrate,
    Other,
}
fn classify(h: &[u8]) -> Result<Text, Errno> {
    if h.len() != HEADER_TEXT.len() {
        return Err(ENXIO);
    }
    Ok(if h == HEADER_TEXT {
        Text::Header
    } else if h == MIGRATE_TEXT {
        Text::Migrate
    } else {
        Text::Other
    })
}

fn set_migration<C: ClsCtx>(c: &mut C, spec: &MigrationSpec, init: bool) -> Result<(), Errno> {
    if init {
        if rd_opt_raw(c, "migration")?.is_some() {
            return Err(EEXIST);
        }
        match rd_u64(c, "features") {
            Err(ENOENT) => match classify(&c.read(0, HEADER_TEXT.len() as u64)?)? {
                Text::Header => {
                    if spec.header_type != 1 {
                        return Err(EINVAL);
                    }
                    c.write(0, MIGRATE_TEXT)?;
                }
                Text::Migrate => return Err(EEXIST),
                Text::Other => return Err(ENXIO),
            },
            Err(e) => return Err(e),
            Ok(f) if f & feature::MIGRATING != 0 => {
                if spec.header_type != 2 {
                    return Err(EEXIST);
                }
            }
            Ok(f) => wr_u64(c, "features", f | feature::MIGRATING)?,
        }
    }
    wr(c, "migration", &enc(spec)?)
}

fn read_migration<C: ClsCtx>(c: &mut C) -> Result<MigrationSpec, Errno> {
    match rd_u64(c, "features") {
        Err(ENOENT) => match classify(&c.read(0, HEADER_TEXT.len() as u64)?)? {
            Text::Migrate => {}
            Text::Header => return Err(EINVAL),
            Text::Other => return Err(ENXIO),
        },
        Err(e) => return Err(e),
        Ok(f) if f & feature::MIGRATING == 0 => return Err(EINVAL),
        Ok(_) => {}
    }
    dec_stored(&rd(c, "migration")?)
}

pub fn migration_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let spec: MigrationSpec = dec_op(inp)?;
    set_migration(c, &spec, true)?;
    Ok(())
}

pub fn migration_set_state<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let state = d.u8().inval()?;
    let desc = Vec::<u8>::decode(&mut d).inval()?;
    let mut spec = read_migration(c)?;
    spec.state = state;
    spec.state_description = desc;
    set_migration(c, &spec, false)?;
    Ok(())
}

pub fn migration_get<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    enc(&read_migration(c)?)
}

pub fn migration_remove<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    match c.omap_remove_key(b"migration") {
        Ok(()) | Err(ENOENT) => {}
        Err(e) => return Err(e),
    }
    match rd_u64(c, "features") {
        Err(ENOENT) => {
            // read error ignored: an unreadable header is "wrong length"
            let h = c.read(0, HEADER_TEXT.len() as u64).unwrap_or_default();
            match classify(&h)? {
                Text::Migrate => c.write(0, HEADER_TEXT)?,
                Text::Header => return Err(EINVAL),
                Text::Other => return Err(ENXIO),
            }
        }
        Err(e) => return Err(e),
        Ok(f) if f & feature::MIGRATING != 0 => wr_u64(c, "features", f & !feature::MIGRATING)?,
        Ok(_) => {}
    }
    Ok(Vec::new())
}
