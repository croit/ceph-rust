// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `sdk` (spec/cls_sdk.md): test-only coverage methods.

use crate::ctx::ClsCtx;
use crate::errno::*;

pub fn test_coverage_write<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Result<(), Errno> {
    c.create(false)?;
    c.stat()?;
    c.write(0, b"test")?;
    c.stat()?;
    c.setxattr("foo", b"test")?;
    c.omap_set(&[(b"foo".as_slice(), b"test".as_slice())])?;
    Ok(())
}

pub fn test_coverage_replay<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Result<(), Errno> {
    let size = c.stat()?.size;
    if c.read(0, size)?.len() as u64 != size {
        return Err(EIO);
    }
    if c.getxattr("foo")?.len() as u64 != size {
        return Err(EIO);
    }
    if c.omap_get_val(b"foo")?.len() as u64 != size {
        return Err(EIO);
    }
    c.remove()?;
    Ok(())
}
