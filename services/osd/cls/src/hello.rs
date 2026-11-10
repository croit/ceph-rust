// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `hello` (spec/cls_hello.md): example/test methods incl. deliberate flag violators.

use crate::ctx::ClsCtx;
use crate::errno::*;
use crate::registry::Reply;

fn greeting(input: &[u8]) -> Vec<u8> {
    let mut v = b"Hello, ".to_vec();
    if input.is_empty() {
        v.extend_from_slice(b"world");
    } else {
        v.extend_from_slice(input);
    }
    v.push(b'!');
    v
}

fn origin_text<C: ClsCtx>(c: &C) -> String {
    let o = c.origin();
    format!("{} {}", o.name, o.addr)
}

fn fail(e: Errno) -> Reply {
    Reply {
        ret: e,
        out: Vec::new(),
    }
}

pub fn say_hello<C: ClsCtx>(_c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    if input.len() > 100 {
        return Err(EINVAL);
    }
    Ok(greeting(input))
}

pub fn record_hello<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    if input.len() > 100 {
        return Err(EINVAL);
    }
    if c.stat().is_ok() {
        return Err(EEXIST);
    }
    c.write_full(&greeting(input))?;
    let who = origin_text(c);
    c.setxattr("said_by", who.as_bytes())?;
    Ok(())
}

/// Also registered as `writes_dont_return_data`.
pub fn write_return_data<C: ClsCtx>(c: &mut C, input: &[u8]) -> Reply {
    if let Err(e) = c.setxattr("foo", b"bar") {
        return fail(e);
    }
    if !input.is_empty() {
        return Reply {
            ret: EINVAL,
            out: b"too much input data!".to_vec(),
        };
    }
    Reply {
        ret: 42,
        out: b"you might see this".to_vec(),
    }
}

pub fn write_too_much_return_data<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Reply {
    if let Err(e) = c.setxattr("foo", b"bar") {
        return fail(e);
    }
    let out = b"you should not see this because it is toooooo long. ".repeat(10);
    Reply { ret: 42, out }
}

pub fn replay<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Result<Vec<u8>, Errno> {
    c.read(0, 1100)
}

pub fn turn_it_to_11<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    if !input.is_empty() {
        return Err(EINVAL);
    }
    let mut d = c.read(0, 1100)?;
    d.make_ascii_uppercase();
    c.write_full(&d)?;
    let who = origin_text(c);
    c.setxattr("amplified_by", who.as_bytes())?;
    Ok(())
}

/// Registered WR-only but reads: the executor must answer -EIO. Returns the byte count.
pub fn bad_reader<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Reply {
    match c.read(0, 100) {
        Ok(out) => Reply {
            ret: out.len() as i32,
            out,
        },
        Err(e) => fail(e),
    }
}

/// Registered RD-only but writes: the executor must answer -EIO.
pub fn bad_writer<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    c.write_full(input)?;
    Ok(())
}
