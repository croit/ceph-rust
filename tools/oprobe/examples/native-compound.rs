// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Own expected content/status fixtures for live compound/class conformance.
use oprobe::client::NativeReads;
use oprobe::{Opts, Probe};
use opwire::{OmapValsOut, OsdOp, StatOut, opflag};
use rustyrados::{Access, CompoundRequest, ReadOutcome, RequestContext, Target};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

fn exec(
    client: &mut NativeReads,
    target: &Target,
    operations: Vec<OsdOp>,
    access: Access,
) -> Result<(i32, u64, Vec<OsdOp>), String> {
    let route = client.prepare(target)?;
    let token = client
        .submit_compound(CompoundRequest {
            target: target.clone(),
            access,
            context: RequestContext::default(),
            operations,
            max_output_bytes: 65536,
        })
        .map_err(|e| format!("admit: {e:?}"))?;
    let fence = client.fence();
    let dispatch = client
        .dispatch(token, route)
        .map_err(|e| format!("dispatch: {e:?}"))?;
    client.send(dispatch)?;
    let end = Instant::now() + Duration::from_secs(10);
    let mut out = [None];
    loop {
        if Instant::now() >= end {
            return Err("WARNING TIMEOUT native-compound exceeded 10s (completion)".into());
        }
        client.step()?;
        if client.poll_into(&mut out) == 1 {
            let done = out[0].take().unwrap();
            if done.token != token || client.outstanding() != 0 || client.charged_bytes() != 0 {
                return Err("compound completion/credit mismatch".into());
            }
            let result = match done.outcome {
                ReadOutcome::RemoteCompound {
                    result,
                    user_version,
                    operations,
                    ..
                } => (result, user_version, operations),
                other => return Err(format!("wrong compound outcome: {other:?}")),
            };
            if matches!(
                client.fence_status(fence),
                Ok(rustyrados::FenceStatus::Pending)
            ) {
                return Err("completed write fence still pending".into());
            }
            client
                .retire_fence(fence)
                .map_err(|e| format!("acknowledge fence: {e:?}"))?;
            return Ok(result);
        }
    }
}

/// Reply op `i` of a compound result; a short/partial reply is an error, never an index panic.
fn out_op<'a>(output: &'a [OsdOp], i: usize, what: &str) -> Result<&'a OsdOp, String> {
    output
        .get(i)
        .ok_or_else(|| format!("short compound reply: no op {i} ({what})"))
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: native-compound POOL OBJECT crc|secure".into());
    }
    let mut probe = Probe::connect(Opts {
        entity: "client.rcprobe".into(),
        mode: args[3].clone(),
        keyring: Some("/etc/ceph/ceph.client.rcprobe.keyring".into()),
        ..Default::default()
    })?;
    let pool = probe.wait_pool(&args[1], 15)?;
    let mut client = probe.native_reads(4, 256 * 1024)?;
    let target = Target {
        pool,
        object: args[2].as_bytes().to_vec(),
        namespace: vec![],
        locator: vec![],
    };
    let values = BTreeMap::from([(b"key".to_vec(), vec![0, 255, 43])]);
    let (status, _, _) = exec(
        &mut client,
        &target,
        vec![
            OsdOp::writefull(vec![42; 4096]),
            OsdOp::setxattr(b"bin", &[255, 0, 42]),
            OsdOp::omap_set_vals(&values),
        ],
        Access::ReadWrite,
    )?;
    if status != 0 {
        return Err(format!("atomic init: {status}"));
    }
    let (status, version, output) = exec(
        &mut client,
        &target,
        vec![
            OsdOp::stat(),
            OsdOp::getxattr(b"bin"),
            OsdOp::omap_get_vals(b"", 16, b""),
        ],
        Access::Read,
    )?;
    let stat: StatOut =
        denc::from_slice(&out_op(&output, 0, "stat")?.outdata).map_err(|e| format!("stat: {e}"))?;
    let omap: OmapValsOut =
        denc::from_slice(&out_op(&output, 2, "omap")?.outdata).map_err(|e| format!("omap: {e}"))?;
    if status < 0
        || stat.size != 4096
        || out_op(&output, 1, "getxattr")?.outdata[..] != [255, 0, 42]
        || omap.vals != values
        || omap.truncated
    {
        return Err("metadata content mismatch".into());
    }
    let wrong_version = version.checked_add(1).ok_or("version overflow")?;
    let (status, _, _) = exec(
        &mut client,
        &target,
        vec![
            OsdOp::assert_version(wrong_version),
            OsdOp::setxattr(b"bin", &[9]),
        ],
        Access::ReadWrite,
    )?;
    if status != -75 {
        return Err(format!("assert rollback expected -EOVERFLOW, got {status}"));
    }
    let mut missing = OsdOp::getxattr(b"missing");
    missing.flags = opflag::FAILOK;
    let (status, _, output) = exec(
        &mut client,
        &target,
        vec![missing, OsdOp::getxattr(b"bin")],
        Access::Read,
    )?;
    if status < 0
        || out_op(&output, 0, "missing")?.rval != -61
        || out_op(&output, 1, "getxattr")?.outdata[..] != [255, 0, 42]
    {
        return Err("FAILOK/rollback metadata mismatch".into());
    }
    let (status, _, output) = exec(
        &mut client,
        &target,
        vec![OsdOp::call(b"hello", b"say_hello", b"native")],
        Access::ReadWrite,
    )?;
    let hello = out_op(&output, 0, "say_hello")?;
    if status != 0 || &hello.outdata[..] != b"Hello, native!" {
        return Err(format!("class read: {status} {:?}", hello.outdata));
    }
    let (status, _, output) = exec(
        &mut client,
        &target,
        vec![OsdOp::call(b"hello", b"write_return_data", b"")],
        Access::ReadWrite,
    )?;
    let positive = out_op(&output, 0, "write_return_data")?;
    if status != 42 || positive.rval != 42 || &positive.outdata[..] != b"you might see this" {
        return Err(format!("positive class: {status} {:?}", positive.outdata));
    }
    let (status, _, output) = exec(
        &mut client,
        &target,
        vec![OsdOp::getxattr(b"foo")],
        Access::Read,
    )?;
    if status < 0 || &out_op(&output, 0, "getxattr foo")?.outdata[..] != b"bar" {
        return Err("class mutation missing".into());
    }
    println!(
        "PASS native-compound mode={} atomic_init binary_xattr omap assertion_rollback failok class_read positive_class fence_retirement requests=7",
        args[3]
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL native-compound: {e}");
        std::process::exit(1);
    }
}
