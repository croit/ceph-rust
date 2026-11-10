// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Isolated lab coordinator controls replicas; no fabricated server messages.
use oprobe::{Opts, Probe};
use rustyrados::{ReadOutcome, ReadRequest, Target};
use std::{
    io::Write,
    path::Path,
    time::{Duration, Instant},
};
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("usage: native-backoff POOL OBJECT crc|secure SYNC_DIR".into());
    }
    let mut probe = Probe::connect(Opts {
        entity: "client.rcprobe".into(),
        mode: args[3].clone(),
        keyring: Some("/etc/ceph/ceph.client.rcprobe.keyring".into()),
        ..Default::default()
    })?;
    let pool = probe.wait_pool(&args[1], 15)?;
    let mut client = probe.native_reads_with_retry_limit(4, 32768, 4)?;
    client.enable_automatic_recovery()?;
    let target = Target {
        pool,
        object: args[2].as_bytes().to_vec(),
        namespace: vec![],
        locator: vec![],
    };
    let route = client.prepare(&target)?;
    println!("READY primary={} mode={}", route.osd, args[3]);
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let end = Instant::now() + Duration::from_secs(90);
    while !Path::new(&args[4]).join("go").exists() {
        if Instant::now() >= end {
            return Err("WARNING TIMEOUT native-backoff start marker exceeded 90s".into());
        }
        client.step()?;
    }
    let token = client
        .submit(ReadRequest {
            target,
            offset: 0,
            length: 4096,
        })
        .map_err(|e| format!("admit: {e:?}"))?;
    client
        .set_deadline_us(token, client.monotonic_us() + 60_000_000)
        .map_err(|e| format!("deadline: {e:?}"))?;
    let dispatch = client
        .dispatch(token, route)
        .map_err(|e| format!("dispatch: {e:?}"))?;
    client.send(dispatch)?;
    let mut reported = false;
    let mut out = [None];
    loop {
        if Instant::now() >= end {
            return Err("WARNING TIMEOUT native-backoff completion exceeded 90s".into());
        }
        client.step()?;
        let (blocks, releases, sends) = client.backoff_stats();
        if blocks > 0 && !reported {
            println!("BLOCKED tid={} blocks={blocks}", token.tid());
            std::io::stdout().flush().map_err(|e| e.to_string())?;
            reported = true;
        }
        if client.poll_into(&mut out) == 1 {
            let done = out[0].take().unwrap();
            if done.token != token || blocks == 0 || releases == 0 || sends == 0 {
                return Err(format!(
                    "no real recovery: blocks={blocks} releases={releases} sends={sends}"
                ));
            }
            if !matches!(done.outcome, ReadOutcome::Remote { result: 0, op_result: 0, data, .. } if data.len() == 4096 && data.iter().all(|&b| b == 42))
            {
                return Err("backoff result/content mismatch".into());
            }
            if client.outstanding() != 0 || client.charged_bytes() != 0 {
                return Err("backoff credit leak".into());
            }
            println!(
                "PASS native-backoff mode={} tid={} blocks={blocks} releases={releases} recovery_sends={sends} bytes=4096",
                args[3],
                token.tid()
            );
            break;
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL native-backoff: {e}");
        std::process::exit(1);
    }
}
