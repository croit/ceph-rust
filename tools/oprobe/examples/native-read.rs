// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Short VM conformance: native-read POOL OBJECT LENGTH EXPECTED_BYTE QD MODE OFFSET.
//! All parallel requests read the same externally seeded object; no performance claim.
use oprobe::{Opts, Probe};
use rustyrados::{ReadOutcome, ReadRequest, Target};
use std::time::{Duration, Instant};

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if !(8..=11).contains(&args.len()) {
        return Err(
            "usage: native-read POOL OBJECT LENGTH BYTE QD crc|secure OFFSET [EXPECTED_LENGTH [EXPECTED_RESULT [plain|reconnect]]]"
                .into(),
        );
    }
    let length: u32 = args[3].parse().map_err(|_| "length")?;
    let byte: u8 = args[4].parse().map_err(|_| "byte")?;
    let qd: usize = args[5].parse().map_err(|_| "qd")?;
    let offset: u64 = args[7].parse().map_err(|_| "offset")?;
    let expected_length: usize = args.get(8).map_or(Ok(length as usize), |s| {
        s.parse().map_err(|_| "expected length")
    })?;
    let expected_result: i32 = args
        .get(9)
        .map_or(Ok(0), |s| s.parse().map_err(|_| "expected result"))?;
    let scenario = args.get(10).map(String::as_str).unwrap_or("plain");
    let deadline_case = scenario == "deadline";
    let automatic = scenario == "automatic";
    let reconnect = match scenario {
        "plain" => false,
        "reconnect" => true,
        "deadline" => false,
        "automatic" => false,
        _ => return Err("invalid retry scenario".into()),
    };
    if (reconnect || automatic) && (qd != 1 || expected_result != 0) {
        return Err("reconnect scenario requires QD1 successful read".into());
    }
    if deadline_case && (qd != 1 || expected_result != 0) {
        return Err("deadline scenario requires QD1 successful read".into());
    }
    if expected_length > length as usize {
        return Err("expected length exceeds read bound".into());
    }
    if length == 0 || qd == 0 || qd > 128 || length > 4 * 1024 * 1024 {
        return Err("bounded probe limits exceeded".into());
    }
    let mut probe = Probe::connect(Opts {
        entity: "client.rcprobe".into(),
        mode: args[6].clone(),
        keyring: Some("/etc/ceph/ceph.client.rcprobe.keyring".into()),
        ..Default::default()
    })?;
    let pool = probe.wait_pool(&args[1], 15)?;
    let mut client = probe.native_reads_with_retry_limit(
        qd,
        u64::from(length + 1024) * qd as u64,
        if reconnect || automatic { 2 } else { 1 },
    )?;
    if automatic {
        client.enable_automatic_recovery()?;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut tokens = Vec::with_capacity(qd);
    for _ in 0..qd {
        let request = ReadRequest {
            target: Target {
                pool,
                object: args[2].as_bytes().to_vec(),
                namespace: vec![],
                locator: vec![],
            },
            offset,
            length,
        };
        let route = client.prepare(&request.target)?;
        let token = client
            .submit(request)
            .map_err(|e| format!("admit: {e:?}"))?;
        if deadline_case {
            client
                .set_deadline_us(token, client.monotonic_us() + 100_000)
                .map_err(|e| format!("set deadline: {e:?}"))?;
        }
        if automatic {
            client
                .set_deadline_us(token, client.monotonic_us() + 10_000_000)
                .map_err(|e| format!("set recovery deadline: {e:?}"))?;
        }
        let dispatch = client
            .dispatch(token, route)
            .map_err(|e| format!("dispatch: {e:?}"))?;
        let initial_session = dispatch.route.session;
        client.send(dispatch)?;
        if automatic {
            client.flush_without_completions();
            client.inject_transport_loss(token)?;
        }
        if deadline_case {
            client.flush_without_completions();
            std::thread::sleep(Duration::from_millis(120));
        }
        if reconnect {
            let retry = client.reconnect_read(token)?;
            if retry.token != token
                || retry.message.retry_attempt != 1
                || retry.route.session == initial_session
            {
                return Err("retry changed identity or retained dead connection".into());
            }
            println!(
                "RETRY tid={} attempt=1 old_session={initial_session} new_session={}",
                token.tid(),
                retry.route.session
            );
            client.send(retry)?;
        }
        tokens.push(token);
    }
    let mut completed = 0;
    let mut out: Vec<_> = (0..qd).map(|_| None).collect();
    while completed < qd {
        if Instant::now() >= deadline {
            return Err("WARNING TIMEOUT native-read completion exceeded 30s".into());
        }
        client.step()?;
        let n = client.poll_into(&mut out);
        for item in &mut out[..n] {
            let completion = item.take().unwrap();
            let index = tokens
                .iter()
                .position(|&t| t == completion.token)
                .ok_or("unknown/duplicate completion")?;
            tokens.swap_remove(index);
            match completion.outcome {
                ReadOutcome::Deadline {
                    possibly_sent: true,
                } if deadline_case => {}
                ReadOutcome::Remote {
                    result,
                    op_result,
                    data,
                    ..
                } if result == expected_result
                    && !deadline_case
                    && (result < 0 || op_result == 0)
                    && data.len() == expected_length
                    && data.iter().all(|&b| b == byte) => {}
                other => return Err(format!("bad result: {other:?}")),
            }
            completed += 1;
        }
    }
    if automatic {
        let (_, _, sends) = client.backoff_stats();
        if sends != 1 {
            return Err(format!("expected one automatic recovery send, got {sends}"));
        }
        println!("AUTOMATIC original_tid=true recovery_sends={sends}");
    }
    if client.charged_bytes() != 0 || client.outstanding() != 0 {
        return Err("credit leak".into());
    }
    println!(
        "PASS native-read mode={} scenario={scenario} qd={qd} bytes={length} offset={offset} completed={completed}",
        args[6]
    );
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL native-read: {e}");
        std::process::exit(1);
    }
}
