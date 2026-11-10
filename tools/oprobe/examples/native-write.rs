// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Isolated native owned-write conformance; deterministic expected content, no perf claim.
use oprobe::client::NativeReads;
use oprobe::{Opts, Probe};
use rustyrados::{
    FrozenPayload, ReadCompletion, ReadOutcome, ReadRequest, RequestToken, Target, WriteOperation,
    WriteRequest,
};
use std::time::{Duration, Instant};

fn wait(client: &mut NativeReads, token: RequestToken) -> Result<ReadOutcome, String> {
    let end = Instant::now() + Duration::from_secs(10);
    let mut out: [Option<ReadCompletion>; 1] = [None];
    loop {
        if Instant::now() >= end {
            return Err("WARNING TIMEOUT native-write exceeded 10s (conformance)".into());
        }
        client.step()?;
        if client.poll_into(&mut out) == 1 {
            let done = out[0].take().unwrap();
            if done.token != token || client.outstanding() != 0 || client.charged_bytes() != 0 {
                return Err("completion/credit mismatch".into());
            }
            return Ok(done.outcome);
        }
    }
}

fn write(
    client: &mut NativeReads,
    target: &Target,
    operation: WriteOperation,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let route = client.prepare(target)?;
    let token = client
        .submit_write(WriteRequest {
            target: target.clone(),
            operation,
            payload: FrozenPayload::from(bytes),
        })
        .map_err(|e| format!("write admission: {e:?}"))?;
    let fence = client.fence();
    if client
        .fence_status(fence)
        .map_err(|e| format!("fence: {e:?}"))?
        != rustyrados::FenceStatus::Pending
    {
        return Err("unsent write fence prematurely ready".into());
    }
    let dispatch = client
        .dispatch(token, route)
        .map_err(|e| format!("write dispatch: {e:?}"))?;
    client.send(dispatch)?;
    match wait(client, token)? {
        ReadOutcome::Remote {
            result: 0,
            op_result: 0,
            data,
            ..
        } if data.is_empty() => {
            if client
                .fence_status(fence)
                .map_err(|e| format!("fence: {e:?}"))?
                != rustyrados::FenceStatus::Ready(Ok(()))
            {
                return Err("durable write fence not successful".into());
            }
            Ok(())
        }
        other => Err(format!("write completion: {other:?}")),
    }
}

fn verify(client: &mut NativeReads, target: &Target, expected: &[u8]) -> Result<(), String> {
    let route = client.prepare(target)?;
    let token = client
        .submit(ReadRequest {
            target: target.clone(),
            offset: 0,
            length: expected.len().max(1) as u32,
        })
        .map_err(|e| format!("read admission: {e:?}"))?;
    let dispatch = client
        .dispatch(token, route)
        .map_err(|e| format!("read dispatch: {e:?}"))?;
    client.send(dispatch)?;
    match wait(client, token)? {
        ReadOutcome::Remote {
            result: 0,
            op_result: 0,
            data,
            ..
        } if &data[..] == expected => Ok(()),
        other => Err(format!("content mismatch: {other:?}")),
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 && args.len() != 5 {
        return Err("usage: native-write POOL OBJECT crc|secure [reconnect]".into());
    }
    let mut probe = Probe::connect(Opts {
        entity: "client.rcprobe".into(),
        mode: args[3].clone(),
        keyring: Some("/etc/ceph/ceph.client.rcprobe.keyring".into()),
        ..Default::default()
    })?;
    let pool = probe.wait_pool(&args[1], 15)?;
    let retry = args.get(4).is_some_and(|arg| arg == "reconnect");
    let mut client =
        probe.native_reads_with_retry_limit(4, 32 * 1024, if retry { 2 } else { 1 })?;
    if retry {
        client
            .enable_mutation_retries()
            .map_err(|e| format!("retry policy: {e:?}"))?;
    }
    let target = Target {
        pool,
        object: args[2].as_bytes().to_vec(),
        namespace: vec![],
        locator: vec![],
    };
    let mut expected = vec![42; 4096];
    write(
        &mut client,
        &target,
        WriteOperation::WriteFull,
        expected.clone(),
    )?;
    verify(&mut client, &target, &expected)?;
    write(
        &mut client,
        &target,
        WriteOperation::Write { offset: 1024 },
        vec![43; 1024],
    )?;
    expected[1024..2048].fill(43);
    verify(&mut client, &target, &expected)?;
    write(&mut client, &target, WriteOperation::Append, vec![44; 512])?;
    expected.extend_from_slice(&[44; 512]);
    verify(&mut client, &target, &expected)?;
    write(&mut client, &target, WriteOperation::WriteFull, vec![])?;
    verify(&mut client, &target, &[])?;
    if retry {
        let route = client.prepare(&target)?;
        let token = client
            .submit_write(WriteRequest {
                target: target.clone(),
                operation: WriteOperation::Append,
                payload: FrozenPayload::from_static(b"once"),
            })
            .map_err(|e| format!("append admit: {e:?}"))?;
        client
            .set_deadline_us(token, client.monotonic_us() + 10_000_000)
            .map_err(|e| format!("append deadline: {e:?}"))?;
        let first = client
            .dispatch(token, route)
            .map_err(|e| format!("append dispatch: {e:?}"))?;
        client.send(first)?;
        let (second, original_version) = client.discard_durable_reply_and_reconnect(token)?;
        if second.token != token || second.message.retry_attempt != 1 {
            return Err("mutation retry identity changed".into());
        }
        client.send(second)?;
        if !matches!(wait(&mut client, token)?, ReadOutcome::Remote { result: 0, user_version, .. } if user_version == original_version)
        {
            return Err("append retry not durable".into());
        }
        verify(&mut client, &target, b"once")?;
        println!(
            "PASS native-append-retry mode={} tid={} appended_once=4 original_durable_version={original_version}",
            args[3],
            token.tid()
        );
    }
    println!(
        "PASS native-write mode={} full=4096 overwrite=1024 append=512 final=0 requests=8",
        args[3]
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL native-write: {e}");
        std::process::exit(1);
    }
}
