// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use oprobe::client::NativeReads;
use oprobe::{Opts, Probe};
use rustyrados::{
    ControlOperation, ControlRequest, FrozenPayload, ReadOutcome, Target, WatchEvent, WatchKind,
};
use std::time::{Duration, Instant};

fn exec(
    client: &mut NativeReads,
    target: &Target,
    operation: ControlOperation,
) -> Result<FrozenPayload, String> {
    let route = client.prepare(target)?;
    let token = client
        .submit_control(ControlRequest {
            target: target.clone(),
            operation,
        })
        .map_err(|e| format!("control admit: {e:?}"))?;
    let dispatch = client
        .dispatch(token, route)
        .map_err(|e| format!("dispatch: {e:?}"))?;
    client.send(dispatch)?;
    let end = Instant::now() + Duration::from_secs(10);
    let mut out = [None];
    loop {
        if Instant::now() >= end {
            return Err("WARNING TIMEOUT native-watch control completion exceeded 10s".into());
        }
        client.step()?;
        if let Some(error) = client.poll_watch_error() {
            return Err(format!("watch error: {error:?}"));
        }
        if client.poll_into(&mut out) == 1 {
            let done = out[0].take().unwrap();
            if done.token != token {
                return Err("control token mismatch".into());
            }
            return match done.outcome {
                ReadOutcome::Remote {
                    result: 0,
                    op_result: 0,
                    data,
                    ..
                } => Ok(data),
                other => Err(format!("control result: {other:?}")),
            };
        }
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: native-watch POOL OBJECT crc|secure".into());
    }
    let mut probe = Probe::connect(Opts {
        entity: "client.rcprobe".into(),
        mode: args[3].clone(),
        keyring: Some("/etc/ceph/ceph.client.rcprobe.keyring".into()),
        ..Default::default()
    })?;
    let pool = probe.wait_pool(&args[1], 15)?;
    let mut client = probe.native_reads(8, 65536)?;
    let target = Target {
        pool,
        object: args[2].as_bytes().to_vec(),
        namespace: vec![],
        locator: vec![],
    };
    let route = client.prepare(&target)?;
    let watch = client
        .reserve_watch(target.clone(), route, WatchKind::Watch)
        .map_err(|e| format!("reserve watch: {e:?}"))?;
    exec(
        &mut client,
        &target,
        ControlOperation::Register {
            cookie: watch.cookie(),
            timeout_seconds: 30,
        },
    )?;
    client
        .activate_watch(watch, 0)
        .map_err(|e| format!("activate: {e:?}"))?;
    exec(
        &mut client,
        &target,
        ControlOperation::Ping {
            cookie: watch.cookie(),
            generation: 0,
        },
    )?;
    let notifier = client
        .reserve_watch(target.clone(), route, WatchKind::Notify)
        .map_err(|e| format!("reserve notify: {e:?}"))?;
    let immediate = exec(
        &mut client,
        &target,
        ControlOperation::Notify {
            cookie: notifier.cookie(),
            timeout_seconds: 5,
            payload: FrozenPayload::from_static(b"native notification"),
        },
    )?;
    let id = u64::from_le_bytes(
        immediate[..]
            .try_into()
            .map_err(|_| "initial notify ID size")?,
    );
    client
        .initial_notify_id(notifier, id)
        .map_err(|e| format!("initial notify: {e:?}"))?;
    let end = Instant::now() + Duration::from_secs(10);
    let mut acked = false;
    let mut completed = false;
    while !completed {
        if Instant::now() >= end {
            return Err("WARNING TIMEOUT native-watch notification exceeded 10s".into());
        }
        client.step()?;
        if let Some(error) = client.poll_watch_error() {
            return Err(format!("event error: {error:?}"));
        }
        while let Some(event) = client.poll_watch() {
            match event {
                WatchEvent::Notification {
                    cookie,
                    notify_id,
                    payload,
                    ..
                } => {
                    if cookie != watch.cookie()
                        || notify_id != id
                        || payload != b"native notification"
                    {
                        return Err("notification mismatch".into());
                    }
                    exec(
                        &mut client,
                        &target,
                        ControlOperation::NotifyAck {
                            cookie,
                            notify_id,
                            response: FrozenPayload::from_static(b"native ack"),
                        },
                    )?;
                    acked = true;
                }
                WatchEvent::NotifyComplete {
                    cookie,
                    notify_id,
                    result,
                    data,
                } => {
                    let aggregate: opwire::NotifyCompleteData =
                        denc::from_slice(&data).map_err(|e| format!("aggregate: {e}"))?;
                    if cookie != notifier.cookie()
                        || notify_id != id
                        || result != 0
                        || !acked
                        || aggregate.replies.len() != 1
                        || aggregate.replies.iter().any(|((_, cookie), bytes)| {
                            *cookie != watch.cookie() || bytes != b"native ack"
                        })
                        || !aggregate.missed.is_empty()
                    {
                        return Err("final notify aggregate mismatch".into());
                    }
                    completed = true;
                }
            }
        }
    }
    exec(
        &mut client,
        &target,
        ControlOperation::Unwatch {
            cookie: watch.cookie(),
        },
    )?;
    client
        .remove_watch(watch)
        .map_err(|e| format!("remove watch: {e:?}"))?;
    client
        .remove_watch(notifier)
        .map_err(|e| format!("remove notify: {e:?}"))?;
    if client.watch_charged_bytes() != 0 || client.charged_bytes() != 0 || client.outstanding() != 0
    {
        return Err("watch/control credit leak".into());
    }
    println!(
        "PASS native-watch mode={} register ping notify explicit_ack final_aggregate unwatch requests=5",
        args[3]
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL native-watch: {e}");
        std::process::exit(1);
    }
}
