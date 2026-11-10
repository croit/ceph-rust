// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Lab-only kernel adapter for standalone rustyrados Bootstrap; never uses Probe.
use cephx::{CryptoKey, key::KeyType, keyring::Keyring};
use denc::types::Uuid;
use monc::IoCmd;
use rustyrados::{Bootstrap, BootstrapConfig, BootstrapError, BootstrapState, MessengerMode};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: native-bootstrap MON_HOST FSID crc|secure ready|wrong-fsid|wrong-key".into(),
        );
    }
    let mode = match args[3].as_str() {
        "crc" => MessengerMode::Crc,
        "secure" => MessengerMode::Secure,
        _ => return Err("mode".into()),
    };
    let scenario = args[4].as_str();
    let expected = match scenario {
        "ready" => None,
        "wrong-fsid" => Some(BootstrapError::FsidMismatch),
        "wrong-key" => Some(BootstrapError::AuthRejected),
        _ => return Err("scenario".into()),
    };
    let fsid = Uuid::parse(&args[2]).map_err(|_| "FSID")?;
    let keyring = std::fs::read_to_string("/etc/ceph/ceph.client.rcprobe.keyring")
        .map_err(|_| "keyring read")?;
    let ring = Keyring::parse(&keyring).map_err(|_| "keyring parse")?;
    let key = if scenario == "wrong-key" {
        CryptoKey::new(KeyType::Aes, Default::default(), &[99; 16])
    } else {
        ring.get("client.rcprobe")
            .and_then(|e| e.key.clone())
            .ok_or("key missing")?
    };
    let origin = Instant::now();
    let mut b = Bootstrap::new(BootstrapConfig {
        entity: "client.rcprobe".into(),
        key,
        monitors: monc::parse_mon_host(&args[1]).map_err(|_| "monitor address")?,
        expected_fsid: Some(if scenario == "wrong-fsid" {
            Uuid([9; 16])
        } else {
            fsid
        }),
        mode,
        startup_timeout: Duration::from_secs(15),
        wall_origin_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "wall clock")?
            .as_secs(),
    })
    .map_err(|e| format!("configure: {e:?}"))?;
    b.start(origin.elapsed())
        .map_err(|e| format!("start: {e:?}"))?;
    let mut sockets = HashMap::new();
    let mut buf = [0; 64 * 1024];
    let hard_end = origin + Duration::from_secs(30);
    loop {
        if Instant::now() >= hard_end {
            return Err("WARNING TIMEOUT native-bootstrap exceeded 30s (bootstrap)".into());
        }
        for _ in 0..32 {
            let Some(io) = b.poll_io() else {
                break;
            };
            match io {
                IoCmd::Close { conn } => {
                    sockets.remove(&conn);
                }
                IoCmd::Dial { conn, target } => {
                    let ip = target
                        .ipv4()
                        .map(IpAddr::from)
                        .or_else(|| target.ipv6().map(|a| IpAddr::V6(Ipv6Addr::from(a))))
                        .ok_or("address family")?;
                    match TcpStream::connect_timeout(
                        &SocketAddr::new(ip, target.port()),
                        Duration::from_secs(2),
                    ) {
                        Ok(s) => {
                            s.set_nodelay(true).map_err(|_| "nodelay")?;
                            s.set_nonblocking(true).map_err(|_| "nonblocking")?;
                            s.set_write_timeout(Some(Duration::from_secs(1)))
                                .map_err(|_| "write timeout")?;
                            sockets.insert(conn, s);
                            b.on_connected(conn, origin.elapsed());
                        }
                        Err(_) => b.on_closed(conn, origin.elapsed()),
                    }
                }
            }
        }
        for id in b.connection_ids() {
            let out = b.poll_output(id);
            if let Some(s) = sockets.get_mut(&id) {
                if !out.is_empty() {
                    s.set_nonblocking(false).map_err(|_| "blocking write")?;
                    let sent = s.write_all(&out).is_ok();
                    s.set_nonblocking(true).map_err(|_| "nonblocking read")?;
                    if !sent {
                        b.on_closed(id, origin.elapsed());
                        continue;
                    }
                }
                for _ in 0..16 {
                    match s.read(&mut buf) {
                        Ok(0) => {
                            b.on_closed(id, origin.elapsed());
                            break;
                        }
                        Ok(n) => b.on_bytes(id, &buf[..n], origin.elapsed()),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            b.on_closed(id, origin.elapsed());
                            break;
                        }
                    }
                }
            }
        }
        if b.next_timer().is_some_and(|d| origin.elapsed() >= d) {
            b.on_timer(origin.elapsed());
        }
        match b.state() {
            BootstrapState::Ready if expected.is_none() => {
                let map = b.osdmap().ok_or("missing map")?;
                if map.fsid != fsid
                    || b.fsid() != Some(fsid)
                    || b.identity().is_none()
                    || map.epoch == 0
                {
                    return Err("readiness invariant".into());
                }
                let has_osd_ticket = b
                    .with_cephx(|c| c.ticket(cephx::none::ENTITY_OSD).is_some())
                    .unwrap_or(false);
                if !has_osd_ticket {
                    return Err("missing OSD ticket".into());
                }
                println!(
                    "PASS native-bootstrap mode={} scenario=ready epoch={} identity=true osd_ticket=true",
                    args[3], map.epoch
                );
                break;
            }
            BootstrapState::Failed(error) if expected == Some(error) => {
                println!(
                    "PASS native-bootstrap mode={} scenario={scenario} rejection={error:?}",
                    args[3]
                );
                break;
            }
            BootstrapState::Failed(error) => return Err(format!("bootstrap: {error:?}")),
            BootstrapState::Ready => return Err("unexpected readiness".into()),
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    b.close();
    while let Some(io) = b.poll_io() {
        match io {
            IoCmd::Close { conn } => {
                sockets.remove(&conn);
            }
            _ => return Err("dial after close".into()),
        }
    }
    if !sockets.is_empty() {
        return Err("monitor socket leak".into());
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL native-bootstrap: {e}");
        std::process::exit(1);
    }
}
