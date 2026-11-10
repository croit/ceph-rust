// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Dev-only probe (ADR 0015 amendment: kernel TCP allowed for tests): drives `MonClient` against a
//! real mon over std::net. Run inside the devcontainer (croit-flashstore-lab-net).
//!
//!   monc_probe [--mode crc|secure|auto] [--entity client.admin] [--keyring PATH] [--mon ADDR]
//!              [--secs N] [--osdmap-start N] [--save-maps DIR] [--cmd JSON]... [--no-default-cmds] [--log-test]
use cephx::keyring::Keyring;
use monc::{Config, IoCmd, MonClient, MonEvent, parse_mon_host};
use msgr2::auth::{MODE_CRC, MODE_SECURE};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter()
        .position(|x| x == k)
        .and_then(|i| a.get(i + 1).cloned())
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = arg(&a, "--mode").unwrap_or_else(|| "auto".into());
    let entity = arg(&a, "--entity").unwrap_or_else(|| "client.admin".into());
    let keyring =
        arg(&a, "--keyring").unwrap_or_else(|| format!("/etc/ceph/ceph.{entity}.keyring"));
    let secs: u64 = arg(&a, "--secs").and_then(|s| s.parse().ok()).unwrap_or(20);
    let osd_start: u64 = arg(&a, "--osdmap-start")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut cmds: Vec<String> = a
        .windows(2)
        .filter(|w| w[0] == "--cmd")
        .map(|w| w[1].clone())
        .collect();
    if !a.iter().any(|x| x == "--no-default-cmds") && cmds.is_empty() {
        cmds.push(r#"{"prefix":"osd tree","format":"json"}"#.into());
        cmds.push(r#"{"prefix":"status","format":"json"}"#.into());
    }
    let mon_host = arg(&a, "--mon").unwrap_or_else(|| {
        std::fs::read_to_string("/etc/ceph/ceph.conf")
            .ok()
            .and_then(|t| {
                t.lines().find_map(|l| {
                    let (k, v) = l.split_once('=')?;
                    (k.trim().replace(' ', "_") == "mon_host").then(|| v.trim().to_string())
                })
            })
            .unwrap_or_else(|| "v2:172.28.0.10:3300".into())
    });
    let text =
        std::fs::read_to_string(&keyring).unwrap_or_else(|e| panic!("keyring {keyring}: {e}"));
    let kr = Keyring::parse(&text).expect("keyring parse");
    let key = kr
        .get(&entity)
        .and_then(|e| e.key.clone())
        .expect("key for entity");

    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut cfg = Config::new(&entity, Some(key));
    cfg.mon_host = parse_mon_host(&mon_host).expect("mon_host");
    cfg.wall_origin = Duration::from_secs(wall);
    cfg.seed = wall ^ (std::process::id() as u64) << 20;
    cfg.hostname = "monc-probe".into();
    cfg.modes = match mode.as_str() {
        "crc" => vec![MODE_CRC],
        "secure" => vec![MODE_SECURE],
        _ => vec![MODE_SECURE, MODE_CRC],
    };
    if let Some(t) = arg(&a, "--ticket-ttl") {
        cfg.service_ticket_ttl = t.parse().unwrap();
    }
    println!("probe: entity={entity} mon_host={mon_host} mode={mode} secs={secs}");

    let mut mc = MonClient::new(cfg);
    let t0 = Instant::now();
    let now = |t0: &Instant| t0.elapsed();
    mc.start(now(&t0));
    let mut socks: HashMap<u64, TcpStream> = HashMap::new();
    let mut cmd_tids: HashMap<u64, String> = HashMap::new();
    let mut ok = true;
    let mut sent_cmds = false;
    let mut last_print = Instant::now();
    let mut maps_seen = 0u32;
    let mut buf = vec![0u8; 1 << 16];
    let log_test = a.iter().any(|x| x == "--log-test");
    let save_maps = arg(&a, "--save-maps");
    let mut ver_h = None;
    loop {
        // io commands
        while let Some(c) = mc.poll_io() {
            match c {
                IoCmd::Dial { conn, target } => {
                    let ip = target.ipv4().map(std::net::IpAddr::from).expect("v4");
                    let sa = SocketAddr::new(ip, target.port());
                    match TcpStream::connect_timeout(&sa, Duration::from_secs(2)) {
                        Ok(s) => {
                            s.set_nodelay(true).ok();
                            s.set_nonblocking(true).unwrap();
                            socks.insert(conn, s);
                            println!(
                                "[{:6.2}] dial {sa} -> conn {conn} ok",
                                t0.elapsed().as_secs_f32()
                            );
                            mc.on_connected(conn, now(&t0));
                        }
                        Err(e) => {
                            println!("[{:6.2}] dial {sa} failed: {e}", t0.elapsed().as_secs_f32());
                            mc.on_closed(conn, now(&t0));
                        }
                    }
                }
                IoCmd::Close { conn } => {
                    socks.remove(&conn);
                }
            }
        }
        // read
        let ids: Vec<u64> = socks.keys().copied().collect();
        for id in ids {
            while let Some(s) = socks.get_mut(&id) {
                match s.read(&mut buf) {
                    Ok(0) => {
                        socks.remove(&id);
                        mc.on_closed(id, now(&t0));
                        break;
                    }
                    Ok(n) => mc.on_bytes(id, &buf[..n], now(&t0)),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        socks.remove(&id);
                        mc.on_closed(id, now(&t0));
                        break;
                    }
                }
            }
        }
        // write
        for id in mc.conn_ids() {
            let out = mc.poll_output(id);
            if out.is_empty() {
                continue;
            }
            if let Some(s) = socks.get_mut(&id) {
                // blocking write for simplicity
                s.set_nonblocking(false).unwrap();
                if s.write_all(&out).is_err() {
                    socks.remove(&id);
                    mc.on_closed(id, now(&t0));
                    continue;
                }
                s.set_nonblocking(true).unwrap();
            }
        }
        if mc.next_timer().is_some_and(|d| d <= now(&t0)) {
            mc.on_timer(now(&t0));
        }
        // events
        while let Some(ev) = mc.poll_event() {
            let ts = t0.elapsed().as_secs_f32();
            match ev {
                MonEvent::Authenticated {
                    global_id,
                    mon,
                    addr,
                    mode,
                    method,
                } => {
                    println!(
                        "[{ts:6.2}] AUTHENTICATED gid={global_id} mon={mon} {addr} mode={} method={method}",
                        if mode == MODE_SECURE { "secure" } else { "crc" }
                    );
                    mc.subscribe("osdmap", osd_start, 0);
                    ver_h = mc.get_version("osdmap");
                    if log_test {
                        mc.log(3, "cluster", "monc probe log test");
                    }
                    if !sent_cmds {
                        sent_cmds = true;
                        for c in &cmds {
                            let t = mc.send_command(c, Vec::new());
                            println!("[{ts:6.2}] cmd tid {t}: {c}");
                            cmd_tids.insert(t, c.clone());
                        }
                    }
                }
                MonEvent::SessionLost(w) => println!("[{ts:6.2}] SESSION LOST: {w}"),
                MonEvent::AuthFailed(w) => {
                    println!("[{ts:6.2}] AUTH FAILED: {w}");
                    ok = false;
                }
                MonEvent::MonMapUpdated { epoch } => {
                    let m = mc.monmap();
                    println!(
                        "[{ts:6.2}] MONMAP epoch {epoch} fsid {} mons {:?}",
                        m.fsid, m.ranks
                    );
                }
                MonEvent::OsdMap { epoch, msg, .. } => {
                    if let Some(dir) = &save_maps {
                        let _ = std::fs::create_dir_all(dir);
                        for (e, b) in &msg.incremental_maps {
                            let _ = std::fs::write(format!("{dir}/{e}.inc"), b);
                        }
                        for (e, b) in &msg.maps {
                            let _ = std::fs::write(format!("{dir}/{e}.full"), b);
                        }
                    }
                    maps_seen += 1;
                    println!(
                        "[{ts:6.2}] OSDMAP -> epoch {epoch} (msg incs {:?} fulls {:?} newest {} lb {}); held crc ok: {:?}",
                        msg.incremental_maps.keys().copied().collect::<Vec<_>>(),
                        msg.maps.keys().copied().collect::<Vec<_>>(),
                        msg.newest_map,
                        msg.cluster_osdmap_trim_lower_bound,
                        mc.osdmap()
                            .map(|m| (m.epoch, m.num_osd(), m.num_up_osd(), m.pools.len()))
                    );
                }
                MonEvent::Config(c) => println!(
                    "[{ts:6.2}] CONFIG {} keys: {:?}",
                    c.len(),
                    c.iter().take(6).collect::<Vec<_>>()
                ),
                MonEvent::CommandReply { tid, r, rs, data } => {
                    let cmd = cmd_tids.remove(&tid).unwrap_or_default();
                    let txt = String::from_utf8_lossy(&data);
                    let shown: String = txt.chars().take(300).collect();
                    println!(
                        "[{ts:6.2}] CMD REPLY tid {tid} ({cmd}) r={r} rs={rs:?} out({}B)={shown}",
                        data.len()
                    );
                    if r != 0 {
                        ok = false;
                    }
                }
                MonEvent::CommandOnceReply {
                    tid,
                    version,
                    r,
                    rs,
                    cmd,
                    data,
                } => {
                    cmd_tids.remove(&tid);
                    println!(
                        "[{ts:6.2}] CMD ONCE REPLY tid {tid} version={version} r={r} rs={rs:?} echo={cmd:?} bytes={}",
                        data.len()
                    );
                    if r != 0 {
                        ok = false;
                    }
                }
                MonEvent::CommandOnceLost { tid } => {
                    cmd_tids.remove(&tid);
                    println!("[{ts:6.2}] CMD ONCE LOST tid {tid}: remote outcome unknown");
                    ok = false;
                }
                MonEvent::VersionReply {
                    handle,
                    version,
                    oldest,
                } => println!(
                    "[{ts:6.2}] VERSION handle {handle} newest {version} oldest {oldest} (asked {ver_h:?})"
                ),
                MonEvent::VersionFailed { handle } => {
                    println!("[{ts:6.2}] VERSION FAILED {handle}")
                }
                MonEvent::KeysUpdated => {
                    let s = mc
                        .with_cephx(|c| (c.rotating().secrets.len(), c.need_mask(mc.wall_now())))
                        .unwrap_or((0, 0));
                    println!(
                        "[{ts:6.2}] KEYS UPDATED rotating={} need_mask={:#x}",
                        s.0, s.1
                    );
                }
                MonEvent::Message { tid, msg } => println!(
                    "[{ts:6.2}] MSG tid {tid} type {} {:?}",
                    msg.msg_type(),
                    format!("{msg:?}").chars().take(120).collect::<String>()
                ),
                MonEvent::Diag(s) => println!("[{ts:6.2}] diag: {s}"),
            }
        }
        if last_print.elapsed() > Duration::from_secs(10) {
            last_print = Instant::now();
            println!(
                "[{:6.2}] alive: connected={} acks={} hunts={} mode={} osdmap={:?} rotating={:?}",
                t0.elapsed().as_secs_f32(),
                mc.is_connected(),
                mc.keepalive_acks(),
                mc.hunts(),
                mc.mode(),
                mc.osdmap().map(|m| m.epoch),
                mc.with_cephx(|c| c.rotating().secrets.len())
            );
        }
        if t0.elapsed() > Duration::from_secs(secs) {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let done = mc.is_connected() && cmd_tids.is_empty() && ok;
    println!(
        "SUMMARY connected={} pending_cmds={} maps_msgs={maps_seen} mode={} acks={} osdmap_epoch={:?}",
        mc.is_connected(),
        cmd_tids.len(),
        mc.mode(),
        mc.keepalive_acks(),
        mc.osdmap().map(|m| m.epoch),
    );
    std::process::exit(if done { 0 } else { 1 });
}
