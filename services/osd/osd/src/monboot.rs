// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Short blocking mon sessions before a daemon runs (std::net, one thread, short timeouts): `croit-flashstore-tool` registration
//! (`osd new`) and the config bootstrap of `croit-flashstore-osd run` (doc/spec/osd-lifecycle.md 2.7). A classic OSD fetches the
//! options the mon config db holds for it before it starts; croit-flashstore-osd does the same for the options it consumes before its
//! own mon session is up (the memory envelope, adr 0175 am. 2).
use denc::types::EntityAddr;
use monc::{MonClient, MonEvent};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Unix seconds now.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Dial target of an address of either family (spec ip-addressing 5).
pub(crate) fn sockaddr(a: &EntityAddr) -> Option<SocketAddr> {
    a.socket_addr()
}

pub(crate) fn dial(sa: SocketAddr) -> Result<TcpStream, bool> {
    match TcpStream::connect_timeout(&sa, Duration::from_millis(1500)) {
        Ok(s) => {
            s.set_nodelay(true).ok();
            s.set_nonblocking(true).ok();
            Ok(s)
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::TimedOut {
                eprintln!("WARNING TIMEOUT tcp connect exceeded 1.5s ({sa})");
            }
            Err(e.kind() == std::io::ErrorKind::ConnectionRefused)
        }
    }
}

/// Read what is available; false = closed/error.
pub(crate) fn read_some(s: &mut TcpStream, buf: &mut [u8], mut f: impl FnMut(&[u8])) -> bool {
    loop {
        match s.read(buf) {
            Ok(0) => return false,
            Ok(n) => f(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return true,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

/// Blocking write with a timeout (mon client / shutdown flush only: a blocking write on the OSD data path
/// deadlocks two OSDs that write large messages to each other while neither reads).
pub(crate) fn write_all(s: &mut TcpStream, data: &[u8]) -> bool {
    let _ = s.set_nonblocking(false);
    let _ = s.set_write_timeout(Some(Duration::from_millis(500)));
    let r = s.write_all(data);
    if let Err(e) = &r
        && matches!(
            e.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        )
    {
        eprintln!(
            "WARNING TIMEOUT tcp write exceeded 0.5s ({} bytes, peer {:?})",
            data.len(),
            s.peer_addr().ok()
        );
    }
    let ok = r.is_ok();
    let _ = s.set_nonblocking(true);
    ok
}

/// Drive a bare [`MonClient`]: dial/IO loop that calls `f` for every event until `f` returns true or `timeout` passes.
/// Returns false on timeout.
pub fn run_mon(
    mc: &mut MonClient,
    timeout: Duration,
    mut f: impl FnMut(&mut MonClient, MonEvent) -> bool,
) -> bool {
    let t0 = Instant::now();
    let mut socks: HashMap<u64, TcpStream> = HashMap::new();
    let mut buf = vec![0u8; 1 << 16];
    mc.start(t0.elapsed());
    loop {
        let now = t0.elapsed();
        while let Some(c) = mc.poll_io() {
            match c {
                monc::IoCmd::Dial { conn, target } => match sockaddr(&target).map(dial) {
                    Some(Ok(s)) => {
                        socks.insert(conn, s);
                        mc.on_connected(conn, t0.elapsed());
                    }
                    _ => mc.on_closed(conn, t0.elapsed()),
                },
                monc::IoCmd::Close { conn } => {
                    socks.remove(&conn);
                }
            }
        }
        let ids: Vec<u64> = socks.keys().copied().collect();
        for id in ids {
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            let alive = match socks.get_mut(&id) {
                Some(s) => read_some(s, &mut buf, |b| chunks.push(b.to_vec())),
                None => continue,
            };
            for c in chunks {
                mc.on_bytes(id, &c, t0.elapsed());
            }
            if !alive {
                socks.remove(&id);
                mc.on_closed(id, t0.elapsed());
            }
        }
        for id in mc.conn_ids() {
            let out = mc.poll_output(id);
            if !out.is_empty()
                && let Some(s) = socks.get_mut(&id)
                && !write_all(s, &out)
            {
                socks.remove(&id);
                mc.on_closed(id, t0.elapsed());
            }
        }
        if mc.next_timer().is_some_and(|d| d <= t0.elapsed()) {
            mc.on_timer(t0.elapsed());
        }
        while let Some(ev) = mc.poll_event() {
            if f(mc, ev) {
                return true;
            }
        }
        if now > timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Mon session settings of OSD `whoami` as its daemon session uses them: its own key ([`crate::keysrc::resolve`];
/// `None` = no key: cephx is dropped from the method list, NONE only when the caller's list allows it), the cluster fsid, the mon hosts, the hostname (the mon resolves
/// `host:` config masks from it) and the mode list (`ms_mon_cluster_mode`).
pub fn osd_config(
    whoami: i64,
    key: Option<cephx::CryptoKey>,
    fsid: &str,
    mon_host: &str,
    hostname: String,
    modes: Option<Vec<u32>>,
) -> Result<monc::Config, String> {
    let entity = format!("osd.{whoami}");
    let mut c = monc::Config::new(&entity, key);
    c.mon_host = monc::parse_mon_host(mon_host).map_err(|e| format!("mon_host: {e}"))?;
    if c.mon_host.is_empty() {
        return Err(format!("mon_host {mon_host:?}: no address"));
    }
    c.fsid = denc::types::Uuid::parse(fsid).map_err(|e| format!("cluster fsid {fsid:?}: {e}"))?;
    c.hostname = hostname;
    let wall = unix_now();
    c.wall_origin = Duration::from_secs(wall);
    c.seed = wall ^ u64::from(std::process::id()) << 20;
    if let Some(m) = modes {
        c.modes = m;
    }
    Ok(c)
}

/// The `mon_client_*` timers from the effective option values `get` (`None` = unset: the pinned default). Classic reads
/// them on every use, so the daemon applies them at start (bootstrap and daemon sessions) and on every config change
/// (doc/spec/osd-lifecycle.md 2.2-2.3). Durations: a value <= 0 is zero (a zero `mon_client_ping_timeout` disables
/// keepalive expiry, as does a negative one in classic), one beyond the clock range never fires. The backoff and the
/// multiples must be finite and > 0 (they divide and scale every hunt interval); another value keeps the default.
pub fn mon_client_timers<'a>(get: impl Fn(&str) -> Option<&'a str>) -> monc::Timers {
    let val = |k: &str| {
        get(k)
            .and_then(|v| v.trim().parse::<f64>().ok())
            .or_else(|| crate::schema::effective_default(k).and_then(|v| v.parse().ok()))
            .unwrap_or(0.0)
    };
    let dur = |k: &str| Duration::try_from_secs_f64(val(k).max(0.0)).unwrap_or(Duration::MAX);
    let factor = |k: &str| {
        Some(val(k))
            .filter(|v| v.is_finite() && *v > 0.0)
            .or_else(|| crate::schema::effective_default(k).and_then(|v| v.parse().ok()))
            .unwrap_or(1.0)
    };
    let count = |k: &str| val(k).max(0.0) as usize;
    monc::Timers {
        hunt_parallel: count("mon_client_hunt_parallel"),
        hunt_interval: dur("mon_client_hunt_interval"),
        hunt_backoff: factor("mon_client_hunt_interval_backoff"),
        hunt_max_multiple: factor("mon_client_hunt_interval_max_multiple"),
        hunt_min_multiple: factor("mon_client_hunt_interval_min_multiple"),
        ping_interval: dur("mon_client_ping_interval"),
        ping_timeout: dur("mon_client_ping_timeout"),
        log_interval: dur("mon_client_log_interval"),
        max_log_entries: count("mon_client_max_log_entries_per_message"),
    }
}

/// Every option [`mon_client_timers`] reads.
pub const MON_CLIENT_TIMER_KEYS: &[&str] = &[
    "mon_client_hunt_parallel",
    "mon_client_hunt_interval",
    "mon_client_hunt_interval_backoff",
    "mon_client_hunt_interval_max_multiple",
    "mon_client_hunt_interval_min_multiple",
    "mon_client_ping_interval",
    "mon_client_ping_timeout",
    "mon_client_log_interval",
    "mon_client_max_log_entries_per_message",
];

/// Start-time mon session options from `get` (as [`mon_client_timers`]): the timers plus `mon_client_target_rank`
/// (>= 0 pins that rank), which classic reads once when its mon client is built.
pub fn apply_mon_client<'a>(cfg: &mut monc::Config, get: impl Fn(&str) -> Option<&'a str>) {
    cfg.set_timers(mon_client_timers(&get));
    cfg.target_rank = get("mon_client_target_rank")
        .and_then(|v| v.trim().parse::<i64>().ok())
        .and_then(|r| usize::try_from(r).ok());
}

/// How long `croit-flashstore-osd run` waits for the mon config before the daemon starts without it (the daemon's own mon session
/// waits as long for its first MConfig, `Osd` `WaitConfig`).
pub const BOOT_TIMEOUT: Duration = Duration::from_secs(10);

/// The options the mon config db holds for `cfg.entity`: one session that ends at the first MConfig (the mon sends one
/// for the `config` subscription, empty when the db holds nothing for the entity). `Err` = the mon refused the key, or no
/// MConfig within `timeout` (printed as a `WARNING TIMEOUT` line here).
pub fn fetch_config(
    cfg: monc::Config,
    timeout: Duration,
) -> Result<BTreeMap<String, String>, String> {
    let who = cfg.entity.clone();
    let mut mc = MonClient::new(cfg);
    let mut got: Option<Result<BTreeMap<String, String>, String>> = None;
    let finished = run_mon(&mut mc, timeout, |_, ev| {
        got = match ev {
            MonEvent::Config(c) => Some(Ok(c)),
            MonEvent::AuthFailed(w) => Some(Err(format!("mon auth failed: {w}"))),
            _ => None,
        };
        got.is_some()
    });
    match got {
        Some(r) => r,
        None => {
            debug_assert!(!finished);
            let e = format!(
                "mon config bootstrap exceeded {}s ({who})",
                timeout.as_secs()
            );
            eprintln!("WARNING TIMEOUT {e}");
            Err(e)
        }
    }
}

/// Mon config db options fetched at start ([`set_boot`]).
static BOOT: OnceLock<BTreeMap<String, String>> = OnceLock::new();

/// Record the mon config fetched before the daemon starts (once; a later call is ignored).
pub fn set_boot(c: BTreeMap<String, String>) {
    let _ = BOOT.set(c);
}

/// The mon config fetched before the daemon started; empty when none was (no OSD dir, mon refused or timed out).
pub fn boot() -> &'static BTreeMap<String, String> {
    static EMPTY: BTreeMap<String, String> = BTreeMap::new();
    BOOT.get().unwrap_or(&EMPTY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cephx::{CryptoKey, KeyType};
    use denc::types::UTime;

    const FSID: &str = "1d5c9f2e-8a1b-4c3d-9e7f-0a1b2c3d4e5f";

    /// Every listed timer option changes the timer set, and only the pinned defaults apply when nothing is set.
    #[test]
    fn mon_client_timers_read_every_listed_option() {
        let base = mon_client_timers(|_| None);
        assert_eq!(base, monc::Config::new("osd.0", None).timers());
        for k in MON_CLIENT_TIMER_KEYS {
            assert_ne!(mon_client_timers(|q| (q == *k).then_some("7")), base, "{k}");
        }
    }

    #[test]
    fn mon_client_values_follow_classic_semantics() {
        let t = mon_client_timers(|k| match k {
            "mon_client_ping_timeout" => Some("-1"),
            "mon_client_hunt_parallel" => Some("0"),
            "mon_client_hunt_interval_backoff" => Some("nan"),
            "mon_client_hunt_interval_max_multiple" => Some("inf"),
            "mon_client_log_interval" => Some("1e300"),
            _ => None,
        });
        assert_eq!(t.ping_timeout, Duration::ZERO, "<= 0 disables expiry");
        assert_eq!(t.hunt_parallel, 0, "0 = every candidate");
        assert_eq!(t.hunt_backoff, 1.5);
        assert_eq!(t.hunt_max_multiple, 10.0);
        assert_eq!(t.log_interval, Duration::MAX);
        let mut c = monc::Config::new("osd.0", None);
        apply_mon_client(&mut c, |k| (k == "mon_client_target_rank").then_some("2"));
        assert_eq!(c.target_rank, Some(2));
        apply_mon_client(&mut c, |k| (k == "mon_client_target_rank").then_some("-1"));
        assert_eq!(c.target_rank, None);
    }

    fn key() -> Option<CryptoKey> {
        Some(CryptoKey::generate(KeyType::Aes256Krb5, UTime::new(unix_now() as u32, 0)).unwrap())
    }

    /// No key: the config carries none (the method list decides whether NONE may run).
    #[test]
    fn osd_config_without_a_key() {
        let c = osd_config(7, None, FSID, "v2:127.0.0.1:3300", "h1".into(), None).unwrap();
        assert!(c.key.is_none());
    }

    /// The bootstrap session is the OSD's own: entity and key, fsid, hostname, `ms_mon_cluster_mode`.
    #[test]
    fn osd_config_from_the_osd_dir() {
        let c = osd_config(
            7,
            key(),
            FSID,
            "v2:127.0.0.1:3300",
            "h1".into(),
            Some(cephx::modes::parse_modes("secure").modes),
        )
        .unwrap();
        assert_eq!(c.entity, "osd.7");
        assert!(c.key.is_some());
        assert_eq!(c.fsid.to_string(), FSID);
        assert_eq!(c.hostname, "h1");
        assert_eq!(c.mon_host.len(), 1);
        assert_eq!(c.modes, cephx::modes::parse_modes("secure").modes);
        // a bad fsid or mon host: refused before any network
        assert!(osd_config(7, key(), "nope", "v2:127.0.0.1:3300", "h1".into(), None).is_err());
        assert!(osd_config(7, key(), FSID, "", "h1".into(), None).is_err());
    }

    /// No mon answers: the fetch gives up after its timeout (loud line), the caller starts without mon values.
    #[test]
    fn fetch_config_times_out_without_a_mon() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let c = osd_config(
            7,
            key(),
            FSID,
            &format!("v2:127.0.0.1:{port}"),
            "h1".into(),
            None,
        )
        .unwrap();
        let t0 = Instant::now();
        let e = fetch_config(c, Duration::from_millis(300)).unwrap_err();
        assert!(e.contains("mon config bootstrap exceeded"), "{e}");
        assert!(t0.elapsed() < Duration::from_secs(5));
    }

    /// cephx-only list and no key (classic `MonClient::init` -ENOENT): the fetch fails at once, without dialing
    /// or waiting out the timeout.
    #[test]
    fn fetch_config_without_key_and_cephx_only_fails_at_once() {
        let mut c = osd_config(7, None, FSID, "v2:127.0.0.1:1", "h1".into(), None).unwrap();
        c.methods = vec![cephx::modes::AUTH_CEPHX];
        let t0 = Instant::now();
        let e = fetch_config(c, Duration::from_secs(30)).unwrap_err();
        assert!(e.contains(monc::client::NO_AUTH_METHOD), "{e}");
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "waited {:?}",
            t0.elapsed()
        );
    }
}
