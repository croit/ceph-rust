// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Listener port selection (spec osd-lifecycle.md, "Listener ports"). Without an explicit override every OSD
//! listener (public, cluster, heartbeat front, heartbeat back) takes the first free TCP port of
//! `[ms_bind_port_min, ms_bind_port_max]` (defaults 6800..7568), skipping ports in use and ports already taken by the
//! OSD's other listeners. A range without room for all four is retried `ms_bind_retry_count` more times, waiting
//! `ms_bind_retry_delay` seconds before each retry, then the start fails. A port given in `public_addr` /
//! `cluster_addr` ([`PortSelect::with_addr_ports`]) is bound exactly for that listener (a taken one is retried the
//! same way); the heartbeat listeners always search. `--port-base N` / `flashstore_port_base` is an explicit override:
//! exactly `N..N+3`, no search, no retry.
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

/// Port choice of one OSD process.
#[derive(Clone, Debug, PartialEq)]
pub struct PortSelect {
    /// `--port-base`: the four listeners take `N..N+3` or the start fails.
    pub explicit: Option<u16>,
    /// `ms_bind_port_min`.
    pub min: u16,
    /// `ms_bind_port_max`.
    pub max: u16,
    /// `ms_bind_retry_count`: repeats of the whole search after the first.
    pub retry_count: u32,
    /// `ms_bind_retry_delay` seconds between searches.
    pub retry_delay: f64,
    /// Ports of `public_addr` / `cluster_addr` for the public / cluster listener; 0 = search.
    pub addr_ports: [u16; 2],
}

impl PortSelect {
    /// From the daemon's local config (`--set k=v`, the last setting of a key wins) and the `--port-base` flag; the
    /// flag wins over the conf key `flashstore_port_base` (`croit-flashstore-osd run` emits both from the one effective option map).
    pub fn from_config(explicit: Option<&str>, local: &[(String, String)]) -> Result<Self, String> {
        fn get<T: std::str::FromStr>(
            local: &[(String, String)],
            key: &str,
            default: T,
        ) -> Result<T, String> {
            match crate::config::local_get(local, key) {
                None => Ok(default),
                Some(v) => v
                    .trim()
                    .parse()
                    .map_err(|_| format!("bad {key} {:?}", v.trim())),
            }
        }
        let from_conf = crate::config::local_get(local, "flashstore_port_base").map(str::trim);
        let explicit = explicit
            .or(from_conf)
            .map(|s| {
                s.parse::<u16>()
                    .ok()
                    .filter(|b| *b <= u16::MAX - 3)
                    .ok_or_else(|| format!("bad --port-base {s:?} (1..65532)"))
            })
            .transpose()?;
        let me = Self {
            explicit,
            min: get(local, "ms_bind_port_min", 6800)?,
            max: get(local, "ms_bind_port_max", 7568)?,
            retry_count: get(local, "ms_bind_retry_count", 3)?,
            retry_delay: get(local, "ms_bind_retry_delay", 5.0)?,
            addr_ports: [0, 0],
        };
        if me.explicit.is_none() && (me.min == 0 || u32::from(me.max) < u32::from(me.min) + 3) {
            return Err(format!(
                "ms_bind_port_min {}..ms_bind_port_max {}: the range must hold 4 ports",
                me.min, me.max
            ));
        }
        if !me.retry_delay.is_finite() || me.retry_delay < 0.0 {
            return Err(format!("bad ms_bind_retry_delay {}", me.retry_delay));
        }
        Ok(me)
    }

    /// The public / cluster listener ports of `public_addr` / `cluster_addr` (0 = none given): bound exactly, as
    /// classic binds an address that carries a port. With `--port-base` too it is an error (two explicit sources).
    pub fn with_addr_ports(mut self, public: u16, cluster: u16) -> Result<Self, String> {
        if let Some(b) = self.explicit
            && (public != 0 || cluster != 0)
        {
            return Err(format!(
                "--port-base/flashstore_port_base {b} and a port in public_addr/cluster_addr ({public}/{cluster}): set one"
            ));
        }
        self.addr_ports = [public, cluster];
        Ok(self)
    }

    /// Short description for the startup line.
    pub fn describe(&self) -> String {
        match (self.explicit, self.addr_ports) {
            (Some(b), _) => format!("explicit {b}..{}", b + 3),
            (None, [0, 0]) => format!("first free of {}..{}", self.min, self.max),
            (None, [p, c]) => format!(
                "public {} cluster {} (address ports, 0 = search), others first free of {}..{}",
                p, c, self.min, self.max
            ),
        }
    }
}

/// Is `a` not taken by another socket? A plain bind without `SO_REUSEPORT`: any listener on the address, also one that
/// joined a reuse-port group, makes it fail with `AddrInUse`. Any other bind error (not a local address, no permission)
/// is no reason to skip the port: the real bind reports it.
fn free(a: SocketAddr) -> bool {
    !matches!(TcpListener::bind(a), Err(e) if e.kind() == io::ErrorKind::AddrInUse)
}

/// Ports for the four listener kinds, pairwise distinct: the address ports as given (the bind tells whether they are
/// free), the others the first free ones of the range; `None` = the range is exhausted. One port per kind is shared by
/// that kind's address families (each of them must be free; classic scans per entry and usually lands on two ports).
fn search(
    sel: &PortSelect,
    ips: [&[SocketAddr]; 4],
    free: impl Fn(SocketAddr) -> bool,
) -> Option<[u16; 4]> {
    let mut out = [sel.addr_ports[0], sel.addr_ports[1], 0, 0];
    for i in 0..4 {
        if out[i] == 0 {
            out[i] = (sel.min..=sel.max).find(|p| {
                !out.contains(p) && ips[i].iter().all(|a| free(SocketAddr::new(a.ip(), *p)))
            })?;
        }
    }
    Some(out)
}

/// Pick ports and run `bind` on them; `bind` takes the real sockets and returns them (a port lost between the search
/// and the bind, `AddrInUse`, starts the next search). Returns the ports and what `bind` returned.
/// Failure: an explicit override that is taken, a non-`AddrInUse` bind error, or the exhausted retries (printed as
/// `WARNING TIMEOUT`); the message is ready for the operator.
pub fn bind_with<T>(
    sel: &PortSelect,
    ips: [&[SocketAddr]; 4],
    bind: impl FnMut([u16; 4]) -> io::Result<T>,
) -> Result<([u16; 4], T), String> {
    run(sel, |s| search(s, ips, free), bind)
}

fn run<T>(
    sel: &PortSelect,
    search: impl Fn(&PortSelect) -> Option<[u16; 4]>,
    mut bind: impl FnMut([u16; 4]) -> io::Result<T>,
) -> Result<([u16; 4], T), String> {
    if let Some(b) = sel.explicit {
        let ports = [b, b + 1, b + 2, b + 3];
        return bind(ports)
            .map(|t| (ports, t))
            .map_err(|e| format!("listen on the explicit ports {b}..{}: {e}", b + 3));
    }
    let mut last = String::new();
    for attempt in 0..=sel.retry_count {
        if attempt > 0 {
            eprintln!(
                "croit-flashstore-osd: WARNING no free listener ports in {}..{} ({last}); retry {attempt}/{} in {}s",
                sel.min, sel.max, sel.retry_count, sel.retry_delay
            );
            std::thread::sleep(Duration::from_secs_f64(sel.retry_delay));
        }
        let Some(ports) = search(sel) else {
            last = "range exhausted".into();
            continue;
        };
        match bind(ports) {
            Ok(t) => return Ok((ports, t)),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                last = if sel.addr_ports == [0, 0] {
                    e.to_string()
                } else {
                    format!("{e}; public_addr/cluster_addr ports {:?}", sel.addr_ports)
                }
            }
            Err(e) => return Err(format!("listen: {e}")),
        }
    }
    let limit = f64::from(sel.retry_count) * sel.retry_delay;
    eprintln!(
        "croit-flashstore-osd: WARNING TIMEOUT bind listener ports exceeded {limit}s (ms_bind_port_min {}..ms_bind_port_max {}, \
         ms_bind_retry_count {}, ms_bind_retry_delay {}s)",
        sel.min, sel.max, sel.retry_count, sel.retry_delay
    );
    Err(format!(
        "no free listener ports in {}..{} after {} retries ({last}); widen ms_bind_port_min/ms_bind_port_max or stop the \
         other daemons",
        sel.min, sel.max, sel.retry_count
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const LO: Ipv4Addr = Ipv4Addr::LOCALHOST;

    /// The tests share the host port space: one at a time.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Window `n` wide of ports that were free a moment ago (ephemeral pick, then a neighbourhood).
    fn window(n: u16) -> u16 {
        loop {
            let p = TcpListener::bind((LO, 0))
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            if p > 20000 && p < 60000 && (p..p + n).all(|q| TcpListener::bind((LO, q)).is_ok()) {
                return p;
            }
        }
    }

    fn sel(min: u16, max: u16, explicit: Option<u16>) -> PortSelect {
        PortSelect {
            explicit,
            min,
            max,
            retry_count: 1,
            retry_delay: 0.01,
            addr_ports: [0, 0],
        }
    }

    fn listen(ports: [u16; 4]) -> io::Result<Vec<TcpListener>> {
        ports.iter().map(|p| TcpListener::bind((LO, *p))).collect()
    }

    /// One IPv4 address per listener kind, port 0 (the search supplies it).
    fn one_set() -> [Vec<SocketAddr>; 4] {
        std::array::from_fn(|_| vec![SocketAddr::from((LO, 0))])
    }

    fn lo_sets() -> [&'static [SocketAddr]; 4] {
        // leak: test-only, four tiny vectors per process
        let v: &'static [Vec<SocketAddr>; 4] = Box::leak(Box::new(one_set()));
        std::array::from_fn(|i| v[i].as_slice())
    }

    #[test]
    fn two_osds_one_ip_skip_foreign_socket() {
        let _g = serial();
        let min = window(16);
        let foreign = TcpListener::bind((LO, min + 1)).unwrap();
        let s = sel(min, min + 15, None);
        let ips = [
            vec![SocketAddr::from((LO, 0))],
            vec![SocketAddr::from((LO, 0))],
            vec![SocketAddr::from((LO, 0))],
            vec![SocketAddr::from((LO, 0))],
        ];
        let ips: [&[SocketAddr]; 4] = std::array::from_fn(|i| ips[i].as_slice());
        let (p1, _l1) = bind_with(&s, ips, listen).unwrap();
        let (p2, _l2) = bind_with(&s, ips, listen).unwrap();
        assert_eq!(p1, [min, min + 2, min + 3, min + 4], "foreign port skipped");
        assert_eq!(p2, [min + 5, min + 6, min + 7, min + 8]);
        assert!(!p1.contains(&foreign.local_addr().unwrap().port()));
    }

    #[test]
    fn lost_race_searches_again() {
        let _g = serial();
        let min = window(16);
        let s = sel(min, min + 15, None);
        let mut thief = None;
        let (p, _l) = bind_with(&s, lo_sets(), |p| {
            // somebody takes the first port between the search and the bind, once
            if thief.is_none() {
                thief = Some(TcpListener::bind((LO, p[0])).unwrap());
            }
            listen(p)
        })
        .unwrap();
        assert_eq!(p[0], min + 1);
    }

    #[test]
    fn exhausted_range_fails_after_retries() {
        let _g = serial();
        let min = window(4);
        let held: Vec<_> = (min..min + 4)
            .map(|p| TcpListener::bind((LO, p)).unwrap())
            .collect();
        let e = bind_with(&sel(min, min + 3, None), lo_sets(), listen).unwrap_err();
        assert!(
            e.contains("no free listener ports") && e.contains("retries"),
            "{e}"
        );
        drop(held);
    }

    #[test]
    fn explicit_override_exact_or_error() {
        let _g = serial();
        let b = window(4);
        let (p, l) = bind_with(&sel(6800, 7568, Some(b)), lo_sets(), listen).unwrap();
        assert_eq!(p, [b, b + 1, b + 2, b + 3]);
        let e = bind_with(&sel(6800, 7568, Some(b)), lo_sets(), listen).unwrap_err();
        assert!(e.contains("explicit ports") && e.contains("in use"), "{e}");
        drop(l);
    }

    /// A port in `public_addr` / `cluster_addr` is bound exactly (review B6: it was dropped for a random port); the
    /// heartbeat listeners search around it; a taken address port fails after the retries, never moves.
    #[test]
    fn address_ports_are_bound_exactly() {
        let _g = serial();
        let min = window(16);
        let s = sel(min, min + 7, None)
            .with_addr_ports(min + 12, min)
            .unwrap();
        let (p, l) = bind_with(&s, lo_sets(), listen).unwrap();
        assert_eq!(p, [min + 12, min, min + 1, min + 2]);
        let e = bind_with(&s, lo_sets(), listen).unwrap_err();
        assert!(e.contains("public_addr/cluster_addr ports"), "{e}");
        drop(l);
        // public only: the cluster listener searches
        let s = sel(min, min + 7, None).with_addr_ports(min + 1, 0).unwrap();
        let (p, _l) = bind_with(&s, lo_sets(), listen).unwrap();
        assert_eq!(p, [min + 1, min, min + 2, min + 3]);
        assert!(
            sel(min, min + 7, Some(min))
                .with_addr_ports(min + 1, 0)
                .is_err(),
            "--port-base plus an address port"
        );
    }

    #[test]
    fn config_defaults_and_overrides() {
        let d = PortSelect::from_config(None, &[]).unwrap();
        assert_eq!(
            (d.min, d.max, d.retry_count, d.retry_delay),
            (6800, 7568, 3, 5.0)
        );
        let l = vec![
            ("ms_bind_port_min".to_owned(), "7000".to_owned()),
            ("ms-bind-port-max".to_owned(), "7100".to_owned()),
            ("ms_bind_retry_count".to_owned(), "0".to_owned()),
        ];
        let c = PortSelect::from_config(Some("6900"), &l).unwrap();
        assert_eq!(
            (c.explicit, c.min, c.max, c.retry_count),
            (Some(6900), 7000, 7100, 0)
        );
        assert!(
            PortSelect::from_config(None, &[("ms_bind_port_max".into(), "6802".into())]).is_err()
        );
        assert!(PortSelect::from_config(Some("x"), &[]).is_err());
        // conf key alone, and the flag winning over it
        let k = vec![("flashstore_port_base".to_owned(), "7000".to_owned())];
        assert_eq!(
            PortSelect::from_config(None, &k).unwrap().explicit,
            Some(7000)
        );
        assert_eq!(
            PortSelect::from_config(Some("7100"), &k).unwrap().explicit,
            Some(7100)
        );
    }
}
