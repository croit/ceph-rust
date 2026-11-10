// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Dev driver CLI: `croit-flashstore-osd --id N --data DIR [--mon-host ADDR] [--public-addr IP] [--cluster-addr IP]
//! [--port-base N] [--hostname H] [--set key=val]...`
use osd::kdrv::{self, Binds};
use osd::{Osd, OsdConfig};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter()
        .position(|x| x == k)
        .and_then(|i| a.get(i + 1).cloned())
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    crate::addr::parse_addr(s).ok().map(|x| x.0)
}

/// 8 bytes of OS randomness for the OSD seed (`rt::os_random` is not part of the dev driver's build shape: the seed must
/// never be derived from the wall clock and pid alone).
fn seed() -> u64 {
    use std::io::Read;
    let mut b = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .unwrap_or_else(|e| panic!("/dev/urandom: {e}"));
    u64::from_le_bytes(b)
}

pub fn main() -> i32 {
    let a = outfmt::normalize_args(&std::env::args().collect::<Vec<_>>());
    let dev = arg(&a, "--dev");
    let Some(data) = arg(&a, "--data").or_else(|| dev.clone()) else {
        eprintln!(
            "usage: croit-flashstore-osd (--dev file:PATH|spdk:PCI | --data DIR) [--mon-host ADDR] [--public-addr IP] [--cluster-addr IP] [--port-base N] [--hostname H] [--set k=v]..."
        );
        return 2;
    };
    let mon_host = match osddir::mon_host_from_args(&a) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("croit-flashstore-osd: {e}");
            return 2;
        }
    };
    let mons = match monc::parse_mon_host(&mon_host) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("mon_host: {e}");
            return 2;
        }
    };
    let mon_ip = mons
        .first()
        .and_then(|m| m.v2())
        .and_then(|a| a.ip().map(|ip| (ip, a.port())));
    let public = arg(&a, "--public-addr")
        .and_then(|s| parse_ip(&s))
        .or_else(|| mon_ip.and_then(|(ip, p)| kdrv::local_ip_towards(ip, p)));
    let Some(public) = public else {
        eprintln!("cannot determine public address (use --public-addr)");
        return 2;
    };
    let cluster = arg(&a, "--cluster-addr")
        .and_then(|s| parse_ip(&s))
        .unwrap_or(public);
    let wall = osd::monboot::unix_now();
    let hostname = arg(&a, "--hostname").unwrap_or_else(osd::sysinfo::short_hostname);
    let local_config = osd::config::local_config(
        a.windows(2)
            .filter(|w| w[0] == "--set")
            .map(|w| w[1].as_str()),
    );
    eprintln!(
        "croit-flashstore-osd: {}",
        osd::nvmestore::set_memory_target(&local_config, osd::monboot::boot())
    );
    if let Err(e) = osd::nvmestore::set_store_options(&local_config) {
        eprintln!("croit-flashstore-osd: {e}");
        return 2;
    }
    let psel = match osd::portsel::PortSelect::from_config(
        arg(&a, "--port-base").as_deref(),
        &local_config,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    // the four listeners are bound on the first free ports of ms_bind_port_min..max (or the explicit --port-base)
    let ips = [public, cluster, public, cluster];
    let kinds: [Vec<SocketAddr>; 4] = std::array::from_fn(|i| vec![SocketAddr::new(ips[i], 0)]);
    let kind_refs: [&[SocketAddr]; 4] = std::array::from_fn(|i| kinds[i].as_slice());
    let (ports, listeners) = match osd::portsel::bind_with(&psel, kind_refs, |p| {
        kdrv::bind_listeners(&Binds {
            public: vec![SocketAddr::new(ips[0], p[0])],
            cluster: vec![SocketAddr::new(ips[1], p[1])],
            hb_front: vec![SocketAddr::new(ips[2], p[2])],
            hb_back: vec![SocketAddr::new(ips[3], p[3])],
        })
    }) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let cfg = OsdConfig {
        hostname,
        public_ips: vec![public],
        cluster_ips: vec![cluster],
        public_port: ports[0],
        cluster_port: ports[1],
        hb_front_port: ports[2],
        hb_back_port: ports[3],
        mon_host: mons,
        wall_origin_unix: wall,
        wall_from_clock: true,
        seed: seed(),
        nonce: osd::sysinfo::fresh_nonce(),
        sys_metadata: osd::sysinfo::collect(),
        local_config,
        // `--set` only: every entry is a command-line setting
        local_sources: Default::default(),
        data_path: data.clone(),
        rdma: false,
        placement: false,
        // source-pull (adr 0665) is kernel tier only: `args::source_pull_lab_enabled` refuses it for other tiers
        source_pull: false,
    };
    if let Some(spec) = &dev {
        return match osd::nvmestore::open_dev_spec(spec) {
            Ok((p, r)) => {
                println!("croit-flashstore-osd: {r}");
                match Osd::<osd::Nvme<nvme::any::AnyDev, store::dev::MonoClock>>::with_pg_store(
                    cfg, p.meta, p.pgs,
                ) {
                    Ok(o) => drive(o, listeners),
                    Err(e) => {
                        eprintln!("croit-flashstore-osd: {e}");
                        1
                    }
                }
            }
            Err(e) => {
                eprintln!("--dev {spec}: {e}");
                1
            }
        };
    }
    let store = match osd::FileMetaStore::open(&data, osd::FileMetaStore::DEFAULT_SIZE) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    match Osd::new(cfg, store) {
        Ok(o) => drive(o, listeners),
        Err(e) => {
            eprintln!("croit-flashstore-osd: {e}");
            1
        }
    }
}

fn drive<B: osd::Backend>(mut osd: Osd<B>, listeners: kdrv::Listeners) -> i32 {
    let _obs = crate::obs::setup(&mut osd);
    let stop = kdrv::stop_flag_on_signals();
    let t0 = Instant::now();
    let r = kdrv::run_osd(&mut osd, listeners, &stop, |l| {
        crate::obs::emit(
            t0,
            osd::LogLine {
                prio: 0,
                text: l.to_owned(),
            },
        );
    });
    match r {
        Ok(c) => c,
        Err(e) => {
            eprintln!("croit-flashstore-osd: {e}");
            1
        }
    }
}
