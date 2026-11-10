# 0022 OSD core M1 design choices
Status: accepted, amended (am. 1)
Date: 2026-10-09
Context: M1 OSD boots into a real cluster (spec/osd-lifecycle.md). Several choices were left open there.
Decision:
- `osd` crate = sans-IO `Osd` (driver API like monc/msgr2: Dial/Close, on_accept/on_bytes/poll_output, time in). Embeds `MonClient`; conn ids `1<<62|id` = mon, others own. Six messengers: public, cluster, hb front/back server, hb front/back client; mgr = client-role conn on public. `MetaStore` trait = seam to the NVMe store; `FileMetaStore` = dev-only dir impl (emulated device size).
- Dev driver (std::net, polling, blocking dial/write with short timeouts) = `osd::kdrv`, cargo feature `kernel-probe` (croit-flashstore-osd: default off; croit-flashstore-tool: default on). Production DPDK driver replaces it.
- Public addr: configured explicitly (ip + port + per-process nonce), not learned from the mon connection; MonClient advertises it (`Config::my_addrs`) so the mon records it as our public addr.
- osdmap subscription: one-shot while booting, then a standing sub (spec U3) from epoch+1 after ACTIVE.
- Wrongly-marked-down rebind: same ports, new nonce for cluster + hb addrs (nonce is part of the identity compared by the mon); public keeps its identity.
- Heartbeat peers: ring neighbours + fill with successive up OSDs up to `osd_heartbeat_min_peers`; crush-subtree diversity not modelled (identical while <= min_peers up OSDs). Ping history survives connection loss so a dead peer still times out.
- Tell auth: only tickets whose osd caps contain `allow *`. Unknown prefix -> -ENOENT. `debug_up_thru <epoch>` = dev hook that exercises MOSDAlive.
- mkfs key type AES256KRB5 (AES keys make the mon raise AUTH_INSECURE_SERVICE_KEY_TYPE and refuse auth on umbrella). `osd new` secrets carry `crush_device_class`. A pending uuid+key file makes mkfs rerunnable after a crash between `osd new` and local persistence.
- Version identity: tracked release (21.2.0 umbrella; `CEPH_VERSION_SHORT` in `services/osd/osd/src/version.rs`) + `(dev - croit-flashstore-osd)` build suffix, so `ceph versions` shows croit-flashstore-osd separately (ADR 0019 keys apply).
Consequences: + M1 proven live (up/in, heartbeats both ways, mgr, tell, restart, down/rebind, clean stop). - map gossip to peers, hb_pingtime stats, admin socket, config_bl deltas not done.

## Amendment 1 (2026-10-25): the standing osdmap sub survives one-shot map requests
Decision: while ACTIVE every osdmap subscription request is sent standing (flags 0, from the requested start); one-shot (ONETIME) only before ACTIVE (boot, waiting for healthy, after a wrong mark-down).
Rationale: a one-shot request (map gap, PG waiting for an epoch, YOU_DIED, `get_latest_osdmap`) replaced the standing entry in the monc table and at the mon; after its answer the OSD got new epochs only by the random mon push or a heartbeat YOU_DIED (up to ~6.5 s). A primary marked down while alive then sent MOSDMarkMeDead late, and the new primary waited for its read lease that long (doc/perf/recov-scrub-20261025.md). Classic has no standing sub and relies on peer map sharing (spec osd-lifecycle 3.9, not built here); the standing sub covers the same need without peer gossip.
Consequences: + down-but-alive OSDs learn their mark-down at the next mon commit. - none new (mon fan-out of a standing sub was already accepted). Test `core_tests::boot_sequence_up_and_beacon`.
