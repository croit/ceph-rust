# 0171 knet dials bind the messenger's own address; stale cluster links are swept per map (am. to 0053)
Status: accepted
Date: 2026-10-18
Context: zen4 z4 has two interfaces in the test network (100G PF + old virtio). Outbound kernel-TCP dials of osd.4 left through the virtio NIC: the kernel picks route + source, croit-flashstore-osd did not bind. Classic has `ms_bind_before_connect` (default false; deployments with multi-homed hosts turn it on).
Decision:
1. Every dial of the knet tier binds the dialling messenger's own IP before connect: cluster + heartbeat back = cluster addr, public + heartbeat front + mon link = public addr (`Osd::dial_src`, `IoCmd::Dial.src`). Always on (KISS; classic's default off only preserves the route-picks-source behaviour). Port: automatic (`IP_BIND_ADDRESS_NO_PORT`, chosen at connect) or the steered port of `pick_src_port` (same IP). Bind failure (address not local) = dial failure, loud on stderr, no fallback to the route's pick. Policy routing (`from <ip> lookup <table>`, lab VMs) then selects the right device.
2. Cluster links (`pg.peers`) dialled for an older incarnation of a peer are closed on every map that names a newer `up_from` (`pg_peer_sweep`, in `pg_maps`). Before, such a lossless link was only replaced when something was next sent to the peer, and redialled the dead nonce every 15 s (ms_max_backoff): the restarted OSD logged `target addr is not ours` (full-equality target check, spec msgr2 10.5) every 15 s. Found live: the baseline osd.3 (old BASE_BIN) held such a link for 22000 s (1423 faults); the sweep needs the dialer to run the fix.
3. The cluster fault line names the dialer on accepted links too: peer socket, the addrs it claims, the target it dialled (`Connection::ident_claim`).
Siblings: DPDK/own TCP stack has one configured IPv4 per stack and always sources from it (`Stack::src_for`): not affected, `src` ignored. AF_XDP uses the same stack. Client tools (oprobe, monc_probe) have no bind address (classic clients neither): not affected. `osd::kdrv` (std `TcpStream`, lab/dev driver, single host): does not bind, not used on multi-homed hosts. Replicated/EC, crc/secure: transport-level, same path.
Gate: lab/baremetal/knet-dial-gate.sh (zen4 r3), handoff doc/perf/knet-dial-20261018.md.

## Amendment 1 (2026-11-05): the source bind follows the target's family

Decision 1 says "binds the dialling messenger's own IP". A dial target can now be of either family
(adr 0659-ip-address-families):
- The source is the dialling messenger's own address of the target's family (`Osd::dial_src`, `IoCmd::Dial.src` =
  `Option<IpAddr>`). With both families enabled, every messenger holds one address per family; the source is the entry
  that matches the target.
- We hold no address of the target's family: the socket stays unbound. knet never binds a cross-family source (classic's
  `ms_bind_before_connect` is broken that way with dual-stack, spec ip-addressing 4/8).
- A source bind failure of an address we do hold is still a loud dial failure (level 0, once per peer purpose and
  family), no fallback to the route's pick.
