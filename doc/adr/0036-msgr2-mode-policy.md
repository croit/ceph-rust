# 0036 msgr2 connection-mode policy honours ms_*_mode
Status: accepted
Date: 2026-10-10
Context: mixed-cluster suite (lab/docker/mixed, case 07a) found croit-flashstore-osd ignored `ms_cluster_mode`/`ms_service_mode`/`ms_mon_client_mode`: it offered and accepted `crc`+`secure` always, so a cluster configured `secure`-only (hardened croit setups) would still get crc links through croit-flashstore-osd (policy hole), and `secure`-first preference was not honoured. Ceph defaults: cluster/service/client `crc secure`, mon links `secure crc`.
Decision:
- `osd::auth::ModePolicy` (cluster = osd/mds/mgr peers, service = clients dialing us, mon = mon peers) read from the layered config (`ms_cluster_mode`, `ms_service_mode`, `ms_mon_cluster_mode`); applied to NEW connections on every config change (mon central config, `config set`, `--set`/conf file); classic reads them only at start. Unparsable or empty value keeps the default. Server side offers exactly that list (peer picks first of its list we allow), client side sends it as preferred order.
- The mon session (daemon and `croit-flashstore-osd run` config bootstrap) uses `ms_mon_cluster_mode` (am. 1), from the local file only (`--set`, conf `[osd]`/`[global]` forwarded by `croit-flashstore-osd run`), as the mon session is up before central config arrives; same as classic. `ms_mon_client_mode` applies to pure clients only (rustyrados), not to the OSD.
- Perf: only mon links default to `secure`. For the 4 GB/s single-stream target keep `ms_cluster_mode`/`ms_service_mode`/`ms_client_mode` = `crc secure` (default) or `crc`; clients that insist on `secure` still negotiate secure with us (encryption on that link costs cycles/byte, charter: off for max perf).
Consequences: + secure-only / crc-only clusters behave like classic; + runtime change without restart; - `ms_client_mode` has no meaning for the OSD (it only dials daemons).
Alternatives: hardcoded both lists (previous, permissive); restart-only config (classic semantics, worse).

## Amendment (2026-11-05, am. 1): mon session modes from `ms_mon_cluster_mode`
Context: review 2026-11-05 (B9): the daemon's mon session and the config bootstrap read `ms_mon_client_mode`; classic selects the mode list by local entity type and a non-mon daemon uses `ms_mon_cluster_mode` toward mons and mgrs (spec cephx.md 255, auth-none.md 40). Our mgr links already did. With `ms_mon_cluster_mode = secure` and a crc-first `ms_mon_client_mode`, croit-flashstore-osd offered crc where classic OSDs connect secure.
Decision: both mon sessions read `ms_mon_cluster_mode` (local config).
Consequences: + same list as classic OSDs and as our own mgr links; - a deployment that tuned `ms_mon_client_mode` for croit-flashstore-osd must move the value (classic ignores it for OSDs too).
