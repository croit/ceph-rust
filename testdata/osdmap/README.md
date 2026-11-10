# osdmap / mon golden data (from the docker lab cluster)

Generated from the nvmeosd lab reference cluster (`nvmeosd/lab/docker`).
Ceph: `ceph version 21.1.1 (815bc6b6f9b4e0fd98daed552ec8e7123a0a8f84) umbrella`, image `quay.io/ceph/ceph:v21.1.1`.
Cluster fsid `6d2f4f0e-6e1a-4a64-9a55-6e766d65736f`, 1 mon, 3 OSDs (bluestore), msgr2 + cephx. Final epoch 91, HEALTH_OK.

## Files
- `full/NNNN.bin`: full OSDMap for every epoch 1..91 (`ceph osd getmap <epoch> -o`). Binary.
- `inc/NNNN.bin`: OSDMap::Incremental for epoch N (N = 1..91), read raw from a copy of the mon store
  (`ceph-kvstore-tool rocksdb <copy>/store.db get osdmap N out ...`; keys `osdmap/N`).
- `expected/osd_dump.json`: `ceph osd dump -f json` at epoch 91.
- `expected/osdmaptool_test_map_pgs_dump.txt`, `..._dump_all.txt`: `osdmaptool --test-map-pgs-dump[-all]` on epoch 91.
- `expected/osdmaptool_dump.json`: `osdmaptool --dump json` on epoch 91.
- `expected/osdmaptool_print_final.txt`, `expected/osdmaptool_print_{1,5,12,24,33,45,58,66}.txt`: `osdmaptool --print` (text).
- `expected/osdmaptool_health_final.txt`: `osdmaptool --health` on epoch 91.
- `expected/pgs_brief.json`: `ceph pg dump pgs_brief -f json` at epoch 91 (up/acting per PG).
- `expected/objmap.json`: one JSON object per line, `ceph osd map <pool> <obj> [<nspace>] -f json`, epoch 91.
  Includes namespaces, spaces, slashes, `%`, `:`, `.`, `..`, quotes/backslash, UTF-8, 150+ char names.
- `expected/inc_final.json`: `ceph-dencoder OSDMap::Incremental decode dump_json` of `inc/0091.bin`.
- `dencoder/<Type>/<i>.bin|.json`: `ceph-dencoder type <T> select_test <i> encode export` and `dump_json`
  for all generated instances of OSDMap, OSDMap::Incremental (dir `OSDMap_Incremental`), pg_pool_t,
  pool_snap_info_t, osd_info_t, osd_xinfo_t, OSDSuperblock, osd_stat_t. Instance counts: 2,1,5,2,2,2,3,2.
- `../mon/monmap.bin` (`ceph mon getmap`, epoch 1), `../mon/monmap.print.txt` (`monmaptool --print`),
  `../mon/dencoder/{MonMap,mon_info_t}/<i>.bin|.json`.

## Epoch history (variety)
Epochs 1-24: bootstrap (pools rbd, .mgr). 25-33: pools nv_rep1 (size 1), nv_rep2 (size 2), nv_rep3 (size 3).
36-42: EC pools nv_ec (default profile), nv_ec_opt (profile nv_k2m1), allow_ec_optimizations on both.
44-45: pool snapshot on nv_rep3 (rbd refused mksnap: unmanaged snaps mode). 46-47: pg-upmap-items.
48: primary-affinity osd.1 0.5. 49: reweight osd.2 0.8. 50-54: noout set/unset, osd out/in 2.
55-56: blocklist add (later removed). 57-58: pool nv_rep_tiny, pg_num 8. 62: pg-temp 4.3.
65: nv_rep2 min_size 1. 66-77: restore (affinity, reweight, upmaps, blocklist, pool nv_rep1 removed) -> HEALTH_OK at 77.
78: pg-temp cleared. 79: nv_ec removed (default k=2,m=2 EC cannot place on 3 OSDs; left PGs undersized -> HEALTH_WARN).
80-91: pg autoscaler epochs; 88-91: application `rados` enabled on nv_rep2, nv_rep3, nv_rep_tiny, nv_ec_opt.
Not done: pg-upmap-primary (needs min_compat_client reef, not changed).

## Notes
- Mgr-owned blocklist entries (172.28.0.11:*) existed before generation and are present in the maps.
- Config changes made temporarily and removed again: mon_allow_pool_size_one, mon_allow_pool_delete.
- Pools left in the cluster: rbd, .mgr, nv_rep2, nv_rep3, nv_rep_tiny, nv_ec_opt.
- Full maps are named by epoch with 4-digit zero padding (`0001.bin` = epoch 1).

## purge/ (lab, 2026-10-09, same cluster after adding+purging osd.3)
`full_0113.bin`, `full_0114.bin` (`ceph osd getmap`), `inc_0114.bin` (via MonClient MOSDMap). Epoch 114 = `osd purge 3`: the inc's
crush blob has max_devices=4, the mon's full map re-encodes it with 3 (max device id in buckets or name_map, +1).
