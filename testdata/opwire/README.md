# testdata/opwire
Inputs for `crates/opwire` tests (spec: `doc/spec/client-ops.md`, clarifications s15).

## Files
- `<scenario>-s<N>-c2s.bin` / `-s2c.bin`: raw msgr2 byte stream of ONE TCP connection (client->OSD / OSD->client), from the banner on, **crc mode** (`ms_client_mode=crc` via client `CEPH_ARGS` only; cluster untouched). Client 172.28.0.45 -> lab OSDs (ceph v21.1.1, 4 OSDs, pool `rbd` 3x + others). Decode with `msgr2::Banner` + `msgr2::Decoder` (`crates/opwire/tests/common`). Auth-only streams and streams > 200 KB per direction were dropped (except `rbd-basic-s16/s23`, `rbd-clone-s5`, `rbd-thick-s24` kept as big-IO samples).
- `capture/cap.sh`, `capture/scenarios.sh`: how they were produced (tcpdump + tshark follow in a helper container sharing the client's netns; `tcpdump -B 262144` is essential, default buffer drops packets on big transfers).
- `gen.sh` -> `<type>/<n>.bin|json`: ceph-dencoder goldens (request_redirect_t, obj_list_snap_response_t, obj_list_watch_response_t, pg_nls_response_t, pg_ls_response_t, watch_item_t, clone_info). MOSDOp/MOSDOpReply/MWatchNotify have 0 dencoder samples.
- `oracle.sh`: `ours/*.msg` (our encodings in dencoder wrapper form, `EMIT_SAMPLES=1 cargo test -p opwire --test samples`) decoded by the real ceph-dencoder -> `oracle/*.json` summaries asserted in tests. Note: dencoder prints MOSDOp ops as "(undecoded)" (two-phase decode); MOSDOpReply and MWatchNotify are fully decoded.
- Dev tools: `cargo run -p opwire --example summarize -- testdata/opwire [prefix | --list | --trace prefix]`, `--example dump -- testdata/opwire <op-name> [n] [reply]`.

## Totals in the committed streams
2500 MOSDOp (all header v9) + 2500 MOSDOpReply (v8) + 272 MWatchNotify (v3), all decode and re-encode byte-exact; MOSDBackoff: none observed (hand vector only).

| Op | Code | Seen | Op | Code | Seen |
|---|---|---|---|---|---|
| read | 0x1201 | 132 | omap-set-vals | 0x2215 | 4 |
| stat | 0x1202 | 176 | omap-set-header | 0x2216 | 2 |
| sparse-read | 0x1205 | 4 | omap-clear | 0x2217 | 2 |
| notify | 0x1206 | 288 | omap-rm-keys | 0x2218 | 2 |
| notify-ack | 0x1207 | 256 | copy-from (old) | 0x221a | 2 |
| list-watchers | 0x1209 | 64 | set-alloc-hint | 0x2223 | 166 |
| list-snaps | 0x120a | 34 | write-same | 0x2226 | 2 |
| omap-get-keys/vals/header/by-keys | 0x1211-14 | 2 each | getxattr / getxattrs | 0x1301/2 | 10 / 6 |
| write | 0x2201 | 256 | cmpxattr | 0x1303 | 2 |
| writefull | 0x2202 | 20 | setxattr / rmxattr | 0x2301/4 | 16 / 2 |
| truncate | 0x2203 | 2 | call | 0x1401 | 4484 |
| delete | 0x2205 | 252 | pgnls | 0x1505 | 448 |
| append | 0x2206 | 4 | create | 0x220d | 34 |
| rollback | 0x220e | 30 | watch | 0x220f | 218 |

Not seen (hand vectors only): zero, cmpext, assert-version, checksum, omap-cmp, omap-rm-key-range, pgls (legacy), cache/tier/tmap ops.

## librbd / CLI action -> ops (one line = one MOSDOp; `+` = ops inside one message; object = what it targets)
Exec classes seen: `lock.{lock,unlock,get_info,assert_locked,break_lock,list_locks}`, `rbd.{create,set_id,get_id,get_size,get_features,get_flags,get_object_prefix,get_snapcontext,get_data_pool,get_create_timestamp,get_access_timestamp,get_modify_timestamp,get_all_features,parent_get,parent_overlap_get,parent_attach,parent_detach,metadata_list,image_group_get,mirror_image_get,mirror_image_remove,snapshot_add,snapshot_get,snapshot_get_limit,snapshot_remove,snapshot_trash_add,get_protection_status,set_protection_status,set_size,object_map_load,object_map_resize,object_map_update,object_map_snap_add,object_map_snap_remove,dir_add_image,dir_remove_image,dir_get_id,dir_get_name,dir_list,add_child,remove_child,get_children,children_list,trash_add,trash_get,trash_list,trash_remove,trash_state_set,sparse_copyup,sparsify}`.

| Action | Ops (target) |
|---|---|
| `rbd create` | `stat`(rbd_id.N, ENOENT); `create + call(rbd.set_id)` (rbd_id.N); `call(rbd.dir_add_image)` (rbd_directory); `call(rbd.get_all_features)` (rbd_info); `create + call(rbd.create)` (rbd_header.ID); `call(rbd.object_map_resize)` (rbd_object_map.ID); mirroring probes `call(rbd.mirror_image_get)` ENOENT |
| image open (every rbd cmd) | `stat`+`call(rbd.get_id)` (rbd_id.N); `call(rbd.metadata_list)` (rbd_info); header reads, each its own message: `get_size+get_object_prefix+get_features`, `get_create_timestamp`, `get_access_timestamp+get_modify_timestamp`, `get_data_pool`, `get_size+get_features+get_flags+get_snapcontext+lock.get_info`, `parent_get+parent_overlap_get`, `metadata_list`, `image_group_get`; then `watch(3)` (rbd_header.ID) |
| image close | `watch(0)`; `notify`/`notify-ack` pairs (header events) |
| exclusive-lock acquire (first write) | `call(lock.get_info)`; `call(lock.lock)` (rbd_header.ID); `notify` (header, new owner); release: `call(lock.unlock)` + `notify` |
| object map attach | `call(lock.lock)`; `call(rbd.object_map_load)` (rbd_object_map.ID); later `call(lock.assert_locked) + call(rbd.object_map_update)` per state change; `call(lock.unlock)` |
| write 4K..128K to new object | `set-alloc-hint + write` (rbd_data.ID.OBJ) (header v9 flags 0x8400024) |
| write to existing object | `write` |
| read < 64K | `read`; ENOENT objects: `stat`->-2 first on clones |
| read >= 64K | `sparse-read` (reply = `map<u64,u64>` + bufferlist) |
| write into a clone (no copyup needed) | `stat + write` / `stat + set-alloc-hint + write` |
| copyup | ONE message `call(rbd.sparse_copyup) + set-alloc-hint + write` |
| `rbd snap create` | `call(rbd.snapshot_add)` (header) + `writefull` (object map snap object) / `call(lock.assert_locked)+call(rbd.object_map_snap_add)`; `notify` x2 |
| `rbd snap rm` | `call(rbd.snapshot_remove)` / `snapshot_trash_add`; `call(lock.assert_locked)+call(rbd.object_map_snap_remove)`; `delete` of snap object map |
| `rbd snap rollback` | per data object `rollback` (4-7 per message batch); `list-snaps` (snapid SNAPDIR) beforehand; `delete`s |
| `rbd snap protect/unprotect` | `call(rbd.set_protection_status)` |
| `rbd diff`, `export-diff` | `list-snaps` per object (+ `read`/`sparse-read`) |
| `rbd resize` | `call(rbd.set_size)` (header) + `call(lock.assert_locked)+call(rbd.object_map_resize)`; shrink: data object `delete`s |
| `rbd clone` | `call(rbd.parent_attach)` (child header), `call(rbd.add_child)` (rbd_children); `flatten`: `parent_detach`, `remove_child` |
| `rbd create --thick-provision` | `set-alloc-hint + write-same` per object |
| `rbd trash mv/ls/restore` | `call(rbd.trash_add)`, `trash_get`, `trash_list`, `trash_state_set`, `trash_remove` (rbd_trash); header `notify` |
| `rbd sparsify` | `call(rbd.sparsify)` |
| `rbd rm` | `delete` per data object; `call(rbd.dir_remove_image)`; `delete` of rbd_id/header/object map; `call(rbd.mirror_image_remove)` ENOENT; `call(rbd.get_children)` against **every pool** (incl. EC pool: pgid shard 0) |
| `rbd status` / `lock ls` | `list-watchers` (header); `call(lock.get_info)` |
| `rados put/get/stat/rm/append/truncate` | `write`/`writefull` (+ `set-alloc-hint + write` for striped bench), `read`, `stat`, `delete`, `append`, `truncate` |
| `rados setxattr/getxattr/listxattr/rmxattr` | `setxattr`, `getxattr`, `getxattrs`, `rmxattr` |
| `rados setomapval/listomapkeys/listomapvals/getomapval/getomapheader/setomapheader/rmomapkey/clearomap` | `omap-set-vals`, `omap-get-keys`, `omap-get-vals`, `omap-get-vals-by-keys`, `omap-get-header`, `omap-set-header`, `omap-rm-keys`, `omap-clear` |
| `rados ls` | `pgnls` per PG (flags 0x8420014, oid empty, snapid NOSNAP, indata = hobject cursor, result 1 at end) |
| `rados listsnaps` / `listwatchers` | `list-snaps`, `list-watchers` |
| `rados lock get/list/info/break` | `call(lock.lock/list_locks/get_info/break_lock)` |
| `rados watch` + `rados notify` | watch: `watch(3)` + `watch(7)` pings + `watch(0)`; notify: `notify` (reply u64 notify_id) -> MWatchNotify NOTIFY to watcher -> `notify-ack` -> MWatchNotify NOTIFY_COMPLETE (+ data segment) |
| `rados cp` | `copy-from` (0x221a, old form) |
| `rados --striper put/get/rm` | `stat + call(lock.lock)`, `create + setxattr x4`, `cmpxattr + setxattr` (U64 GT guard, ECANCELED -125 when it fails), `write`/`writefull`, `call(lock.unlock)` |
