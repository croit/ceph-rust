# Reference: exit codes

| Program | Code | Meaning | Restart policy |
|---|---|---|---|
| `croit-flashstore-osd run` | 0 | Clean stop, or the id was purged or re-created | Do not restart |
| `croit-flashstore-osd run` | 1 | Runtime error | Restart |
| `croit-flashstore-osd run` | 2 | Usage error | Do not restart |
| `croit-flashstore-osd run` | 3 | Refused by policy: `require_osd_release` outside the supported window, bad configuration, or failed precondition | Do not restart hot |
| `croit-flashstore-osd run` | 78 | Store format: an offline upgrade step is needed or was interrupted (the message names the `croit-flashstore-tool upgrade` command), or a newer build wrote the store (no downgrade) | Do not restart |
| `croit-flashstore-osd run` | 134, 137 | Killed or crashed | Restart |
| `croit-flashstore-osd --check` | 0 | No FAIL (WARN passes) | - |
| `croit-flashstore-osd --check` | 1 | At least one FAIL | - |
| `croit-flashstore-osd --check` | 2 | Usage error | - |
| `croit-flashstore-tool` | 0 | OK | - |
| `croit-flashstore-tool` | 1 | Error or inconsistent store | - |
| `croit-flashstore-tool` | 2 | Usage error | - |
| `croit-flashstore-tool` | 3 | Refused: OSD running or device held | - |
| `croit-flashstore-tool` | 4 | Already prepared (`prepare` rerun) | - |
| `croit-flashstore-tool asok` | 124 | A timeout fired: socket connect, or the reply wait bounded by `--timeout <s>` (a `WARNING TIMEOUT` line names it) | - |
| `croit-flashstore-tool upgrade` | 5 | A shard lacks the free space for the upgrade; nothing was changed | - |
| `croit-flashstore-tool host-tune` | 0 | OK (a dry run is OK) | - |
| `croit-flashstore-tool host-tune` | 1 | A command failed or a re-checked item is still not ok | - |
| `croit-flashstore-tool host-tune` | 2 | Usage error | - |
| `croit-flashstore-tool host-tune` | 3 | `--apply` or `--revert` without root | - |
| `croit-flashstore-tool objectstore` | 10 | Pool of the imported PG no longer exists | - |
| `croit-flashstore-tool objectstore` | 12 | Pool split or merged since export; child or merge target already exists | - |
| `cephfs2-fuse` | 0 | OK (`version`, `status`, or a mount that ended cleanly) | - |
| `cephfs2-fuse` | 1 | Configuration, backend or mount error (no BE backend exists yet) | Restart |
| `cephfs2-fuse` | 2 | Usage error | - |

## Systemd

The unit sets `RestartPreventExitStatus=2 3 78` and `Restart=on-failure`. A refusal (3, 78) stays failed and does not loop. Crashes restart, subject to a start limit of 3 in 30 minutes.

## Containers

Without systemd, `--restart unless-stopped` loops on 0 and 3. Set `FLASHSTORE_HOLD_EXIT="0 2 3 78"` so the entry parks the container instead of exiting. Stop it with `docker stop`.
