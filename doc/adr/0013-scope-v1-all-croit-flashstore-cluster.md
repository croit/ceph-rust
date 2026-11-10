# 0013 Scope v1: cluster of ONLY croit-flashstore-osd, replicated size 1-3 (supersedes 0009)
Status: accepted
Date: 2026-10-09
Goal: run a replicated (size 1, 2, 3; min_size per pool) cluster exclusively on croit-flashstore-osd for RBD. Mixed acting sets with classic OSDs still mandatory (migration path).
Consequence: our OSD serves ALL pools incl. RBD metadata pool and `.mgr` -> no "data-pool only" shortcut in final scope.
Required beyond 0009:
- xattrs + omap fully exposed to clients: omap get keys/vals/header (+by keys), set, rm keys/range, clear, set header; getxattr(s), setxattr, rmxattr, cmpxattr, omap cmp.
- cls_rbd: subset actually called by librbd for main default features (layering, exclusive-lock, object-map, fast-diff, deep-flatten) - confirmed by user 2026-10-09; journaling/mirroring later. 133 methods upstream -> derive list by tracing librbd vs real cluster; spec in spec/cls_rbd.md.
- cls_lock (all 7 methods): rbd exclusive-lock + libcephsqlite (`.mgr` pool, mgr devicehealth).
- Watch/notify full (MWatchNotify, linger reconnect, timeouts, list-watchers): rbd header + exclusive-lock depend on it.
- Object create/exclusive create, pgnls listing (rbd ls via directory omap; tooling may list).
- Pool snaps not needed for RBD (self-managed snaps only).
Staging (roadmap): M2/M3 mixed cluster, RBD data pool only (0009 subset) -> M4 omap/xattr/cls_lock/cls_rbd/watch-notify -> all-croit-flashstore-osd cluster.
In since (current scope, 2026-10-20): EC both roles (adr 0039, 0049; default on) incl. optimized EC (adr 0067; go-live default on), RGW cls (adr 0044), CephFS (adr 0041; cls_cephfs tools only).
Out: msgr1, cache tiering.
