# 0032 Adaptive idle polling (no 100 % burn when idle)
Status: accepted, amended (am. 1; the tier design below is superseded in part). Date 2026-10-10.
Problem: thread-per-core busy-poll (0006) burns 100 % per core even idle; hosts run 10-24 OSDs.
Decision: per-core tiered idle, load path unchanged:
1. busy-poll while work seen (rx, mesh, NVMe completions with IOs in flight, due timers).
2. idle > T1 (default 100 us): monitor/wait on rx descriptor + mesh ring heads: x86 UMWAIT/TPAUSE (Intel), MONITORX/MWAITX (AMD); fallback PAUSE loop. Use DPDK rte_power_pmd_mgmt monitor mode where available. Wake sub-us.
3. idle > T2 (default 1 ms): arm NIC rx interrupt (rte_eth_dev_rx_intr_enable), eventfd doorbell for cross-core mesh (sender rings only if target flagged sleeping), epoll_wait(timeout = next timer deadline). Wake ~10-30 us.
NVMe: poll completions only while IOs outstanding (no IO -> nothing to poll). SPDK interrupt mode not needed.
Config: osd idle thresholds T1/T2; T2=off for max-perf deployments. Lab af_packet: stage 3 via fd poll.
Cost: first packet after >T2 idle pays interrupt latency; none under sustained load.

## Amendment 1 (2026-10-25): idle = measured wake latency + ring sleep
Decision: UMWAIT/TPAUSE, MONITORX/MWAITX, fixed T1/T2 thresholds and NIC rx-interrupt arming (steps 2-3) were not built. Implemented idle (knet, default): a core with a quiet store and no mesh backlog sleeps in its io_uring at once (cap 1 ms); while the store is busy it polls for one measured wake latency, then timer-sleeps by learned bounds; cross-core mesh sends poke sleepers by eventfd (adr 0053 "Idle and busy poll", adr 0162, adr 0004 am. 1). AF_XDP/DPDK poll-mode loops keep a fixed idle. `rt::core_loop` keeps a lab-only fixed sleep (`umwait: later` comment, not implemented).
