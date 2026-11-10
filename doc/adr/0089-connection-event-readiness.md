# 0089 Per-core connection event readiness
Status: accepted
Date: 2026-10-14
Context: performance finding 4, event portion. OSD pump allocated an ID vector and visited every link for each progress round, including idle links. Output already used ADR 0074's readiness primitive.

Decision:
- Reuse that primitive in a separate per-core EventQueue. Reserve notifications at cold connection registration; coalesce one queued token per registration. Notify when an empty event deque gains an event, including pre-registration dials and events created during handoff adoption.
- Dispatch only notified, input-ready links with pending events. Keep each connection's event FIFO and existing pump progress rounds. Monitor IO/events remain the existing constant-size poll; superseded session cleanup stays separate.
- An input pause consumes its notification and retains its event deque. Successful destination admission explicitly re-arms remaining events before pump, so buffered frames resume without new wire input. No repeated idle probes of a blocked link.
- Detach event registration before cross-core handoff and attach it on the owning core. Drop cancels the registration's queued token by cell identity, preventing stale notification accumulation under connection churn. Notification/pop allocate nothing; registration reserves capacity and drop cleanup is cold work over ready tokens.
- No next_timer, deadline handling, scheduling-budget, store FIFO, authentication or wire changes. Timers remain the separately gated portion of finding 4.

Validation: empty pump visits zero of 1,000 idle links; active-event benchmark measures visits and time as idle count grows; notification coalescing/re-arm/pre-existing dial/drop tests; existing buffered admission, handoff, relay close and ordering suites; native/LINUX kernel runtime suites. Results: `../perf/codex-perf3-2026-10-13.md`.
