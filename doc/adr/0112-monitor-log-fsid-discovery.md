# 0112 Monitor logs wait for cluster FSID discovery

Status: accepted
Date: 2026-10-14
Context: a clean-main sans-IO regression receives MLog with FSID zero after authentication when MonMap discovery has not finished. Command sending already waits for configured/discovered FSID; log sending did not. The separate perf4 wire investigation also exposes reentrant Ready -> Subscription -> buffered MonMap -> command replay.

Decision:
- Retain managed logs unsent while cluster FSID is unknown. Do not allocate an MLog tid or consume the retained entries at that point.
- Flush genuinely held logs when MonMap first provides FSID. During an enclosing Ready resend, let that enclosing handler finish its existing command pass and flush logs at its existing position; the nested callback must not move valid log output earlier.
- Keep held-log state across session loss and an incomplete zero-FSID map. A later valid map resumes without another log entry or periodic tick.
- Reject caller-provided zero-FSID MLog through generic sending. Do not invent fields or rewrite payloads. Preserve the existing failed-send tid-allocation convention. Do not blanket-reject zero UUIDs on other message types; some generic command modes permit them and bootstrap messages may have no FSID field.
- No scheduling budget, message schema, authentication, disk or durability change. Known-FSID outputs retain their bytes/order. This intentional invalid-Log correction is independent of the unmerged shared-budget work.

Validation: native in-memory monitor regressions fail original main and pass with the correction; discovery/subscriptions and existing logging/rehunt tests pass. Original vs fixed known-FSID startup and reentrant 42-frame Header2/payload transcripts are byte-identical. Evidence and scope: `../perf/perf4-mon-wire.md`. No live/hardware claim.
