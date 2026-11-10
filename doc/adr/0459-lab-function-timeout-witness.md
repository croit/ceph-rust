<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# Lab function timeout expiry witness

Status: accepted (implemented in lab/lib/tmo.sh). Date: 2026-10-19. Scope: function/builtin fallback in lab/lib/tmo.sh.

Context: child124 can be an inner timeout or a normal command status. Reporting
that status as expiry of the outer timer produces a false WARNING TIMEOUT.
Mac nested1s/5s units reproduce this without a qualification deadline expiring.

Decision: a per-call private file witnesses the fallback watchdog reaching its
own deadline. Initialize/readback armed before work, write expired before TERM.
Cancel/reap watchdog and require a complete record plus its real failure status.
Use an owned asynchronous sleep child and interruptible wait; cancellation marks
a flag, kills/reaps the exact timer PID, then returns retained watcher status.
Cancel watcher by positive PID, not its process group. Its fatal status survives
a failed write retaining armed. Only a witnessed expiry normalizes status124 and emits this timer's
canonical warning; unwitnessed child statuses124/137/143 propagate unchanged.

Alternatives: elapsed-time inference cannot prove timer expiry; blanket timeout
suppression loses actual expiry evidence. A scoped file adds one temporary file
per function/builtin call, outside client/service hot paths, without dependencies.

Consequences: unwitnessed child124 is not attributed to this timer. This does NOT
prove nested timeout retirement. GNU external-command path remains unchanged and its124/137
ambiguity explicitly open. No process-group/handshake rewrite; no claim the rare
Mac child-setpgid diagnostic is fixed or harmless. Such investigation and any
whole-tree cancellation change need separate evidence and review.

Action: own small shell regressions; no VM qualification until root review.
Earlier drafts have real RED evidence: empty-witness write failure plus TERM
exit0 returned success; foreground-sleep watcher cancellation stalled. Neither
failure is erased by the narrow async-timer units. Workgroup scope remains open.
