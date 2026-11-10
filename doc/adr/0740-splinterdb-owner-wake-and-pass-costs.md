<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0740 SplinterDB owner wake and per-pass scan admission

Status: proposed; measured candidate pending
Date: 2026-11-09
Extends: 0727-splinterdb-omap-engine, 0736-splinterdb-read-credit-yield

## Context

The SplinterDB worker published completions without waking the owner core, so an
owner parked in its idle wait saw a finished page only after its own wake-up (the
RocksDB worker gained such a wake; measured ~0.13 ms per page there). Each listed
entry also took two full scan admissions (expiry check, credit lookup, two clock
reads) although the credit cannot change inside one synchronous owner pass.

## Decision

- The worker calls the owner wake after every pushed completion, including the
  failure push, using the same publish-then-wake contract as the RocksDB worker:
  the owner's post-announcement re-check (`handed_completion`) or the wake sees
  it. Installed once per core after mount; none means the previous idle cap.
- A listing pass admits its scan credit once at its start and again after any
  blocking miss wait; within the pass, per-entry growth only updates the charge.
  Rare reply-buffer growth keeps its full admission. Charges, fairness and the
  credit-yield rules are otherwise unchanged.

## Consequences

Production `dyn` use: one wake hook per SplinterDB shard, called on the worker
thread (allowlisted like the RocksDB hook). Regression tests cover one wake per
completion, first-install-wins and the owner's completion re-check.
