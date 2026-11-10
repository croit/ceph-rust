<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0508: checked wide client operation deadlines
Status: accepted
Date: 2026-10-22

## Context
Both pinned librados versions accept ordinary operation timeouts of 2^32
seconds. Our u32 captures and internal u32-second horizons reject or shorten
those requests. The source-supported finite timer domain depends on checked
nanosecond conversion and current monotonic time; config storage has a wider
range. See the own-words contract (doc not in the source snapshot).

## Decision
rustyrados captures ordinary timeout seconds as u64.
Shared client scheduling uses checked microseconds within the signed-nanosecond
finite domain and an explicit enrolled-unlimited state without an armed timer.
Unrepresentable finite scheduling returns EOVERFLOW without changing config
storage, shortening the interval, wrapping, or turning it into unlimited.
Actual protocol timestamp, notify and watch-server widths remain unchanged.
API-specific capture boundaries, original resend budgets and strict directed
zero-duration semantics remain intact.

## Rationale
The representation covers the pinned references' non-overflowing timer domain
at our existing microsecond resolution. Explicit unlimited enrollment preserves
retry contracts while avoiding artificial wakeups. Checked arithmetic adds a
stable error outside that supported domain rather than reproducing reference
overflow defects, as permitted by ADR0256.

## Consequences
- + Supported large ordinary timeouts survive every FFI/native/transport layer.
- + Unlimited requests retain ordering and retry enrollment without timers.
- - Queue and transport siblings must share the same clock/deadline invariant.
- - Arithmetic errors outside the reference-supported domain have an explicit
  own errno and must remain documented.

## Alternatives
- Widen FFI captures only: native admission and deadline clipping still fail.
- Increase a fixed horizon: retains an unsupported arbitrary compatibility cap.
- Saturate overflow: silently shortens finite requests or makes them unlimited.
