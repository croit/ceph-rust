# 0188 native OSD service authorizer
Status: accepted
Date: 2026-10-14
Context: standalone bootstrap exists; native OSD transport still needs authorizer logic currently confined to lab Probe.
Decision: bootstrap-feature OsdAuth composes own cephx/msgr2, explicit mode policy, caller clock/expiry, immutable client identity and secret-free errors. Contract RC-OSDAUTH (doc not in the source snapshot).
Consequences: production coordinator can connect without importing kernel probe; auth remains cold/allocation-bearing. Renewed-ticket/session ownership and real classic integration remain required; no automatic identity replacement.
Alternatives: import Probe (tool/kernel dependency); ignore ticket expiry on reconnect (stale credential); adopt service AUTH_DONE global id (wrong lifecycle).
