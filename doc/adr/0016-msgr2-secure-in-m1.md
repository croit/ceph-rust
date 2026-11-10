# 0016 msgr2 secure mode in M1 (amends 0013/0009 "crc only")
Status: accepted
Date: 2026-10-09
Decision: implement msgr2 secure mode (AES-128-GCM, v2.0 + v2.1 nonce rules) together with crc mode in M1. Crypto lib: aws-lc-rs (Apache-2.0/ISC; VAES/AVX-512 AES-GCM). Mode selection per peer type follows Ceph config (ms_*_mode).
Design: frame path does in-place decrypt on rx buffers and encrypt-while-writing into tx buffers (no extra copy). Crypto per connection on owning core.
Consequences: + can join clusters forcing secure; + no later datapath rework. - ~1-2k LOC, AES-GCM cost (est. 5-15 GB/s/core) only where enabled; data path default stays crc.
