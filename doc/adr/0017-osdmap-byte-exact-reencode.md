# 0017 OSDMap: byte-exact re-encode + crc verify
Status: accepted
Date: 2026-10-09
Context: after applying Incremental, Ceph OSDs re-encode full map and compare crc with inc.full_crc (spec/osdmap.md). OSDs also share maps with peers/clients (MOSDMap).
Decision: implement byte-exact OSDMap encoder (incl. pg_pool_t, crush bl kept verbatim unless changed) for the feature set of `main`. After apply: re-encode, crc check; mismatch -> request full map from mon, log loudly (indicates encoder bug). Store received full/inc maps verbatim for forwarding.
Test: decode->encode byte-equality vs every map from reference cluster + ceph-dencoder vectors.
