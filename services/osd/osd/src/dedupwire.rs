// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Dedup info listing request (croit fork `wip-ifed-dedup`: MOSDDedupList 137 / reply 138, doc/spec/dedup-listing.md 4;
//! adr 0593-dedup-deep-scrub-reformat). Served only with `flashstore_dedup_list` (the OSD then advertises feature bit 51 in
//! MOSDBoot). The core that receives a request validates it in the fork's order (session, fsid, arguments, pool, caps) and
//! answers errors itself; a valid request runs as the scattered `bluestore dedup list` on every core (each core's part is
//! bounded by `flashstore_dedup_list_slice_ms` and never waits for a tree page), and the merged answer becomes the reply.

use crate::backend::Backend;
use crate::osd::Osd;
use crate::tell::ReplyTo;
use messages::{AnyMessage, DedupListEntry, DedupListResult, MOSDDedupList, MOSDDedupListReply};
use serde_json::{Value, json};

const EPERM: i32 = -1;
const ENOENT: i32 = -2;
const EACCES: i32 = -13;
const EINVAL: i32 = -22;
const EOPNOTSUPP: i32 = -95;

fn wall_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (s.len().is_multiple_of(2))
        .then(|| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                .collect()
        })
        .flatten()
}

/// Validation of one request (dedup-listing.md 3.5 / 4.1): `Err(r)` = answer with `r` and the default result.
pub(crate) fn check_args(m: &MOSDDedupList) -> Result<(), i32> {
    // at most 2^32 shards, so the shift below stays inside u64
    if m.shard_bits > 32 {
        return Err(EINVAL);
    }
    if m.shard >= 1u64 << m.shard_bits {
        return Err(EINVAL);
    }
    if m.max == 0 || m.max > i32::MAX as u32 {
        return Err(EINVAL);
    }
    Ok(())
}

/// The reply of a merged `bluestore dedup list` answer (`tellx::dedup_merge` JSON) at request time `now_ns`.
pub(crate) fn reply_of(r: i32, out: &[u8], now_ns: u64) -> MOSDDedupListReply {
    if r < 0 {
        return MOSDDedupListReply {
            r,
            result: DedupListResult::default(),
        };
    }
    let v: Value = serde_json::from_slice(out).unwrap_or(Value::Null);
    let l = &v["deduplication list"];
    let entries = l["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| {
            Some(DedupListEntry {
                digest: unhex(e["digest"].as_str()?)?,
                timestamp: e["timestamp"].as_u64()?,
                // the admin view shows the plain hash; the wire carries the bitwise-key form
                oid_hash: (e["hash"].as_u64()? as u32).reverse_bits(),
            })
        })
        .collect();
    MOSDDedupListReply {
        r: 0,
        result: DedupListResult {
            completed: l["completed"].as_bool().unwrap_or(false),
            next: unhex(l["next"].as_str().unwrap_or("")).unwrap_or_default(),
            now: now_ns,
            entries,
        },
    }
}

impl<B: Backend> Osd<B> {
    /// A MOSDDedupList on `link` (any core).
    pub(crate) fn on_dedup_list(&mut self, link: u64, tid: u64, m: MOSDDedupList) {
        let r = self.dedup_list_check(link, &m);
        if r == Err(EINVAL) && m.fsid != self.id.cluster_fsid {
            self.log(format!(
                "dedup list on link {link}: fsid {} is not ours",
                m.fsid
            ));
        }
        if let Err(r) = r {
            self.send_link_tid(
                link,
                tid,
                MOSDDedupListReply {
                    r,
                    result: DedupListResult::default(),
                },
            );
            return;
        }
        if self.is_control() {
            self.dedup_list_scatter(link, tid, &m);
        } else {
            self.forward_ctl(link, tid, AnyMessage::MOSDDedupList(m));
        }
    }

    fn dedup_list_check(&self, link: u64, m: &MOSDDedupList) -> Result<(), i32> {
        if !self.conf.bool("flashstore_dedup_list", false) {
            return Err(EOPNOTSUPP);
        }
        let l = self.links.get(&link).ok_or(EACCES)?;
        let caps = l.caps.as_ref().ok_or(EACCES)?;
        let peer = l.caps_peer;
        if m.fsid != self.id.cluster_fsid {
            return Err(EINVAL);
        }
        check_args(m)?;
        let map = self.map.as_deref().ok_or(ENOENT)?;
        map.pool(m.pool).ok_or(ENOENT)?;
        if !caps.is_allow_all() {
            // pool-wide: empty namespace and object (records cover every namespace); write to prune
            let (name, apps) = crate::ops::pool_caps_info(Some(map), m.pool);
            let ctx = opexec::caps::Ctx {
                pool: name,
                apps,
                ns: b"",
                key: b"",
                peer,
            };
            let need = opexec::caps::Need {
                read: true,
                write: m.prune_older_than > 0,
                classes: &[],
            };
            if !caps.is_capable(&ctx, &need) {
                return Err(EPERM);
            }
        }
        Ok(())
    }

    /// Control core: run a validated request on every core; the merged answer is the reply.
    pub(crate) fn dedup_list_scatter(&mut self, link: u64, tid: u64, m: &MOSDDedupList) {
        let max = self.conf.f64("osd_dedup_list_max_duration", 1.0).max(0.0);
        let slice = self.conf.u64("flashstore_dedup_list_slice_ms", 5).max(1) as f64 / 1000.0;
        let budget = if max > 0.0 { max.min(slice) } else { slice };
        let v = json!({"prefix": "bluestore dedup list", "pool": m.pool, "shard": m.shard,
            "shard_bits": m.shard_bits, "after": hex(&m.after), "max": m.max, "newer_than": m.newer_than,
            "prune_older_than": m.prune_older_than, "max_duration": budget});
        let to = ReplyTo::DedupList {
            link,
            tid,
            now_ns: wall_ns(),
        };
        if let Some(res) = self.scatter(&v, &to) {
            self.finish_cmd(to, res);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_checks() {
        let ok = MOSDDedupList {
            shard: 15,
            shard_bits: 4,
            max: 1,
            ..Default::default()
        };
        assert_eq!(check_args(&ok), Ok(()));
        for bad in [
            MOSDDedupList {
                shard: 16,
                ..ok.clone()
            },
            MOSDDedupList {
                shard_bits: 33,
                shard: 0,
                ..ok.clone()
            },
            MOSDDedupList {
                max: 0,
                ..ok.clone()
            },
            MOSDDedupList {
                max: i32::MAX as u32 + 1,
                ..ok.clone()
            },
        ] {
            assert_eq!(check_args(&bad), Err(EINVAL), "{bad:?}");
        }
        assert_eq!(
            check_args(&MOSDDedupList {
                shard_bits: 32,
                shard: u32::MAX as u64,
                ..ok
            }),
            Ok(())
        );
    }

    #[test]
    fn reply_from_the_merged_answer() {
        let out = json!({"deduplication list": {"pool": 1, "shard": 0, "shard_bits": 0, "completed": true,
            "next": "0A0B", "entries": [{"digest": "AABB", "hash": 0x1E6A_2C48u32, "timestamp": 77, "age": 1.0}]}});
        let r = reply_of(0, out.to_string().as_bytes(), 99);
        assert_eq!(
            r,
            MOSDDedupListReply {
                r: 0,
                result: DedupListResult {
                    completed: true,
                    next: vec![10, 11],
                    now: 99,
                    entries: vec![DedupListEntry {
                        digest: vec![0xAA, 0xBB],
                        timestamp: 77,
                        oid_hash: 0x1234_5678,
                    }],
                },
            }
        );
        assert_eq!(
            reply_of(-5, b"", 99),
            MOSDDedupListReply {
                r: -5,
                result: Default::default()
            }
        );
    }
}
