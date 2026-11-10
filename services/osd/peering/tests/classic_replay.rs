// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Ground truth for the classic-peer model: real classic ceph-osd logs (lab/docker/mixed/capture-classic.sh, converted by
//! classic-log-to-fixture.sh, slimmed by slim-fixtures.sh into tests/fixtures/classic/*.jsonl.gz) are replayed through the state x event table. Every
//! peering event a REAL classic OSD processed must be accepted (H or I, never A) in the state its own log says the PG was in;
//! a rejection is a gap of the table / spec, not of croit-flashstore-osd. A `Crashed` state in a fixture is a failure of the capture.
mod common;
use common::classic_table::{CEv, CSt, V, verdict};
use serde_json::Value;
use std::collections::BTreeMap;

fn state_of(name: &str) -> Option<CSt> {
    let leaf = name.rsplit('/').next().unwrap_or(name);
    Some(match leaf {
        "Reset" | "Initial" => CSt::Reset,
        "Stray" => CSt::Stray,
        "RepNotRecovering" => CSt::RepNot,
        "RepWaitRecoveryReserved" => CSt::RepWaitRec,
        "RepWaitBackfillReserved" => CSt::RepWaitBf,
        "RepRecovering" => CSt::RepRec,
        "WaitActingChange" => CSt::WaitActingChange,
        "GetInfo" => CSt::GetInfo,
        "GetLog" => CSt::GetLog,
        "GetMissing" => CSt::GetMissing,
        "WaitUpThru" => CSt::WaitUpThru,
        "Down" => CSt::Down,
        "Incomplete" => CSt::Incomplete,
        "Activating" | "Clean" | "Recovered" | "NotRecovering" | "WaitLocalRecoveryReserved" => {
            CSt::ActOther
        }
        "WaitRemoteRecoveryReserved" => CSt::WaitRemoteRec,
        "Recovering" => CSt::Recovering,
        "Backfilling" => CSt::Backfilling,
        "WaitLocalBackfillReserved" => CSt::WaitLocalBf,
        "WaitRemoteBackfillReserved" => CSt::WaitRemoteBf,
        "NotBackfilling" => CSt::NotBackfilling,
        "ToDelete" | "WaitDeleteReserved" | "Deleting" => CSt::ToDelete,
        _ => return None,
    })
}

fn event_of(name: &str) -> Option<CEv> {
    Some(match name {
        "MQuery" => CEv::Query,
        "MNotifyRec" => CEv::Notify,
        "MInfoRec" => CEv::Info,
        "MLogRec" => CEv::Log,
        "MTrim" => CEv::Trim,
        "MLease" => CEv::Lease,
        "MLeaseAck" => CEv::LeaseAck,
        "DeleteStart" => CEv::Remove,
        "RequestRecoveryPrio" => CEv::RrReq,
        "RemoteRecoveryReserved" => CEv::RrGrant,
        "RecoveryDone" => CEv::RrRelease,
        "DeferRecovery" => CEv::RrRevoke,
        "RequestBackfillPrio" => CEv::BrReq,
        "RemoteBackfillReserved" => CEv::BrGrant,
        "RemoteReservationRejectedTooFull" => CEv::BrReject,
        "RemoteReservationCanceled" => CEv::BrRelease,
        "RemoteReservationRevokedTooFull" => CEv::BrRevokeTooFull,
        "RemoteReservationRevoked" => CEv::BrRevoke,
        _ => return None,
    })
}

#[test]
fn real_classic_sequences_are_accepted_by_the_table() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/classic");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        eprintln!("no fixtures in {dir:?} (run lab/docker/mixed/capture-classic.sh): skipped");
        return;
    };
    let (mut files, mut events, mut rejected) = (0, 0u64, vec![]);
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();
    for ent in rd.flatten() {
        let p = ent.path();
        let name = p.to_string_lossy().to_string();
        let text = if name.ends_with(".jsonl.gz") {
            let mut s = String::new();
            std::io::Read::read_to_string(
                &mut flate2::read::GzDecoder::new(std::fs::File::open(&p).unwrap()),
                &mut s,
            )
            .unwrap();
            s
        } else if name.ends_with(".jsonl") {
            std::fs::read_to_string(&p).unwrap()
        } else {
            continue;
        };
        files += 1;
        let mut state: BTreeMap<String, CSt> = BTreeMap::new();
        for (ln, l) in text.lines().enumerate() {
            let v: Value = serde_json::from_str(l).unwrap_or_else(|e| panic!("{p:?}:{ln}: {e}"));
            let pg = v["pgid"].as_str().unwrap_or("").to_string();
            match v["ev"].as_str() {
                Some("abort") => panic!("{p:?}:{ln}: the captured classic OSD aborted: {l}"),
                Some("state") => {
                    if let Some(n) = v["enter"].as_str() {
                        if n.ends_with("Crashed") {
                            panic!("{p:?}:{ln}: classic entered Crashed: {l}");
                        }
                        if let Some(s) = state_of(n) {
                            state.insert(pg, s);
                        }
                    }
                }
                Some("event") => {
                    let (Some(name), Some(st)) = (v["name"].as_str(), state.get(&pg).copied())
                    else {
                        continue;
                    };
                    let Some(ev) = event_of(name) else { continue };
                    events += 1;
                    let verd = verdict(st, ev);
                    *seen.entry(format!("{st:?} {ev:?} {verd:?}")).or_default() += 1;
                    if verd == V::A {
                        rejected.push(format!(
                            "{p:?}:{ln}: {st:?} + {ev:?} accepted by real classic: {l}"
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    for (k, n) in &seen {
        eprintln!("REPLAY {n:>7} {k}");
    }
    eprintln!("{files} fixture files, {events} classified events");
    assert!(
        rejected.is_empty(),
        "table rejects what real classic handled (model gap):\n{}",
        rejected[..rejected.len().min(20)].join("\n")
    );
}
