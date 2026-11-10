// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! State x event table of a classic PG copy (doc/spec/classic-peer-model.md 2.1, 2.2, 6; encoded verbatim).
#![allow(clippy::allow_attributes, dead_code)]

use super::*;
use pgwire::PeeringMsg;
use replwire::{MBackfillReserve, MRecoveryReserve, ReplMsg};

/// Classic PeeringState, grouped where the wire reactions are identical.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum CSt {
    /// Initial / Reset.
    Reset,
    /// No PG object on the peer.
    NoPg,
    Stray,
    /// ReplicaActive substates.
    RepNot,
    RepWaitRec,
    RepWaitBf,
    RepRec,
    /// Primary / Peering substates and WaitActingChange.
    WaitActingChange,
    GetInfo,
    GetLog,
    GetMissing,
    WaitUpThru,
    Down,
    Incomplete,
    /// Primary / Active substates (group rows of table 2.2 kept apart where they differ).
    ActOther,
    /// Active but held by cluster flags: the stand-in leaves WaitRemote* for it on a flag, classic does not (it stays in
    /// WaitRemote* and takes the GRANT): replies of replicas are not checked here, a stand-in artifact.
    FlagHeld,
    WaitRemoteRec,
    Recovering,
    Backfilling,
    WaitLocalBf,
    WaitRemoteBf,
    NotBackfilling,
    ToDelete,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CEv {
    Query,
    Notify,
    Info,
    Log,
    Trim,
    Lease,
    LeaseAck,
    Remove,
    RrReq,
    RrGrant,
    RrRelease,
    RrRevoke,
    BrReq,
    BrGrant,
    BrReject,
    BrRelease,
    BrRevokeTooFull,
    BrRevoke,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum V {
    /// Handled.
    H,
    /// Silently discarded.
    I,
    /// Abort (Crashed or an explicit assert).
    A,
}

/// Wire events of a body, with the PG each addresses (MOSDPGRemove carries a list).
pub fn classify(b: &Body) -> Vec<(SpgT, CEv)> {
    match b {
        Body::Peering(p) => match p {
            PeeringMsg::MOSDPGQuery2(m) => vec![(m.spgid, CEv::Query)],
            PeeringMsg::MOSDPGNotify2(m) => vec![(m.spgid, CEv::Notify)],
            PeeringMsg::MOSDPGInfo2(m) => vec![(m.spgid, CEv::Info)],
            PeeringMsg::MOSDPGLog(m) => vec![(m.spgid(), CEv::Log)],
            PeeringMsg::MOSDPGTrim(m) => vec![(
                SpgT {
                    pgid: m.pgid,
                    shard: m.shard,
                },
                CEv::Trim,
            )],
            PeeringMsg::MOSDPGLease(m) => vec![(m.spgid, CEv::Lease)],
            PeeringMsg::MOSDPGLeaseAck(m) => vec![(m.spgid, CEv::LeaseAck)],
            PeeringMsg::MOSDPGRemove(m) => m.pgs.iter().map(|s| (*s, CEv::Remove)).collect(),
            _ => vec![],
        },
        Body::Repl(ReplMsg::RecoveryReserve(m)) => vec![(
            m.pgid,
            match m.ty {
                MRecoveryReserve::REQUEST => CEv::RrReq,
                MRecoveryReserve::GRANT => CEv::RrGrant,
                MRecoveryReserve::RELEASE => CEv::RrRelease,
                _ => CEv::RrRevoke,
            },
        )],
        Body::Repl(ReplMsg::BackfillReserve(m)) => vec![(
            m.pgid,
            match m.ty {
                MBackfillReserve::REQUEST => CEv::BrReq,
                MBackfillReserve::GRANT => CEv::BrGrant,
                MBackfillReserve::REJECT_TOOFULL => CEv::BrReject,
                MBackfillReserve::RELEASE => CEv::BrRelease,
                MBackfillReserve::REVOKE_TOOFULL => CEv::BrRevokeTooFull,
                _ => CEv::BrRevoke,
            },
        )],
        _ => vec![],
    }
}

/// Unknown reserve `type` values abort the whole classic process at decode time.
pub fn bad_reserve_type(b: &Body) -> bool {
    match b {
        Body::Repl(ReplMsg::RecoveryReserve(m)) => m.ty > MRecoveryReserve::REVOKE,
        Body::Repl(ReplMsg::BackfillReserve(m)) => m.ty > MBackfillReserve::REVOKE,
        _ => false,
    }
}

fn is_active(s: CSt) -> bool {
    use CSt::*;
    matches!(
        s,
        ActOther
            | FlagHeld
            | WaitRemoteRec
            | Recovering
            | Backfilling
            | WaitLocalBf
            | WaitRemoteBf
            | NotBackfilling
    )
}
fn is_rep(s: CSt) -> bool {
    use CSt::*;
    matches!(s, RepNot | RepWaitRec | RepWaitBf | RepRec)
}

/// The canonical table. `NoPg` is answered by the caller (create / drop rules).
pub fn verdict(s: CSt, e: CEv) -> V {
    use CEv::*;
    use CSt::*;
    use V::*;
    match e {
        Query | Notify | Info | Log | Trim | Lease | LeaseAck | Remove => {
            if matches!(s, Reset | ToDelete) {
                return A;
            }
            if s == NoPg {
                return H;
            }
            if s == Stray {
                return match e {
                    Query | Info | Log | Remove => H,
                    _ => A,
                };
            }
            if is_rep(s) {
                return match e {
                    Query | Info | Log | Trim | Lease | Remove => H,
                    Notify | LeaseAck => A,
                    _ => A,
                };
            }
            if is_active(s) {
                return match e {
                    Notify | Info | Log | Trim | LeaseAck => H,
                    _ => A,
                };
            }
            // Peering substates and WaitActingChange
            match (s, e) {
                (WaitActingChange, Notify | Info | Log) => I,
                (GetInfo, Notify) => H,
                (GetLog | GetMissing | WaitUpThru, Notify | Log) => H,
                (Down | Incomplete, Notify) => H,
                _ => A,
            }
        }
        _ => {
            if matches!(s, Reset | ToDelete | NoPg) {
                return if s == NoPg { I } else { A };
            }
            match s {
                Stray => match e {
                    RrRelease => I,
                    _ => A,
                },
                RepNot => match e {
                    RrReq | BrReq | RrRelease | BrReject | BrRelease => H,
                    RrGrant | BrGrant | RrRevoke => I,
                    _ => A,
                },
                RepWaitRec => match e {
                    RrGrant | BrReject | BrRelease => H,
                    RrRelease | RrRevoke => I,
                    _ => A,
                },
                RepWaitBf => match e {
                    BrGrant | BrReject | BrRelease => H,
                    RrRelease | RrRevoke => I,
                    _ => A,
                },
                RepRec => match e {
                    RrRelease | BrReject | BrRelease => H,
                    RrRevoke => I,
                    _ => A,
                },
                FlagHeld => match e {
                    RrReq | RrRelease | BrReq | BrRelease => A,
                    _ => I,
                },
                ActOther => match e {
                    RrRevoke | BrRevokeTooFull | BrRevoke => I,
                    _ => A,
                },
                WaitRemoteRec => match e {
                    RrGrant => H,
                    RrRevoke | BrRevokeTooFull | BrRevoke => I,
                    _ => A,
                },
                Recovering => match e {
                    RrRevoke => H,
                    BrRevokeTooFull | BrRevoke => I,
                    _ => A,
                },
                Backfilling => match e {
                    BrReject | BrRevokeTooFull | BrRevoke => H,
                    RrRevoke => I,
                    _ => A,
                },
                WaitLocalBf => match e {
                    BrGrant | RrRevoke | BrRevokeTooFull | BrRevoke => I,
                    _ => A,
                },
                WaitRemoteBf => match e {
                    BrGrant | BrReject | BrRevoke => H,
                    RrRevoke | BrRevokeTooFull => I,
                    _ => A,
                },
                NotBackfilling => match e {
                    BrGrant | BrReject | RrRevoke | BrRevokeTooFull | BrRevoke => I,
                    _ => A,
                },
                _ => A,
            }
        }
    }
}
