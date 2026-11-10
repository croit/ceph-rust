// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Dev tool: dump messages containing an op. `dump <dir> <op-name|msgtype> [max]`
#[path = "../tests/common/mod.rs"]
mod common;
use common::*;
use opwire::*;

fn hx(b: &[u8]) -> String {
    b.iter()
        .take(64)
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
fn ops(v: &[OsdOp]) {
    for o in v {
        println!(
            "  {} {:#06x} fl={:#x} u={} in[{}]={} out[{}]={} rval={}",
            op::name(o.op).unwrap_or("?"),
            o.op,
            o.flags,
            hx(&o.u),
            o.indata.len(),
            hx(&o.indata),
            o.outdata.len(),
            hx(&o.outdata),
            o.rval
        );
    }
}
fn show(m: &ClientMsg) {
    match m {
        ClientMsg::Op(o) => {
            println!(
                "OP pg={} shard={} hash={:#x} ep={} fl={:#x} reqid={:?} inc={} mtime={:?} oloc={:?} oid={} snapid={:#x} seq={} snaps={:?} retry={} feat={:#x} otel={:?}",
                o.pgid.pgid,
                o.pgid.shard.0,
                o.hash,
                o.osdmap_epoch,
                o.flags,
                o.reqid,
                o.client_inc,
                o.mtime,
                o.oloc,
                String::from_utf8_lossy(&o.oid),
                o.snapid,
                o.snap_seq,
                o.snaps,
                o.retry_attempt,
                o.features,
                o.otel
            );
            ops(&o.ops)
        }
        ClientMsg::OpReply(o) => {
            println!(
                "REPLY oid={} pg={} fl={:#x} res={} bad={} ep={} retry={} rv={} uv={} redir={:?}",
                String::from_utf8_lossy(&o.oid),
                o.pgid,
                o.flags,
                o.result,
                o.bad_replay_version,
                o.osdmap_epoch,
                o.retry_attempt,
                o.replay_version,
                o.user_version,
                o.redirect
            );
            ops(&o.ops)
        }
        m => println!("{m:#?}"),
    }
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    // SAFETY: single-threaded at startup.
    unsafe { std::env::set_var("OPWIRE_CAPDIR", &a[1]) };
    let want = &a[2];
    let max: usize = a.get(3).and_then(|x| x.parse().ok()).unwrap_or(1);
    let mut n = 0;
    for (name, bytes) in capture_files() {
        let Some(frs) = frames(&bytes) else { continue };
        for (h, f, m, d) in frs {
            if !matches!(h.ty, 42 | 43 | 44 | 61) {
                continue;
            }
            let msg = decode_client_parts(h.ty, h.version, &f, &m, &d).unwrap();
            let hit = match &msg {
                ClientMsg::Op(o) => o.ops.iter().any(|x| op::name(x.op) == Some(want)),
                ClientMsg::OpReply(o) => o.ops.iter().any(|x| op::name(x.op) == Some(want)),
                ClientMsg::WatchNotify(_) => want == "wn",
                _ => false,
            } && (h.ty == 42 || (a.get(4).is_some() && h.ty == 43) || h.ty == 44);
            if hit {
                println!(
                    "--- {name} hdr tid={} seq={} data_off={} flags={:#x} dpad={} ver={} compat={}",
                    h.tid,
                    h.seq,
                    h.data_off,
                    h.flags,
                    h.data_pre_padding_len,
                    h.version,
                    h.compat_version
                );
                show(&msg);
                n += 1;
                if n >= max {
                    return;
                }
            }
        }
    }
}
