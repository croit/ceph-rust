// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Dev tool: extract replication MESSAGE frames from a tcpdump pcap of OSD<->OSD msgr2 traffic
//! (crc mode, flows seen from their SYN). Writes a selected, deduplicated subset to a container file
//! (record = u16 type, u16 version, u16 compat, u32 front, u32 middle, u32 data, bytes) that
//! tests/capture.rs decodes. Usage: `pcap_extract <in.pcap> <out.bin>`.
//! Selection: RepOp deduplicated by (struct_v, middle?, op-code signature, #log entries); other
//! types by (type, version, item count); frames over 300 KB are skipped.
use messages::Header2;
use msgr2::{Banner, Decoder};
use replwire::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufReader, Read, Write};

struct Dir {
    next: u32,
    buf: Vec<u8>,
    dec: Option<Decoder>,
    dead: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut r =
        BufReader::with_capacity(1 << 24, std::fs::File::open(&args[1]).expect("open pcap"));
    let mut gh = [0u8; 24];
    r.read_exact(&mut gh).unwrap();
    let be = gh[0] == 0xa1;
    let rd32 = |b: &[u8]| {
        if be {
            u32::from_be_bytes(b.try_into().unwrap())
        } else {
            u32::from_le_bytes(b.try_into().unwrap())
        }
    };
    let mut flows: HashMap<(u32, u16, u32, u16), Dir> = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut out = std::fs::File::create(&args[2]).unwrap();
    let (mut pk, mut frames_total, mut kept) = (0u64, 0u64, 0u64);
    let mut rec = [0u8; 16];
    let mut pkt = Vec::new();
    while r.read_exact(&mut rec).is_ok() {
        let incl = rd32(&rec[8..12]) as usize;
        pkt.resize(incl, 0);
        if r.read_exact(&mut pkt).is_err() {
            break;
        }
        pk += 1;
        if incl < 54 || pkt[12] != 0x08 || pkt[13] != 0x00 || pkt[23] != 6 {
            continue;
        }
        let ihl = (pkt[14] & 0xf) as usize * 4;
        let tot = u16::from_be_bytes([pkt[16], pkt[17]]) as usize;
        let ip = &pkt[14..];
        let tcp = &ip[ihl..];
        let doff = (tcp[12] >> 4) as usize * 4;
        let payload_end = if tot == 0 {
            ip.len()
        } else {
            tot.min(ip.len())
        };
        if ihl + doff > payload_end {
            continue;
        }
        let payload = &ip[ihl + doff..payload_end];
        let src = u32::from_be_bytes(ip[12..16].try_into().unwrap());
        let dst = u32::from_be_bytes(ip[16..20].try_into().unwrap());
        let (sp, dp) = (
            u16::from_be_bytes([tcp[0], tcp[1]]),
            u16::from_be_bytes([tcp[2], tcp[3]]),
        );
        let seq = u32::from_be_bytes(tcp[4..8].try_into().unwrap());
        let flags = tcp[13];
        let key = (src, sp, dst, dp);
        if flags & 0x02 != 0 {
            flows.insert(
                key,
                Dir {
                    next: seq.wrapping_add(1),
                    buf: Vec::new(),
                    dec: None,
                    dead: false,
                },
            );
            continue;
        }
        let Some(f) = flows.get_mut(&key) else {
            continue;
        };
        if f.dead || payload.is_empty() {
            continue;
        }
        let mut data = payload;
        if seq != f.next {
            let behind = f.next.wrapping_sub(seq);
            if behind < 0x8000_0000 && (behind as usize) < data.len() {
                data = &data[behind as usize..];
            } else if behind < 0x8000_0000 {
                continue; // pure retransmit
            } else {
                eprintln!(
                    "gap on flow {:08x}:{}->{:08x}:{} exp {} got {} plen {} tot {} incl {} ",
                    key.0,
                    key.1,
                    key.2,
                    key.3,
                    f.next,
                    seq,
                    payload.len(),
                    tot,
                    incl
                );
                f.dead = true; // gap
                continue;
            }
        }
        f.next = f.next.wrapping_add(data.len() as u32);
        if f.dec.is_none() {
            f.buf.extend_from_slice(data);
            match Banner::parse(&f.buf) {
                Ok(Some((b, n))) => {
                    let mut d = Decoder::new(b.revision());
                    d.feed(&f.buf[n..]);
                    f.dec = Some(d);
                    f.buf.clear();
                }
                Ok(None) => continue,
                Err(_) => {
                    f.dead = true;
                    continue;
                }
            }
        } else if let Some(d) = f.dec.as_mut() {
            d.feed(data);
        }
        let Some(d) = f.dec.as_mut() else { continue };
        loop {
            let fr = match d.poll() {
                Ok(Some(fr)) => fr,
                Ok(None) => break,
                Err(e) => {
                    eprintln!(
                        "flow {:08x}:{}->{:08x}:{} decode error: {e}",
                        key.0, key.1, key.2, key.3
                    );
                    f.dead = true;
                    break;
                }
            };
            if fr.tag != 17 || fr.segments().len() < 2 {
                continue;
            }
            let Ok(h) = Header2::parse(fr.segment(0)) else {
                continue;
            };
            let n = fr.segments().len();
            let front = fr.segment(1);
            let mid = if n > 2 { fr.segment(2) } else { &[][..] };
            let dat = if n > 3 { fr.segment(3) } else { &[][..] };
            let segs = messages::Segments {
                front_zc: Vec::new(),
                front_hints: Default::default(),
                front: front.to_vec(),
                middle: mid.to_vec(),
                data: dat.to_vec().into(),
            };
            let Ok(Some(m)) = decode_repl(h.ty, h.version, &segs) else {
                continue;
            };
            frames_total += 1;
            let name = format!("{:?}", m)
                .split('(')
                .next()
                .unwrap_or("?")
                .to_string();
            *counts.entry(format!("{name} v{}", h.version)).or_default() += 1;
            if let ReplMsg::RepOp(r) = &m {
                let p = if r.txn_middle.is_empty() {
                    &r.txn_data
                } else {
                    &r.txn_middle
                };
                if p.len() > 16 && p[0] == 10 {
                    let (la, lm) = (
                        u32::from_le_bytes(p[p.len() - 8..p.len() - 4].try_into().unwrap()),
                        u32::from_le_bytes(p[p.len() - 4..].try_into().unwrap()),
                    );
                    *counts
                        .entry(format!(
                            "v10 la>0:{} lm>0:{} midseg:{} datalen>1M:{}",
                            la > 0,
                            lm > 0,
                            !r.txn_middle.is_empty(),
                            r.txn_data.len() > (1 << 20)
                        ))
                        .or_default() += 1;
                }
            }
            let size = front.len() + mid.len() + dat.len();
            if size > 300_000 {
                continue;
            }
            let sig = match &m {
                ReplMsg::RepOp(r) => match r.txn(DEFAULT_PAGE) {
                    Ok(t) => {
                        let mut codes: Vec<u32> = t.ops.iter().map(|o| o.op.code()).collect();
                        codes.dedup();
                        let n = u32::from_le_bytes(r.logbl[..4].try_into().unwrap_or([0; 4]));
                        format!(
                            "repop v{} m{} {:?} n{} hs{}",
                            t.struct_v,
                            !r.txn_middle.is_empty(),
                            codes,
                            n,
                            r.updated_hit_set_history.is_some()
                        )
                    }
                    Err(e) => format!(
                        "repop TXN-ERR {e} mid {} data {} p0 {:02x?}",
                        r.txn_middle.len(),
                        r.txn_data.len(),
                        &(if r.txn_middle.is_empty() {
                            &r.txn_data
                        } else {
                            &r.txn_middle
                        })[..r.txn_data.len().min(64)]
                    ),
                },
                ReplMsg::Push(p) => format!(
                    "push v{} n{} r{}",
                    h.version,
                    p.pushes.len(),
                    p.pushes
                        .iter()
                        .map(|x| x.after_progress.first as u8 + 2 * x.before_progress.first as u8)
                        .sum::<u8>()
                ),
                ReplMsg::Pull(p) => format!("pull n{}", p.pulls.len()),
                ReplMsg::PushReply(p) => format!("pushreply n{}", p.replies.len()),
                ReplMsg::RecoveryDelete(p) => format!("rdel n{}", p.objects.len()),
                ReplMsg::RecoveryDeleteReply(p) => format!("rdelr n{}", p.objects.len()),
                ReplMsg::BackfillReserve(p) => format!("bres t{}", p.ty),
                ReplMsg::RecoveryReserve(p) => format!("rres t{}", p.ty),
                ReplMsg::Scan(p) => format!("scan op{}", p.op),
                ReplMsg::Backfill(p) => format!("bf op{}", p.op),
                other => format!("{} v{}", other.msg_type(), h.version),
            };
            if sig.contains("TXN-ERR") {
                eprintln!("{sig}");
            }
            let cap = if sig.starts_with("repop") { 1 } else { 3 };
            let mut k = 0;
            while seen.contains(&format!("{sig}#{k}")) {
                k += 1;
            }
            if k >= cap {
                continue;
            }
            seen.insert(format!("{sig}#{k}"));
            kept += 1;
            let mut rec = Vec::new();
            rec.extend_from_slice(&h.ty.to_le_bytes());
            rec.extend_from_slice(&h.version.to_le_bytes());
            rec.extend_from_slice(&h.compat_version.to_le_bytes());
            for s in [front, mid, dat] {
                rec.extend_from_slice(&(s.len() as u32).to_le_bytes());
            }
            for s in [front, mid, dat] {
                rec.extend_from_slice(s);
            }
            out.write_all(&rec).unwrap();
        }
    }
    eprintln!("packets {pk}, repl frames {frames_total}, kept {kept}");
    for (k, v) in counts {
        eprintln!("{k}: {v}");
    }
}
