// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! lrc k=2 m=1 l=3: the local layer touches every position, so a full-stripe encode never runs the global layer (its parity
//! position stays zero, as classic writes it, spec ec-lrc.md 3.1). Such a chunk must never serve a decode: every read set the
//! planner gives must decode to the data (live: wrong client reads after a 2-position move, adr 0081).
use std::collections::BTreeMap;

#[test]
fn lrc_k2m1l3_every_subset_decodes() {
    let p: BTreeMap<String, String> = [("plugin", "lrc"), ("k", "2"), ("m", "1"), ("l", "3")]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    let c = ec::code::Code::from_profile(&p).unwrap();
    let u = 4096;
    let d0: Vec<u8> = (0..u).map(|i| (i * 7 % 251) as u8).collect();
    let d1: Vec<u8> = (0..u).map(|i| (i * 13 % 239) as u8).collect();
    let mut p0 = vec![0u8; u];
    let mut p1 = vec![0u8; u];
    {
        let mut par: Vec<&mut [u8]> = vec![&mut p0, &mut p1];
        c.encode(&[&d0, &d1], &mut par);
    }
    assert!(
        p0.iter().all(|b| *b == 0),
        "global parity of a skipped layer is zero"
    );
    assert!(
        c.read_set(&[0, 1], &[0, 2]).is_none(),
        "D0 + the never-encoded parity cannot rebuild D1"
    );
    let all = [d0.clone(), d1.clone(), p0.clone(), p1.clone()];
    for mask in 1u32..16 {
        let avail: Vec<usize> = (0..4).filter(|i| mask & (1 << i) != 0).collect();
        let Some(set) = c.read_set(&[0, 1], &avail) else {
            continue;
        };
        let want: Vec<usize> = [0usize, 1]
            .into_iter()
            .filter(|r| !set.contains(r))
            .collect();
        if want.is_empty() {
            continue;
        }
        let have: Vec<(usize, &[u8])> = set.iter().map(|r| (*r, &all[*r][..])).collect();
        let mut outs: Vec<Vec<u8>> = want.iter().map(|_| vec![0u8; u]).collect();
        {
            let mut o: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..]).collect();
            c.decode_into(&have, &want, &mut o).unwrap();
        }
        for (i, r) in want.iter().enumerate() {
            assert!(outs[i] == all[*r], "avail {avail:?} set {set:?} raw {r}");
        }
    }
}
