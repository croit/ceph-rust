// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use msgr2::{ConnSecret, Decoder, Encoder, Revision, Role};
use std::time::Instant;

#[test]
#[ignore = "local receive/feed/authentication/ownership benchmark"]
fn perf_secure_rx_stream() {
    let secret = ConnSecret::new(&[7; 64]).unwrap();
    for len in [1 << 20, 4 << 20] {
        let mut enc = Encoder::new(Revision::V21);
        enc.set_secure(&secret, Role::Client).unwrap();
        let mut dec = Decoder::new(Revision::V21);
        dec.set_secure(&secret, Role::Server).unwrap();
        let data = vec![0x6a; len];
        let mut wire = Vec::with_capacity(len + 256);
        let mut ns = 0;
        for i in 0..160 {
            wire.clear();
            enc.encode_message(&[1; 41], &[2; 17], &[3; 7], &data, &mut wire)
                .unwrap();
            let start = Instant::now();
            dec.feed(&wire);
            let frame = dec.poll_owned().unwrap().unwrap();
            let elapsed = start.elapsed().as_nanos();
            if i >= 32 {
                ns += elapsed;
            }
            assert_eq!(frame.segs[3].as_ref(), data);
            drop(frame);
        }
        println!(
            "secure receive stream len={len} feed_auth_own_ns={}",
            ns / 128
        );
    }
}
