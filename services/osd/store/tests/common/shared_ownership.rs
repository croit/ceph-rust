// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Lifetime/retry regressions on the segmented public API, not a flat-buffer implementation.
use super::*;

fn retry(r: &mut Rig, c: &CollT, o: &Ghobject, len: usize) -> Vec<(bytes::Bytes, Option<u32>)> {
    for _ in 0..100_000 {
        r.st.read_session(Some((91, 1)), true);
        match r.st.read_shared(c, o, 0, len as u64) {
            Ok(p) => return p,
            Err(ObjError::WouldBlock) => {
                r.st.read_session(None, true);
                r.st.take_blocked();
                r.st.poll(&mut Vec::new()).unwrap();
                r.st.idle();
            }
            Err(e) => panic!("shared read: {e:?}"),
        }
    }
    panic!("segmented read never completed");
}

#[test]
fn shared_output_survives_session_release_overwrite_and_store_destruction() {
    let (mut r, c, o, data) = shared_rig(b"shared-owned", 1 << 20);
    r.st.set_nonblock_reads(true);
    let first = retry(&mut r, &c, &o, data.len());
    assert_eq!(flat_checked(&first), data);
    assert!(first.len() > 1, "exercise independent segment owners");
    let ios = r.st.shards[0].stats.read_ios;
    let again = r.st.read_shared(&c, &o, 0, data.len() as u64).unwrap();
    assert_eq!(flat_checked(&again), data);
    assert_eq!(first.len(), again.len());
    for ((a, _), (b, _)) in first.iter().zip(&again) {
        assert_eq!(a.as_ptr(), b.as_ptr());
    }
    assert_eq!(r.st.shards[0].stats.read_ios, ios);
    assert!(r.st.shards[0].rolling_usage().0 >= data.len());
    r.st.read_session(None, false);
    assert_eq!(r.st.shards[0].rolling_usage(), (0, 0));
    r.st.set_nonblock_reads(false);
    let changed = vec![0x9a; data.len()];
    let mut t = OTxn::new();
    t.write(c, &o, 0, &changed);
    commit(&mut r.st, &t);
    assert_eq!(r.st.read(&c, &o, 0, data.len() as u64).unwrap(), changed);
    drop(r);
    assert_eq!(flat_checked(&first), data);
    assert_eq!(flat_checked(&again), data);
}

#[test]
fn shared_ranges_keep_segment_identity_when_a_later_range_parks() {
    let (mut r, c, o, data) = shared_rig(b"shared-retry", 6 * 65536);
    r.st.set_nonblock_reads(true);
    let (mut first, mut done, mut parked_after_success) = (None, false, false);
    for _ in 0..100_000 {
        r.st.read_session(Some((92, 1)), true);
        let mut successes = 0;
        done = true;
        for i in 0..6 {
            match r.st.read_shared(&c, &o, i * 65536, 65536) {
                Ok(p) => {
                    assert_eq!(
                        flat_checked(&p),
                        data[i as usize * 65536..(i as usize + 1) * 65536]
                    );
                    if i == 0 {
                        if let Some(previous) = &first {
                            let previous: &Vec<(bytes::Bytes, Option<u32>)> = previous;
                            assert_eq!(p.len(), previous.len());
                            for ((a, _), (b, _)) in p.iter().zip(previous) {
                                assert_eq!(a.as_ptr(), b.as_ptr());
                            }
                        } else {
                            first = Some(p);
                        }
                    }
                    successes += 1;
                }
                Err(ObjError::WouldBlock) => {
                    parked_after_success |= successes > 0;
                    done = false;
                    break;
                }
                Err(e) => panic!("segmented retry: {e:?}"),
            }
        }
        r.st.read_session(None, !done);
        if done {
            break;
        }
        r.st.take_blocked();
        r.st.poll(&mut Vec::new()).unwrap();
        r.st.idle();
    }
    assert!(done && parked_after_success);
    assert_eq!(r.st.shards[0].rolling_usage(), (0, 0));
    drop(r);
    assert_eq!(flat_checked(&first.unwrap()), data[..65536]);
}

#[test]
fn shared_inline_and_compressed_fallback_owners_survive_store_destruction() {
    let mut r = rig(64, 1);
    let (c, inline, compressed) = (c1(), g(b"owned-inline", 1), g(b"owned-compressed", 2));
    let small = vec![0x42; 117];
    let data = cdata(256 << 10, 3);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.write(c, &inline, 0, &small);
    commit(&mut r.st, &t);
    let mut t = OTxn::new();
    t.comp = Some(cspec(Alg::Lz4));
    t.write(c, &compressed, 0, &data);
    commit(&mut r.st, &t);
    assert!(r.st.shards[0].stats.inline_writes > 0);
    assert!(r.st.shards[0].stats.comp_ok > 0);
    r.clean_remount();
    r.st.set_nonblock_reads(true);
    let a = retry(&mut r, &c, &inline, small.len());
    r.st.read_session(None, false);
    let b = retry(&mut r, &c, &compressed, data.len());
    r.st.read_session(None, false);
    for (off, len) in [(data.len() as u64, 4096), (u64::MAX, 4096), (0, 0)] {
        assert!(
            r.st.read_shared(&c, &compressed, off, len)
                .unwrap()
                .is_empty()
        );
    }
    drop(r);
    assert_eq!(flat_checked(&a), small);
    assert_eq!(flat_checked(&b), data);
}
