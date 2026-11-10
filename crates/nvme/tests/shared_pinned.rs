// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `shared_pinned`: buffers handed out as shared read data are counted until the last `Bytes` reference drops.
use nvme::{IoBuf, shared_pinned};

struct Buf(Vec<u8>);

impl IoBuf for Buf {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[test]
fn pinned_pieces_are_counted_until_the_last_reference_drops() {
    assert_eq!(shared_pinned(), (0, 0));
    let a = Buf(vec![1; 8192]).into_shared();
    let b = Buf(vec![2; 4096]).into_shared();
    assert_eq!(shared_pinned(), (2, 12288));
    let a2 = a.slice(4096..); // a slice keeps the whole buffer pinned
    drop(a);
    assert_eq!(shared_pinned(), (2, 12288));
    drop(a2);
    assert_eq!(shared_pinned(), (1, 4096));
    std::thread::spawn(move || drop(b)).join().unwrap(); // released on another thread
    assert_eq!(shared_pinned(), (0, 0));
}
