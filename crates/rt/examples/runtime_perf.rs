// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
// Public runtime API benchmark; compare identical fixtures in isolated checkouts.
use rt::mesh::{Route, mesh_store};
use std::sync::{Arc, Barrier};
use std::time::Instant;

fn mesh_run(producers: usize, messages: usize) -> u128 {
    let mut endpoints = mesh_store::<u64>(32, 256, 32);
    let mut receiver = endpoints.remove(0);
    let barrier = Arc::new(Barrier::new(producers + 1));
    let mut joins = Vec::new();
    for mut sender in endpoints.drain(..producers) {
        let barrier = barrier.clone();
        joins.push(std::thread::spawn(move || {
            barrier.wait();
            for value in 0..messages as u64 {
                let mut message = sender.stamp(0, Route::Data(0), value);
                while let Err(retained) = sender.send_stamped(0, message) {
                    message = retained;
                    std::hint::spin_loop();
                }
            }
        }));
    }
    let mut expected = [0u64; 32];
    barrier.wait();
    let started = Instant::now();
    let mut count = 0;
    while count < producers * messages {
        if let Some((from, value)) = receiver.poll() {
            assert_eq!(value, expected[from]);
            expected[from] += 1;
            count += 1;
        } else {
            std::hint::spin_loop();
        }
    }
    let elapsed = started.elapsed().as_nanos();
    for join in joins {
        join.join().unwrap();
    }
    elapsed
}

fn spsc_run(messages: usize) -> u128 {
    let (mut producer, mut consumer) = rt::spsc::channel::<u64>(256);
    let barrier = Arc::new(Barrier::new(2));
    let consumer_barrier = barrier.clone();
    let receiver = std::thread::spawn(move || {
        consumer_barrier.wait();
        for expected in 0..messages as u64 {
            while consumer.peek().is_none() {
                std::hint::spin_loop();
            }
            assert_eq!(consumer.pop(), Some(expected));
        }
    });
    barrier.wait();
    let start = Instant::now();
    for value in 0..messages as u64 {
        let mut message = value;
        while let Err(retained) = producer.push(message) {
            message = retained;
            std::hint::spin_loop();
        }
    }
    receiver.join().unwrap();
    start.elapsed().as_nanos()
}

fn main() {
    for sample in 0..5 {
        let mut receiver = mesh_store::<u64>(32, 256, 32).remove(0);
        let iterations = 200_000;
        let start = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(receiver.poll());
        }
        println!(
            "empty sample={sample} ns_poll={}",
            start.elapsed().as_nanos() / iterations
        );
        for producers in [1, 4, 8] {
            println!(
                "mesh sample={sample} producers={producers} ns_msg={}",
                mesh_run(producers, 50_000) / (producers * 50_000) as u128
            );
        }
        println!(
            "spsc sample={sample} ns_msg={}",
            spsc_run(1_000_000) / 1_000_000
        );
    }
}
