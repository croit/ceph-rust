// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#![cfg(feature = "profile")]
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime},
};

#[test]
fn profile_dump() {
    if std::env::var_os("RUSTYRADOS_PROFILE_TEST_CHILD").is_some() {
        {
            let _root = msgr2::profile::span("test.root", 64);
            {
                let _child = msgr2::profile::span("test.child", 32);
                std::hint::black_box((0u64..4096).fold(0u64, u64::wrapping_add));
            }
        }
        msgr2::profile::flush();
        msgr2::profile::flush(); // Empty flush must not duplicate completed samples.
        {
            let _root = msgr2::profile::span("test.root", 8);
        }
        msgr2::profile::flush();
        return;
    }
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = std::env::temp_dir().join(format!(
        "rustyrados-profile-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let scratch = Scratch(directory);
    // Config is process-global: use a child, never mutate the parallel test process's environment.
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "profile_dump", "--nocapture"])
        .env("RUSTYRADOS_PROFILE_TEST_CHILD", "1")
        .env("RUSTYRADOS_PROFILE_DIR", &scratch.0)
        .env("RUSTYRADOS_PROFILE_SAMPLE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() >= Duration::from_secs(10) {
            eprintln!("WARNING TIMEOUT profile-test-child exceeded 10s (msgr2 profile dump)");
            let _ = child.kill();
            let _ = child.wait();
            panic!("profile child timed out");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let files: Vec<_> = std::fs::read_dir(&scratch.0)
        .unwrap()
        .map(|p| p.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    let raw = std::fs::read_to_string(&files[0]).unwrap();
    assert!(raw.ends_with('\n'));
    let rows: Vec<serde_json::Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        rows.len(),
        3,
        "empty flush duplicates no data; second batch keeps only new root"
    );
    for row in &rows {
        assert_eq!(row["schema"], 1);
        assert_eq!(row["stage_overflow"], 0);
        assert_eq!(row["samples"], 1);
        let histogram = row["wall_log2_ns"].as_array().unwrap();
        assert_eq!(histogram.len(), 64);
        assert_eq!(
            histogram.iter().map(|n| n.as_u64().unwrap()).sum::<u64>(),
            1
        );
    }
    let root = rows
        .iter()
        .find(|r| r["batch"] == 0 && r["stage"] == "test.root")
        .unwrap();
    let nested = rows.iter().find(|r| r["stage"] == "test.child").unwrap();
    assert_eq!(root["bytes"], 64);
    assert_eq!(nested["bytes"], 32);
    assert_eq!(
        root["wall_ns"].as_u64().unwrap(),
        root["self_wall_ns"].as_u64().unwrap() + nested["wall_ns"].as_u64().unwrap()
    );
    #[cfg(target_os = "linux")]
    {
        assert_eq!(root["cpu_samples"], 1);
        assert_eq!(root["clock_errors"], 0);
        assert_eq!(
            root["cpu_ns"].as_u64().unwrap(),
            root["self_cpu_ns"].as_u64().unwrap() + nested["cpu_ns"].as_u64().unwrap()
        );
    }
    let second = rows.iter().find(|r| r["batch"] == 1).unwrap();
    assert_eq!(second["bytes"], 8);
    assert_eq!(second["root_calls"], 1);
}
