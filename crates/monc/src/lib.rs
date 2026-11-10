// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! monc: sans-IO Ceph MonClient (spec: doc/spec/osd-lifecycle.md section 2, cephx.md 8-9).
//!
//! [`MonClient`] hunts for a mon over msgr2, authenticates (cephx / none, crc or secure), keeps the
//! session alive and handles subscriptions, commands, MConfig, MLog and OSDMap feeding. The
//! driver supplies sockets and time; see [`client`].
#![deny(clippy::print_stderr, clippy::print_stdout)]
#![cfg_attr(test, allow(clippy::print_stderr, clippy::print_stdout))]
pub mod auth;
pub mod client;
pub mod config;
pub mod subs;

pub use client::{
    IoCmd, MonClient, MonEvent, MonSendError, MonitorTarget, MonitorTargetError, MonitorTargetSeed,
};
pub use config::{Config, Timers, monmap_from_addrs, parse_mon_host};
