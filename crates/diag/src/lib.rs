// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH

//! Panic-free stderr diagnostics for Ceph client libraries.
//!
//! `diag!` writes one formatted line to stderr and drops the write on error.
//! It never panics, even when stderr is closed or returns EPIPE, which would
//! abort a `panic = "abort"` client library loaded into a foreign host
//! (QEMU, tools). Output is byte-identical to `eprintln!`.

/// Emit one diagnostic line to stderr, ignoring a failed write.
///
/// Output is byte-identical to `eprintln!`; a failed write (e.g. EPIPE when
/// the host process closed stderr) is dropped instead of panicking.
#[macro_export]
macro_rules! diag {
    ($($arg:tt)*) => {{
        let _ = ::std::io::Write::write_fmt(
            &mut ::std::io::stderr().lock(),
            format_args!("{}\n", format_args!($($arg)*)),
        );
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn diag_writes_line() {
        diag!("hello {}", 42);
        diag!("plain");
    }
}
