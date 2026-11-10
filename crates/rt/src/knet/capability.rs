// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Startup capability detection. Release numbers cannot describe backports or disabled features.
use super::*;
use std::io::Write;
use std::net::{TcpListener, TcpStream};

fn unsupported(feature: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("io_uring kernel TCP tier requires {feature}"),
    )
}

/// Outcome of the receive-buffer part of [`check`].
#[derive(Debug)]
pub(super) struct RxCaps {
    /// Mode the transport's buffer pool uses.
    pub provide: Provide,
    /// Why the registered ring was not usable ([`Provide::Classic`] only): printed once at startup.
    pub ring_err: Option<io::Error>,
}

/// Required features; the receive-buffer mode is the first of ring / classic provided buffers whose multishot test
/// passes. `Err` names the missing capability (both modes failed: their errors).
pub(super) fn check(ring: &IoUring) -> io::Result<RxCaps> {
    if !ring.params().is_feature_ext_arg() {
        return Err(unsupported("IORING_FEAT_EXT_ARG (bounded idle waits)"));
    }
    let mut probe = Probe::new();
    ring.submitter().register_probe(&mut probe)?;
    for (code, name) in [
        (opcode::AcceptMulti::CODE, "ACCEPT"),
        (opcode::Recv::CODE, "RECV"),
        (opcode::SendMsg::CODE, "SENDMSG"),
        (opcode::Connect::CODE, "CONNECT"),
        (opcode::LinkTimeout::CODE, "LINK_TIMEOUT"),
        (opcode::AsyncCancel::CODE, "ASYNC_CANCEL"),
        (opcode::Read::CODE, "READ"),
    ] {
        if !probe.is_supported(code) {
            return Err(unsupported(name));
        }
    }
    // Multishot is a modifier of ACCEPT/RECV, invisible to the opcode probe. A failing ring registration is not fatal
    // (adr 0053 am. 9): classic provided buffers serve the same multishot receive.
    let ring_err = match multishot(Provide::Ring) {
        Ok(()) => {
            return Ok(RxCaps {
                provide: Provide::Ring,
                ring_err: None,
            });
        }
        Err(e) => e,
    };
    let classic = if probe.is_supported(opcode::ProvideBuffers::CODE) {
        multishot(Provide::Classic)
    } else {
        Err(unsupported("PROVIDE_BUFFERS"))
    };
    match classic {
        Ok(()) => Ok(RxCaps {
            provide: Provide::Classic,
            ring_err: Some(ring_err),
        }),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!(
                "io_uring capability test: multishot receive with provided buffers: ring: {ring_err}; classic: {e}"
            ),
        )),
    }
}

fn completion(ring: &mut IoUring) -> io::Result<(i32, u32)> {
    let ts = Timespec::from(Duration::from_secs(1));
    let args = io_uring::types::SubmitArgs::new().timespec(&ts);
    ring.submitter().submit_with_args(1, &args)?;
    let cqe = ring.completion().next().ok_or_else(|| {
        eprintln!("WARNING TIMEOUT io_uring capability test exceeded 1s (no completion)");
        io::Error::new(io::ErrorKind::TimedOut, "no capability-test completion")
    })?;
    Ok((cqe.result(), cqe.flags()))
}

fn multishot_result(feature: &str, res: i32, flags: u32) -> io::Result<()> {
    if res < 0 {
        return Err(io::Error::new(
            io::Error::from_raw_os_error(-res).kind(),
            format!("{feature}: {}", io::Error::from_raw_os_error(-res)),
        ));
    }
    if !cqueue::more(flags) {
        return Err(unsupported(feature));
    }
    Ok(())
}

fn multishot(mode: Provide) -> io::Result<()> {
    let (mut ring, _) = make_ring(8)?;
    let mut bufs = BufRing::new(&ring.submitter(), 4, 64, mode)
        .map_err(|e| io::Error::new(e.kind(), format!("provided-buffer ring registration: {e}")))?;
    // Keep buffer storage alive until the scratch ring is closed, including error paths.
    let result = (|| {
        if mode == Provide::Classic {
            let mut entries = Vec::new();
            bufs.commit(|e, _, _| entries.push(e));
            for e in &entries {
                // SAFETY: the buffers live until the scratch ring is closed; this SQ is empty.
                unsafe { ring.submission().push(e) }.map_err(|_| io::ErrorKind::Other)?;
            }
            for _ in &entries {
                let (res, _) = completion(&mut ring)?;
                if res < 0 {
                    return Err(io::Error::new(
                        io::Error::from_raw_os_error(-res).kind(),
                        format!(
                            "classic provided buffers: {}",
                            io::Error::from_raw_os_error(-res)
                        ),
                    ));
                }
            }
        }
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let mut sender =
            TcpStream::connect_timeout(&listener.local_addr()?, Duration::from_secs(1))?;
        sender.set_write_timeout(Some(Duration::from_secs(1)))?;
        let accept = opcode::AcceptMulti::new(Fd(listener.as_raw_fd()))
            .flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
            .build();
        // SAFETY: listener lives through submission; this scratch SQ is empty.
        unsafe { ring.submission().push(&accept) }.map_err(|_| io::ErrorKind::Other)?;
        let (res, flags) = completion(&mut ring)?;
        // Own successful accept results even when the multishot flag is missing.
        let receiver = if res >= 0 {
            // SAFETY: successful ACCEPT transfers ownership of a new fd.
            Some(unsafe { OwnedFd::from_raw_fd(res) })
        } else {
            None
        };
        multishot_result("multishot accept", res, flags)?;
        let receiver = receiver.expect("validated successful accept");
        let recv = opcode::RecvMulti::new(Fd(receiver.as_raw_fd()), BGID).build();
        // SAFETY: receiver and registered buffer storage live through submission.
        unsafe { ring.submission().push(&recv) }.map_err(|_| io::ErrorKind::Other)?;
        sender.write_all(b"x")?;
        let (res, flags) = completion(&mut ring)?;
        multishot_result("multishot receive", res, flags)?;
        let bid = cqueue::buffer_select(flags)
            .filter(|&bid| bid < 4)
            .ok_or_else(|| unsupported("multishot receive with provided buffers"))?;
        if res != 1 || bufs.buf(bid, 1) != b"x" {
            return Err(unsupported("multishot receive data delivery"));
        }
        Ok(())
    })();
    bufs.unregister(&ring.submitter());
    drop(ring);
    drop(bufs);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_single_shot_and_failed_completions() {
        assert_eq!(
            multishot_result("recv", 1, 0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let err = multishot_result("recv", -libc::EINVAL, 0).unwrap_err();
        assert!(err.to_string().contains("recv"));
        assert!(multishot_result("recv", 1, 1 << 1 /* IORING_CQE_F_MORE */).is_ok());
    }

    #[test]
    fn classic_provided_buffers_pass_the_multishot_test() {
        multishot(Provide::Classic).unwrap();
    }

    #[test]
    fn coalesces_returned_ids_into_provide_runs() {
        let (ring, _) = make_ring(8).unwrap();
        let mut b = BufRing::new(&ring.submitter(), 8, 64, Provide::Classic).unwrap();
        let mut runs = Vec::new();
        b.commit(|_, first, n| runs.push((first, n)));
        assert_eq!(runs, [(0, 8)]);
        runs.clear();
        b.commit(|_, first, n| runs.push((first, n)));
        assert!(runs.is_empty());
        for bid in [3, 4, 5, 1, 7] {
            b.give(bid);
        }
        b.commit(|_, first, n| runs.push((first, n)));
        assert_eq!(runs, [(3, 3), (1, 1), (7, 1)]);
    }

    #[test]
    fn ring_mode_follows_defer_probe() {
        let (_ring, mode) = make_ring(8).unwrap();
        assert_eq!(
            mode == "single-issuer+defer-taskrun",
            defer_taskrun_usable(),
            "{mode}"
        );
        eprintln!(
            "ring mode on this kernel: {mode} missing={:?}",
            ring_mode_missing(mode)
        );
    }

    #[test]
    fn detects_required_capabilities_on_running_kernel() {
        let (ring, _) = make_ring(8).unwrap();
        check(&ring).unwrap();
    }

    #[test]
    fn detects_seccomp_disabled_io_uring() {
        for syscall in [libc::SYS_io_uring_setup, libc::SYS_io_uring_register] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "knet::capability::tests::blocked_syscall_child",
                    "--nocapture",
                ])
                .env("KNET_TEST_BLOCK_SYSCALL", syscall.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        }
    }

    #[test]
    fn blocked_syscall_child() {
        let Ok(syscall) = std::env::var("KNET_TEST_BLOCK_SYSCALL") else {
            return;
        };
        let syscall: u32 = syscall.parse().unwrap();
        // Install only in an isolated test subprocess; never alter the parent test runner.
        let mut filter = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            }, // LD W ABS: seccomp_data.nr
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: syscall,
            }, // JEQ
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: valid filter/program pointers; prctl copies the filter before returning.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog),
                0
            );
        }
        if syscall == libc::SYS_io_uring_setup as u32 {
            assert_eq!(
                make_ring(8).err().expect("setup must fail").raw_os_error(),
                Some(libc::ENOSYS)
            );
        } else {
            let (ring, _) = make_ring(8).unwrap();
            assert_eq!(check(&ring).unwrap_err().raw_os_error(), Some(libc::ENOSYS));
        }
    }
}

/// Result of the read-only capability report used by `croit-flashstore-osd --check` (hwcheck, adr 0166): same ring construction and
/// the same `check` as the transport startup, plus the optional features. Creates and drops a scratch ring only.
#[derive(Debug)]
pub struct IoUringReport {
    /// Ring setup flags that worked (best first: `single-issuer+defer-taskrun`, `single-issuer+coop-taskrun`, `coop-taskrun`, `plain`).
    pub ring_mode: &'static str,
    /// Required features (EXT_ARG, opcodes, multishot accept/recv with provided buffers): `Err` = first missing one.
    pub required: io::Result<()>,
    /// Receive buffers: `ring` (registered provided-buffer ring) or `classic` (`PROVIDE_BUFFERS` fallback), with the
    /// ring registration error in the classic case. `None` when `required` failed.
    pub rx_buffers: Option<(&'static str, Option<String>)>,
    /// `SENDMSG_ZC` opcode (probed; mainline since 6.1).
    pub send_zc: bool,
    /// `READ_FIXED`/`WRITE_FIXED` opcodes (registered buffers).
    pub fixed_buffers: bool,
}

/// Probe io_uring; `Err` when no ring can be created at all (disabled, seccomp, EPERM).
pub fn report() -> io::Result<IoUringReport> {
    let (ring, ring_mode) = make_ring(8)?;
    let caps = check(&ring);
    let rx_buffers = caps.as_ref().ok().map(|c| {
        (
            c.provide.name(),
            c.ring_err.as_ref().map(ToString::to_string),
        )
    });
    let required = caps.map(|_| ());
    let mut probe = Probe::new();
    let have = ring.submitter().register_probe(&mut probe).is_ok();
    Ok(IoUringReport {
        ring_mode,
        required,
        rx_buffers,
        send_zc: have && probe.is_supported(opcode::SendMsgZc::CODE),
        fixed_buffers: have
            && probe.is_supported(opcode::ReadFixed::CODE)
            && probe.is_supported(opcode::WriteFixed::CODE),
    })
}
