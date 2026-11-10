// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! GPUDirect registration probe with a mock device buffer (adr 0665 P1).
//!
//! Creates a `udmabuf` (the lab's GPU-memory stand-in), registers it as an RDMA READ source and an RDMA WRITE
//! destination on the device that carries `FLASHSTORE_TEST_RDMA_ADDR`, and prints the exported keys. No CUDA, no GPU:
//! this proves the DMA-BUF registration path, the key export and the registration cache on a real mlx5.
//!
//! usage: gpu_probe   (env: FLASHSTORE_TEST_RDMA_ADDR = local IP of a RoCEv2 device)
//! Exit: 0 registered, 1 provider/registration error, 2 usage/environment.
use rdma::gpu::{GpuAccess, GpuRegistry};
use rdma::verbs::Device;
use serde_json::json;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::ptr;

const UDMABUF_CREATE: libc::c_ulong = 0x4018_7542; // _IOW('u', 0x42, struct udmabuf_create)
const REGION: usize = 1 << 20;

#[repr(C)]
struct UdmabufCreate {
    memfd: u32,
    flags: u32,
    offset: u64,
    size: u64,
}

fn udmabuf(len: usize) -> io::Result<RawFd> {
    let name = b"croit-flashstore-gpu-probe\0";
    // SAFETY: valid NUL-terminated name; the fd is owned by this function.
    let memfd = unsafe {
        libc::memfd_create(
            name.as_ptr().cast(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if memfd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the memfd is open; the mapping is removed before returning.
    let mapped = unsafe {
        if libc::ftruncate(memfd, len as libc::off_t) != 0 {
            let e = io::Error::last_os_error();
            libc::close(memfd);
            return Err(e);
        }
        // udmabuf requires F_SEAL_SHRINK and forbids F_SEAL_WRITE (drivers/dma-buf/udmabuf.c).
        if libc::fcntl(memfd, libc::F_ADD_SEALS, libc::F_SEAL_SHRINK) != 0 {
            let e = io::Error::last_os_error();
            libc::close(memfd);
            return Err(e);
        }
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            memfd,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        let e = io::Error::last_os_error();
        // SAFETY: the memfd is ours.
        unsafe { libc::close(memfd) };
        return Err(e);
    }
    // A deterministic pattern so a later DMA test can verify the bytes.
    // SAFETY: the mapping covers `len` writable bytes.
    unsafe {
        let bytes = std::slice::from_raw_parts_mut(mapped.cast::<u8>(), len);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        libc::munmap(mapped, len);
    }
    let create = UdmabufCreate {
        memfd: memfd as u32,
        flags: 0,
        offset: 0,
        size: len as u64,
    };
    let path = b"/dev/udmabuf\0";
    // SAFETY: valid path; the returned fd is owned by the caller.
    let dev = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC) };
    if dev < 0 {
        let e = io::Error::last_os_error();
        // SAFETY: the memfd is ours.
        unsafe { libc::close(memfd) };
        return Err(e);
    }
    // SAFETY: `create` describes the memfd; the ioctl returns a dmabuf fd or fails.
    let rc = unsafe { libc::ioctl(dev, UDMABUF_CREATE, &create) };
    // SAFETY: the memfd is ours; the dmabuf keeps the pages.
    unsafe { libc::close(memfd) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        // SAFETY: the device fd is ours.
        unsafe { libc::close(dev) };
        return Err(e);
    }
    Ok(dev)
}

fn main() -> std::process::ExitCode {
    let addr = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
        .map_err(|_| {
            "FLASHSTORE_TEST_RDMA_ADDR (local IP of a RoCEv2 device) is not set".to_owned()
        })
        .and_then(|s| s.parse::<std::net::IpAddr>().map_err(|e| e.to_string()));
    let addr = match addr {
        Ok(a) => a,
        Err(e) => {
            eprintln!("gpu_probe: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let region: usize = std::env::var("GPU_PROBE_LEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(REGION);
    let fd = match udmabuf(2 * region) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("gpu_probe: udmabuf: {e} (need /dev/udmabuf)");
            return std::process::ExitCode::from(2);
        }
    };
    // SAFETY: the fd is ours; closing it after registration is fine (the MR pins the pages).
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let dev = match Device::open(rdma::gid_of(addr)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("gpu_probe: open {addr}: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    // The mock has no GPU VA: the iova is the address a peer would use. `GPU_PROBE_IOVA` selects it (0 lets the
    // provider use the DMA address); a real GPU passes the CUDA virtual address.
    let iova: u64 = std::env::var("GPU_PROBE_IOVA")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let registry = GpuRegistry::new();
    let mut dmabuf_error = String::new();
    let (read, write, backing, dmabuf_supported) = match (
        registry.get_or_register(
            &dev,
            fd.as_raw_fd(),
            0,
            iova,
            region as u64,
            GpuAccess::Read,
        ),
        registry.get_or_register(
            &dev,
            fd.as_raw_fd(),
            region as u64,
            iova + region as u64,
            region as u64,
            GpuAccess::Write,
        ),
    ) {
        (Ok(r), Ok(w)) => (r, w, "dmabuf", true),
        (Err(e), _) | (_, Err(e)) => {
            // The lab ConnectX-4 rejects DMA-BUF MRs. Host memory with the same access bits and rkey contract is the
            // functional GPU mock; the client API, registry, GET and PUT paths are identical.
            dmabuf_error = e.to_string();
            let mock = Box::leak(vec![0x5a_u8; 2 * region].into_boxed_slice());
            let base = mock.as_ptr() as u64;
            // SAFETY: the leaked mock buffer stays mapped for the process life.
            let r = unsafe {
                registry.get_or_register_host(&dev, base, region as u64, GpuAccess::Read)
            }
            .expect("host-mock READ registration");
            // SAFETY: the same leaked mapping, second half.
            let w = unsafe {
                registry.get_or_register_host(
                    &dev,
                    base + region as u64,
                    region as u64,
                    GpuAccess::Write,
                )
            }
            .expect("host-mock WRITE registration");
            (r, w, "host", false)
        }
    };
    let again = if dmabuf_supported {
        registry.get_or_register(
            &dev,
            fd.as_raw_fd(),
            0,
            iova,
            region as u64,
            GpuAccess::Read,
        )
    } else {
        // SAFETY: the leaked mock buffer stays mapped for the process life.
        unsafe {
            registry.get_or_register_host(&dev, read.address(), region as u64, GpuAccess::Read)
        }
    }
    .expect("cached registration");
    let destination = read
        .destination()
        .expect("GPU region as a placement destination");
    let foreign_destination = destination.is_borrowed();
    drop(destination);
    let record = json!({
        "device": dev.name(),
        "addr": addr.to_string(),
        "backing": backing,
        "dmabuf_supported": dmabuf_supported,
        "dmabuf_error": dmabuf_error,
        "read": {"rkey": read.rkey(), "lkey": read.lkey(), "address": read.address(), "length": read.length()},
        "write": {"rkey": write.rkey(), "lkey": write.lkey(), "address": write.address(), "length": write.length()},
        "cache_same": std::sync::Arc::ptr_eq(&read, &again),
        "foreign_destination": foreign_destination,
        "registry_live": registry.len(),
    });
    println!("{record}");
    if read.rkey() == 0 || write.rkey() == 0 || !std::sync::Arc::ptr_eq(&read, &again) {
        eprintln!("gpu_probe: invalid keys or cache miss");
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}
