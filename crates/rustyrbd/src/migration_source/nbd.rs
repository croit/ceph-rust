// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! The `nbd` client: fixed-newstyle handshake, option haggling and the
//! transmission phase, over TCP, AF_UNIX and AF_VSOCK.
//!
//! Spec: `doc/spec/rustyrbd/migration-source-http-s3-nbd.md`, "Stream
//! `nbd`", "URI forms" and "Protocol subset". Stage 10c PART 1 is the
//! client and the URI parser ([`super::nbd_uri`]); the `SourceStream`
//! adapter (`nbd` stream incl. `list_sparse`) is PART 2 and is not built
//! here.
//!
//! One connection per client behind a mutex, one request in flight (stock
//! serialises all NBD I/O per stream). `open` runs the whole handshake
//! (prepare time); `size`, [`NbdClient::read_at`] and
//! [`NbdClient::block_status`] are execute-time calls. Every failure is a
//! negative Linux errno. A protocol violation, a timeout or an I/O error
//! drops the connection: the call returns its errno and every later call is
//! `-ENOTCONN` (no reconnect, like stock).
//!
//! Deliberate divergences from stock (spec "Our behaviour"): a `HOLE`
//! descriptor without the `ZERO` bit is DATA ([`BlockStatusExtent::zeroed`]),
//! a read above the payload limit is split instead of refused, a
//! zero-length extent is a no-op, and every timeout is loud
//! (`WARNING TIMEOUT nbd <connect|handshake|read|block-status> exceeded
//! <n>s (<uri without query>)`) with `-ETIMEDOUT`. TLS (`nbds*`) is stage
//! 10c-tls: [`NbdClient::open`] refuses a TLS URI with `-ENOTSUP` for now.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use deadline::timeout_line;

use crate::journal_backend::{EINVAL, EIO, ENOENT, EPERM};
use crate::migration_source::ENOTSUP;
use crate::migration_source::nbd_uri::{NbdUri, Transport};

/// `ENOTCONN`: the client is not open, or a failed call left it unusable.
const ENOTCONN: i32 = -denc::errno::ENOTCONN;
/// `ETIMEDOUT`: a connect or I/O idle timeout fired and printed its
/// `WARNING TIMEOUT` line.
const ETIMEDOUT: i32 = -denc::errno::ETIMEDOUT;
/// `ESHUTDOWN` (108): the server answered an option with `SHUTDOWN`; Ceph's
/// `EBLOCKLISTED` alias carries the same value.
const ESHUTDOWN: i32 = -denc::errno::EBLOCKLISTED;
/// `ENOMEM`: the server carried a memory error on the wire.
const ENOMEM: i32 = crate::migration_source::ENOMEM;
/// `ENOSPC`: the server carried a space error on the wire.
const ENOSPC: i32 = -denc::errno::ENOSPC;
/// `EOVERFLOW`: the server carried an overflow error on the wire.
const EOVERFLOW: i32 = -denc::errno::EOVERFLOW;

/// Connect timeout of the loud-timeout rule (spec "Lead decisions", 2).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// I/O idle timeout of the loud-timeout rule (spec "Lead decisions", 2).
pub const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// `NBDMAGIC`: the first 8 bytes of every greeting.
const NBDMAGIC: u64 = 0x4e42_444d_4147_4943;
/// `IHAVEOPT`: the second 8 bytes of a newstyle greeting.
const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
/// The oldstyle greeting magic; we do not implement oldstyle (`-ENOTSUP`).
const OLDSTYLE_MAGIC: u64 = 0x0000_4202_8186_1253;
/// The magic of every option reply.
const OPTION_REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
/// The magic of a transmission request.
const REQUEST_MAGIC: u32 = 0x2560_9513;
/// The magic of a simple reply.
const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
/// The magic of a structured reply chunk.
const STRUCTURED_REPLY_MAGIC: u32 = 0x668e_33ef;

/// Handshake flag: the server supports option haggling.
const FLAG_FIXED_NEWSTYLE: u16 = 1;
/// Handshake flag: the server omits the 124 zero bytes after the size.
const FLAG_NO_ZEROES: u16 = 2;

/// `NBD_OPT_EXPORT_NAME`.
const OPT_EXPORT_NAME: u32 = 1;
/// `NBD_OPT_GO`.
const OPT_GO: u32 = 7;
/// `NBD_OPT_STRUCTURED_REPLY`.
const OPT_STRUCTURED_REPLY: u32 = 8;
/// `NBD_OPT_SET_META_CONTEXT`.
const OPT_SET_META_CONTEXT: u32 = 10;

/// `NBD_REP_ACK`.
const REPLY_ACK: u32 = 1;
/// `NBD_REP_INFO`.
const REPLY_INFO: u32 = 3;
/// `NBD_REP_META_CONTEXT`.
const REPLY_META_CONTEXT: u32 = 4;
/// The error bit of an option reply type.
const REPLY_ERROR: u32 = 1 << 31;

/// `NBD_REP_ERR_UNSUP`: the server does not implement the option.
const ERROR_UNSUP: u32 = 1;
/// `NBD_REP_ERR_POLICY`: the server refuses the option.
const ERROR_POLICY: u32 = 2;
/// `NBD_REP_ERR_TLS_REQD`: the server requires TLS first.
const ERROR_TLS_REQD: u32 = 5;
/// `NBD_REP_ERR_UNKNOWN`: the export does not exist.
const ERROR_UNKNOWN: u32 = 6;
/// `NBD_REP_ERR_SHUTDOWN`: the server is shutting down.
const ERROR_SHUTDOWN: u32 = 7;

/// `NBD_INFO_EXPORT`.
const INFO_EXPORT: u16 = 0;
/// `NBD_INFO_BLOCK_SIZE`.
const INFO_BLOCK_SIZE: u16 = 3;

/// `NBD_CMD_READ`.
const CMD_READ: u16 = 0;
/// `NBD_CMD_DISC`.
const CMD_DISC: u16 = 2;
/// `NBD_CMD_BLOCK_STATUS`.
const CMD_BLOCK_STATUS: u16 = 7;

/// `NBD_REPLY_FLAG_DONE`: the last chunk of one request.
const CHUNK_DONE: u16 = 1;
/// `NBD_REPLY_TYPE_NONE`.
const CHUNK_NONE: u16 = 0;
/// `NBD_REPLY_TYPE_OFFSET_DATA`.
const CHUNK_OFFSET_DATA: u16 = 1;
/// `NBD_REPLY_TYPE_OFFSET_HOLE`.
const CHUNK_OFFSET_HOLE: u16 = 2;
/// `NBD_REPLY_TYPE_BLOCK_STATUS`.
const CHUNK_BLOCK_STATUS: u16 = 5;
/// `NBD_REPLY_TYPE_ERROR`.
const CHUNK_ERROR: u16 = 32769;
/// `NBD_REPLY_TYPE_ERROR_OFFSET`.
const CHUNK_ERROR_OFFSET: u16 = 32770;
/// The error bit of a structured reply chunk type.
const CHUNK_ERROR_BIT: u16 = 0x8000;

/// `NBD_STATE_HOLE`: the range is sparse (it may still read non-zero).
pub const STATE_HOLE: u32 = 1;
/// `NBD_STATE_ZERO`: the range reads as zeroes.
pub const STATE_ZERO: u32 = 2;

/// The meta context the client asks for.
const META_CONTEXT: &[u8] = b"base:allocation";

/// The largest option reply payload we accept (spec: a sane bound).
const MAX_OPTION_REPLY: u32 = 64 * 1024;
/// The largest structured chunk payload we accept (a 32 MiB read plus its
/// offset field, with room for block-status descriptors).
const MAX_CHUNK_PAYLOAD: u32 = 64 * 1024 * 1024;
/// The payload limit when the server advertises none (protocol default).
const DEFAULT_MAX_PAYLOAD: u32 = 32 * 1024 * 1024;

/// The operation names of the loud-timeout line.
const OP_CONNECT: &str = "connect";
const OP_HANDSHAKE: &str = "handshake";
const OP_READ: &str = "read";
const OP_BLOCK_STATUS: &str = "block-status";

/// One block-status extent: a range the server described, with its raw
/// `base:allocation` flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockStatusExtent {
    /// Image offset of the extent start.
    pub offset: u64,
    /// Extent length in bytes.
    pub length: u64,
    /// The `base:allocation` flags ([`STATE_HOLE`], [`STATE_ZERO`]).
    pub flags: u32,
}

impl BlockStatusExtent {
    /// `true` when the range reads as zeroes, i.e. the `ZERO` bit is set.
    ///
    /// Spec divergence (lead decision 3): a `HOLE` without `ZERO` is DATA,
    /// because such a range may read non-zero and stock's hole-means-zero
    /// rule can drop data.
    pub fn zeroed(&self) -> bool {
        self.flags & STATE_ZERO != 0
    }
}

/// A blocking NBD client on one export.
#[derive(Debug)]
pub struct NbdClient {
    uri: NbdUri,
    timeouts: Timeouts,
    state: Mutex<State>,
}

/// The timeout pair of one client; the unit tests lower it.
#[derive(Clone, Copy, Debug)]
struct Timeouts {
    connect: Duration,
    io: Duration,
}

/// The mutable client state behind the mutex.
#[derive(Debug, Default)]
struct State {
    conn: Option<Conn>,
    timeouts: usize,
}

impl NbdClient {
    /// A client on one parsed URI; nothing is connected yet.
    pub fn new(uri: NbdUri) -> Self {
        Self::with_timeouts(uri, CONNECT_TIMEOUT, IO_TIMEOUT)
    }

    /// A client with explicit timeouts; the unit tests lower them.
    fn with_timeouts(uri: NbdUri, connect: Duration, io: Duration) -> Self {
        Self {
            uri,
            timeouts: Timeouts { connect, io },
            state: Mutex::new(State::default()),
        }
    }

    /// Connect and run the whole handshake (prepare time). A second call on
    /// an open client is a no-op. `-ENOTSUP` for a TLS URI (stage 10c-tls).
    pub fn open(&self) -> Result<(), i32> {
        let mut state = self.lock();
        if state.conn.is_some() {
            return Ok(());
        }
        if self.uri.tls().is_some() {
            return Err(ENOTSUP);
        }
        let result = connect(&self.uri, self.timeouts.connect).and_then(|socket| {
            let mut conn = Conn::new(socket, &self.uri, self.timeouts.io)?;
            conn.handshake(self.uri.export())?;
            Ok(conn)
        });
        match result {
            Ok(conn) => {
                state.conn = Some(conn);
                Ok(())
            }
            Err(errno) => {
                if errno == ETIMEDOUT {
                    state.timeouts += 1;
                }
                Err(errno)
            }
        }
    }

    /// The export size from the handshake; `-ENOTCONN` when not open.
    pub fn size(&self) -> Result<u64, i32> {
        self.run(|conn| Ok(conn.size))
    }

    /// Read exactly `out.len()` bytes at `offset`. A request past the export
    /// end is `-EINVAL` and sends nothing; a zero-length read is a no-op;
    /// any failure clears `out`.
    pub fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<(), i32> {
        self.run(|conn| conn.read_at(offset, out))
    }

    /// The `base:allocation` descriptors of `[offset, offset + length)`,
    /// trimmed to that range and offset ascending; empty when the server
    /// negotiated no meta context. A request past the export end is
    /// `-EINVAL`.
    pub fn block_status(&self, offset: u64, length: u64) -> Result<Vec<BlockStatusExtent>, i32> {
        self.run(|conn| conn.block_status(offset, length))
    }

    /// Send `NBD_CMD_DISC`, shut the socket down and forget the connection.
    /// Errors are ignored; the client can be opened again.
    pub fn close(&self) {
        let mut state = self.lock();
        if let Some(mut conn) = state.conn.take() {
            conn.disconnect();
        }
    }

    /// The timeouts that fired so far; each one printed a `WARNING TIMEOUT`
    /// line.
    pub fn timeouts(&self) -> usize {
        self.lock().timeouts
    }

    /// Run one call on the connection; a dead connection is forgotten, so
    /// every later call is `-ENOTCONN`.
    fn run<T>(&self, call: impl FnOnce(&mut Conn) -> Result<T, i32>) -> Result<T, i32> {
        let mut state = self.lock();
        let Some(conn) = state.conn.as_mut() else {
            return Err(ENOTCONN);
        };
        let result = call(conn);
        let dead = conn.dead;
        if dead {
            state.conn = None;
        }
        if matches!(result, Err(ETIMEDOUT)) {
            state.timeouts += 1;
        }
        result
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for NbdClient {
    fn drop(&mut self) {
        self.close();
    }
}

/// One live connection: the socket plus everything the handshake
/// negotiated.
#[derive(Debug)]
struct Conn {
    socket: Socket,
    display: String,
    io_timeout: Duration,
    fixed: bool,
    no_zeroes: bool,
    structured: bool,
    allocation_context: Option<u32>,
    size: u64,
    min_block: u32,
    max_payload: u32,
    next_cookie: u64,
    dead: bool,
}

impl Conn {
    fn new(socket: Socket, uri: &NbdUri, io_timeout: Duration) -> Result<Self, i32> {
        socket
            .set_timeouts(io_timeout)
            .map_err(|error| os_errno(&error))?;
        Ok(Self {
            socket,
            display: uri.display().to_owned(),
            io_timeout,
            fixed: false,
            no_zeroes: false,
            structured: false,
            allocation_context: None,
            size: 0,
            min_block: 1,
            max_payload: DEFAULT_MAX_PAYLOAD,
            next_cookie: 1,
            dead: false,
        })
    }

    /// Fixed-newstyle handshake, options, then export selection (spec
    /// "Protocol subset", steps 1-8).
    fn handshake(&mut self, export: &str) -> Result<(), i32> {
        let mut greeting = [0u8; 16];
        self.read_exact(OP_HANDSHAKE, &mut greeting)?;
        if be_u64(&greeting, 0) != NBDMAGIC {
            self.dead = true;
            return Err(EINVAL);
        }
        match be_u64(&greeting, 8) {
            IHAVEOPT => {}
            OLDSTYLE_MAGIC => {
                self.dead = true;
                return Err(ENOTSUP);
            }
            _ => {
                self.dead = true;
                return Err(EINVAL);
            }
        }
        let mut flags = [0u8; 2];
        self.read_exact(OP_HANDSHAKE, &mut flags)?;
        let offered = be_u16(&flags, 0);
        self.fixed = offered & FLAG_FIXED_NEWSTYLE != 0;
        self.no_zeroes = offered & FLAG_NO_ZEROES != 0;
        let client_flags = offered & (FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES);
        self.write_all(OP_HANDSHAKE, &u32::from(client_flags).to_be_bytes())?;
        if !self.fixed {
            // Without FIXED_NEWSTYLE no option may be sent: the export name
            // follows bare and there is no option reply.
            return self.export_name(export);
        }
        match self.option_exchange(OPT_STRUCTURED_REPLY, &[], |_, _| Ok(())) {
            Ok(()) => self.structured = true,
            Err(ENOTSUP) => self.structured = false,
            Err(errno) => return Err(errno),
        }
        if self.structured {
            self.negotiate_meta_context(export)?;
        }
        match self.go(export) {
            Ok(()) => Ok(()),
            Err(ENOTSUP) => self.export_name(export),
            Err(errno) => Err(errno),
        }
    }

    /// `NBD_OPT_SET_META_CONTEXT` for `base:allocation`; an error reply or
    /// no matching entry only means "no block status" (not a failure).
    fn negotiate_meta_context(&mut self, export: &str) -> Result<(), i32> {
        let mut data = Vec::with_capacity(12 + export.len() + META_CONTEXT.len());
        data.extend_from_slice(&(export.len() as u32).to_be_bytes());
        data.extend_from_slice(export.as_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&(META_CONTEXT.len() as u32).to_be_bytes());
        data.extend_from_slice(META_CONTEXT);
        let mut context = None;
        let result = self.option_exchange(OPT_SET_META_CONTEXT, &data, |reply, payload| {
            if reply == REPLY_META_CONTEXT {
                if payload.len() < 4 {
                    return Err(EINVAL);
                }
                if &payload[4..] == META_CONTEXT {
                    context = Some(be_u32(payload, 0));
                }
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                self.allocation_context = context;
                Ok(())
            }
            Err(errno) if self.dead => Err(errno),
            Err(_) => {
                self.allocation_context = None;
                Ok(())
            }
        }
    }

    /// `NBD_OPT_GO` with one `NBD_INFO_BLOCK_SIZE` request.
    fn go(&mut self, export: &str) -> Result<(), i32> {
        let mut data = Vec::with_capacity(10 + export.len());
        data.extend_from_slice(&(export.len() as u32).to_be_bytes());
        data.extend_from_slice(export.as_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&INFO_BLOCK_SIZE.to_be_bytes());
        let mut size = None;
        let mut block = None;
        self.option_exchange(OPT_GO, &data, |reply, payload| {
            if reply == REPLY_INFO {
                parse_info(payload, &mut size, &mut block)?;
            }
            Ok(())
        })?;
        let Some(size) = size else {
            // NBD_INFO_EXPORT is mandatory in a GO reply.
            self.dead = true;
            return Err(EINVAL);
        };
        self.size = size;
        if let Some((minimum, maximum)) = block {
            self.min_block = minimum;
            self.max_payload = maximum;
        }
        Ok(())
    }

    /// `NBD_OPT_EXPORT_NAME`: the name, then the size, the transmission
    /// flags and (unless NO_ZEROES was agreed) 124 zero bytes. A server that
    /// closes instead does not have the export (`-ENOENT`).
    fn export_name(&mut self, export: &str) -> Result<(), i32> {
        if self.fixed {
            self.send_option(OPT_EXPORT_NAME, export.as_bytes())?;
        } else {
            let mut frame = Vec::with_capacity(4 + export.len());
            frame.extend_from_slice(&(export.len() as u32).to_be_bytes());
            frame.extend_from_slice(export.as_bytes());
            self.write_all(OP_HANDSHAKE, &frame)?;
        }
        let mut tail = [0u8; 10];
        if !self.read_fill(OP_HANDSHAKE, &mut tail, true)? {
            self.dead = true;
            return Err(ENOENT);
        }
        self.size = be_u64(&tail, 0);
        if !self.no_zeroes {
            let mut zeroes = [0u8; 124];
            self.read_exact(OP_HANDSHAKE, &mut zeroes)?;
        }
        self.min_block = 1;
        self.max_payload = DEFAULT_MAX_PAYLOAD;
        Ok(())
    }

    /// Send one option frame and consume its replies up to the ACK; the
    /// callback sees every non-ACK reply. An error reply is returned as its
    /// errno.
    fn option_exchange(
        &mut self,
        option: u32,
        data: &[u8],
        mut on_reply: impl FnMut(u32, &[u8]) -> Result<(), i32>,
    ) -> Result<(), i32> {
        self.send_option(option, data)?;
        loop {
            let mut header = [0u8; 20];
            self.read_exact(OP_HANDSHAKE, &mut header)?;
            if be_u64(&header, 0) != OPTION_REPLY_MAGIC || be_u32(&header, 8) != option {
                self.dead = true;
                return Err(EINVAL);
            }
            let reply = be_u32(&header, 12);
            let length = be_u32(&header, 16);
            if length > MAX_OPTION_REPLY {
                self.dead = true;
                return Err(EINVAL);
            }
            let mut payload = vec![0u8; length as usize];
            self.read_exact(OP_HANDSHAKE, &mut payload)?;
            if reply & REPLY_ERROR != 0 {
                return Err(option_error_errno(reply & !REPLY_ERROR));
            }
            if reply == REPLY_ACK {
                return Ok(());
            }
            if let Err(errno) = on_reply(reply, &payload) {
                self.dead = true;
                return Err(errno);
            }
        }
    }

    fn send_option(&mut self, option: u32, data: &[u8]) -> Result<(), i32> {
        let mut frame = Vec::with_capacity(16 + data.len());
        frame.extend_from_slice(&IHAVEOPT.to_be_bytes());
        frame.extend_from_slice(&option.to_be_bytes());
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
        frame.extend_from_slice(data);
        self.write_all(OP_HANDSHAKE, &frame)
    }

    /// Read `out.len()` bytes at `offset`; any failure clears `out`.
    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), i32> {
        let result = self.read_chunks(offset, out);
        if result.is_err() {
            out.fill(0);
        }
        result
    }

    fn read_chunks(&mut self, offset: u64, out: &mut [u8]) -> Result<(), i32> {
        let end = offset.checked_add(out.len() as u64).ok_or(EINVAL)?;
        if end > self.size {
            // Client-side, before anything is sent (stock strict mode).
            return Err(EINVAL);
        }
        let mut done = 0usize;
        while done < out.len() {
            let chunk = (out.len() - done).min(self.max_payload as usize);
            let at = offset + done as u64;
            let cookie = self.send_request(OP_READ, CMD_READ, at, chunk as u32, &[])?;
            let slice = &mut out[done..done + chunk];
            if self.structured {
                self.read_structured_reply(at, slice, cookie)?;
            } else {
                self.read_simple_reply(slice, cookie)?;
            }
            done += chunk;
        }
        Ok(())
    }

    fn read_simple_reply(&mut self, out: &mut [u8], cookie: u64) -> Result<(), i32> {
        let mut header = [0u8; 16];
        self.read_exact(OP_READ, &mut header)?;
        if be_u32(&header, 0) != SIMPLE_REPLY_MAGIC || be_u64(&header, 8) != cookie {
            self.dead = true;
            return Err(EIO);
        }
        let error = be_u32(&header, 4);
        if error != 0 {
            return Err(wire_errno(error));
        }
        self.read_exact(OP_READ, out)
    }

    /// One structured reply: chunks until DONE, every byte of the request
    /// covered exactly once, then the data or the carried error.
    fn read_structured_reply(
        &mut self,
        offset: u64,
        out: &mut [u8],
        cookie: u64,
    ) -> Result<(), i32> {
        let mut covered = vec![0u8; out.len().div_ceil(8)];
        let mut error = None;
        loop {
            let (flags, ty, length) = self.read_chunk_header(OP_READ, cookie)?;
            let done = flags & CHUNK_DONE != 0;
            match ty {
                CHUNK_NONE => {
                    if !done || length != 0 {
                        self.dead = true;
                        return Err(EINVAL);
                    }
                }
                CHUNK_OFFSET_DATA => {
                    if length < 8 {
                        self.dead = true;
                        return Err(EINVAL);
                    }
                    let mut field = [0u8; 8];
                    self.read_exact(OP_READ, &mut field)?;
                    let at = be_u64(&field, 0);
                    let data_length = u64::from(length) - 8;
                    let start = match reserve(&mut covered, out, offset, at, data_length) {
                        Ok(start) => start,
                        Err(errno) => {
                            self.dead = true;
                            return Err(errno);
                        }
                    };
                    // The payload goes straight into the caller's buffer: no
                    // staging copy and no request-sized allocation.
                    self.read_exact(OP_READ, &mut out[start..start + data_length as usize])?;
                }
                CHUNK_OFFSET_HOLE => {
                    if length != 12 {
                        self.dead = true;
                        return Err(EINVAL);
                    }
                    let mut field = [0u8; 12];
                    self.read_exact(OP_READ, &mut field)?;
                    let at = be_u64(&field, 0);
                    let hole = u64::from(be_u32(&field, 8));
                    let start = match reserve(&mut covered, out, offset, at, hole) {
                        Ok(start) => start,
                        Err(errno) => {
                            self.dead = true;
                            return Err(errno);
                        }
                    };
                    out[start..start + hole as usize].fill(0);
                }
                CHUNK_ERROR | CHUNK_ERROR_OFFSET => {
                    let payload = self.read_payload(OP_READ, length)?;
                    match error_chunk(&payload, ty == CHUNK_ERROR_OFFSET) {
                        Ok(errno) => error = Some(errno),
                        Err(errno) => {
                            self.dead = true;
                            return Err(errno);
                        }
                    }
                }
                _ if ty & CHUNK_ERROR_BIT != 0 => {
                    // An unknown error chunk must not be skipped.
                    self.dead = true;
                    return Err(EINVAL);
                }
                _ => {
                    // A chunk type the protocol allows to be skipped; any
                    // other known type (e.g. BLOCK_STATUS) is invalid here.
                    if ty == CHUNK_BLOCK_STATUS {
                        self.dead = true;
                        return Err(EINVAL);
                    }
                    self.skip_payload(OP_READ, length)?;
                }
            }
            if done {
                break;
            }
        }
        if let Some(errno) = error {
            return Err(errno);
        }
        if (0..out.len()).any(|at| covered[at / 8] & (1 << (at % 8)) == 0) {
            self.dead = true;
            return Err(EIO);
        }
        Ok(())
    }

    /// One structured chunk header: magic, cookie and the sane payload
    /// bound.
    fn read_chunk_header(&mut self, op: &str, cookie: u64) -> Result<(u16, u16, u32), i32> {
        let mut header = [0u8; 20];
        self.read_exact(op, &mut header)?;
        if be_u32(&header, 0) != STRUCTURED_REPLY_MAGIC || be_u64(&header, 8) != cookie {
            self.dead = true;
            return Err(EIO);
        }
        let length = be_u32(&header, 16);
        if length > MAX_CHUNK_PAYLOAD {
            self.dead = true;
            return Err(EINVAL);
        }
        Ok((be_u16(&header, 4), be_u16(&header, 6), length))
    }

    /// Read and return one chunk payload (error and unknown chunks).
    fn read_payload(&mut self, op: &str, length: u32) -> Result<Vec<u8>, i32> {
        let mut payload = vec![0u8; length as usize];
        self.read_exact(op, &mut payload)?;
        Ok(payload)
    }

    /// Consume and drop one chunk payload.
    fn skip_payload(&mut self, op: &str, length: u32) -> Result<(), i32> {
        let mut remaining = length as usize;
        let mut scratch = [0u8; 1024];
        while remaining > 0 {
            let chunk = remaining.min(scratch.len());
            self.read_exact(op, &mut scratch[..chunk])?;
            remaining -= chunk;
        }
        Ok(())
    }

    /// `NBD_CMD_BLOCK_STATUS` over `[offset, offset + length)`; empty when no
    /// meta context was negotiated, the range is empty, or it does not
    /// intersect the export.
    fn block_status(&mut self, offset: u64, length: u64) -> Result<Vec<BlockStatusExtent>, i32> {
        let Some(context) = self.allocation_context else {
            return Ok(Vec::new());
        };
        if length == 0 {
            return Ok(Vec::new());
        }
        let end = offset.checked_add(length).ok_or(EINVAL)?;
        if end > self.size {
            return Err(EINVAL);
        }
        // The count must fit the 32-bit length field and be aligned to the
        // minimum block size (spec "block status").
        let limit = u64::from(u32::MAX) - u64::from(self.min_block);
        let count = length.min(limit);
        let count = count - count % u64::from(self.min_block);
        if count == 0 {
            return Ok(Vec::new());
        }
        let cookie = self.send_request(
            OP_BLOCK_STATUS,
            CMD_BLOCK_STATUS,
            offset,
            count as u32,
            &context.to_be_bytes(),
        )?;
        let mut extents = Vec::new();
        let mut walk = offset;
        let mut error = None;
        loop {
            let (flags, ty, length) = self.read_chunk_header(OP_BLOCK_STATUS, cookie)?;
            let done = flags & CHUNK_DONE != 0;
            match ty {
                CHUNK_NONE => {
                    if !done || length != 0 {
                        self.dead = true;
                        return Err(EINVAL);
                    }
                }
                CHUNK_BLOCK_STATUS => {
                    let payload = self.read_payload(OP_BLOCK_STATUS, length)?;
                    if payload.len() < 4 || (payload.len() - 4) % 8 != 0 {
                        self.dead = true;
                        return Err(EINVAL);
                    }
                    if be_u32(&payload, 0) == context {
                        let descriptors = &payload[4..];
                        for at in (0..descriptors.len()).step_by(8) {
                            let length = u64::from(be_u32(descriptors, at));
                            let flags = be_u32(descriptors, at + 4);
                            if length == 0 {
                                continue;
                            }
                            extents.push(BlockStatusExtent {
                                offset: walk,
                                length,
                                flags,
                            });
                            walk = walk.saturating_add(length);
                        }
                    }
                }
                CHUNK_ERROR | CHUNK_ERROR_OFFSET => {
                    let payload = self.read_payload(OP_BLOCK_STATUS, length)?;
                    match error_chunk(&payload, ty == CHUNK_ERROR_OFFSET) {
                        Ok(errno) => error = Some(errno),
                        Err(errno) => {
                            self.dead = true;
                            return Err(errno);
                        }
                    }
                }
                CHUNK_OFFSET_DATA | CHUNK_OFFSET_HOLE => {
                    self.dead = true;
                    return Err(EINVAL);
                }
                _ if ty & CHUNK_ERROR_BIT != 0 => {
                    self.dead = true;
                    return Err(EINVAL);
                }
                _ => self.skip_payload(OP_BLOCK_STATUS, length)?,
            }
            if done {
                break;
            }
        }
        if let Some(errno) = error {
            return Err(errno);
        }
        // Servers may describe more than was asked; trim to the request.
        let mut trimmed = Vec::with_capacity(extents.len());
        for mut extent in extents {
            if extent.offset >= end {
                continue;
            }
            extent.length = extent.length.min(end - extent.offset);
            trimmed.push(extent);
        }
        Ok(trimmed)
    }

    /// One request header (and an optional extra payload); returns the
    /// cookie the reply must echo.
    fn send_request(
        &mut self,
        op: &str,
        ty: u16,
        offset: u64,
        length: u32,
        extra: &[u8],
    ) -> Result<u64, i32> {
        let cookie = self.next_cookie;
        self.next_cookie = self.next_cookie.wrapping_add(1);
        let mut frame = [0u8; 28];
        frame[0..4].copy_from_slice(&REQUEST_MAGIC.to_be_bytes());
        frame[6..8].copy_from_slice(&ty.to_be_bytes());
        frame[8..16].copy_from_slice(&cookie.to_be_bytes());
        frame[16..24].copy_from_slice(&offset.to_be_bytes());
        frame[24..28].copy_from_slice(&length.to_be_bytes());
        self.write_all(op, &frame)?;
        if !extra.is_empty() {
            self.write_all(op, extra)?;
        }
        Ok(cookie)
    }

    /// `NBD_CMD_DISC` and a socket shutdown; errors are ignored.
    fn disconnect(&mut self) {
        let mut frame = [0u8; 28];
        frame[0..4].copy_from_slice(&REQUEST_MAGIC.to_be_bytes());
        frame[6..8].copy_from_slice(&CMD_DISC.to_be_bytes());
        let _ = self.socket.write_all(&frame);
        self.socket.shutdown();
        self.dead = true;
    }

    fn read_exact(&mut self, op: &str, buf: &mut [u8]) -> Result<(), i32> {
        self.read_fill(op, buf, false).map(|_| ())
    }

    /// Fill `buf`; `Ok(false)` when the peer closed before the first byte
    /// and `eof_at_start` allows it, `-EIO` for a close mid-buffer.
    fn read_fill(&mut self, op: &str, buf: &mut [u8], eof_at_start: bool) -> Result<bool, i32> {
        let mut done = 0usize;
        while done < buf.len() {
            match self.socket.read(&mut buf[done..]) {
                Ok(0) if done == 0 && eof_at_start => return Ok(false),
                Ok(0) => {
                    self.dead = true;
                    return Err(EIO);
                }
                Ok(read) => done += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(self.io_error(op, &error)),
            }
        }
        Ok(true)
    }

    fn write_all(&mut self, op: &str, buf: &[u8]) -> Result<(), i32> {
        match self.socket.write_all(buf) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.io_error(op, &error)),
        }
    }

    /// Map one socket error: a timeout prints the loud line, everything else
    /// is its errno; the connection is always dropped.
    fn io_error(&mut self, op: &str, error: &io::Error) -> i32 {
        self.dead = true;
        match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                diag::diag!(
                    "{}",
                    timeout_line(&format!("nbd {op}"), self.io_timeout, &self.display)
                );
                ETIMEDOUT
            }
            io::ErrorKind::UnexpectedEof => EIO,
            _ => os_errno(error),
        }
    }
}

/// One connected socket; AF_VSOCK has no `std` wrapper, so it stays a raw
/// descriptor.
#[derive(Debug)]
enum Socket {
    Tcp(TcpStream),
    Unix(UnixStream),
    Vsock(OwnedFd),
}

impl Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            Self::Unix(stream) => stream.read(buf),
            Self::Vsock(fd) => read_fd(fd.as_raw_fd(), buf),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(buf),
            Self::Unix(stream) => stream.write_all(buf),
            Self::Vsock(fd) => write_all_fd(fd.as_raw_fd(), buf),
        }
    }

    fn set_timeouts(&self, io_timeout: Duration) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => {
                stream.set_read_timeout(Some(io_timeout))?;
                stream.set_write_timeout(Some(io_timeout))
            }
            Self::Unix(stream) => {
                stream.set_read_timeout(Some(io_timeout))?;
                stream.set_write_timeout(Some(io_timeout))
            }
            Self::Vsock(fd) => set_socket_timeouts(fd.as_raw_fd(), io_timeout),
        }
    }

    fn shutdown(&mut self) {
        match self {
            Self::Tcp(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
            }
            Self::Unix(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
            }
            Self::Vsock(fd) => {
                // SAFETY: the descriptor is owned by the client and alive.
                unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR) };
            }
        }
    }
}

/// `libc::read` on a raw descriptor, retrying `EINTR`.
fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `buf` is a valid writable slice for its whole length.
        let read = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if read >= 0 {
            return Ok(read as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// `libc::write` of the whole buffer on a raw descriptor, retrying `EINTR`.
fn write_all_fd(fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        // SAFETY: the slice starts at `done` and is readable to its end.
        let written = unsafe {
            libc::write(
                fd,
                buf[done..].as_ptr().cast(),
                buf.len().saturating_sub(done),
            )
        };
        if written > 0 {
            done += written as usize;
            continue;
        }
        if written == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

/// `SO_RCVTIMEO` and `SO_SNDTIMEO` of a raw descriptor (AF_VSOCK).
fn set_socket_timeouts(fd: RawFd, io_timeout: Duration) -> io::Result<()> {
    let timeval = libc::timeval {
        tv_sec: io_timeout.as_secs() as libc::time_t,
        tv_usec: io_timeout.subsec_micros() as libc::suseconds_t,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: `timeval` is a live, correctly sized value for both options.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&raw const timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Connect one parsed URI; `-errno` on failure, with a loud line for a
/// connect timeout.
fn connect(uri: &NbdUri, timeout: Duration) -> Result<Socket, i32> {
    match uri.transport() {
        Transport::Tcp { host, port } => connect_tcp(host, *port, timeout, uri.display()),
        Transport::Unix { socket } => connect_unix(socket, timeout, uri.display()),
        Transport::Vsock { cid, port } => connect_vsock(*cid, *port, timeout, uri.display()),
    }
}

/// Every resolved address is tried in order; not-found is `-ENOENT`, every
/// other resolver failure `-EIO` (lead decision 6).
fn connect_tcp(host: &str, port: u16, timeout: Duration, display: &str) -> Result<Socket, i32> {
    let addrs = (host, port).to_socket_addrs().map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ENOENT
        } else {
            EIO
        }
    })?;
    let mut last = EIO;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(Socket::Tcp(stream)),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                diag::diag!(
                    "{}",
                    timeout_line(&format!("nbd {OP_CONNECT}"), timeout, display)
                );
                last = ETIMEDOUT;
            }
            Err(error) => last = os_errno(&error),
        }
    }
    Err(last)
}

/// An AF_UNIX connect with the connect timeout; a path that does not fit
/// `sun_path` is `-ENAMETOOLONG`.
fn connect_unix(path: &str, timeout: Duration, display: &str) -> Result<Socket, i32> {
    // SAFETY: a zeroed `sockaddr_un` is an empty address; family and path
    // bytes are filled below.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(-denc::errno::ENAMETOOLONG);
    }
    for (slot, byte) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let length = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    let fd = connect_socket(
        libc::AF_UNIX,
        (&raw const addr).cast(),
        length,
        timeout,
        display,
    )?;
    // SAFETY: `fd` is a fresh, connected AF_UNIX stream socket owned here.
    Ok(Socket::Unix(unsafe { UnixStream::from_raw_fd(fd) }))
}

/// An AF_VSOCK connect with the connect timeout.
fn connect_vsock(cid: u32, port: u32, timeout: Duration, display: &str) -> Result<Socket, i32> {
    // SAFETY: a zeroed `sockaddr_vm` is an empty address; the family, cid
    // and port are filled below.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = cid;
    addr.svm_port = port;
    let length = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
    let fd = connect_socket(
        libc::AF_VSOCK,
        (&raw const addr).cast(),
        length,
        timeout,
        display,
    )?;
    // SAFETY: `fd` is a fresh, connected AF_VSOCK stream socket owned here.
    Ok(Socket::Vsock(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// A nonblocking connect bounded by `timeout`; the descriptor is returned
/// in blocking mode.
fn connect_socket(
    family: libc::c_int,
    addr: *const libc::sockaddr,
    length: libc::socklen_t,
    timeout: Duration,
    display: &str,
) -> Result<RawFd, i32> {
    // SAFETY: a plain socket creation; the descriptor is checked below.
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(os_errno(&io::Error::last_os_error()));
    }
    // SAFETY: plain fcntl call on the new descriptor; FD_CLOEXEC keeps the
    // socket out of exec'd children on every Unix.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(os_errno(&error));
    }
    match connect_fd(fd, addr, length, timeout, display) {
        Ok(()) => Ok(fd),
        Err(errno) => {
            // SAFETY: `fd` is owned here and not used after the close.
            unsafe { libc::close(fd) };
            Err(errno)
        }
    }
}

fn connect_fd(
    fd: RawFd,
    addr: *const libc::sockaddr,
    length: libc::socklen_t,
    timeout: Duration,
    display: &str,
) -> Result<(), i32> {
    // SAFETY: plain fcntl calls on an owned descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(os_errno(&io::Error::last_os_error()));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(os_errno(&io::Error::last_os_error()));
    }
    // SAFETY: `addr` and `length` describe one valid socket address.
    if unsafe { libc::connect(fd, addr, length) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(os_errno(&error));
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                diag::diag!(
                    "{}",
                    timeout_line(&format!("nbd {OP_CONNECT}"), timeout, display)
                );
                return Err(ETIMEDOUT);
            }
            let mut polled = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: one live `pollfd` entry.
            let ready = unsafe { libc::poll(&mut polled, 1, millis) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(os_errno(&error));
            }
            if ready == 0 {
                diag::diag!(
                    "{}",
                    timeout_line(&format!("nbd {OP_CONNECT}"), timeout, display)
                );
                return Err(ETIMEDOUT);
            }
            break;
        }
        let mut so_error: libc::c_int = 0;
        let mut so_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `so_error` and `so_length` are correctly sized for
        // `SO_ERROR`.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut so_error).cast(),
                &mut so_length,
            )
        };
        if rc != 0 {
            return Err(os_errno(&io::Error::last_os_error()));
        }
        if so_error != 0 {
            return Err(-so_error);
        }
    }
    // SAFETY: plain fcntl call on an owned descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
        return Err(os_errno(&io::Error::last_os_error()));
    }
    Ok(())
}

/// `-errno` of one socket error; `-EIO` when it carries none.
fn os_errno(error: &io::Error) -> i32 {
    error.raw_os_error().map_or(EIO, |code| -code)
}

/// Mark `[at, at + length)` of one request as covered and return its start
/// index in `out`. A range outside the request or a byte covered twice is
/// `-EIO`; the caller then writes the bytes or the zeroes itself, so a data
/// chunk needs no staging buffer.
fn reserve(
    covered: &mut [u8],
    out: &[u8],
    request: u64,
    at: u64,
    length: u64,
) -> Result<usize, i32> {
    let end = at.checked_add(length).ok_or(EIO)?;
    let request_end = request + out.len() as u64;
    if at < request || end > request_end {
        return Err(EIO);
    }
    let start = (at - request) as usize;
    let stop = start + length as usize;
    for byte in start..stop {
        let (index, bit) = (byte / 8, 1u8 << (byte % 8));
        if covered[index] & bit != 0 {
            return Err(EIO);
        }
        covered[index] |= bit;
    }
    Ok(start)
}

/// The errno of one structured error chunk: `u32` error, `u16` message
/// length, message and (ERROR_OFFSET) a `u64` offset.
fn error_chunk(payload: &[u8], with_offset: bool) -> Result<i32, i32> {
    if payload.len() < 6 {
        return Err(EINVAL);
    }
    let code = be_u32(payload, 0);
    let message = usize::from(be_u16(payload, 4));
    let extra = if with_offset { 8 } else { 0 };
    if payload.len() != 6 + message + extra {
        return Err(EINVAL);
    }
    Ok(wire_errno(code))
}

/// A wire error value is a Linux errno number, returned negated; an unknown
/// value is `-EINVAL` (protocol rule).
fn wire_errno(code: u32) -> i32 {
    match code {
        1 => EPERM,
        5 => EIO,
        12 => ENOMEM,
        22 => EINVAL,
        28 => ENOSPC,
        75 => EOVERFLOW,
        95 => ENOTSUP,
        108 => ESHUTDOWN,
        _ => EINVAL,
    }
}

/// The errno of one option error reply type.
fn option_error_errno(code: u32) -> i32 {
    match code {
        ERROR_UNSUP => ENOTSUP,
        ERROR_POLICY | ERROR_TLS_REQD => EPERM,
        ERROR_UNKNOWN => ENOENT,
        ERROR_SHUTDOWN => ESHUTDOWN,
        _ => EINVAL,
    }
}

/// Parse one `NBD_REP_INFO` payload: the export size and, when present, the
/// block size limits.
fn parse_info(
    payload: &[u8],
    size: &mut Option<u64>,
    block: &mut Option<(u32, u32)>,
) -> Result<(), i32> {
    if payload.len() < 2 {
        return Err(EINVAL);
    }
    let body = &payload[2..];
    match be_u16(payload, 0) {
        INFO_EXPORT => {
            if body.len() != 10 {
                return Err(EINVAL);
            }
            *size = Some(be_u64(body, 0));
        }
        INFO_BLOCK_SIZE => {
            if body.len() != 12 {
                return Err(EINVAL);
            }
            let (minimum, preferred, maximum) = (be_u32(body, 0), be_u32(body, 4), be_u32(body, 8));
            if minimum == 0 || preferred < minimum || maximum < minimum {
                return Err(EINVAL);
            }
            *block = Some((minimum, maximum));
        }
        _ => {}
    }
    Ok(())
}

fn be_u16(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn be_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn be_u64(buf: &[u8], at: usize) -> u64 {
    u64::from_be_bytes([
        buf[at],
        buf[at + 1],
        buf[at + 2],
        buf[at + 3],
        buf[at + 4],
        buf[at + 5],
        buf[at + 6],
        buf[at + 7],
    ])
}

#[cfg(test)]
#[path = "nbd_tests.rs"]
mod tests;
