// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! In-process NBD servers and the client unit tests.
//!
//! Spec: `doc/spec/rustyrbd/migration-source-http-s3-nbd.md`, "Test vectors
//! and fixtures", "nbd (in-test server)": a fixed-newstyle server over TCP
//! and a Unix socket with switchable behaviours (structured replies, meta
//! context, GO, per-region flags, error injection, split replies, malicious
//! replies). Every test has a hard deadline; a server that does not finish
//! within it panics with a loud line instead of hanging.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use deadline::timeout_line;

use crate::migration_source::nbd_uri::NbdUri;
use crate::migration_source::testutil;

use super::*;

/// Hard deadline of one test's server interaction.
const DEADLINE: Duration = Duration::from_secs(20);
/// Connect and I/O timeouts of the ordinary tests; a broken test fails
/// instead of hanging.
const SHORT: Duration = Duration::from_secs(5);
/// The transmission flags of the test export: HAS_FLAGS | READ_ONLY.
const TRANSMISSION_FLAGS: u16 = 3;

/// One piece of a read reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Piece {
    Data(u64, u64),
    Hole(u64, u64),
}

/// A malformed option reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OptionFault {
    /// A wrong option reply magic.
    BadMagic,
    /// A different option number echoed back.
    WrongOption,
    /// A reply length beyond the sane bound.
    HugeLength,
}

/// The malicious or unusual replies a test can ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// The reply carries a different cookie.
    WrongCookie,
    /// The second chunk repeats the first.
    Overlap,
    /// The first chunk starts before the request.
    OutOfRange,
    /// The last chunk is missing.
    Missing,
    /// The connection closes in the middle of a chunk.
    Disconnect,
    /// A structured error chunk with this wire value.
    Error(u32),
    /// A BLOCK_STATUS chunk in a READ reply.
    WrongChunkType,
    /// An unknown chunk type without the error bit (skipped).
    UnknownChunk,
    /// An unknown chunk type with the error bit (refused).
    UnknownErrorChunk,
}

/// The test server's behaviour.
#[derive(Clone, Debug)]
struct Config {
    data: Vec<u8>,
    /// Block status regions: offset, length, `base:allocation` flags.
    regions: Vec<(u64, u64, u32)>,
    structured: bool,
    meta_context: bool,
    go: bool,
    fixed_newstyle: bool,
    no_zeroes: bool,
    oldstyle: bool,
    close_on_export_name: bool,
    export_error: Option<u32>,
    fault: Option<Fault>,
    block_status_error: Option<u32>,
    /// Extra bytes appended to the last block-status descriptor.
    overshoot: u64,
    /// Split every read piece at this size.
    split: Option<u64>,
    /// An explicit read plan instead of the region walk.
    plan: Option<Vec<Piece>>,
    /// Accept and never answer anything.
    stall: bool,
    /// Answer the handshake, then never answer a request.
    stall_reads: bool,
    /// Advertised `NBD_INFO_BLOCK_SIZE` maximum.
    max_block: Option<u32>,
    /// A malformed reply to the first option.
    option_fault: Option<OptionFault>,
}

impl Config {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            regions: Vec::new(),
            structured: true,
            meta_context: true,
            go: true,
            fixed_newstyle: true,
            no_zeroes: true,
            oldstyle: false,
            close_on_export_name: false,
            export_error: None,
            fault: None,
            block_status_error: None,
            overshoot: 0,
            split: None,
            plan: None,
            stall: false,
            stall_reads: false,
            max_block: None,
            option_fault: None,
        }
    }
}

/// One recorded transmission request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Request {
    ty: u16,
    offset: u64,
    length: u32,
}

/// What the server saw.
#[derive(Clone, Debug, Default)]
struct Log {
    options: Vec<u32>,
    requests: Vec<Request>,
}

impl Log {
    /// The READ requests only; a closing client's DISC is not part of an
    /// assertion about the data path.
    fn reads(&self) -> Vec<Request> {
        self.requests
            .iter()
            .copied()
            .filter(|request| request.ty == CMD_READ)
            .collect()
    }
}

/// One running test server; [`Server::wait`] joins it with the deadline.
struct Server {
    log: Arc<Mutex<Log>>,
    stop: Arc<AtomicBool>,
    done: Option<mpsc::Receiver<()>>,
    join: Option<JoinHandle<()>>,
}

impl Server {
    /// A TCP server on `127.0.0.1:0`; returns its port.
    fn tcp(cfg: Config) -> (u16, Self) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let port = listener.local_addr().expect("local addr").port();
        listener.set_nonblocking(true).expect("nonblocking");
        (port, spawn(listener, cfg))
    }

    /// A Unix server on `path`.
    fn unix(cfg: Config, path: &Path) -> Self {
        let listener = UnixListener::bind(path).expect("bind unix");
        listener.set_nonblocking(true).expect("nonblocking");
        spawn(listener, cfg)
    }

    /// Wait for the server thread within the hard deadline and return its
    /// log.
    fn wait(mut self) -> Log {
        let done = self.done.take().expect("done receiver");
        if done.recv_timeout(DEADLINE).is_err() {
            panic!(
                "WARNING TIMEOUT test server exceeded {}s (no completion)",
                DEADLINE.as_secs()
            );
        }
        if let Some(join) = self.join.take() {
            assert!(join.join().is_ok(), "the test server thread panicked");
        }
        self.log.lock().expect("server log").clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// One listener the server thread accepts from.
trait Accept {
    fn accept_one(&self) -> io::Result<Box<dyn Stream>>;
}

/// The read/write half of one accepted connection.
trait Stream: Read + Write {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
}

impl Stream for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
}

impl Stream for UnixStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }
}

impl Accept for TcpListener {
    fn accept_one(&self) -> io::Result<Box<dyn Stream>> {
        let (stream, _) = self.accept()?;
        stream.set_nonblocking(false)?;
        Ok(Box::new(stream))
    }
}

impl Accept for UnixListener {
    fn accept_one(&self) -> io::Result<Box<dyn Stream>> {
        let (stream, _) = self.accept()?;
        stream.set_nonblocking(false)?;
        Ok(Box::new(stream))
    }
}

fn spawn<L: Accept + Send + 'static>(listener: L, cfg: Config) -> Server {
    let log = Arc::new(Mutex::new(Log::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let (done, receiver) = mpsc::channel();
    let thread_log = Arc::clone(&log);
    let thread_stop = Arc::clone(&stop);
    let join = thread::spawn(move || {
        let mut accepted = None;
        while !thread_stop.load(Ordering::Relaxed) {
            match listener.accept_one() {
                Ok(stream) => {
                    accepted = Some(stream);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        if let Some(mut stream) = accepted {
            let _ = serve(&cfg, stream.as_mut(), &thread_log, &thread_stop);
        }
        let _ = done.send(());
    });
    Server {
        log,
        stop,
        done: Some(receiver),
        join: Some(join),
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn serve(
    cfg: &Config,
    stream: &mut dyn Stream,
    log: &Mutex<Log>,
    stop: &AtomicBool,
) -> io::Result<()> {
    if cfg.stall {
        return hold(stream, stop);
    }
    if cfg.oldstyle {
        stream.write_all(&NBDMAGIC.to_be_bytes())?;
        stream.write_all(&OLDSTYLE_MAGIC.to_be_bytes())?;
        stream.write_all(&0u64.to_be_bytes())?;
        return hold(stream, stop);
    }
    stream.write_all(&NBDMAGIC.to_be_bytes())?;
    stream.write_all(&IHAVEOPT.to_be_bytes())?;
    let mut flags = 0u16;
    if cfg.fixed_newstyle {
        flags |= FLAG_FIXED_NEWSTYLE;
    }
    if cfg.no_zeroes {
        flags |= FLAG_NO_ZEROES;
    }
    stream.write_all(&flags.to_be_bytes())?;
    let mut client_flags = [0u8; 4];
    stream.read_exact(&mut client_flags)?;
    let no_zeroes = u32::from_be_bytes(client_flags) & u32::from(FLAG_NO_ZEROES) != 0;
    if !cfg.fixed_newstyle {
        read_export_name(stream)?;
        return export_tail(cfg, stream, log, no_zeroes, false);
    }
    let mut structured = false;
    loop {
        let mut header = [0u8; 16];
        stream.read_exact(&mut header)?;
        let option = be_u32(&header, 8);
        let length = be_u32(&header, 12);
        let mut data = vec![0u8; length as usize];
        stream.read_exact(&mut data)?;
        log.lock().expect("server log").options.push(option);
        match option {
            OPT_STRUCTURED_REPLY => {
                if let Some(fault) = cfg.option_fault {
                    return malformed_reply(stream, option, fault);
                }
                if cfg.structured {
                    structured = true;
                    reply_ack(stream, option)?;
                } else {
                    reply_error(stream, option, ERROR_UNSUP)?;
                }
            }
            OPT_SET_META_CONTEXT => {
                if structured && cfg.meta_context {
                    let mut payload = 1u32.to_be_bytes().to_vec();
                    payload.extend_from_slice(META_CONTEXT);
                    reply(stream, option, REPLY_META_CONTEXT, &payload)?;
                    reply_ack(stream, option)?;
                } else {
                    reply_error(stream, option, ERROR_UNSUP)?;
                }
            }
            OPT_GO => {
                if !cfg.go {
                    reply_error(stream, option, ERROR_UNSUP)?;
                    continue;
                }
                if let Some(code) = cfg.export_error {
                    reply_error(stream, option, code)?;
                    continue;
                }
                let mut payload = INFO_EXPORT.to_be_bytes().to_vec();
                payload.extend_from_slice(&(cfg.data.len() as u64).to_be_bytes());
                payload.extend_from_slice(&TRANSMISSION_FLAGS.to_be_bytes());
                reply(stream, option, REPLY_INFO, &payload)?;
                if let Some(maximum) = cfg.max_block {
                    let mut payload = INFO_BLOCK_SIZE.to_be_bytes().to_vec();
                    payload.extend_from_slice(&1u32.to_be_bytes());
                    payload.extend_from_slice(&4096u32.to_be_bytes());
                    payload.extend_from_slice(&maximum.to_be_bytes());
                    reply(stream, option, REPLY_INFO, &payload)?;
                }
                reply_ack(stream, option)?;
                return transmission(cfg, stream, log, structured, stop);
            }
            OPT_EXPORT_NAME => {
                if cfg.close_on_export_name {
                    return Ok(());
                }
                return export_tail(cfg, stream, log, no_zeroes, structured);
            }
            _ => reply_error(stream, option, ERROR_UNSUP)?,
        }
    }
}

/// Keep the connection open and consume input until the peer closes or the
/// test ends; used by the stalling servers.
fn hold(stream: &mut dyn Stream, stop: &AtomicBool) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(20)))?;
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if is_timeout(&error) => {
                if stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
            }
            Err(_) => return Ok(()),
        }
    }
}

fn read_export_name(stream: &mut dyn Stream) -> io::Result<String> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let mut name = vec![0u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut name)?;
    Ok(String::from_utf8_lossy(&name).into_owned())
}

fn export_tail(
    cfg: &Config,
    stream: &mut dyn Stream,
    log: &Mutex<Log>,
    no_zeroes: bool,
    structured: bool,
) -> io::Result<()> {
    stream.write_all(&(cfg.data.len() as u64).to_be_bytes())?;
    stream.write_all(&TRANSMISSION_FLAGS.to_be_bytes())?;
    if !no_zeroes {
        stream.write_all(&[0u8; 124])?;
    }
    transmission(cfg, stream, log, structured, &AtomicBool::new(false))
}

fn transmission(
    cfg: &Config,
    stream: &mut dyn Stream,
    log: &Mutex<Log>,
    structured: bool,
    stop: &AtomicBool,
) -> io::Result<()> {
    loop {
        let mut header = [0u8; 28];
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let ty = u16::from_be_bytes([header[6], header[7]]);
        let cookie = be_u64(&header, 8);
        let offset = be_u64(&header, 16);
        let length = be_u32(&header, 24);
        log.lock()
            .expect("server log")
            .requests
            .push(Request { ty, offset, length });
        match ty {
            CMD_READ => {
                if cfg.stall_reads {
                    return hold(stream, stop);
                }
                emit_read(cfg, stream, structured, cookie, offset, length)?;
            }
            CMD_BLOCK_STATUS => {
                let mut context = [0u8; 4];
                stream.read_exact(&mut context)?;
                emit_block_status(cfg, stream, cookie, offset, u64::from(length))?;
            }
            CMD_DISC => return Ok(()),
            _ => return Ok(()),
        }
    }
}

fn reply(stream: &mut dyn Stream, option: u32, kind: u32, payload: &[u8]) -> io::Result<()> {
    let mut header = Vec::with_capacity(20);
    header.extend_from_slice(&OPTION_REPLY_MAGIC.to_be_bytes());
    header.extend_from_slice(&option.to_be_bytes());
    header.extend_from_slice(&kind.to_be_bytes());
    header.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    stream.write_all(&header)?;
    stream.write_all(payload)
}

fn reply_ack(stream: &mut dyn Stream, option: u32) -> io::Result<()> {
    reply(stream, option, REPLY_ACK, &[])
}

fn reply_error(stream: &mut dyn Stream, option: u32, code: u32) -> io::Result<()> {
    reply(stream, option, REPLY_ERROR | code, &[])
}

/// One malformed option reply header; the client must refuse it before any
/// payload.
fn malformed_reply(stream: &mut dyn Stream, option: u32, fault: OptionFault) -> io::Result<()> {
    let magic = match fault {
        OptionFault::BadMagic => OPTION_REPLY_MAGIC ^ 1,
        _ => OPTION_REPLY_MAGIC,
    };
    let echoed = match fault {
        OptionFault::WrongOption => option.wrapping_add(1),
        _ => option,
    };
    let length = match fault {
        OptionFault::HugeLength => MAX_OPTION_REPLY + 1,
        _ => 0,
    };
    let mut header = Vec::with_capacity(20);
    header.extend_from_slice(&magic.to_be_bytes());
    header.extend_from_slice(&echoed.to_be_bytes());
    header.extend_from_slice(&REPLY_ACK.to_be_bytes());
    header.extend_from_slice(&length.to_be_bytes());
    stream.write_all(&header)
}

fn chunk_header(ty: u16, cookie: u64, done: bool, length: usize) -> [u8; 20] {
    let mut header = [0u8; 20];
    header[0..4].copy_from_slice(&STRUCTURED_REPLY_MAGIC.to_be_bytes());
    header[4..6].copy_from_slice(&(if done { CHUNK_DONE } else { 0 }).to_be_bytes());
    header[6..8].copy_from_slice(&ty.to_be_bytes());
    header[8..16].copy_from_slice(&cookie.to_be_bytes());
    header[16..20].copy_from_slice(&(length as u32).to_be_bytes());
    header
}

/// The flags of the region containing `at`; zero (data) outside every
/// region.
fn region_flags(cfg: &Config, at: u64) -> u32 {
    cfg.regions
        .iter()
        .find(|&&(start, length, _)| at >= start && at < start + length)
        .map_or(0, |&(_, _, flags)| flags)
}

/// The data/hole pieces of one read request: the explicit plan, else the
/// region walk split at `cfg.split`.
fn pieces_for(cfg: &Config, offset: u64, length: u64) -> Vec<Piece> {
    if let Some(plan) = &cfg.plan {
        return plan.clone();
    }
    let end = offset + length;
    let mut pieces = Vec::new();
    let mut at = offset;
    while at < end {
        let hole = region_flags(cfg, at) & (STATE_HOLE | STATE_ZERO) != 0;
        let mut next = end;
        for &(start, region_length, _) in &cfg.regions {
            for boundary in [start, start + region_length] {
                if boundary > at && boundary < next {
                    next = boundary;
                }
            }
        }
        let step = cfg.split.unwrap_or(u64::MAX);
        let mut from = at;
        while from < next {
            let to = from.saturating_add(step).min(next);
            pieces.push(if hole {
                Piece::Hole(from, to - from)
            } else {
                Piece::Data(from, to - from)
            });
            from = to;
        }
        at = next;
    }
    pieces
}

/// The bytes of a simple reply body (holes read as zeroes).
fn request_bytes(cfg: &Config, offset: u64, length: u64) -> Vec<u8> {
    let mut out = vec![0u8; length as usize];
    for piece in pieces_for(cfg, offset, length) {
        if let Piece::Data(at, length) = piece {
            let start = (at - offset) as usize;
            out[start..start + length as usize]
                .copy_from_slice(&cfg.data[at as usize..(at + length) as usize]);
        }
    }
    out
}

fn build_chunks(cfg: &Config, offset: u64, length: u64) -> Vec<(u16, Vec<u8>)> {
    pieces_for(cfg, offset, length)
        .into_iter()
        .map(|piece| match piece {
            Piece::Data(at, length) => {
                let mut payload = at.to_be_bytes().to_vec();
                payload.extend_from_slice(&cfg.data[at as usize..(at + length) as usize]);
                (CHUNK_OFFSET_DATA, payload)
            }
            Piece::Hole(at, length) => {
                let mut payload = at.to_be_bytes().to_vec();
                payload.extend_from_slice(&(length as u32).to_be_bytes());
                (CHUNK_OFFSET_HOLE, payload)
            }
        })
        .collect()
}

fn emit_read(
    cfg: &Config,
    stream: &mut dyn Stream,
    structured: bool,
    cookie: u64,
    offset: u64,
    length: u32,
) -> io::Result<()> {
    let cookie = if cfg.fault == Some(Fault::WrongCookie) {
        cookie.wrapping_add(1)
    } else {
        cookie
    };
    if !structured {
        let error = match cfg.fault {
            Some(Fault::Error(code)) => code,
            _ => 0,
        };
        let mut header = Vec::with_capacity(16);
        header.extend_from_slice(&SIMPLE_REPLY_MAGIC.to_be_bytes());
        header.extend_from_slice(&error.to_be_bytes());
        header.extend_from_slice(&cookie.to_be_bytes());
        stream.write_all(&header)?;
        if error != 0 {
            return Ok(());
        }
        let body = request_bytes(cfg, offset, u64::from(length));
        if cfg.fault == Some(Fault::Disconnect) {
            stream.write_all(&body[..body.len() / 2])?;
            return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
        }
        return stream.write_all(&body);
    }
    let mut chunks = build_chunks(cfg, offset, u64::from(length));
    match cfg.fault {
        Some(Fault::Overlap) if chunks.len() > 1 => chunks[1] = chunks[0].clone(),
        Some(Fault::OutOfRange) => {
            if let Some((_, payload)) = chunks.first_mut() {
                payload[0..8].copy_from_slice(&0u64.to_be_bytes());
            }
        }
        Some(Fault::Missing) => {
            chunks.pop();
        }
        Some(Fault::Error(code)) => {
            let mut payload = code.to_be_bytes().to_vec();
            payload.extend_from_slice(&0u16.to_be_bytes());
            chunks = vec![(CHUNK_ERROR, payload)];
        }
        Some(Fault::WrongChunkType) => {
            if let Some((ty, _)) = chunks.first_mut() {
                *ty = CHUNK_BLOCK_STATUS;
            }
        }
        Some(Fault::UnknownChunk) => chunks.insert(0, (1000, vec![1, 2, 3])),
        Some(Fault::UnknownErrorChunk) => {
            chunks = vec![(CHUNK_ERROR_BIT | 42, Vec::new())];
        }
        _ => {}
    }
    let count = chunks.len();
    for (index, (ty, payload)) in chunks.iter().enumerate() {
        let done = index + 1 == count;
        stream.write_all(&chunk_header(*ty, cookie, done, payload.len()))?;
        if cfg.fault == Some(Fault::Disconnect) {
            stream.write_all(&payload[..payload.len() / 2])?;
            return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
        }
        stream.write_all(payload)?;
    }
    Ok(())
}

fn emit_block_status(
    cfg: &Config,
    stream: &mut dyn Stream,
    cookie: u64,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if let Some(code) = cfg.block_status_error {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(&0u16.to_be_bytes());
        stream.write_all(&chunk_header(CHUNK_ERROR, cookie, true, payload.len()))?;
        return stream.write_all(&payload);
    }
    let end = offset + length;
    let mut payload = 1u32.to_be_bytes().to_vec();
    let mut at = offset;
    while at < end {
        let mut next = end;
        for &(start, region_length, _) in &cfg.regions {
            for boundary in [start, start + region_length] {
                if boundary > at && boundary < next {
                    next = boundary;
                }
            }
        }
        let mut described = next - at;
        if next == end {
            described += cfg.overshoot;
        }
        payload.extend_from_slice(&(described as u32).to_be_bytes());
        payload.extend_from_slice(&region_flags(cfg, at).to_be_bytes());
        at = next;
    }
    stream.write_all(&chunk_header(
        CHUNK_BLOCK_STATUS,
        cookie,
        true,
        payload.len(),
    ))?;
    stream.write_all(&payload)
}

fn payload(length: usize) -> Vec<u8> {
    (0..length).map(|at| (at % 251) as u8).collect()
}

fn client(port: u16, export: &str) -> NbdClient {
    let uri = format!("nbd://127.0.0.1:{port}/{export}");
    let parsed = NbdUri::parse(&uri).expect("uri");
    NbdClient::with_timeouts(parsed, SHORT, SHORT)
}

/// splitmix64, the test's deterministic random source.
fn next(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *seed;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[test]
fn tcp_read_matches_the_payload() {
    let data = payload(8192);
    let (port, server) = Server::tcp(Config::new(data.clone()));
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(client.size(), Ok(8192));
    let mut out = vec![0u8; 8192];
    client.read_at(0, &mut out).expect("read");
    assert_eq!(out, data);
    // Every call is its own request at its own offset.
    let mut out = [0u8; 4];
    client.read_at(0, &mut out[..2]).expect("read head");
    client.read_at(8190, &mut out[2..]).expect("read tail");
    assert_eq!(&out[..2], &data[..2]);
    assert_eq!(&out[2..], &data[8190..]);
    // A zero-length read is a no-op.
    client.read_at(0, &mut []).expect("zero length");
    client.close();
    assert_eq!(
        server.wait().reads(),
        vec![
            Request {
                ty: CMD_READ,
                offset: 0,
                length: 8192
            },
            Request {
                ty: CMD_READ,
                offset: 0,
                length: 2
            },
            Request {
                ty: CMD_READ,
                offset: 8190,
                length: 2
            },
        ]
    );
}

#[test]
fn unix_socket_reads_the_export() {
    let dir = testutil::temp_dir("nbd");
    let path = dir.as_ref().join("s");
    let data = payload(2048);
    let server = Server::unix(Config::new(data.clone()), &path);
    let uri = NbdUri::parse(&format!("nbd+unix:///head?socket={}", path.display())).expect("uri");
    let client = NbdClient::with_timeouts(uri, SHORT, SHORT);
    client.open().expect("open");
    assert_eq!(client.size(), Ok(2048));
    let mut out = vec![0u8; 2048];
    client.read_at(0, &mut out).expect("read");
    assert_eq!(out, data);
    client.close();
    server.wait();
}

#[test]
fn read_past_the_end_sends_nothing() {
    let (port, server) = Server::tcp(Config::new(payload(4096)));
    let client = client(port, "head");
    client.open().expect("open");
    let mut out = [0u8; 8];
    // Spec vector: past the export end is -EINVAL and the server sees
    // nothing.
    assert_eq!(client.read_at(4092, &mut out), Err(-22));
    assert_eq!(client.read_at(4096, &mut [0u8; 1]), Err(-22));
    assert_eq!(client.read_at(u64::MAX, &mut out), Err(-22));
    client.close();
    assert!(server.wait().reads().is_empty(), "nothing was sent");
}

#[test]
fn block_status_reports_the_region_flags() {
    let mut cfg = Config::new(vec![0u8; 8192]);
    cfg.regions = vec![
        (0, 4096, 0),
        (4096, 2048, STATE_HOLE | STATE_ZERO),
        (6144, 1024, STATE_HOLE),
        (7168, 1024, STATE_ZERO),
    ];
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    let extents = client.block_status(0, 8192).expect("block status");
    assert_eq!(
        extents,
        vec![
            BlockStatusExtent {
                offset: 0,
                length: 4096,
                flags: 0
            },
            BlockStatusExtent {
                offset: 4096,
                length: 2048,
                flags: STATE_HOLE | STATE_ZERO
            },
            BlockStatusExtent {
                offset: 6144,
                length: 1024,
                flags: STATE_HOLE
            },
            BlockStatusExtent {
                offset: 7168,
                length: 1024,
                flags: STATE_ZERO
            },
        ]
    );
    // The sparse map of the spec vector: ZEROED [4K,6K) and [7K,8K); the
    // HOLE-only range [6K,7K) stays DATA.
    let zeroed: Vec<(u64, u64)> = extents
        .iter()
        .filter(|extent| extent.zeroed())
        .map(|extent| (extent.offset, extent.length))
        .collect();
    assert_eq!(zeroed, vec![(4096, 2048), (7168, 1024)]);
    assert!(!extents[2].zeroed(), "HOLE without ZERO is DATA");
    // A sub-range request describes only that range.
    assert_eq!(
        client.block_status(4096, 2048).expect("sub range"),
        vec![BlockStatusExtent {
            offset: 4096,
            length: 2048,
            flags: STATE_HOLE | STATE_ZERO
        }]
    );
    // An empty and an out-of-range request.
    assert_eq!(client.block_status(0, 0), Ok(Vec::new()));
    assert_eq!(client.block_status(8192, 1), Err(-22));
    client.close();
    server.wait();
}

#[test]
fn block_status_overshoot_is_trimmed() {
    let mut cfg = Config::new(vec![0u8; 8192]);
    cfg.regions = vec![(0, 8192, STATE_ZERO)];
    cfg.overshoot = 4096;
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(
        client.block_status(0, 4096).expect("block status"),
        vec![BlockStatusExtent {
            offset: 0,
            length: 4096,
            flags: STATE_ZERO
        }],
        "a descriptor beyond the request is trimmed"
    );
    client.close();
    server.wait();
}

#[test]
fn block_status_errors_leave_the_range_undescribed() {
    // An error reply is -EIO here; the stream adapter maps it to "all DATA"
    // (stage 10c PART 2).
    let mut cfg = Config::new(vec![0u8; 4096]);
    cfg.block_status_error = Some(5);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(client.block_status(0, 4096), Err(-5));
    client.close();
    server.wait();
}

#[test]
fn block_status_needs_a_meta_context() {
    // Spec vector: simple replies only (or no meta context) means no block
    // status at all.
    let mut cfg = Config::new(vec![0u8; 4096]);
    cfg.meta_context = false;
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(client.block_status(0, 4096), Ok(Vec::new()));
    client.close();
    server.wait();
}

#[test]
fn structured_read_splits_data_and_holes() {
    let data = payload(8192);
    let mut cfg = Config::new(data.clone());
    cfg.regions = vec![(2048, 2048, STATE_HOLE | STATE_ZERO)];
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    let mut out = vec![0xaau8; 8192];
    client.read_at(0, &mut out).expect("read");
    let mut expected = data;
    expected[2048..4096].fill(0);
    assert_eq!(out, expected, "OFFSET_HOLE chunks zero-fill");
    client.close();
    server.wait();
}

#[test]
fn overlapping_chunks_are_eio_and_drop_the_connection() {
    let mut cfg = Config::new(payload(8192));
    cfg.split = Some(4096);
    cfg.fault = Some(Fault::Overlap);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    let mut out = vec![0x55u8; 8192];
    assert_eq!(client.read_at(0, &mut out), Err(-5));
    assert!(out.iter().all(|&byte| byte == 0), "the output is cleared");
    // No reconnect (stock): every later call is -ENOTCONN.
    assert_eq!(client.size(), Err(-107));
    server.wait();
}

#[test]
fn missing_chunks_are_eio() {
    let mut cfg = Config::new(payload(8192));
    cfg.split = Some(4096);
    cfg.fault = Some(Fault::Missing);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(client.read_at(0, &mut [0u8; 8192]), Err(-5));
    assert_eq!(client.size(), Err(-107));
    server.wait();
}

#[test]
fn out_of_range_chunks_are_eio() {
    let mut cfg = Config::new(payload(8192));
    cfg.fault = Some(Fault::OutOfRange);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(client.read_at(4096, &mut [0u8; 4096]), Err(-5));
    assert_eq!(client.size(), Err(-107));
    server.wait();
}

#[test]
fn a_wrong_cookie_is_eio() {
    let mut cfg = Config::new(payload(4096));
    cfg.fault = Some(Fault::WrongCookie);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(client.read_at(0, &mut [0u8; 4096]), Err(-5));
    assert_eq!(client.size(), Err(-107));
    server.wait();
}

#[test]
fn an_invalid_chunk_type_is_einval() {
    let mut cfg = Config::new(payload(4096));
    cfg.fault = Some(Fault::WrongChunkType);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(client.read_at(0, &mut [0u8; 4096]), Err(-22));
    assert_eq!(client.size(), Err(-107));
    server.wait();
}

#[test]
fn an_unknown_chunk_is_skipped() {
    let data = payload(4096);
    let mut cfg = Config::new(data.clone());
    cfg.fault = Some(Fault::UnknownChunk);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    let mut out = vec![0u8; 4096];
    client.read_at(0, &mut out).expect("read");
    assert_eq!(out, data);
    client.close();
    server.wait();
}

#[test]
fn an_unknown_error_chunk_is_einval() {
    let mut cfg = Config::new(payload(4096));
    cfg.fault = Some(Fault::UnknownErrorChunk);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(client.read_at(0, &mut [0u8; 4096]), Err(-22));
    assert_eq!(client.size(), Err(-107));
    server.wait();
}

#[test]
fn a_structured_error_chunk_maps_the_wire_errno() {
    for (code, expected) in [(5u32, -5i32), (99, -22), (108, -108), (12, -12), (95, -95)] {
        let mut cfg = Config::new(payload(4096));
        cfg.fault = Some(Fault::Error(code));
        let (port, server) = Server::tcp(cfg);
        let client = client(port, "head");
        client.open().expect("open");
        assert_eq!(
            client.read_at(0, &mut [1u8; 4096]),
            Err(expected),
            "wire error {code}"
        );
        client.close();
        server.wait();
    }
}

#[test]
fn simple_replies_read_and_have_no_block_status() {
    let data = payload(4096);
    let mut cfg = Config::new(data.clone());
    cfg.structured = false;
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    let mut out = vec![0u8; 4096];
    client.read_at(0, &mut out).expect("read");
    assert_eq!(out, data);
    assert_eq!(client.block_status(0, 4096), Ok(Vec::new()));
    client.close();
    server.wait();
}

#[test]
fn a_simple_error_reply_maps_the_wire_errno() {
    for (code, expected) in [(5u32, -5i32), (99, -22)] {
        let mut cfg = Config::new(payload(4096));
        cfg.structured = false;
        cfg.fault = Some(Fault::Error(code));
        let (port, server) = Server::tcp(cfg);
        let client = client(port, "head");
        client.open().expect("open");
        assert_eq!(client.read_at(0, &mut [0u8; 4096]), Err(expected));
        client.close();
        server.wait();
    }
}

#[test]
fn a_server_disconnect_mid_reply_is_eio() {
    let mut cfg = Config::new(payload(4096));
    cfg.fault = Some(Fault::Disconnect);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    let mut out = vec![0x11u8; 4096];
    assert_eq!(client.read_at(0, &mut out), Err(-5));
    assert!(out.iter().all(|&byte| byte == 0));
    assert_eq!(client.size(), Err(-107));
    server.wait();
}

#[test]
fn go_unsupported_falls_back_to_export_name() {
    let data = payload(2048);
    let mut cfg = Config::new(data.clone());
    cfg.go = false;
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(client.size(), Ok(2048));
    let mut out = vec![0u8; 2048];
    client.read_at(0, &mut out).expect("read");
    assert_eq!(out, data);
    client.close();
    let log = server.wait();
    assert!(
        log.options.contains(&OPT_EXPORT_NAME),
        "the fallback option was sent"
    );
}

#[test]
fn unknown_export_with_go_is_enoent() {
    let mut cfg = Config::new(payload(1024));
    cfg.export_error = Some(ERROR_UNKNOWN);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "missing");
    assert_eq!(client.open(), Err(-2));
    server.wait();
}

#[test]
fn export_name_close_is_enoent() {
    let mut cfg = Config::new(payload(1024));
    cfg.go = false;
    cfg.close_on_export_name = true;
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "missing");
    assert_eq!(client.open(), Err(-2));
    server.wait();
}

#[test]
fn a_server_without_fixed_newstyle_works() {
    let data = payload(1024);
    let mut cfg = Config::new(data.clone());
    cfg.fixed_newstyle = false;
    cfg.no_zeroes = false;
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    let mut out = vec![0u8; 1024];
    client.read_at(0, &mut out).expect("read");
    assert_eq!(out, data);
    client.close();
    let log = server.wait();
    assert!(log.options.is_empty(), "no option may be sent");
}

#[test]
fn malformed_option_replies_are_einval() {
    for fault in [
        OptionFault::BadMagic,
        OptionFault::WrongOption,
        OptionFault::HugeLength,
    ] {
        let mut cfg = Config::new(payload(1024));
        cfg.option_fault = Some(fault);
        let (port, server) = Server::tcp(cfg);
        let client = client(port, "head");
        assert_eq!(client.open(), Err(-22), "{fault:?}");
        server.wait();
    }
}

#[test]
fn option_error_replies_map_their_errno() {
    // UNSUP is the fallback path and has its own test; the others are
    // terminal (spec step 7).
    for (code, expected) in [
        (ERROR_POLICY, -1),
        (ERROR_TLS_REQD, -1),
        (ERROR_UNKNOWN, -2),
        (ERROR_SHUTDOWN, -108),
        (3, -22),
        (9, -22),
    ] {
        let mut cfg = Config::new(payload(1024));
        cfg.export_error = Some(code);
        let (port, server) = Server::tcp(cfg);
        let client = client(port, "head");
        assert_eq!(client.open(), Err(expected), "option error {code}");
        server.wait();
    }
}

#[test]
fn oldstyle_greeting_is_enotsup() {
    let mut cfg = Config::new(payload(1024));
    cfg.oldstyle = true;
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    assert_eq!(client.open(), Err(-95));
    server.wait();
}

#[test]
fn a_large_read_is_split_at_the_payload_limit() {
    // Spec vector: a 40 MiB read with no advertised maximum is two requests
    // (32 + 8 MiB).
    let data = vec![0x5au8; 40 * 1024 * 1024];
    let (port, server) = Server::tcp(Config::new(data.clone()));
    let client = client(port, "head");
    client.open().expect("open");
    let mut out = vec![0u8; data.len()];
    client.read_at(0, &mut out).expect("read");
    assert_eq!(out, data);
    client.close();
    assert_eq!(
        server.wait().reads(),
        vec![
            Request {
                ty: CMD_READ,
                offset: 0,
                length: 32 * 1024 * 1024
            },
            Request {
                ty: CMD_READ,
                offset: 32 * 1024 * 1024,
                length: 8 * 1024 * 1024
            },
        ]
    );
}

#[test]
fn the_advertised_maximum_bounds_each_request() {
    let data = payload(4 * 1024 * 1024);
    let mut cfg = Config::new(data.clone());
    cfg.max_block = Some(1024 * 1024);
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    let mut out = vec![0u8; data.len()];
    client.read_at(0, &mut out).expect("read");
    assert_eq!(out, data);
    client.close();
    let requests = server.wait().reads();
    assert_eq!(requests.len(), 4);
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request.length, 1024 * 1024);
        assert_eq!(request.offset, index as u64 * 1024 * 1024);
    }
}

#[test]
fn stalled_handshake_times_out_loudly() {
    let mut cfg = Config::new(payload(1024));
    cfg.stall = true;
    let (port, server) = Server::tcp(cfg);
    let uri = NbdUri::parse(&format!("nbd://127.0.0.1:{port}/head")).expect("uri");
    let limit = Duration::from_millis(200);
    let client = NbdClient::with_timeouts(uri, SHORT, limit);
    assert_eq!(client.open(), Err(-110));
    assert_eq!(client.timeouts(), 1, "the timeout is counted");
    // The loud line names the operation, the limit and the URI (without its
    // query).
    assert_eq!(
        timeout_line(
            "nbd handshake",
            limit,
            &format!("nbd://127.0.0.1:{port}/head")
        ),
        format!("WARNING TIMEOUT nbd handshake exceeded 0.200s (nbd://127.0.0.1:{port}/head)")
    );
    server.wait();
}

#[test]
fn stalled_read_times_out_loudly() {
    let mut cfg = Config::new(payload(4096));
    cfg.stall_reads = true;
    let (port, server) = Server::tcp(cfg);
    let uri = NbdUri::parse(&format!("nbd://127.0.0.1:{port}/head")).expect("uri");
    let limit = Duration::from_millis(200);
    let client = NbdClient::with_timeouts(uri, SHORT, limit);
    client.open().expect("open");
    assert_eq!(client.read_at(0, &mut [0u8; 64]), Err(-110));
    assert_eq!(client.timeouts(), 1);
    assert_eq!(client.size(), Err(-107));
    server.wait();
}

#[test]
fn calls_before_open_are_enotconn() {
    let uri = NbdUri::parse("nbd://127.0.0.1:1/head").expect("uri");
    let client = NbdClient::with_timeouts(uri, SHORT, SHORT);
    assert_eq!(client.size(), Err(-107));
    assert_eq!(client.read_at(0, &mut [0u8; 1]), Err(-107));
    assert_eq!(client.block_status(0, 1), Err(-107));
}

#[test]
fn a_tls_uri_is_enotsup_for_now() {
    // Stage 10c-tls adds the STARTTLS handshake; the parser already accepts
    // the scheme.
    let uri = NbdUri::parse("nbds://127.0.0.1:1/head").expect("uri");
    let client = NbdClient::new(uri);
    assert_eq!(client.open(), Err(-95));
}

#[test]
fn close_sends_disc_and_forgets_the_connection() {
    let (port, server) = Server::tcp(Config::new(payload(1024)));
    let client = client(port, "head");
    client.open().expect("open");
    client.close();
    assert_eq!(client.size(), Err(-107));
    assert!(
        server
            .wait()
            .requests
            .iter()
            .any(|request| request.ty == CMD_DISC)
    );
}

#[test]
fn random_chunk_splits_reproduce_the_reference() {
    // Brief: a property test with random data/hole splits against a
    // reference buffer.
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..8 {
        let size = 64 * 1024usize;
        let data: Vec<u8> = (0..size).map(|at| (at % 253) as u8).collect();
        let mut plan = Vec::new();
        let mut expected = vec![0u8; size];
        let mut at = 0u64;
        while at < size as u64 {
            let length = (next(&mut seed) % 8192 + 1).min(size as u64 - at);
            if next(&mut seed).is_multiple_of(3) {
                plan.push(Piece::Hole(at, length));
            } else {
                plan.push(Piece::Data(at, length));
                expected[at as usize..(at + length) as usize]
                    .copy_from_slice(&data[at as usize..(at + length) as usize]);
            }
            at += length;
        }
        let mut cfg = Config::new(data);
        cfg.plan = Some(plan);
        let (port, server) = Server::tcp(cfg);
        let client = client(port, "head");
        client.open().expect("open");
        let mut out = vec![0xffu8; size];
        client.read_at(0, &mut out).expect("read");
        assert_eq!(out, expected);
        client.close();
        server.wait();
    }
}

#[test]
fn the_client_is_send_and_sync() {
    // `SourceStream` is `Debug + Send + Sync` with `read(&self)` (WP-10a-w),
    // so the adapter needs a client that satisfies both bounds; a missing
    // bound fails here at compile time, not in the stream adapter.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NbdClient>();
    assert_send_sync::<NbdUri>();
    assert_send_sync::<BlockStatusExtent>();
}

#[test]
fn two_threads_share_one_client() {
    // One connection behind the mutex: two threads read through the same
    // `&NbdClient`, the requests serialise on the wire.
    let data = payload(8192);
    let (port, server) = Server::tcp(Config::new(data.clone()));
    let client = Arc::new(client(port, "head"));
    client.open().expect("open");
    let mut threads = Vec::new();
    for (offset, length) in [(0u64, 4096usize), (4096, 4096)] {
        let client = Arc::clone(&client);
        let expected = data[offset as usize..offset as usize + length].to_vec();
        threads.push(thread::spawn(move || {
            let mut out = vec![0u8; length];
            client.read_at(offset, &mut out).expect("read");
            assert_eq!(out, expected);
        }));
    }
    for thread in threads {
        thread.join().expect("reader thread");
    }
    client.close();
    assert_eq!(server.wait().reads().len(), 2);
}

#[test]
fn a_server_error_keeps_the_connection_usable() {
    // A wire error reply is a request failure, not a protocol violation.
    let mut cfg = Config::new(payload(4096));
    cfg.fault = Some(Fault::Error(5));
    let (port, server) = Server::tcp(cfg);
    let client = client(port, "head");
    client.open().expect("open");
    assert_eq!(client.read_at(0, &mut [0u8; 4096]), Err(-5));
    assert_eq!(client.size(), Ok(4096), "the connection stays alive");
    client.close();
    server.wait();
}
