// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Lab-only authenticated driver for rustyrados. No Probe::exec / retry-loop reuse.
//! Hash maps, scans, kernel I/O and cold connection setup are not a performance driver.
use super::*;
use rustyrados::{ReadCompletion, ReadDispatch, ReadQueue, ReadRoute, RequestToken};

#[derive(Debug)]
pub struct NativeReads {
    probe: Probe,
    queue: ReadQueue,
    identity: u64,
    pending: HashMap<u64, (RequestToken, ReadRoute)>,
    watches: rustyrados::WatchRegistry,
    backoffs: rustyrados::BackoffTable,
    parked: VecDeque<ReadDispatch>,
    recovery: rustyrados::RecoveryQueue,
    automatic_recovery: bool,
    backoff_blocks: u64,
    backoff_releases: u64,
    recovery_sends: u64,
}

impl Probe {
    /// Consume a fresh probe, preventing simultaneous synchronous/native TID domains.
    /// Mon commands/pool lookup are allowed; previous object operations are not.
    pub fn native_reads(self, capacity: usize, byte_limit: u64) -> Res<NativeReads> {
        self.native_reads_with_retry_limit(capacity, byte_limit, 1)
    }

    pub fn native_reads_with_retry_limit(
        self,
        capacity: usize,
        byte_limit: u64,
        total_attempts: u32,
    ) -> Res<NativeReads> {
        if self.next_tid != 1 {
            return Err("native driver requires a fresh object TID domain".into());
        }
        let identity = self
            .mc
            .with_cephx(|c| c.global_id())
            .ok_or("CephX identity missing")?;
        let queue = ReadQueue::with_retry_limit(capacity, byte_limit, 0, total_attempts)
            .ok_or("invalid queue capacity/identity exhaustion")?;
        let watches = rustyrados::WatchRegistry::new(capacity, capacity, byte_limit)
            .ok_or("invalid watch capacity/identity exhaustion")?;
        Ok(NativeReads {
            probe: self,
            queue,
            identity,
            pending: HashMap::with_capacity(capacity),
            watches,
            backoffs: rustyrados::BackoffTable::new(capacity, byte_limit),
            parked: VecDeque::with_capacity(capacity),
            recovery: rustyrados::RecoveryQueue::new(capacity),
            automatic_recovery: false,
            backoff_blocks: 0,
            backoff_releases: 0,
            recovery_sends: 0,
        })
    }
}

impl NativeReads {
    pub fn enable_automatic_recovery(&mut self) -> Res<()> {
        if self.queue.outstanding() != 0 {
            return Err("recovery policy requires no outstanding admissions".into());
        }
        self.automatic_recovery = true;
        Ok(())
    }

    /// Lab-only fault injection. Recovery is performed by normal `step`, not this hook.
    pub fn inject_transport_loss(&mut self, token: RequestToken) -> Res<()> {
        let &(_, route) = self
            .pending
            .values()
            .find(|(registered, _)| *registered == token)
            .ok_or("no pending request")?;
        let c = self
            .probe
            .osds
            .get_mut(&route.osd)
            .ok_or("no OSD session")?;
        if c.conn.id() != route.session {
            return Err("stale OSD session".into());
        }
        c.note_transport_loss();
        c.conn.close();
        c.sock = None;
        c.inbox.clear();
        c.dead = Some("own injected transport loss".into());
        Ok(())
    }
    pub fn backoff_stats(&self) -> (u64, u64, u64) {
        (
            self.backoff_blocks,
            self.backoff_releases,
            self.recovery_sends,
        )
    }
    fn now_us(&self) -> u64 {
        self.probe
            .now()
            .as_micros()
            .try_into()
            .expect("monotonic runtime below u64 microseconds")
    }
    pub fn set_deadline_us(
        &mut self,
        token: RequestToken,
        absolute_us: u64,
    ) -> Result<(), rustyrados::DriverError> {
        self.queue.set_deadline_us(token, absolute_us)
    }
    pub fn monotonic_us(&self) -> u64 {
        self.now_us()
    }
    pub fn enable_mutation_retries(&mut self) -> Result<(), rustyrados::DriverError> {
        self.queue.enable_mutation_retries()
    }
    /// Lab-only delayed-delivery injection: flush queued transport data without handing
    /// decoded replies to the logical request engine.
    pub fn flush_without_completions(&mut self) {
        self.probe.step();
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_control(
        &mut self,
        request: rustyrados::ControlRequest,
    ) -> Result<RequestToken, rustyrados::RejectedControl> {
        self.queue.submit_control(request)
    }
    pub fn reserve_watch(
        &mut self,
        target: rustyrados::Target,
        route: ReadRoute,
        kind: rustyrados::WatchKind,
    ) -> Result<rustyrados::WatchHandle, (rustyrados::WatchError, rustyrados::Target)> {
        self.watches.reserve(target, route, kind)
    }
    pub fn activate_watch(
        &mut self,
        handle: rustyrados::WatchHandle,
        generation: u32,
    ) -> Result<(), rustyrados::WatchError> {
        self.watches.activate(handle, generation)
    }
    pub fn initial_notify_id(
        &mut self,
        handle: rustyrados::WatchHandle,
        id: u64,
    ) -> Result<(), rustyrados::WatchError> {
        self.watches.initial_notify_id(handle, id)
    }
    pub fn remove_watch(
        &mut self,
        handle: rustyrados::WatchHandle,
    ) -> Result<(), rustyrados::WatchError> {
        self.watches.remove(handle)
    }
    pub fn poll_watch(&mut self) -> Option<rustyrados::WatchEvent> {
        self.watches.poll()
    }
    pub fn poll_watch_error(
        &mut self,
    ) -> Option<(rustyrados::WatchHandle, rustyrados::WatchError)> {
        self.watches.poll_error()
    }
    pub fn watch_charged_bytes(&self) -> u64 {
        self.watches.charged_bytes()
    }
    /// Explicit VM fault injection. Restrict to one outstanding driver request, flush
    /// queued bytes, discard old connection/replies, then resend the same logical read.
    /// Never an automatic recovery path; unsupported backoff/errors stay terminal.
    pub fn reconnect_read(&mut self, token: RequestToken) -> Res<ReadDispatch> {
        if self.queue.request(token).is_none() {
            return Err("read reconnect requires a read".into());
        }
        self.reconnect_request(token)
    }

    pub fn reconnect_request(&mut self, token: RequestToken) -> Res<ReadDispatch> {
        if self.pending.len() != 1 || !self.identity_valid() {
            return Err("reconnect requires one pending read and unchanged identity".into());
        }
        let &(_, old) = self
            .pending
            .values()
            .find(|(registered, _)| *registered == token)
            .ok_or("no pending read")?;
        let target = self.queue.target(token).ok_or("stale retry")?.clone();
        self.queue
            .retry(token)
            .map_err(|e| format!("retry: {e:?}"))?;
        self.probe.step();
        if let Some(c) = self.probe.osds.get_mut(&old.osd) {
            c.conn.close();
            c.sock = None;
            c.dead = Some("own injected disconnect".into());
        }
        self.pending
            .retain(|_, (registered, _)| *registered != token);
        let result = self.prepare(&target).and_then(|route| {
            self.queue
                .dispatch(token, route)
                .map_err(|e| format!("redispatch: {e:?}"))
        });
        if result.is_err() {
            let _ = self.queue.cancel(token);
        }
        result
    }

    /// Lab oracle: confirm the first write's durable reply reached the transport, then
    /// deliberately withhold it from the logical queue. Proves resend hits dedup rather
    /// than merely replacing an initial request that never executed.
    pub fn discard_durable_reply_and_reconnect(
        &mut self,
        token: RequestToken,
    ) -> Res<(ReadDispatch, u64)> {
        let (&wire_tid, &(_, route)) = self
            .pending
            .iter()
            .find(|(_, (registered, _))| *registered == token)
            .ok_or("no pending mutation")?;
        let end = Instant::now() + Duration::from_secs(5);
        let version = loop {
            if !self.identity_valid() {
                return Err("durable reply injection: authenticated identity changed".into());
            }
            if Instant::now() >= end {
                eprintln!(
                    "WARNING TIMEOUT durable reply injection exceeded 5s (token {}, wire tid {wire_tid})",
                    token.tid()
                );
                return Err("durable reply injection deadline".into());
            }
            self.probe.step();
            let conn = self
                .probe
                .osds
                .get_mut(&route.osd)
                .ok_or("mutation connection missing")?;
            if let Some(index) = conn.inbox.iter().position(|inc| {
                inc.header.tid == wire_tid && inc.header.msg_type == opwire::consts::ty::OSD_OPREPLY
            }) {
                let inc = conn.inbox.remove(index).unwrap();
                let segs = Segments {
                    front: inc.front.to_vec(),
                    middle: inc.middle.to_vec(),
                    data: inc.data,
                    ..Default::default()
                };
                let ClientMsg::OpReply(reply) =
                    opwire::decode_client(inc.header.msg_type, inc.header.version, &segs)
                        .map_err(|e| e.to_string())?
                else {
                    return Err("wrong reply".into());
                };
                if reply.result != 0
                    || reply.flags & u64::from(flag::ONDISK) == 0
                    || reply.retry_attempt != 0
                {
                    return Err("first mutation did not complete durably".into());
                }
                break reply.user_version;
            }
        };
        self.reconnect_request(token)
            .map(|dispatch| (dispatch, version))
    }

    pub fn submit(
        &mut self,
        request: rustyrados::ReadRequest,
    ) -> Result<RequestToken, rustyrados::RejectedRead> {
        self.queue.submit(request)
    }

    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_write(
        &mut self,
        request: rustyrados::WriteRequest,
    ) -> Result<RequestToken, rustyrados::RejectedWrite> {
        self.queue.submit_write(request)
    }

    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn submit_compound(
        &mut self,
        request: rustyrados::CompoundRequest,
    ) -> Result<RequestToken, rustyrados::RejectedCompound> {
        self.queue.submit_compound(request)
    }

    pub fn retire_fence(
        &mut self,
        fence: rustyrados::FenceToken,
    ) -> Result<(), rustyrados::DriverError> {
        self.queue.retire_fence(fence)
    }

    pub fn dispatch(
        &mut self,
        token: RequestToken,
        route: ReadRoute,
    ) -> Result<ReadDispatch, rustyrados::DriverError> {
        self.queue.expire_token_us(token, self.now_us())?;
        self.queue
            .dispatch_with_backoff(token, route, &self.backoffs)
    }

    pub fn cancel(&mut self, token: RequestToken) -> Result<(), rustyrados::DriverError> {
        self.queue.cancel(token)?;
        self.pending
            .retain(|_, (registered, _)| *registered != token);
        self.recovery.remove(token);
        Ok(())
    }

    pub fn charged_bytes(&self) -> u64 {
        self.queue.charged_bytes()
    }
    pub fn outstanding(&self) -> usize {
        self.queue.outstanding()
    }

    pub fn fence(&self) -> rustyrados::FenceToken {
        self.queue.fence()
    }
    pub fn fence_status(
        &self,
        fence: rustyrados::FenceToken,
    ) -> Result<rustyrados::FenceStatus, rustyrados::DriverError> {
        self.queue.fence_status(fence)
    }

    fn identity_valid(&mut self) -> bool {
        self.probe.mc.with_cephx(|c| c.global_id()) == Some(self.identity)
    }

    /// Cold setup only; use the returned route immediately. No EC outbound traffic.
    pub fn prepare(&mut self, target: &rustyrados::Target) -> Res<ReadRoute> {
        if !self.identity_valid() {
            return Err("authenticated identity changed".into());
        }
        if !self
            .probe
            .osdmap()
            .pools
            .get(&target.pool)
            .is_some_and(|p| p.is_replicated())
        {
            return Err("native read prototype requires a replicated pool".into());
        }
        let t = Target {
            pool: target.pool,
            oid: target.object.clone(),
            nspace: target.namespace.clone(),
            key: target.locator.clone(),
            force_osd: None,
        };
        let pl = self.probe.locate(&t)?;
        if pl.primary < 0 {
            return Err("no acting primary".into());
        }
        let old_session = self.probe.osds.get(&pl.primary).map(|c| c.conn.id());
        self.probe.ensure_conn(pl.primary)?;
        let session = self.probe.osds[&pl.primary].conn.id();
        if let Some(old) = old_session.filter(|&old| old != session) {
            self.backoffs.reset_session(pl.primary, old);
            self.watches
                .fault_route(pl.primary, old, rustyrados::WatchError::Disconnected);
            self.pending.retain(|_, (token, route)| {
                if route.osd != pl.primary || route.session != old {
                    return true;
                }
                if !self.recovery.contains(*token) {
                    let _ = self.queue.cancel(*token);
                }
                false
            });
            self.parked.retain(|d| {
                if d.route.osd != pl.primary || d.route.session != old {
                    return true;
                }
                let _ = self.queue.cancel(d.token);
                false
            });
        }
        let current = self.probe.locate(&t)?;
        if current.primary != pl.primary || !self.identity_valid() {
            return Err("placement/identity changed during connection setup".into());
        }
        let c = &mut self
            .probe
            .osds
            .get_mut(&pl.primary)
            .ok_or("missing connection")?;
        if let Some(sock) = &c.sock {
            sock.set_write_timeout(Some(self.probe.opts.timeout))
                .map_err(|e| e.to_string())?;
        }
        Ok(ReadRoute {
            direct_read: false,
            base_pool: target.pool,
            osd: pl.primary,
            session: c.conn.id(),
            pg: current.pg,
            hash: current.raw_pg.seed,
            epoch: current.epoch,
            features: c.features,
            generation: self.probe.mc.osdmap_generation(),
            pool: rustyrados::PoolRoute::Replicated,
        })
    }

    pub fn send(&mut self, dispatch: ReadDispatch) -> Res<()> {
        let t = dispatch.token;
        let wire_tid = dispatch.wire_tid();
        self.queue
            .expire_token_us(t, self.now_us())
            .map_err(|e| format!("deadline: {e:?}"))?;
        let r = dispatch.route;
        if !self.queue.is_pending(t) {
            return Err("stale request handoff".into());
        }
        if dispatch.message.pgid.shard != ShardId::NO_SHARD
            || dispatch.message.pgid.pgid != r.pg
            || !self
                .probe
                .osdmap()
                .pools
                .get(&(r.pg.pool as i64))
                .is_some_and(|p| p.is_replicated())
        {
            let _ = self.queue.cancel(t);
            return Err("outbound replicated PG validation failed".into());
        }
        let valid = self.identity_valid()
            && self.probe.osds.get(&r.osd).is_some_and(|c| {
                c.ready && c.dead.is_none() && c.conn.id() == r.session && c.features == r.features
            });
        if !valid {
            self.queue.cancel(t).map_err(|e| format!("cancel: {e:?}"))?;
            return Err("stale authenticated connection".into());
        }
        if self
            .pending
            .values()
            .any(|(registered, _)| *registered == t)
        {
            return Err("duplicate driver TID".into());
        }
        if self.parked.iter().any(|d| d.token == t) {
            return Err("duplicate parked TID".into());
        }
        if self.queue.target(t).is_some_and(|target| {
            self.backoffs
                .blocked(r, target, self.queue.snapshot(t).unwrap())
        }) {
            self.parked.push_back(dispatch);
            return Ok(());
        }
        if let Err(e) = self.probe.send(
            r.osd,
            &ClientMsg::Op(dispatch.message.into_owned_identity()),
            wire_tid,
        ) {
            let _ = self.queue.cancel(t);
            return Err(e);
        }
        self.pending.insert(wire_tid, (t, r));
        Ok(())
    }

    /// Progress authenticated connections; malformed reply/backoff faults the peer.
    /// Recovery is opt-in and limited to known UNBLOCK and typed connection loss.
    pub fn step(&mut self) -> Res<()> {
        self.queue.expire_us(self.now_us(), 64);
        self.pending
            .retain(|_, (token, _)| self.queue.is_pending(*token));
        self.recovery
            .retain_live(|token| self.queue.is_pending(token));
        self.probe.step();
        if !self.identity_valid() {
            for (_, (token, _)) in self.pending.drain() {
                let _ = self.queue.cancel(token);
            }
            for dispatch in self.parked.drain(..) {
                let _ = self.queue.cancel(dispatch.token);
            }
            while let Some(item) = self.recovery.pop() {
                let _ = self.queue.cancel(item.token);
            }
            for (&osd, c) in &self.probe.osds {
                self.watches
                    .fault_route(osd, c.conn.id(), rustyrados::WatchError::Disconnected);
            }
            return Err("authenticated identity lost".into());
        }
        let mut error = None;
        let mut backoff_acks = Vec::new();
        let pools = &self.probe.mc.osdmap().ok_or("missing map")?.pools;
        for (&osd, c) in &mut self.probe.osds {
            while let Some(inc) = c.inbox.pop_front() {
                let hdr = inc.header;
                if hdr.msg_type == messages::ty::OSD_MAP {
                    continue;
                } // placement comes from mon subscription
                let segs = segments(inc);
                if hdr.msg_type == opwire::consts::ty::OSD_BACKOFF && hdr.version == 1 {
                    let result = match opwire::decode_client(hdr.msg_type, hdr.version, &segs) {
                        Ok(ClientMsg::Backoff(message))
                            if message.pgid.shard == ShardId::NO_SHARD
                                && pools
                                    .get(&(message.pgid.pgid.pool as i64))
                                    .is_some_and(|p| p.is_replicated()) =>
                        {
                            let release = (message.op == opwire::consts::backoff::UNBLOCK)
                                .then(|| {
                                    self.backoffs
                                        .block_for_id(osd, c.conn.id(), message.id)
                                        .cloned()
                                })
                                .flatten();
                            let result = self.backoffs.on_message(osd, c.conn.id(), message);
                            if result.is_ok() {
                                if let Some(release) = release {
                                    self.backoff_releases += 1;
                                    if self.automatic_recovery {
                                        for &(token, route) in
                                            self.pending.values().filter(|(_, route)| {
                                                route.osd == osd && route.session == c.conn.id()
                                            })
                                        {
                                            if self.queue.target(token).is_some_and(|target| {
                                                rustyrados::BackoffTable::contains(
                                                    &release,
                                                    route,
                                                    target,
                                                    self.queue.snapshot(token).unwrap(),
                                                )
                                            }) && self
                                                .recovery
                                                .push(rustyrados::RecoveryItem {
                                                    token,
                                                    previous: route,
                                                    cause:
                                                        rustyrados::RecoveryCause::BackoffReleased,
                                                })
                                                .is_err()
                                            {
                                                return Err(
                                                    "bounded recovery queue exhausted".into()
                                                );
                                            }
                                        }
                                    }
                                } else if matches!(&result, Ok(Some(_))) {
                                    self.backoff_blocks += 1;
                                }
                            }
                            result
                        }
                        _ => Err(rustyrados::BackoffError::Invalid),
                    };
                    match result {
                        Ok(Some(ack)) => backoff_acks.push((osd, c.conn.id(), ack)),
                        Ok(None) => {}
                        Err(reason) => {
                            error = Some(format!("backoff: {reason:?}"));
                            c.note_rejection();
                            c.dead = error.clone();
                            c.conn.close();
                            c.sock = None;
                            break;
                        }
                    }
                    continue;
                }
                if hdr.msg_type == opwire::consts::ty::WATCH_NOTIFY && hdr.version == 3 {
                    let accepted = match opwire::decode_client(hdr.msg_type, hdr.version, &segs) {
                        Ok(ClientMsg::WatchNotify(msg)) => {
                            self.watches.on_event(osd, c.conn.id(), msg)
                        }
                        _ => Err(rustyrados::WatchError::InvalidEvent),
                    };
                    if let Err(reason) = accepted {
                        self.watches.fault_route(osd, c.conn.id(), reason);
                        error = Some(format!("watch event: {reason:?}"));
                        c.note_rejection();
                        c.dead = error.clone();
                        c.conn.close();
                        c.sock = None;
                        break;
                    }
                    continue;
                }
                if hdr.msg_type != opwire::consts::ty::OSD_OPREPLY || hdr.version != 8 {
                    error = Some(format!(
                        "unsupported OSD message {} v{}",
                        hdr.msg_type, hdr.version
                    ));
                    c.note_rejection();
                    c.dead = error.clone();
                    c.conn.close();
                    c.sock = None;
                    break;
                }
                let Some(&(token, route)) = self.pending.get(&hdr.tid) else {
                    continue;
                };
                if route.osd != osd || route.session != c.conn.id() {
                    continue;
                }
                if !self.queue.is_pending(token) {
                    self.pending.remove(&hdr.tid);
                    continue;
                }
                let result = match opwire::decode_client(hdr.msg_type, hdr.version, &segs) {
                    Ok(ClientMsg::OpReply(reply)) => {
                        let accepted = if self.automatic_recovery {
                            self.queue
                                .reply_for_recovery(token, osd, route.session, reply)
                        } else {
                            self.queue
                                .reply(token, osd, route.session, reply)
                                .map(|done| {
                                    if done {
                                        rustyrados::ReplyAction::Completed
                                    } else {
                                        rustyrados::ReplyAction::AwaitDurable
                                    }
                                })
                        };
                        match accepted {
                            Err(rustyrados::DriverError::Stale) => continue,
                            Ok(rustyrados::ReplyAction::AwaitDurable) => continue,
                            Ok(rustyrados::ReplyAction::Redirected { .. }) => {
                                self.recovery
                                    .push(rustyrados::RecoveryItem {
                                        token,
                                        previous: route,
                                        cause: rustyrados::RecoveryCause::Redirect,
                                    })
                                    .map_err(|_| "redirect recovery capacity")?;
                                self.pending.remove(&hdr.tid);
                                continue;
                            }
                            Ok(rustyrados::ReplyAction::Recover) => {
                                self.recovery
                                    .push(rustyrados::RecoveryItem {
                                        token,
                                        previous: route,
                                        cause: rustyrados::RecoveryCause::TryAgain,
                                    })
                                    .map_err(|_| "EAGAIN recovery capacity")?;
                                continue;
                            }
                            other => other.map(|_| ()).map_err(|e| format!("reply: {e:?}")),
                        }
                    }
                    _ => Err("malformed OSD reply".into()),
                };
                if let Err(e) = result {
                    error = Some(e);
                    c.note_rejection();
                    c.dead = error.clone();
                    c.conn.close();
                    c.sock = None;
                    break;
                }
                self.pending.remove(&hdr.tid);
            }
            if c.dead.is_some() {
                // A socket close can follow on_bytes in the same Probe step. Consume
                // queued rejection faults before classifying that close for recovery.
                while let Some(event) = c.conn.poll_event() {
                    match event {
                        msgr2::Event::Fault(reason) => c.note_fault(&reason),
                        msgr2::Event::Reset | msgr2::Event::RemoteReset => c.note_reset(),
                        _ => {} // this dead transport is replaced, never resumed
                    }
                }
                self.backoffs.reset_session(osd, c.conn.id());
                let recover = self.automatic_recovery
                    && c.failure.is_some_and(|failure| failure.recoverable());
                if recover {
                    for &(token, route) in self
                        .pending
                        .values()
                        .filter(|(_, route)| route.osd == osd && route.session == c.conn.id())
                    {
                        if self.queue.is_pending(token) {
                            self.recovery
                                .push(rustyrados::RecoveryItem {
                                    token,
                                    previous: route,
                                    cause: rustyrados::RecoveryCause::ConnectionLost,
                                })
                                .map_err(|_| "connection recovery capacity")?;
                        }
                    }
                    for dispatch in self
                        .parked
                        .iter()
                        .filter(|d| d.route.osd == osd && d.route.session == c.conn.id())
                    {
                        if self.queue.is_pending(dispatch.token) {
                            self.recovery
                                .push(rustyrados::RecoveryItem {
                                    token: dispatch.token,
                                    previous: dispatch.route,
                                    cause: rustyrados::RecoveryCause::ConnectionLost,
                                })
                                .map_err(|_| "parked recovery capacity")?;
                        }
                    }
                }
                self.parked.retain(|d| {
                    if d.route.osd != osd || d.route.session != c.conn.id() {
                        return true;
                    }
                    if !recover {
                        let _ = self.queue.cancel(d.token);
                    }
                    false
                });
                self.watches
                    .fault_route(osd, c.conn.id(), rustyrados::WatchError::Disconnected);
                self.pending.retain(|_, (token, route)| {
                    if route.osd != osd || route.session != c.conn.id() {
                        return true;
                    }
                    if !recover {
                        let _ = self.queue.cancel(*token);
                    }
                    false
                });
            }
        }
        for (osd, session, ack) in backoff_acks {
            if self
                .probe
                .osds
                .get(&osd)
                .is_some_and(|c| c.conn.id() == session && c.dead.is_none())
            {
                self.probe.send(osd, &ClientMsg::Backoff(ack), 0)?;
            }
        }
        for _ in 0..self.parked.len() {
            let dispatch = self.parked.pop_front().unwrap();
            if self.queue.is_pending(dispatch.token) {
                self.send(dispatch)?;
            }
        }
        for _ in 0..self.recovery.len().min(16) {
            let Some(item) = self.recovery.pop_ready(self.now_us()) else {
                break;
            };
            let token = item.token;
            if !self.queue.is_pending(token) {
                continue;
            }
            if self.queue.deadline_us(token).is_none() {
                let _ = self.cancel(token);
                continue;
            }
            let target = self.queue.target(token).unwrap().clone();
            let route = match self.prepare(&target) {
                Ok(route) => route,
                Err(_) => {
                    self.recovery
                        .push(item)
                        .map_err(|_| "recovery wait capacity")?;
                    continue;
                }
            };
            if self
                .queue
                .expire_token_us(token, self.now_us())
                .unwrap_or(true)
            {
                self.pending
                    .retain(|_, (registered, _)| *registered != token);
                continue;
            }
            if self
                .backoffs
                .blocked(route, &target, self.queue.snapshot(token).unwrap())
            {
                self.recovery
                    .push(item)
                    .map_err(|_| "recovery backoff capacity")?;
                continue;
            }
            if item.cause != rustyrados::RecoveryCause::Redirect && self.queue.retry(token).is_err()
            {
                let _ = self.cancel(token);
                continue;
            }
            self.pending
                .retain(|_, (registered, _)| *registered != token);
            let dispatch = self
                .queue
                .dispatch_with_backoff(token, route, &self.backoffs)
                .map_err(|e| format!("recovery dispatch: {e:?}"))?;
            self.send(dispatch)?;
            self.recovery_sends += 1;
        }
        error.map_or(Ok(()), Err)
    }

    pub fn poll_into(&mut self, output: &mut [Option<ReadCompletion>]) -> usize {
        self.queue.poll_into(output)
    }
}
