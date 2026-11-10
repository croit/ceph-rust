/* SPDX-License-Identifier: MPL-2.0
 * SPDX-FileCopyrightText: 2026 croit GmbH
 * SPDX-FileContributor: Martin Verges, croit GmbH
 * SPDX-FileContributor: Igor Fedotov, croit GmbH
 * SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
 *
 * Thin shim over libibverbs (rdma-core, static, all providers): wraps static-inline verbs and struct-heavy setup so
 * Rust needs only opaque pointers and flat arguments. Data path: rv_post_send(_list), rv_post_srq_recv_list, rv_poll. Everything
 * else is a control call (blocking ioctl) and runs on the control thread only (0469-rdma-transport). */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <infiniband/verbs.h>

struct rv_dev {
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    uint8_t port;
    int32_t gid_idx; /* GID table index of `gid` last seen; re-resolved by rv_gid_index (control thread only) */
    int32_t active_mtu;
    int32_t max_cqe;
    int32_t max_sge;
    uint8_t gid[16];
    char name[64];
    struct ibv_async_event ev; /* read by rv_async_next, acknowledged by rv_async_ack (async-event thread only) */
};

struct rv_wc {
    uint64_t wr_id;
    uint32_t status, opcode, byte_len, flags, imm, qp_num, vendor_err, pad;
};

/* Open the device + port that has a RoCEv2 GID equal to `gid` (IPv4-mapped or IPv6 of the TCP local address). Fails with
 * ENODEV when the host has no RoCE port at all (permanent), EADDRNOTAVAIL when it has RoCE ports but none carries the GID
 * (the address is not configured now: environmental, the caller tries again later). */
struct rv_dev *rv_open_gid(const uint8_t *gid) {
    int n = 0;
    struct ibv_device **l = ibv_get_device_list(&n);
    if (!l) return NULL;
    struct rv_dev *d = NULL;
    int roce_ports = 0;
    for (int i = 0; i < n && !d; i++) {
        struct ibv_context *c = ibv_open_device(l[i]);
        if (!c) continue;
        struct ibv_device_attr a;
        if (ibv_query_device(c, &a)) { ibv_close_device(c); continue; }
        for (uint8_t p = 1; p <= a.phys_port_cnt && !d; p++) {
            struct ibv_port_attr pa;
            if (ibv_query_port(c, p, &pa) || pa.link_layer != IBV_LINK_LAYER_ETHERNET) continue;
            roce_ports++;
            for (int g = 0; g < pa.gid_tbl_len; g++) {
                struct ibv_gid_entry e;
                if (ibv_query_gid_ex(c, p, (uint32_t)g, &e, 0)) continue;
                if (e.gid_type != IBV_GID_TYPE_ROCE_V2 || memcmp(e.gid.raw, gid, 16)) continue;
                d = calloc(1, sizeof *d);
                if (!d) break;
                d->ctx = c; d->port = p; d->gid_idx = g; d->active_mtu = pa.active_mtu;
                d->max_cqe = a.max_cqe;
                d->max_sge = a.max_sge;
                memcpy(d->gid, gid, 16);
                snprintf(d->name, sizeof d->name, "%s", ibv_get_device_name(l[i]));
                break;
            }
        }
        if (!d) ibv_close_device(c);
    }
    ibv_free_device_list(l);
    if (!d) { errno = roce_ports ? EADDRNOTAVAIL : ENODEV; return NULL; }
    d->pd = ibv_alloc_pd(d->ctx);
    if (!d->pd) { int e = errno; ibv_close_device(d->ctx); free(d); errno = e; return NULL; }
    return d;
}

/* Index of the RoCEv2 GID `d->gid` in the port's GID table now. The kernel rebuilds the table when addresses of the netdev
 * change (removed and re-added: the GID may come back at another index), so the index is never trusted from the open:
 * one query confirms the last one, a changed table is scanned again. -EADDRNOTAVAIL: the GID is not on the port (the
 * local address is gone). Control thread only. */
int rv_gid_index(struct rv_dev *d) {
    struct ibv_gid_entry e;
    int g = __atomic_load_n(&d->gid_idx, __ATOMIC_RELAXED);
    if (!ibv_query_gid_ex(d->ctx, d->port, (uint32_t)g, &e, 0) && e.gid_type == IBV_GID_TYPE_ROCE_V2 && !memcmp(e.gid.raw, d->gid, 16))
        return g;
    struct ibv_port_attr pa;
    int rc = ibv_query_port(d->ctx, d->port, &pa);
    if (rc) return -rc;
    for (g = 0; g < pa.gid_tbl_len; g++) {
        if (ibv_query_gid_ex(d->ctx, d->port, (uint32_t)g, &e, 0)) continue;
        if (e.gid_type != IBV_GID_TYPE_ROCE_V2 || memcmp(e.gid.raw, d->gid, 16)) continue;
        __atomic_store_n(&d->gid_idx, g, __ATOMIC_RELAXED);
        return g;
    }
    return -EADDRNOTAVAIL;
}

void rv_close(struct rv_dev *d) {
    ibv_dealloc_pd(d->pd);
    ibv_close_device(d->ctx);
    free(d);
}

const char *rv_name(struct rv_dev *d) { return d->name; }
int rv_active_mtu(struct rv_dev *d) { return d->active_mtu; }
#ifdef FLASHSTORE_MEMORY_WINDOWS
int rv_read_limits(struct rv_dev *d, int *initiator, int *responder, int *sge) {
    struct ibv_device_attr a;
    int rc = ibv_query_device(d->ctx, &a);
    if (rc) return -rc;
    *initiator = a.max_qp_init_rd_atom;
    *responder = a.max_qp_rd_atom;
    *sge = a.max_sge_rd;
    return 0;
}
int rv_qp_read_depths(struct ibv_qp *q, uint8_t *outgoing, uint8_t *incoming) {
    struct ibv_qp_attr a = {0};
    struct ibv_qp_init_attr init = {0};
    int rc = ibv_query_qp(q, &a, IBV_QP_MAX_QP_RD_ATOMIC | IBV_QP_MAX_DEST_RD_ATOMIC, &init);
    if (rc) return -rc;
    *outgoing = a.max_rd_atomic;
    *incoming = a.max_dest_rd_atomic;
    return 0;
}
#endif
int rv_max_cqe(struct rv_dev *d) { return d->max_cqe; }
/* Control-path unbound type-2 window. Deallocation returns the verbs errno value directly. */
struct ibv_mw *rv_alloc_window(struct rv_dev *d) { return ibv_alloc_mw(d->pd, IBV_MW_TYPE_2); }
int rv_dealloc_window(struct ibv_mw *mw) { return ibv_dealloc_mw(mw); }
#ifdef FLASHSTORE_MEMORY_WINDOWS
/* Same RC SQ and wr_id accounting as SEND. No remote descriptor is exported by this unadvertised owner API. */
int rv_post_window_bind(struct ibv_qp *qp, struct ibv_mw *mw, struct ibv_mr *mr, uint64_t id,
                        uint64_t addr, uint64_t len, int read_only) {
    uint32_t key = ibv_inc_rkey(mw->rkey);
    struct ibv_send_wr wr = { .wr_id = id, .opcode = IBV_WR_BIND_MW, .send_flags = IBV_SEND_SIGNALED };
    wr.bind_mw.mw = mw;
    wr.bind_mw.rkey = key;
    wr.bind_mw.bind_info = (struct ibv_mw_bind_info){ .mr = mr, .addr = addr, .length = len,
                                                   .mw_access_flags = read_only ? IBV_ACCESS_REMOTE_READ : IBV_ACCESS_REMOTE_WRITE };
    struct ibv_send_wr *bad = NULL;
    int rc = ibv_post_send(qp, &wr, &bad);
    if (!rc) mw->rkey = key;
    return rc ? -rc : 0;
}
int rv_post_window_invalidate(struct ibv_qp *qp, struct ibv_mw *mw, uint64_t id) {
    struct ibv_send_wr wr = { .wr_id = id, .opcode = IBV_WR_LOCAL_INV, .send_flags = IBV_SEND_SIGNALED,
                              .invalidate_rkey = mw->rkey };
    struct ibv_send_wr *bad = NULL;
    int rc = ibv_post_send(qp, &wr, &bad);
    return rc ? -rc : 0;
}
/* Ordered after prior WRs on this RC SQ. SEND_WITH_INV has no immediate credit field. */
int rv_post_send_invalidate(struct ibv_qp *qp, uint64_t id, uint32_t rkey) {
    struct ibv_send_wr wr = { .wr_id = id, .opcode = IBV_WR_SEND_WITH_INV,
                              .send_flags = IBV_SEND_SIGNALED, .invalidate_rkey = rkey };
    struct ibv_send_wr *bad = NULL;
    int rc = ibv_post_send(qp, &wr, &bad);
    return rc ? -rc : 0;
}
uint32_t rv_window_rkey(struct ibv_mw *mw) { return mw->rkey; }
int rv_post_read(struct ibv_qp *qp, uint64_t id, uint64_t target, uint32_t length, uint32_t lkey,
                 uint64_t source, uint32_t rkey) {
    struct ibv_sge sg = { .addr = target, .length = length, .lkey = lkey };
    struct ibv_send_wr wr = { .wr_id = id, .sg_list = &sg, .num_sge = 1,
                            .opcode = IBV_WR_RDMA_READ, .send_flags = IBV_SEND_SIGNALED };
    wr.wr.rdma.remote_addr = source;
    wr.wr.rdma.rkey = rkey;
    struct ibv_send_wr *bad = NULL;
    int rc = ibv_post_send(qp, &wr, &bad);
    return rc ? -rc : 0;
}
#ifdef FLASHSTORE_FAULT_INJECT
/* Lab-only immutable source registration. No production export/rkey API. */
struct ibv_mr *rv_test_read_source(struct rv_dev *d, const void *addr, uint64_t len) {
    return ibv_reg_mr(d->pd, (void *)addr, len, IBV_ACCESS_REMOTE_READ);
}
uint32_t rv_test_mr_rkey(struct ibv_mr *mr) { return mr->rkey; }
#endif
int rv_post_write(struct ibv_qp *qp, uint64_t id, uint64_t source, uint32_t length, uint32_t lkey,
                  uint64_t target, uint32_t rkey) {
    struct ibv_sge sg = { .addr = source, .length = length, .lkey = lkey };
    struct ibv_send_wr wr = { .wr_id = id, .sg_list = &sg, .num_sge = 1,
                              .opcode = IBV_WR_RDMA_WRITE, .send_flags = IBV_SEND_SIGNALED };
    wr.wr.rdma.remote_addr = target;
    wr.wr.rdma.rkey = rkey;
    struct ibv_send_wr *bad = NULL;
    int rc = ibv_post_send(qp, &wr, &bad);
    return rc ? -rc : 0;
}
#endif
/* Probe actual type-2 allocation, not only the capability bit. 0 = explicitly unsupported, 1 = usable, <0 = -errno. */
int rv_type2_mw_probe(struct rv_dev *d) {
    struct ibv_mw *mw = ibv_alloc_mw(d->pd, IBV_MW_TYPE_2);
    if (!mw) {
        if (errno == EOPNOTSUPP || errno == ENOSYS) return 0;
        return -errno;
    }
    int rc = ibv_dealloc_mw(mw);
    if (rc) return -rc;
    return 1;
}
/* Completion vectors of the device context (a CQ's event comes from the vector it was created on). */
int rv_comp_vectors(struct rv_dev *d) { return d->ctx->num_comp_vectors > 0 ? d->ctx->num_comp_vectors : 1; }

struct ibv_mr *rv_reg(struct rv_dev *d, void *addr, uint64_t len) {
    return ibv_reg_mr(d->pd, addr, len, IBV_ACCESS_LOCAL_WRITE);
}
/* Unbound host destination parent MR: remote access is granted only by a later MW, never through its parent rkey. */
struct ibv_mr *rv_reg_destination(struct rv_dev *d, void *addr, uint64_t len) {
    return ibv_reg_mr(d->pd, addr, len, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_MW_BIND);
}
#ifdef FLASHSTORE_MEMORY_WINDOWS
/* Immutable host source: no local writes or direct remote access; only a later READ-only MW. */
struct ibv_mr *rv_reg_read_window_source(struct rv_dev *d, const void *addr, uint64_t len) {
    return ibv_reg_mr(d->pd, (void *)addr, len, IBV_ACCESS_MW_BIND);
}
#endif
int rv_dereg(struct ibv_mr *m) { return ibv_dereg_mr(m); }
uint32_t rv_lkey(struct ibv_mr *m) { return m->lkey; }
/* DMA-BUF memory (GPUDirect RDMA, adr 0665): register a device buffer as an MR. `iova` is the address a peer uses;
 * `access` is the ibv access bitmask (LOCAL_WRITE for a WRITE target, REMOTE_READ for a READ source). */
struct ibv_mr *rv_reg_dmabuf(struct rv_dev *d, int fd, uint64_t offset, uint64_t iova, uint64_t len, int access) {
    return ibv_reg_dmabuf_mr(d->pd, offset, len, iova, fd, access);
}
struct ibv_mr *rv_reg_access(struct rv_dev *d, void *addr, uint64_t len, int access) {
    return ibv_reg_mr(d->pd, addr, len, access);
}
uint32_t rv_rkey(struct ibv_mr *m) { return m->rkey; }
uint64_t rv_mr_addr(struct ibv_mr *m) { return (uint64_t)(uintptr_t)m->addr; }
uint64_t rv_mr_len(struct ibv_mr *m) { return (uint64_t)m->length; }

/* CQ with its own completion channel (non-blocking fd): an idle core arms it and sleeps on the fd. `vec` is the
 * requested completion vector, taken modulo the device's vectors (cores spread over the interrupt lines). */
struct ibv_cq *rv_cq(struct rv_dev *d, int depth, int vec) {
    struct ibv_comp_channel *ch = ibv_create_comp_channel(d->ctx);
    if (!ch) return NULL;
    int fl = fcntl(ch->fd, F_GETFL);
    if (fl < 0 || fcntl(ch->fd, F_SETFL, fl | O_NONBLOCK) < 0) { int e = errno; ibv_destroy_comp_channel(ch); errno = e; return NULL; }
    struct ibv_cq *c = ibv_create_cq(d->ctx, depth, NULL, ch, vec % rv_comp_vectors(d));
    if (!c) { int e = errno; ibv_destroy_comp_channel(ch); errno = e; return NULL; }
    return c;
}
int rv_cq_destroy(struct ibv_cq *c) {
    struct ibv_comp_channel *ch = c->channel;
    int rc = ibv_destroy_cq(c);
    if (!rc && ch) rc = ibv_destroy_comp_channel(ch);
    return rc;
}
int rv_cq_fd(struct ibv_cq *c) { return c->channel->fd; }
/* Request one event for the next completion (data path: a doorbell write, no syscall). */
int rv_cq_arm(struct ibv_cq *c) { int rc = ibv_req_notify_cq(c, 0); return rc ? -rc : 0; }
/* Consume one pending channel event (one read; the fd is non-blocking): 1, or 0 when none. The event stays unacknowledged
 * until rv_cq_ack_events (a locked call, batched by the caller); the CQ cannot be destroyed before all are acknowledged. */
int rv_cq_ack(struct ibv_cq *c) {
    struct ibv_cq *ec; void *ctx;
    return ibv_get_cq_event(c->channel, &ec, &ctx) == 0;
}
void rv_cq_ack_events(struct ibv_cq *c, unsigned n) { ibv_ack_cq_events(c, n); }

struct ibv_srq *rv_srq(struct rv_dev *d, int depth) {
    struct ibv_srq_init_attr a = { .attr = { .max_wr = (uint32_t)depth, .max_sge = 1 } };
    return ibv_create_srq(d->pd, &a);
}
int rv_srq_destroy(struct ibv_srq *q) { return ibv_destroy_srq(q); }

/* RC QP in INIT on `cq` (send + receive) and `srq`. `read_access` enables remote READ at the QP (explicit READ
 * constructor only); under FLASHSTORE_MEMORY_WINDOWS the QP also permits remote WRITE. Either way only a bound MW grants a
 * remote address/key and MR/MW permissions still gate memory access; the SEND baseline has no remote access.
 * *inl: inline size in, granted size out. *sge: send SGEs per WR wanted in (2 = header + payload by reference), granted
 * out (1 when the device refuses 2). */
struct ibv_qp *rv_qp(struct rv_dev *d, struct ibv_cq *cq, struct ibv_srq *srq, int sq, uint32_t *inl, uint32_t *sge, int read_access) {
    uint32_t want = (*sge > 1 && d->max_sge >= 2) ? 2 : 1;
    struct ibv_qp_init_attr a = {
        .send_cq = cq, .recv_cq = cq, .srq = srq, .qp_type = IBV_QPT_RC, .sq_sig_all = 0,
        .cap = { .max_send_wr = (uint32_t)sq, .max_send_sge = want, .max_recv_sge = 1, .max_inline_data = *inl },
    };
    struct ibv_qp *q = ibv_create_qp(d->pd, &a);
    if (!q && *inl) {
        a.cap.max_inline_data = 0;
        q = ibv_create_qp(d->pd, &a);
    }
    if (!q && want > 1) {
        a.cap.max_send_sge = want = 1;
        a.cap.max_inline_data = *inl;
        q = ibv_create_qp(d->pd, &a);
        if (!q && *inl) {
            a.cap.max_inline_data = 0;
            q = ibv_create_qp(d->pd, &a);
        }
    }
    if (!q) return NULL;
    *inl = a.cap.max_inline_data;
    *sge = a.cap.max_send_sge > 1 ? 2 : 1;
    struct ibv_qp_attr m = { .qp_state = IBV_QPS_INIT, .pkey_index = 0, .port_num = d->port,
#ifdef FLASHSTORE_MEMORY_WINDOWS
                             .qp_access_flags = IBV_ACCESS_REMOTE_WRITE | (read_access ? IBV_ACCESS_REMOTE_READ : 0) };
#else
                             .qp_access_flags = read_access ? IBV_ACCESS_REMOTE_READ : 0 };
#endif
    int rc = ibv_modify_qp(q, &m, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
    if (rc) {
        ibv_destroy_qp(q); errno = rc; return NULL;
    }
    return q;
}
int rv_qp_destroy(struct ibv_qp *q) { return ibv_destroy_qp(q); }
uint32_t rv_qp_num(struct ibv_qp *q) { return q->qp_num; }

/* INIT -> RTR -> RTS. mtu = enum ibv_mtu; tclass = IPv4 TOS of the RoCEv2 packets; timeout/retry/rnr as ibv_modify_qp(3).
 * read_out/read_in are the explicitly negotiated initiator/responder depths (zero for ordinary SEND/WRITE).
 * *rtr = 1 once RTR is reached (from then on SENDs of the peer may land in the SRQ, even if RTS fails). */
int rv_qp_connect(struct rv_dev *d, struct ibv_qp *q, uint32_t rqpn, const uint8_t *rgid, uint32_t rpsn, uint32_t lpsn, int mtu,
                  int timeout, int retry, int rnr, int tclass, uint8_t read_out, uint8_t read_in, int *rtr) {
    *rtr = 0;
    int gidx = rv_gid_index(d);
    if (gidx < 0) return gidx;
    struct ibv_qp_attr a = {
        .qp_state = IBV_QPS_RTR, .path_mtu = (enum ibv_mtu)mtu, .dest_qp_num = rqpn, .rq_psn = rpsn,
        .max_dest_rd_atomic = read_in, .min_rnr_timer = 12,
        .ah_attr = { .is_global = 1, .port_num = d->port, .sl = 0,
                     .grh = { .sgid_index = (uint8_t)gidx, .hop_limit = 64, .traffic_class = (uint8_t)tclass } },
    };
    memcpy(a.ah_attr.grh.dgid.raw, rgid, 16);
    int rc = ibv_modify_qp(q, &a, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                                 IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);
    if (rc) return -rc;
    *rtr = 1;
    struct ibv_qp_attr b = { .qp_state = IBV_QPS_RTS, .timeout = (uint8_t)timeout, .retry_cnt = (uint8_t)retry,
                             .rnr_retry = (uint8_t)rnr, .sq_psn = lpsn, .max_rd_atomic = read_out };
    rc = ibv_modify_qp(q, &b, IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
                                 IBV_QP_MAX_QP_RD_ATOMIC);
    if (rc) return -rc;
    return 0;
}

/* Async events of the device (control plane, the async-event thread of the control thread). rv_async_wait blocks until
 * the device's async channel is readable (1) or `stop` (an eventfd) is signaled (0); < 0 = -errno. */
int rv_async_wait(struct rv_dev *d, int stop) {
    int fl = fcntl(d->ctx->async_fd, F_GETFL);
    if (fl < 0 || fcntl(d->ctx->async_fd, F_SETFL, fl | O_NONBLOCK) < 0) return -errno;
    struct pollfd p[2] = { { .fd = d->ctx->async_fd, .events = POLLIN }, { .fd = stop, .events = POLLIN } };
    for (;;) {
        int n = poll(p, 2, -1);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -errno;
        if (p[1].revents) return 0;
        if (p[0].revents) return 1;
    }
}

/* Next async event: 1 = LAST_WQE_REACHED of QP *qpn (an SRQ QP in ERR consumes no receive WQE any more, the completions of
 * the consumed ones are in the CQ), 2 = another event, 3 = fatal CQ/SRQ/device event (*type; *qpn for a QP event, else 0),
 * 0 = none pending, < 0 = -errno. After 1, 2 or 3 the caller records the event, then calls rv_async_ack: ibv_destroy_qp waits for the acks of its QP's events,
 * so a destroy that returned guarantees every event of that QP is recorded (never attributed to a later QP with the same
 * number). */
int rv_async_next(struct rv_dev *d, int *type, uint32_t *qpn) {
    struct ibv_async_event e;
    if (ibv_get_async_event(d->ctx, &e)) return errno == EAGAIN ? 0 : -errno;
    d->ev = e;
    *type = (int)e.event_type;
    *qpn = 0;
    switch (e.event_type) {
    case IBV_EVENT_QP_FATAL: case IBV_EVENT_QP_REQ_ERR: case IBV_EVENT_QP_ACCESS_ERR: case IBV_EVENT_COMM_EST:
    case IBV_EVENT_SQ_DRAINED: case IBV_EVENT_PATH_MIG: case IBV_EVENT_PATH_MIG_ERR: case IBV_EVENT_QP_LAST_WQE_REACHED:
        *qpn = e.element.qp->qp_num;
        break;
    default:
        break;
    }
    if (e.event_type == IBV_EVENT_CQ_ERR || e.event_type == IBV_EVENT_SRQ_ERR ||
        e.event_type == IBV_EVENT_DEVICE_FATAL) return 3;
    return e.event_type == IBV_EVENT_QP_LAST_WQE_REACHED ? 1 : 2;
}
void rv_async_ack(struct rv_dev *d) { ibv_ack_async_event(&d->ev); }
const char *rv_event_str(int type) { return ibv_event_type_str((enum ibv_event_type)type); }
int rv_efd(void) { int fd = eventfd(0, EFD_CLOEXEC); return fd < 0 ? -errno : fd; }
void rv_efd_signal(int fd) { uint64_t one = 1; if (write(fd, &one, sizeof one) < 0) { /* counter full: already signaled */ } }
void rv_fd_close(int fd) { close(fd); }

/* Any state -> ERR: every outstanding WR completes with a flush error. */
int rv_qp_err(struct ibv_qp *q) {
    struct ibv_qp_attr a = { .qp_state = IBV_QPS_ERR };
    int rc = ibv_modify_qp(q, &a, IBV_QP_STATE);
    return rc ? -rc : 0;
}

/* SEND_WITH_IMM of [addr, addr+len) (len 0 = no SGE: credit-only). imm = credits returned. signaled: completion wanted. */
int rv_post_send(struct ibv_qp *q, uint64_t wr_id, uint64_t addr, uint32_t len, uint32_t lkey, uint32_t imm, int signaled,
                 int inl) {
    struct ibv_sge sg = { .addr = addr, .length = len, .lkey = lkey };
    struct ibv_send_wr w = { .wr_id = wr_id, .sg_list = len ? &sg : NULL, .num_sge = len ? 1 : 0,
                             .opcode = IBV_WR_SEND_WITH_IMM,
                             .send_flags = (signaled ? IBV_SEND_SIGNALED : 0u) | (inl ? IBV_SEND_INLINE : 0u) };
    w.imm_data = htobe32(imm);
    struct ibv_send_wr *bad;
    int rc = ibv_post_send(q, &w, &bad);
    return rc ? -rc : 0;
}

#define RV_BATCH 64 /* WRs per list post; equals BATCH in verbs.rs */

struct rv_send {
    uint64_t wr_id, addr[2];
    uint32_t len[2], lkey[2], imm, flags /* 1 signaled, 2 inline */, nsge, pad;
};
struct rv_recv {
    uint64_t wr_id, addr;
    uint32_t len, lkey;
};

/* A confirmed prefix requires an aligned bad-WR pointer inside the offered
 * list. Missing or malformed pointers cannot prove an empty accepted prefix. */
int rv_posted_prefix(const void *first, size_t stride, int n, const void *bad) {
    uintptr_t base = (uintptr_t)first, at = (uintptr_t)bad;
    if (!bad || at < base || at - base >= (size_t)n * stride || (at - base) % stride) return -1;
    return (int)((at - base) / stride);
}

/* One doorbell for `n` SEND_WITH_IMM WRs (chained list, one or two SGEs each, order kept). *posted = WRs the provider
 * confirmed accepted (a prefix, or -1 when unknown); returns 0 or -errno. */
int rv_post_send_list(struct ibv_qp *q, const struct rv_send *w, int n, int *posted) {
    struct ibv_send_wr wr[RV_BATCH], *bad = NULL;
    struct ibv_sge sg[RV_BATCH * 2];
    if (n < 1 || n > RV_BATCH) { *posted = 0; return -EINVAL; }
    for (int i = 0; i < n; i++) if (w[i].nsge > 2) { *posted = 0; return -EINVAL; }
    for (int i = 0; i < n; i++) {
        for (uint32_t k = 0; k < w[i].nsge; k++) sg[2 * i + k] = (struct ibv_sge){ .addr = w[i].addr[k], .length = w[i].len[k], .lkey = w[i].lkey[k] };
        wr[i] = (struct ibv_send_wr){ .wr_id = w[i].wr_id, .next = i + 1 < n ? &wr[i + 1] : NULL, .sg_list = w[i].nsge ? &sg[2 * i] : NULL,
                                      .num_sge = (int)w[i].nsge, .opcode = IBV_WR_SEND_WITH_IMM,
                                      .send_flags = ((w[i].flags & 1) ? IBV_SEND_SIGNALED : 0u) | ((w[i].flags & 2) ? IBV_SEND_INLINE : 0u) };
        wr[i].imm_data = htobe32(w[i].imm);
    }
    int rc = ibv_post_send(q, wr, &bad);
    *posted = rc ? rv_posted_prefix(wr, sizeof *wr, n, bad) : n;
    return rc ? -rc : 0;
}

/* `n` receive slots to the SRQ in one call; *posted as above. */
int rv_post_srq_recv_list(struct ibv_srq *q, const struct rv_recv *w, int n, int *posted) {
    struct ibv_recv_wr wr[RV_BATCH], *bad = NULL;
    struct ibv_sge sg[RV_BATCH];
    if (n < 1 || n > RV_BATCH) { *posted = 0; return -EINVAL; }
    for (int i = 0; i < n; i++) {
        sg[i] = (struct ibv_sge){ .addr = w[i].addr, .length = w[i].len, .lkey = w[i].lkey };
        wr[i] = (struct ibv_recv_wr){ .wr_id = w[i].wr_id, .next = i + 1 < n ? &wr[i + 1] : NULL, .sg_list = &sg[i], .num_sge = 1 };
    }
    int rc = ibv_post_srq_recv(q, wr, &bad);
    *posted = rc ? rv_posted_prefix(wr, sizeof *wr, n, bad) : n;
    return rc ? -rc : 0;
}

int rv_poll(struct ibv_cq *c, struct rv_wc *out, int n) {
    struct ibv_wc w[32];
    if (n > 32) n = 32;
    int k = ibv_poll_cq(c, n, w);
    for (int i = 0; i < k; i++) {
        out[i].wr_id = w[i].wr_id; out[i].status = w[i].status; out[i].opcode = w[i].opcode; out[i].byte_len = w[i].byte_len;
        /* Normalize only the two mutually exclusive RC receive payload kinds. Rust must reject a missing
         * immediate credit field or an unexpected remote invalidation before processing stream bytes. */
        out[i].flags = ((w[i].wc_flags & IBV_WC_WITH_IMM) ? 1u : 0u) |
                       ((w[i].wc_flags & IBV_WC_WITH_INV) ? 2u : 0u);
        out[i].imm = (w[i].wc_flags & IBV_WC_WITH_IMM) ? be32toh(w[i].imm_data) :
                     (w[i].wc_flags & IBV_WC_WITH_INV) ? w[i].invalidated_rkey : 0;
        out[i].qp_num = w[i].qp_num; out[i].vendor_err = w[i].vendor_err;
        out[i].pad = w[i].wc_flags;
    }
    return k;
}

const char *rv_wc_str(int status) { return ibv_wc_status_str((enum ibv_wc_status)status); }
