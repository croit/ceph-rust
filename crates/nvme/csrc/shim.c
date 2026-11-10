/* SPDX-License-Identifier: LGPL-3.0-only
 * SPDX-FileCopyrightText: 2026 croit GmbH
 * SPDX-FileContributor: Martin Verges, croit GmbH
 * SPDX-FileContributor: Igor Fedotov, croit GmbH
 * SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
 * SPDX-FileContributor: Matthias Grandl, croit GmbH
 * Thin shim over the SPDK NVMe driver: opaque handles, completion ring per queue, no SPDK types in Rust. */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>
#include <unistd.h>
#include <spdk/stdinc.h>
#include <spdk/env.h>
#include <spdk/env_dpdk.h>
#include <spdk/nvme.h>
#include <openssl/ssl.h>

struct nvs_ctrlr {
    struct spdk_nvme_ctrlr *ctrlr;
    struct spdk_nvme_ns *ns;
    uint32_t nsid;
};

struct nvs_info {
    uint32_t lba_size;
    uint64_t lba_count;
    uint32_t awupf_lbas;
    uint32_t awun_lbas;
    uint32_t vwc;
    uint32_t max_xfer_lbas;
    uint32_t dealloc;
    uint32_t write_zeroes;
    /* deallocate (DSM) limits: ranges per command, LBAs per range, LBAs per command (0 = no limit reported) and the
     * preferred deallocate granularity in LBAs (1 when the namespace reports none) */
    uint32_t dsm_ranges;
    uint32_t dsm_range_lbas;
    uint64_t dsm_total_lbas;
    uint32_t dsm_gran_lbas;
};

struct nvs_done { uint32_t slot; int32_t status; }; /* status: 0 ok, else (sct<<8|sc) | 0x10000 (| 0x20000 when DNR) or -1 on abort */

struct nvs_q;
struct nvs_req {
    struct nvs_q *q;
    uint32_t slot;
};

struct nvs_q {
    struct nvs_ctrlr *c;
    struct spdk_nvme_qpair *qp;
    uint32_t depth;
    struct nvs_req *reqs;      /* depth entries, indexed by slot */
    struct nvs_done *ring;     /* depth entries */
    uint32_t head, tail, count;
};

static int g_env_inited;

/* OpenSSL is linked static (adr 0052 am. 5): its built-in config path is the build machine's (Debian /usr/lib/ssl), and
 * SPDK's env init loads that config and fails where the file is missing (non-Debian hosts, minimal images; found by
 * lab/e2e). One self-contained binary reads no host OpenSSL config: initialising without it first makes SPDK's later
 * OPENSSL_INIT_LOAD_CONFIG a no-op (config init runs once). Both env entry points (own EAL, shared EAL) call it. */
static int nvs_openssl_init(void) { return OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) == 1 ? 0 : -1; }

/* `env_context`: extra EAL args or NULL; multi-process mode (adr 0463) passes `--proc-type=primary|secondary` with
 * shm_id >= 0 (SPDK adds `--proc-type=auto` only when env_context names no process type). */
int nvs_env_init(const char *name, const char *core_mask, int shm_id, int mem_mb, const char *const *pci, size_t npci,
                 const char *env_context) {
    if (g_env_inited) return 0;
    /* never a blank probe: only the listed devices (P0 safety) */
    if (!pci || npci == 0 || npci > 64) return -1;
    struct spdk_pci_addr addrs[64];
    for (size_t i = 0; i < npci; i++)
        if (spdk_pci_addr_parse(&addrs[i], pci[i]) != 0) return -1;
    struct spdk_env_opts o;
    o.opts_size = sizeof o; /* read by spdk_env_opts_init / spdk_env_init (fields after it are versioned) */
    spdk_env_opts_init(&o);
    o.name = name;
    if (core_mask) o.core_mask = core_mask;
    o.shm_id = shm_id;
    o.env_context = (void *)env_context; /* SPDK only reads it */
    o.pci_allowed = addrs;
    o.num_pci_addr = npci;
    if (mem_mb > 0) o.mem_size = mem_mb;
    /* lab hosts without an IOMMU (uio_pci_generic): NVS_IOVA_MODE=pa, NVS_HUGE_DIR=/dev/hugepages-1G */
    if (getenv("NVS_IOVA_MODE")) o.iova_mode = getenv("NVS_IOVA_MODE");
    if (getenv("NVS_HUGE_DIR")) o.hugedir = getenv("NVS_HUGE_DIR");
    if (nvs_openssl_init() < 0) return -1;
    if (spdk_env_init(&o) < 0) return -1;
    g_env_inited = 1;
    return 0;
}

struct nvs_ctrlr *nvs_attach(const char *trid_str, uint32_t nsid, struct nvs_info *out) {
    struct spdk_nvme_transport_id trid;
    memset(&trid, 0, sizeof trid);
    if (spdk_nvme_transport_id_parse(&trid, trid_str) != 0) return NULL;
    struct spdk_nvme_ctrlr *ctrlr = spdk_nvme_connect(&trid, NULL, 0);
    if (!ctrlr) return NULL;
    struct spdk_nvme_ns *ns = spdk_nvme_ctrlr_get_ns(ctrlr, nsid);
    if (!ns || !spdk_nvme_ns_is_active(ns)) { spdk_nvme_detach(ctrlr); return NULL; }
    const struct spdk_nvme_ctrlr_data *cd = spdk_nvme_ctrlr_get_data(ctrlr);
    const struct spdk_nvme_ns_data *nd = spdk_nvme_ns_get_data(ns);
    uint32_t ss = spdk_nvme_ns_get_sector_size(ns);
    /* AWUPF/AWUN are 0's based (value 0 = 1 LBA). The namespace-level NAWUPF/NAWUN override when NSFEAT bit 1 is set. */
    uint32_t awupf = (uint32_t)cd->awupf + 1, awun = (uint32_t)cd->awun + 1;
    if (nd->nsfeat.ns_atomic_write_unit) { awupf = (uint32_t)nd->nawupf + 1; awun = (uint32_t)nd->nawun + 1; }
    uint32_t maxx = spdk_nvme_ns_get_max_io_xfer_size(ns) / ss;
    struct nvs_ctrlr *c = calloc(1, sizeof *c);
    if (!c) { spdk_nvme_detach(ctrlr); return NULL; }
    c->ctrlr = ctrlr; c->ns = ns; c->nsid = nsid;
    out->lba_size = ss;
    out->lba_count = spdk_nvme_ns_get_num_sectors(ns);
    out->awupf_lbas = awupf;
    out->awun_lbas = awun;
    out->vwc = cd->vwc.present ? 1 : 0;
    out->max_xfer_lbas = maxx ? maxx : 1;
    out->dealloc = (spdk_nvme_ns_get_flags(ns) & SPDK_NVME_NS_DEALLOCATE_SUPPORTED) ? 1 : 0;
    out->write_zeroes = (spdk_nvme_ns_get_flags(ns) & SPDK_NVME_NS_WRITE_ZEROES_SUPPORTED) ? 1 : 0;
    /* DMRL (0 = no limit: 256), DMRSL, DMSL from the I/O command set specific controller data (NULL when the controller
     * reports none); NPDG (0's based) only when NSFEAT.OPTPERF says the namespace fields are valid */
    const struct spdk_nvme_nvm_ctrlr_data *nvm = spdk_nvme_nvm_ctrlr_get_data(ctrlr);
    out->dsm_ranges = (nvm && nvm->dmrl) ? nvm->dmrl : 256;
    out->dsm_range_lbas = nvm ? nvm->dmrsl : 0;
    out->dsm_total_lbas = nvm ? nvm->dmsl : 0;
    out->dsm_gran_lbas = nd->nsfeat.optperf ? (uint32_t)nd->npdg + 1 : 1;
    return c;
}

/* ---- multi-process primary (adr 0463): construct the controller only (no namespace), poll its admin queue. */
struct nvs_ctrlr *nvs_connect(const char *trid_str) {
    struct spdk_nvme_transport_id trid;
    memset(&trid, 0, sizeof trid);
    if (spdk_nvme_transport_id_parse(&trid, trid_str) != 0) return NULL;
    struct spdk_nvme_ctrlr *ctrlr = spdk_nvme_connect(&trid, NULL, 0);
    if (!ctrlr) return NULL;
    struct nvs_ctrlr *c = calloc(1, sizeof *c);
    if (!c) { spdk_nvme_detach(ctrlr); return NULL; }
    c->ctrlr = ctrlr;
    return c;
}

/* AERs, timeouts and cleanup of dead secondaries (their io qpairs) happen here. <0 = controller failed. */
int nvs_admin_poll(struct nvs_ctrlr *c) { return spdk_nvme_ctrlr_process_admin_completions(c->ctrlr); }

int nvs_is_primary(void) { return spdk_process_is_primary() ? 1 : 0; }

void nvs_detach(struct nvs_ctrlr *c) {
    if (!c) return;
    spdk_nvme_detach(c->ctrlr);
    free(c);
}

struct nvs_q *nvs_q_open(struct nvs_ctrlr *c, uint32_t depth) {
    struct nvs_q *q = calloc(1, sizeof *q);
    if (!q) return NULL;
    q->c = c; q->depth = depth;
    q->reqs = calloc(depth, sizeof *q->reqs);
    q->ring = calloc(depth, sizeof *q->ring);
    /* Doorbell batching: commands go to the SQ at submit, the SQ tail doorbell is written by the next
     * process_completions (`nvs_q_poll`), which the owner calls at the end of its loop pass (`BlockDev::issue`):
     * one MMIO write per pass instead of one per command (the kernel tier's one submit per pass, adr 0004 am. 1). */
    struct spdk_nvme_io_qpair_opts o;
    spdk_nvme_ctrlr_get_default_io_qpair_opts(c->ctrlr, &o, sizeof o);
    o.delay_cmd_submit = true;
    q->qp = spdk_nvme_ctrlr_alloc_io_qpair(c->ctrlr, &o, sizeof o);
    if (!q->reqs || !q->ring || !q->qp) {
        if (q->qp) spdk_nvme_ctrlr_free_io_qpair(q->qp);
        free(q->reqs); free(q->ring); free(q);
        return NULL;
    }
    for (uint32_t i = 0; i < depth; i++) { q->reqs[i].q = q; q->reqs[i].slot = i; }
    return q;
}

void nvs_q_close(struct nvs_q *q) {
    if (!q) return;
    spdk_nvme_ctrlr_free_io_qpair(q->qp);
    free(q->reqs); free(q->ring); free(q);
}

static void done_cb(void *arg, const struct spdk_nvme_cpl *cpl) {
    struct nvs_req *r = arg;
    struct nvs_q *q = r->q;
    struct nvs_done *d = &q->ring[q->tail];
    q->tail = (q->tail + 1) % q->depth;
    q->count++;
    d->slot = r->slot;
    /* bit 16: error, bit 17: do-not-retry (outside the 0xffff status mask the store error mapping uses) */
    d->status = spdk_nvme_cpl_is_error(cpl) ? (int32_t)((cpl->status.sct << 8) | cpl->status.sc) | 0x10000 | (cpl->status.dnr ? 0x20000 : 0) : 0;
}

/* `io_flags` come from Rust (`nvme::write_io_flags`): FUA on every durable write when the device has a volatile cache (adr 0008). */
_Static_assert(SPDK_NVME_IO_FLAGS_FORCE_UNIT_ACCESS == (1u << 30), "FUA bit must match nvme::IO_FLAG_FUA");
int nvs_q_write(struct nvs_q *q, uint32_t slot, void *buf, uint64_t lba, uint32_t n, uint32_t io_flags) {
    return spdk_nvme_ns_cmd_write(q->c->ns, q->qp, buf, lba, n, done_cb, &q->reqs[slot], io_flags);
}
int nvs_q_read(struct nvs_q *q, uint32_t slot, void *buf, uint64_t lba, uint32_t n) {
    return spdk_nvme_ns_cmd_read(q->c->ns, q->qp, buf, lba, n, done_cb, &q->reqs[slot], 0);
}
/* `ranges`: `n` DSM range descriptors (16 bytes each, `nvme::dsm_ranges_into`); SPDK copies them into the request, the
 * caller's memory is free again on return. */
_Static_assert(sizeof(struct spdk_nvme_dsm_range) == 16, "DSM range must match nvme::DSM_RANGE_BYTES");
int nvs_q_dealloc(struct nvs_q *q, uint32_t slot, const void *ranges, uint16_t n) {
    return spdk_nvme_ns_cmd_dataset_management(q->c->ns, q->qp, SPDK_NVME_DSM_ATTR_DEALLOCATE,
                                               (const struct spdk_nvme_dsm_range *)ranges, n, done_cb, &q->reqs[slot]);
}
int nvs_q_write_zeroes(struct nvs_q *q, uint32_t slot, uint64_t lba, uint32_t n, uint32_t io_flags) {
    return spdk_nvme_ns_cmd_write_zeroes(q->c->ns, q->qp, lba, n, done_cb, &q->reqs[slot], io_flags);
}

/* Process completions and write the SQ doorbell for commands submitted since the last call (delay_cmd_submit);
 * returns number of finished IOs now in the ring; on qpair failure (process_completions < 0) the ring count when
 * IOs (e.g. ones SPDK just aborted) wait in it, else the negative error: finished IOs are never hidden by a failure. */
int nvs_q_poll(struct nvs_q *q) {
    int64_t r = spdk_nvme_qpair_process_completions(q->qp, 0);
    if (r < 0 && !q->count) return (int)r;
    return (int)q->count;
}

/* Pop one finished IO; returns 0 if none. */
int nvs_q_pop(struct nvs_q *q, uint32_t *slot, int32_t *status) {
    if (!q->count) return 0;
    struct nvs_done *d = &q->ring[q->head];
    q->head = (q->head + 1) % q->depth;
    q->count--;
    *slot = d->slot; *status = d->status;
    return 1;
}

void *nvs_dma_alloc(size_t len, size_t align) { return spdk_dma_malloc(len, align, NULL); }
void nvs_dma_free(void *p) { spdk_dma_free(p); }

/* ---- shared EAL (daemon): DPDK already initialised by crate `net`, finish SPDK's env on top of it (adr 0004). */
int nvs_env_post_init(void) {
    if (g_env_inited) return 0;
    if (nvs_openssl_init() < 0) return -1;
    int r = spdk_env_dpdk_post_init(false);
    if (r < 0) return r;
    g_env_inited = 1;
    return 0;
}

/* ---- LBA format management (mkfs): query the namespace formats, Format NVM to 4096 B + 0 metadata. */
struct nvs_lbafs {
    uint32_t cur;       /* current LBAF index */
    uint32_t cur_lbads; /* current data size in bytes */
    uint32_t cur_ms;    /* current metadata bytes per LBA */
    int32_t best4k;     /* index of the best 4096+0 LBAF (lowest relative performance value), -1 if none */
    uint32_t nlbaf;
    uint32_t pi;        /* DPS PI type currently enabled (0 = none) */
};

int nvs_lbaf_query(struct nvs_ctrlr *c, struct nvs_lbafs *o) {
    const struct spdk_nvme_ns_data *nd = spdk_nvme_ns_get_data(c->ns);
    o->nlbaf = (uint32_t)nd->nlbaf + 1;
    o->cur = (uint32_t)nd->flbas.format | ((uint32_t)nd->flbas.msb_format << 4); /* NVMe 2.0: 6-bit index */
    o->cur_lbads = 1u << nd->lbaf[o->cur].lbads;
    o->cur_ms = nd->lbaf[o->cur].ms;
    o->pi = nd->dps.pit;
    o->best4k = -1;
    uint32_t best_rp = 99;
    for (uint32_t i = 0; i < o->nlbaf && i < 64; i++) {
        if (nd->lbaf[i].lbads == 12 && nd->lbaf[i].ms == 0 && nd->lbaf[i].rp < best_rp) {
            best_rp = nd->lbaf[i].rp; o->best4k = (int32_t)i;
        }
    }
    return 0;
}

/* Format NVM (admin command, synchronous, DESTROYS the namespace content): lbaf, no metadata, no PI, no secure erase. */
int nvs_format(struct nvs_ctrlr *c, uint32_t lbaf) {
    /* never under other processes (adr 0463): format the namespace while the controller is not shared */
    if (!spdk_process_is_primary()) return -EPERM;
    struct spdk_nvme_format f;
    memset(&f, 0, sizeof f);
    f.lbaf = lbaf & 0xf; f.lbafu = (lbaf >> 4) & 0x3; f.ms = 0; f.pi = 0; f.pil = 0; f.ses = 0;
    return spdk_nvme_ctrlr_format(c->ctrlr, c->nsid, &f);
}

/* ---- identity + SMART (device metadata, devicehealth): admin commands only, safe next to running io queues. */
struct nvs_ident { char model[41]; char serial[21]; char fw[9]; };

int nvs_ident(struct nvs_ctrlr *c, struct nvs_ident *o) {
    const struct spdk_nvme_ctrlr_data *cd = spdk_nvme_ctrlr_get_data(c->ctrlr);
    memset(o, 0, sizeof *o);
    memcpy(o->model, cd->mn, 40);
    memcpy(o->serial, cd->sn, 20);
    memcpy(o->fw, cd->fr, 8);
    return 0;
}

/* A metadata admin request (context + DMA buffer) lives on the heap, never on the caller's stack: a timed-out request
 * stays queued on the admin queue and any later admin poll of the controller (this or another thread, another wrapper of
 * the same native controller) runs its callback. Ownership passes by one atomic exchange: the waiter owns the request
 * while PENDING/DONE; after a timeout (ABANDONED) the callback owns it and frees it on completion. A request whose
 * callback never arrives stays allocated until process exit (the controller may still DMA into its buffer). */
enum { NVS_ADMIN_PENDING, NVS_ADMIN_DONE, NVS_ADMIN_ABANDONED };
struct nvs_log_done {
    _Atomic int state;
    int err;
    void *buf;
};

static void nvs_admin_release(struct nvs_log_done *d) {
    spdk_dma_free(d->buf);
    free(d);
}

static struct nvs_log_done *nvs_admin_alloc(size_t len) {
    struct nvs_log_done *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    atomic_init(&d->state, NVS_ADMIN_PENDING);
    d->buf = spdk_dma_zmalloc(len, 4096, NULL);
    if (!d->buf) { free(d); return NULL; }
    return d;
}

static void log_cb(void *arg, const struct spdk_nvme_cpl *cpl) {
    struct nvs_log_done *d = arg;
    d->err = spdk_nvme_cpl_is_error(cpl);
    /* last access unless the waiter gave up: then the request is ours to free */
    if (atomic_exchange(&d->state, NVS_ADMIN_DONE) == NVS_ADMIN_ABANDONED) nvs_admin_release(d);
}

/* Bound of the metadata admin commands (SMART log page, namespace list): 5 s of 10 us polls. A controller that does not
 * answer must say so loudly (WARNING TIMEOUT) instead of leaving a silent "failed" line or a missing namespace count. */
#define NVS_ADMIN_TIMEOUT_US (5 * 1000 * 1000)
#define NVS_ADMIN_POLL_US 10

/* Poll `c`'s admin queue until `d` is done or NVS_ADMIN_TIMEOUT_US passed; 1 = done, 0 = timed out (logged). */
static int nvs_admin_wait(struct nvs_ctrlr *c, struct nvs_log_done *d, const char *op) {
    for (int64_t us = 0; us < NVS_ADMIN_TIMEOUT_US; us += NVS_ADMIN_POLL_US) {
        spdk_nvme_ctrlr_process_admin_completions(c->ctrlr);
        if (atomic_load(&d->state) == NVS_ADMIN_DONE) return 1;
        usleep(NVS_ADMIN_POLL_US);
    }
    /* a completion that raced the deadline (another thread's poll) still belongs to the waiter */
    if (atomic_exchange(&d->state, NVS_ADMIN_ABANDONED) == NVS_ADMIN_DONE) return 1;
    fprintf(stderr, "WARNING TIMEOUT %s exceeded %llds (admin command did not complete)\n",
            op, (long long)(NVS_ADMIN_TIMEOUT_US / 1000000));
    return 0;
}

/* Get Log Page 0x02 (SMART / Health Information, 512 B) into out[512]. 0 ok, <0 failure/timeout (~5 s). */
int nvs_smart(struct nvs_ctrlr *c, uint8_t *out) {
    struct nvs_log_done *d = nvs_admin_alloc(512);
    if (!d) return -1;
    int r = spdk_nvme_ctrlr_cmd_get_log_page(c->ctrlr, SPDK_NVME_LOG_HEALTH_INFORMATION, SPDK_NVME_GLOBAL_NS_TAG,
                                              d->buf, 512, 0, log_cb, d);
    if (r != 0) { nvs_admin_release(d); return -2; }
    if (!nvs_admin_wait(c, d, "nvme get-log-page 0x02 (smart read)")) return -3;
    r = d->err ? -4 : 0;
    if (!r) memcpy(out, d->buf, 512);
    nvs_admin_release(d);
    return r;
}

/* ---- Format NVM scope (mkfs safety): FNA + how many namespaces exist. With FNA bit 0 set a format of ONE namespace
 * formats every namespace of the subsystem (bit 1: same for secure erase); the decision lives in Rust (`nvme::fna`). */
struct nvs_nsscope {
    uint32_t fna;        /* Identify Controller FNA byte */
    uint32_t active;     /* active namespaces attached to this controller */
    int32_t allocated;   /* allocated namespaces in the subsystem (Identify CNS 10h), -1 = unknown */
    uint32_t ns_mgmt;    /* OACS namespace management supported */
    uint32_t multi_ctrl; /* CMIC: the subsystem may have more controllers */
};

int nvs_ns_scope(struct nvs_ctrlr *c, struct nvs_nsscope *o) {
    const struct spdk_nvme_ctrlr_data *cd = spdk_nvme_ctrlr_get_data(c->ctrlr);
    memset(o, 0, sizeof *o);
    uint8_t fna;
    memcpy(&fna, &cd->fna, 1);
    o->fna = fna;
    o->ns_mgmt = cd->oacs.nms;
    o->multi_ctrl = cd->cmic.mctrs;
    for (uint32_t n = spdk_nvme_ctrlr_get_first_active_ns(c->ctrlr); n; n = spdk_nvme_ctrlr_get_next_active_ns(c->ctrlr, n))
        o->active++;
    o->allocated = -1;
    if (!o->ns_mgmt) return 0;
    struct nvs_log_done *d = nvs_admin_alloc(sizeof(struct spdk_nvme_ns_list));
    if (!d) return 0;
    struct spdk_nvme_ns_list *l = d->buf;
    struct spdk_nvme_cmd cmd;
    memset(&cmd, 0, sizeof cmd);
    cmd.opc = SPDK_NVME_OPC_IDENTIFY;
    cmd.nsid = 0; /* list every NSID > 0 */
    cmd.cdw10_bits.identify.cns = SPDK_NVME_IDENTIFY_ALLOCATED_NS_LIST;
    if (spdk_nvme_ctrlr_cmd_admin_raw(c->ctrlr, &cmd, l, sizeof *l, log_cb, d) != 0) {
        nvs_admin_release(d); return 0;
    }
    if (!nvs_admin_wait(c, d, "nvme identify allocated-ns-list (namespace scope)"))
        return 0; /* callback-owned until completion; allocated stays unknown */
    if (!d->err) {
        int32_t n = 0;
        while (n < 1024 && l->ns_list[n]) n++;
        o->allocated = n;
    }
    nvs_admin_release(d);
    return 0;
}

/* Can the device DMA from [p, p+len)? (registered hugepage memory: rte_malloc / spdk_dma_malloc; adr 0061 am. 4).
 * A buffer is one heap element, so its first and last byte decide; PRP needs dword alignment. */
int nvs_dma_ok(const void *p, size_t len) {
    if (len == 0 || ((uintptr_t)p & 3) != 0) return 0;
    return spdk_vtophys(p, NULL) != SPDK_VTOPHYS_ERROR &&
           spdk_vtophys((const char *)p + len - 1, NULL) != SPDK_VTOPHYS_ERROR;
}
