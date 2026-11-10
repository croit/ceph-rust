/* SPDX-License-Identifier: MPL-2.0
 * SPDX-FileCopyrightText: 2026 croit GmbH
 * SPDX-FileContributor: Martin Verges, croit GmbH
 * SPDX-FileContributor: Igor Fedotov, croit GmbH
 * SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
 * Thin shim over the DPDK EAL: wraps static-inline functions so Rust needs only plain calls. */
#include <stdint.h>
#include <stddef.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

int nv_eal_init(int argc, char **argv) { return rte_eal_init(argc, argv); }
int nv_errno(void) { return rte_errno; }
const char *nv_strerror(int e) { return rte_strerror(e); }

/* Payload buffers >= the allocator threshold live in the EAL heap: SPDK and RDMA devices can DMA from them, so a heap
 * `Bytes` is stored / sent by reference without a copy (HugeAlloc). */
void *nv_big_alloc(size_t size, size_t align, int zero) {
    unsigned a = align > 64 ? (unsigned)align : 0;
    return zero ? rte_zmalloc(NULL, size, a) : rte_malloc(NULL, size, a);
}
void nv_big_free(void *p) { rte_free(p); }
int nv_is_dpdk_mem(const void *p) { return rte_mem_virt2memseg(p, NULL) != NULL; }
/* EAL malloc heap over all NUMA nodes: out = {total, free, largest free block} bytes. The payload heap (rte_malloc) and
 * SPDK's DMA buffers (spdk_dma_malloc) share it: what is free here is the headroom of both. */
void nv_heap_stats(uint64_t out[3]) {
    out[0] = out[1] = out[2] = 0;
    for (unsigned i = 0; i < rte_socket_count(); i++) {
        struct rte_malloc_socket_stats st;
        if (rte_malloc_get_socket_stats(rte_socket_id_by_idx(i), &st) != 0) continue;
        out[0] += st.heap_totalsz_bytes;
        out[1] += st.heap_freesz_bytes;
        if (st.greatest_free_size > out[2]) out[2] = st.greatest_free_size;
    }
}

/* VA ranges of the EAL memory that stays mapped for the life of the process: segments preallocated at init (-m, flag
 * DO_NOT_FREE), adjacent ones merged. Pages the heap adds or frees later are not listed. (addr, len) pairs into `out`;
 * returns the pair count, or -1 when there are more than `max`. Used to register the payload heap with an RDMA device
 * once at start (zero-copy SEND). */
struct nv_ranges { uint64_t *out; int max; int n; };
static int nv_range_cb(const struct rte_memseg_list *msl, const struct rte_memseg *ms, void *arg) {
    struct nv_ranges *r = arg;
    if (msl->external || !(ms->flags & RTE_MEMSEG_FLAG_DO_NOT_FREE)) return 0;
    uint64_t a = (uint64_t)(uintptr_t)ms->addr, l = ms->len;
    if (r->n > 0 && r->out[2 * (r->n - 1)] + r->out[2 * (r->n - 1) + 1] == a) {
        r->out[2 * (r->n - 1) + 1] += l;
        return 0;
    }
    if (r->n == r->max) return -1;
    r->out[2 * r->n] = a;
    r->out[2 * r->n + 1] = l;
    r->n++;
    return 0;
}
int nv_pinned_ranges(uint64_t *out, int max) {
    struct nv_ranges r = { out, max, 0 };
    return rte_memseg_walk(nv_range_cb, &r) < 0 ? -1 : r.n;
}
