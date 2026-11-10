// SPDX-License-Identifier: LGPL-3.0-only
// Native ABI glue only. Engine policy and persistent identity are Rust-owned.
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include "splinterdb/splinterdb.h"
#include "splinterdb/default_data_config.h"
#include "allocator.h"
#include "clockcache.h"
#include "platform_linux/laio.h"
#include "task.h"
// Revision-pinned internal diagnostic accessor; not a synchronization primitive.
extern const allocator *splinterdb_get_allocator_handle(const splinterdb *kvs);
extern const cache *splinterdb_get_cache_handle(const splinterdb *kvs);
extern const io_handle *splinterdb_get_io_handle(const splinterdb *kvs);
extern const task_system *splinterdb_get_task_system_handle(const splinterdb *kvs);

typedef struct {
    data_config data;
    splinterdb *db;
} nv_sdb;

typedef struct {
    splinterdb_iterator *it;
    int done;
} nv_sdb_iter;

int nv_sdb_open(const char *path, uint64_t cache_bytes, uint64_t capacity,
                int create, int buffered, uint64_t prefetch_bytes, int stats,
                int normal_maintenance, int memtable_maintenance,
                uint64_t checkpoint_log_bytes, int defer_log_writeback,
                int no_log, void **out) {
    *out = NULL;
    if (normal_maintenance && stats) return EINVAL;
    // The memtable helper is layered on the normal-maintenance mode only.
    if (memtable_maintenance && !normal_maintenance) return EINVAL;
    nv_sdb *p = calloc(1, sizeof(*p));
    if (!p) return ENOMEM;
    default_data_config_init(&p->data);
    splinterdb_config cfg = {0};
    cfg.filename = path;
    cfg.cache_size = cache_bytes;
    cfg.disk_size = capacity;
    cfg.data_cfg = &p->data;
    cfg.io_flags = O_RDWR | O_NOFOLLOW | (buffered ? 0 : O_DIRECT)
                   | (create ? O_CREAT | O_EXCL : 0);
    cfg.prefetch_budget = prefetch_bytes;
    cfg.cache_use_stats = stats != 0;
    // At this pin the cache constructor is driven by use_stats, not by the
    // separately exposed cache_use_stats field. Enable both for explicit sampling.
    cfg.use_stats = stats != 0;
    // Without the library log, durability comes only from checkpoints (each barrier
    // checkpoints the tree); the caller's own redo must cover everything after.
    cfg.use_log = no_log ? 0 : 1;
    cfg.log_group_size_pages = UINT64_MAX; // explicit blocking barriers own durability
    cfg.memtable_capacity = cache_bytes / 8;
    // Log growth that arms an automatic checkpoint (full-cache writeback and
    // sync); zero keeps the pinned default of one cache size.
    cfg.checkpoint_log_size_bytes = checkpoint_log_bytes;
    // Patched library option (crates/splinterdb/patches): issue filled log
    // pages at the next durability wait rather than as each page fills.
    cfg.log_defer_writeback = defer_log_writeback != 0;
    // Optional single memtable helper: incorporation leaves the inserting caller.
    cfg.num_memtable_bg_threads = memtable_maintenance ? 1 : 0;
    cfg.num_normal_bg_threads = normal_maintenance ? 1 : 0;
    // One normal helper: defer ordinary assistance for one waiting normal task,
    // assist at two. Zero-worker memtable and forced progress remain eligible.
    // This is not a hard queue/latency bound; see the pinned own-words contract.
    cfg.queue_scale_percent = normal_maintenance ? 101 : 0;
    int rc = create ? splinterdb_create(&cfg, &p->db) : splinterdb_open(&cfg, &p->db);
    if (rc) { free(p); return rc; }
    *out = p;
    return 0;
}

// Registration is process-wide, not owned by an individual database handle.
// Rust calls release only after its last handle on this caller has closed.
int nv_sdb_acquire_caller(uint64_t *registration) {
    if (platform_get_tid() != INVALID_TID) return EBUSY;
    if (platform_register_thread() != 0) return EAGAIN;
    *registration = platform_get_tid();
    return 0;
}
int nv_sdb_release_caller(uint64_t registration) {
    // Never recycle a credit for registration that disappeared or changed in
    // a failed library startup. Its cleanup cannot be inferred from DB close.
    if (platform_get_tid() != registration) return EOWNERDEAD;
    platform_deregister_thread();
    return 0;
}
int nv_sdb_caller_matches(uint64_t registration) {
    return platform_get_tid() == registration;
}

int nv_sdb_maintenance_stack_bytes(uint64_t *bytes) {
    pthread_attr_t attr;
    int rc = pthread_getattr_default_np(&attr);
    if (rc) return rc;
    size_t stack = 0, guard = 0;
    rc = pthread_attr_getstacksize(&attr, &stack);
    if (!rc) rc = pthread_attr_getguardsize(&attr, &guard);
    int cleanup = pthread_attr_destroy(&attr);
    if (rc) return rc;
    if (cleanup) return cleanup;
    if (!stack) return EINVAL;
    if (stack > UINT64_MAX - guard) return EOVERFLOW;
    *bytes = stack + guard;
    return 0;
}

int nv_sdb_maintenance(void *handle, uint64_t out[4]) {
    nv_sdb *p = handle;
    const splinterdb_config *cfg = splinterdb_get_config(p->db);
    task_system *tasks = (task_system *)splinterdb_get_task_system_handle(p->db);
    out[0] = cfg->num_normal_bg_threads;
    // Uses both existing group locks: separate queued/running reads could
    // falsely report idle while a worker transfers a task between the counts.
    out[1] = !task_system_is_quiescent(tasks);
    out[2] = cfg->num_memtable_bg_threads;
    out[3] = cfg->queue_scale_percent;
    return 0;
}

int nv_sdb_close(void **handle, int force) {
    nv_sdb *p = *handle;
    if (!p) return 0;
    int rc = splinterdb_close(&p->db, force);
    if (!p->db) { free(p); *handle = NULL; }
    return rc;
}

int nv_sdb_put(void *handle, const void *key, size_t key_len,
               const void *value, size_t value_len) {
    nv_sdb *p = handle;
    return splinterdb_insert(p->db, slice_create(key_len, key),
                            message_create(value_len, value), NULL);
}

int nv_sdb_delete(void *handle, const void *key, size_t key_len) {
    nv_sdb *p = handle;
    return splinterdb_delete(p->db, slice_create(key_len, key), NULL);
}

int nv_sdb_barrier(void *handle) {
    return splinterdb_durable_barrier(((nv_sdb *)handle)->db, SPLINTERDB_NOTIFICATION_BLOCKING);
}

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int ready;
} nv_sdb_prime_ready;

static void nv_sdb_prime_notify(void *arg) {
    nv_sdb_prime_ready *r = arg;
    pthread_mutex_lock(&r->mutex);
    r->ready = 1;
    pthread_cond_signal(&r->changed);
    pthread_mutex_unlock(&r->mutex);
}

// Cold startup only. A nonempty async read creates/reuses LAIO's existing
// per-handle process context and cleaner under this caller's current affinity.
// A readiness callback can also mean EAGAIN progress: retain state and page
// until run reports terminal completion, not merely until the first callback.
int nv_sdb_prime_io(void *handle) {
    nv_sdb *p = handle;
    const splinterdb_config *cfg = splinterdb_get_config(p->db);
    io_handle *io = (io_handle *)splinterdb_get_io_handle(p->db);
    if (cfg->page_size < IO_MIN_PAGE_SIZE || cfg->page_size > IO_MAX_PAGE_SIZE) return EINVAL;
    bool32 readable = FALSE;
    platform_status st = io_range_is_readable(io, 0, cfg->page_size, &readable);
    if (!SUCCESS(st)) return st.r;
    if (!readable) return EIO;
    void *page = NULL;
    int rc = posix_memalign(&page, cfg->page_size, cfg->page_size);
    if (rc) return rc;
    nv_sdb_prime_ready ready = {0};
    rc = pthread_mutex_init(&ready.mutex, NULL);
    if (rc) { free(page); return rc; }
    rc = pthread_cond_init(&ready.changed, NULL);
    if (rc) { pthread_mutex_destroy(&ready.mutex); free(page); return rc; }
    io_async_state_page_buffer request;
    st = io_async_state_init_page(request, io, io_async_preadv, 0, nv_sdb_prime_notify, &ready);
    if (!SUCCESS(st)) { rc = st.r; goto finished; }
    st = io_async_state_append_page(request, page);
    if (!SUCCESS(st)) { rc = st.r; goto initialized; }
    for (;;) {
        pthread_mutex_lock(&ready.mutex);
        ready.ready = 0;
        pthread_mutex_unlock(&ready.mutex);
        if (io_async_run(request) == ASYNC_STATUS_DONE) break;
        pthread_mutex_lock(&ready.mutex);
        while (!ready.ready) pthread_cond_wait(&ready.changed, &ready.mutex);
        pthread_mutex_unlock(&ready.mutex);
    }
    st = io_async_state_get_result(request);
    rc = st.r;
initialized:
    io_async_state_deinit(request);
finished:
    pthread_cond_destroy(&ready.changed);
    pthread_mutex_destroy(&ready.mutex);
    free(page);
    return rc;
}

void nv_sdb_space(void *handle, uint64_t *used, uint64_t *capacity) {
    nv_sdb *p = handle;
    allocator *a = (allocator *)splinterdb_get_allocator_handle(p->db);
    const splinterdb_config *cfg = splinterdb_get_config(p->db);
    *used = allocator_in_use(a) * cfg->extent_size;
    *capacity = allocator_get_capacity(a);
}

// Sample on the owning worker. With maintenance enabled statistics are refused;
// only immutable configuration metadata is then sampled here.
// Counters describe engine cache work, NOT physical-device IO or OS cache hits.
int nv_sdb_read_stats(void *handle, uint64_t out[9]) {
    nv_sdb *p = handle;
    const splinterdb_config *cfg = splinterdb_get_config(p->db);
    const laio_handle *io = (const laio_handle *)splinterdb_get_io_handle(p->db);
    int flags = fcntl(io->fd, F_GETFL);
    if (flags < 0) return errno;
    for (unsigned i = 0; i < 9; i++) out[i] = 0;
    cache *cc = (cache *)splinterdb_get_cache_handle(p->db);
    const clockcache *clock = (const clockcache *)cc;
    out[0] = clock->cfg->use_stats;
    out[6] = (flags & O_DIRECT) != 0;
    out[7] = cfg->cache_size;
    out[8] = cfg->prefetch_budget;
    if (!out[0]) return 0;
    cache_io_stats(cc, &out[3], &out[4]);
    for (unsigned thread = 0; thread < MAX_THREADS; thread++) {
        for (unsigned type = 0; type < NUM_PAGE_TYPES; type++) {
            out[1] += clock->stats[thread].cache_hits[type];
            out[2] += clock->stats[thread].cache_misses[type];
            out[5] += clock->stats[thread].prefetches_issued[type];
        }
    }
    return 0;
}

int nv_sdb_lookup_new(void *handle, void **result) {
    nv_sdb *p = handle;
    *result = NULL;
    splinterdb_lookup_result *r = malloc(sizeof(*r));
    if (!r) return ENOMEM;
    splinterdb_lookup_result_init(p->db, r);
    *result = r;
    return 0;
}

int nv_sdb_lookup(void *handle, const void *key, size_t key_len,
                  void *result, const void **value, size_t *value_len, int *found) {
    nv_sdb *p = handle;
    splinterdb_lookup_result *r = result;
    *value = NULL; *value_len = 0; *found = 0;
    int rc = splinterdb_lookup(p->db, slice_create(key_len, key), r);
    if (!rc && splinterdb_lookup_found(r)) {
        slice v;
        rc = splinterdb_lookup_result_value(r, &v);
        if (!rc) { *value = slice_data(v); *value_len = slice_length(v); *found = 1; }
    }
    return rc;
}

void nv_sdb_lookup_free(void *result) {
    splinterdb_lookup_result *r = result;
    if (r) { splinterdb_lookup_result_deinit(r); free(r); }
}

int nv_sdb_iter_open(void *handle, const void *from, size_t from_len, int exclusive,
                     const void *end, size_t end_len, void **out) {
    *out = NULL;
    nv_sdb_iter *p = calloc(1, sizeof(*p));
    if (!p) return ENOMEM;
    slice start = slice_create(from_len, from);
    slice upper = end ? slice_create(end_len, end) : NULL_SLICE;
    int rc = splinterdb_iterator_init(((nv_sdb *)handle)->db, &p->it,
        .start_position = splinterdb_make_start_position(exclusive ? greater_than : greater_than_or_equal, start),
        .upper_limit = splinterdb_less_than(upper));
    if (rc) { free(p); return rc; }
    *out = p;
    return 0;
}

int nv_sdb_iter_current(void *handle, const void **key, size_t *key_len,
                        const void **value, size_t *value_len, int *found) {
    nv_sdb_iter *p = handle;
    *key = NULL; *value = NULL; *key_len = 0; *value_len = 0; *found = 0;
    if (p->done || !splinterdb_iterator_valid(p->it))
        return splinterdb_iterator_status(p->it);
    slice k = NULL_SLICE, v = NULL_SLICE;
    splinterdb_iterator_get_current(p->it, &k, &v);
    int rc = splinterdb_iterator_status(p->it); // getter can fail while materializing blobs
    if (rc) return rc;
    *key = slice_data(k); *key_len = slice_length(k);
    *value = slice_data(v); *value_len = slice_length(v); *found = 1;
    return 0;
}

int nv_sdb_iter_next(void *handle) {
    nv_sdb_iter *p = handle;
    if (!p->done && splinterdb_iterator_can_next(p->it)) splinterdb_iterator_next(p->it);
    else p->done = 1;
    return splinterdb_iterator_status(p->it);
}

void nv_sdb_iter_close(void *handle) {
    nv_sdb_iter *p = handle;
    if (p) { splinterdb_iterator_deinit(p->it); free(p); }
}
