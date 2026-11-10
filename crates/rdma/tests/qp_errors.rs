// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Exercise the actual shim transition bodies against a provider that returns errors without setting errno.
use std::process::Command;

fn function(source: &str, name: &str) -> String {
    let start = source.find(&format!("int {name}(")).unwrap();
    let open = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return source[start..=open + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function {name}")
}

#[test]
fn qp_transition_errors_do_not_depend_on_errno() {
    let shim = include_str!("../csrc/shim.c");
    let mut source = String::from(
        r#"
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#define IBV_QPS_RTR 1
#define IBV_QPS_RTS 2
#define IBV_QPS_ERR 3
#define IBV_QP_STATE 1
#define IBV_QP_AV 2
#define IBV_QP_PATH_MTU 4
#define IBV_QP_DEST_QPN 8
#define IBV_QP_RQ_PSN 16
#define IBV_QP_MAX_DEST_RD_ATOMIC 32
#define IBV_QP_MIN_RNR_TIMER 64
#define IBV_QP_TIMEOUT 128
#define IBV_QP_RETRY_CNT 256
#define IBV_QP_RNR_RETRY 512
#define IBV_QP_SQ_PSN 1024
#define IBV_QP_MAX_QP_RD_ATOMIC 2048
enum ibv_mtu { MTU = 5 };
struct rv_dev { int port; };
struct ibv_qp { int unused; };
struct ibv_qp_attr {
    int qp_state, path_mtu, dest_qp_num, rq_psn, max_dest_rd_atomic, min_rnr_timer;
    int timeout, retry_cnt, rnr_retry, sq_psn, max_rd_atomic;
    struct { int is_global, port_num, sl;
        struct { int sgid_index, hop_limit, traffic_class;
            struct { unsigned char raw[16]; } dgid;
        } grh;
    } ah_attr;
};
static int fail_state;
static int rv_gid_index(struct rv_dev *d) { (void)d; return 0; }
static int ibv_modify_qp(struct ibv_qp *q, struct ibv_qp_attr *a, int mask) {
    (void)q; (void)mask;
    return a->qp_state == fail_state ? EINVAL : 0;
}
"#,
    );
    source.push_str(&function(shim, "rv_qp_connect"));
    source.push_str(&function(shim, "rv_qp_err"));
    source.push_str(r#"
int main(void) {
    struct rv_dev dev = { .port = 1 };
    struct ibv_qp qp = {0};
    uint8_t gid[16] = {0};
    for (int stale = 0; stale < 2; stale++) {
        for (int state = IBV_QPS_RTR; state <= IBV_QPS_ERR; state++) {
            fail_state = state;
            errno = stale ? EIO : 0;
            int rtr = -1;
            int rc = state == IBV_QPS_ERR ? rv_qp_err(&qp) :
                rv_qp_connect(&dev, &qp, 1, gid, 1, 1, MTU, 14, 7, 6, 106, 0, 0, &rtr);
            if (rc != -EINVAL || (state != IBV_QPS_ERR && rtr != (state == IBV_QPS_RTS))) {
                fprintf(stderr, "state=%d stale=%d rc=%d rtr=%d\n", state, stale, rc, rtr);
                return 1;
            }
        }
    }
    fail_state = 0;
    errno = EIO;
    int rtr = 0;
    if (rv_qp_connect(&dev, &qp, 1, gid, 1, 1, MTU, 14, 7, 6, 106, 0, 0, &rtr) || rtr != 1 || rv_qp_err(&qp)) return 2;
    return 0;
}
"#);
    run(&source, "transitions");
}

fn run(source: &str, name: &str) {
    let dir = std::env::temp_dir().join(format!("rdma-qp-errors-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("transitions.c");
    let binary = dir.join("transitions");
    std::fs::write(&input, source).unwrap();
    let compiled = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn gid_query_errors_do_not_become_a_valid_gid_index() {
    let mut source = String::from(
        r#"
#include <stdint.h>
#include <errno.h>
#include <string.h>
#define IBV_GID_TYPE_ROCE_V2 2
struct rv_dev { void *ctx; int port, gid_idx; uint8_t gid[16]; };
struct ibv_gid_entry { int gid_type; struct { uint8_t raw[16]; } gid; };
struct ibv_port_attr { int gid_tbl_len; };
static int ibv_query_gid_ex(void *ctx, int port, uint32_t idx, struct ibv_gid_entry *e, int flags) {
    (void)ctx; (void)port; (void)idx; (void)e; (void)flags; return ENODEV;
}
static int ibv_query_port(void *ctx, int port, struct ibv_port_attr *attr) {
    (void)ctx; (void)port; (void)attr; return ENODEV;
}
"#,
    );
    source.push_str(&function(include_str!("../csrc/shim.c"), "rv_gid_index"));
    source.push_str(
        r#"
int main(void) {
    struct rv_dev dev = { .port = 1, .gid_idx = 3 };
    errno = 0;
    if (rv_gid_index(&dev) != -ENODEV) return 1;
    errno = EIO;
    if (rv_gid_index(&dev) != -ENODEV) return 2;
    return 0;
}
"#,
    );
    run(&source, "gid-query");
}
