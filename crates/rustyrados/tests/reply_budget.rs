// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::types::{Hobject, PgT};
use rustyrados::*;
fn target() -> Target {
    Target {
        pool: 7,
        object: b"object".to_vec(),
        namespace: vec![],
        locator: vec![],
    }
}
fn route(session: u64) -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 7,
        osd: 0,
        session,
        pg: PgT { pool: 7, seed: 0 },
        hash: 0,
        epoch: session as u32,
        features: 0,
        generation: 1,
        pool: rustyrados::PoolRoute::Replicated,
    }
}
#[test]
fn declared_reply_data_is_captured_per_family_and_survives_refresh_and_retry() {
    let mut q = ObjectQueue::with_retry_limit(8, 100_000, 9, 2).unwrap();
    let read = q
        .submit(ReadRequest {
            target: target(),
            offset: 0,
            length: 4096,
        })
        .unwrap();
    let write = q
        .submit_write(WriteRequest {
            target: target(),
            operation: WriteOperation::WriteFull,
            payload: vec![1; 8192].into(),
        })
        .unwrap();
    let compound = q
        .submit_compound(CompoundRequest {
            target: target(),
            access: Access::Read,
            context: Default::default(),
            operations: vec![opwire::OsdOp::read(0, 64)],
            max_output_bytes: 128,
        })
        .unwrap();
    let notify = q
        .submit_control(ControlRequest {
            target: target(),
            operation: ControlOperation::Notify {
                cookie: 1,
                timeout_seconds: 1,
                payload: Bytes::from_static(b"payload"),
            },
        })
        .unwrap();
    let register = q
        .submit_control(ControlRequest {
            target: target(),
            operation: ControlOperation::Register {
                cookie: 2,
                timeout_seconds: 1,
            },
        })
        .unwrap();
    let list = q
        .submit_pg_list(PgListRequest::new(
            7,
            ListNamespace::All,
            0,
            1,
            Hobject::MIN(),
            1,
            1024,
        ))
        .unwrap();
    for (token, budget) in [
        (read, 4096),
        (write, 0),
        (compound, 128),
        (notify, 8),
        (register, 0),
        (list, 1024),
    ] {
        let mut dispatch = q.dispatch(token, route(1)).unwrap();
        assert_eq!(dispatch.max_reply_data(), budget);
        q.refresh_unaccepted(&mut dispatch, route(2)).unwrap();
        assert_eq!(dispatch.max_reply_data(), budget);
        assert_eq!(dispatch.message.retry_attempt, 0);
        if token == read {
            q.retry(token).unwrap();
            let retry = q.dispatch(token, route(3)).unwrap();
            assert_eq!(retry.max_reply_data(), 4096);
            assert_eq!(retry.message.retry_attempt, 1);
        }
    }
}
