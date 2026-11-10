// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
#![cfg(feature = "registered-memory")]
use bytes::Bytes;
use denc::types::PgT;
use opwire::MOSDOpReply;
use rustyrados::*;

fn request() -> ReadIntoRequest {
    ReadIntoRequest {
        read: ReadRequest {
            target: Target {
                pool: 7,
                object: b"owned-read".to_vec(),
                namespace: vec![],
                locator: vec![],
            },
            offset: 10,
            length: 16,
        },
        buffer: vec![0xa5; 48],
        buffer_offset: 7,
        policy: ReadIntoPolicy::AllowStaging,
    }
}

fn route(session: u64) -> ReadRoute {
    ReadRoute {
        osd: 2,
        base_pool: 7,
        direct_read: false,
        session,
        pg: PgT { pool: 7, seed: 4 },
        hash: 55,
        epoch: 9,
        features: 0,
        generation: 1,
        pool: PoolRoute::Replicated,
    }
}

fn reply(dispatch: &ReadDispatch, data: &'static [u8]) -> MOSDOpReply {
    let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
    let mut extent = reply.ops[0].extent();
    extent.length = data.len() as u64;
    reply.ops[0].set_extent(extent);
    reply.ops[0].outdata = Bytes::from_static(data);
    reply.user_version = 123;
    reply
}

fn consume(q: &mut ReadQueue) -> ReadCompletion {
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    out[0].take().unwrap()
}

#[test]
fn short_and_eof_reads_return_original_allocation_and_exact_initialized_extent() {
    for data in [&b"short"[..], &b""[..]] {
        let mut q = ReadQueue::new(1, 64, 0).unwrap();
        let request = request();
        let pointer = request.buffer.as_ptr();
        let token = q.submit_read_into(request).unwrap();
        let dispatch = q.dispatch(token, route(3)).unwrap();
        assert!(q.reply(token, 2, 3, reply(&dispatch, data)).unwrap());
        let done = consume(&mut q);
        assert_eq!(done.token, token);
        assert!(
            matches!(done.outcome, ReadOutcome::Remote {result: 0, op_result: 0, user_version: 123, ref data} if data.is_empty())
        );
        let output = done.read_into.unwrap();
        assert_eq!(output.data(), data);
        assert_eq!(output.initialized(), data.len());
        assert_eq!(output.buffer_offset(), 7);
        assert_eq!(output.delivery(), Some(ReadDeliveryPath::Staged));
        assert_eq!(&output.buffer()[..7], &[0xa5; 7]);
        assert!(output.buffer()[7 + data.len()..].iter().all(|&b| b == 0xa5));
        let original = output.into_buffer();
        assert_eq!(original.as_ptr(), pointer);
        assert_eq!(q.charged_bytes(), 0);
    }
}

#[test]
fn rejected_modes_bounds_and_admission_return_the_original_request() {
    for case in 0..6 {
        let mut q = ReadQueue::new(1, 8, 0).unwrap();
        let mut request = request();
        let expected = match case {
            0 => {
                request.policy = ReadIntoPolicy::DirectOnly;
                AdmissionError::UnsupportedOperation
            }
            1 => {
                request.buffer_offset = usize::MAX;
                AdmissionError::InvalidExtent
            }
            2 => {
                request.buffer_offset = 40;
                AdmissionError::InvalidExtent
            }
            3 => {
                request.read.length = 0;
                AdmissionError::InvalidExtent
            }
            4 => {
                request.read.target.object.clear();
                AdmissionError::InvalidTarget
            }
            _ => AdmissionError::NoCredit,
        };
        let pointer = request.buffer.as_ptr();
        let rejected = q.submit_read_into(request).unwrap_err();
        assert_eq!(rejected.reason, expected);
        assert_eq!(rejected.request.buffer.as_ptr(), pointer);
        assert_eq!(rejected.request.buffer, vec![0xa5; 48]);
        assert_eq!(q.outstanding(), 0);
    }
}

#[test]
fn cancel_deadline_and_remote_error_never_publish_staged_bytes() {
    for case in 0..4 {
        let mut q = ReadQueue::new(1, 64, 0).unwrap();
        let request = request();
        let pointer = request.buffer.as_ptr();
        let token = q.submit_read_into(request).unwrap();
        if case == 2 {
            q.set_deadline_us(token, 10, 10).unwrap();
        }
        let dispatch = if case != 0 {
            Some(q.dispatch(token, route(3)).unwrap())
        } else {
            None
        };
        match case {
            0 | 1 => q.cancel(token).unwrap(),
            2 => {
                assert!(q.expire_token_us(token, 10).unwrap());
            }
            _ => {
                let mut error = reply(dispatch.as_ref().unwrap(), b"");
                error.result = -2;
                assert!(q.reply(token, 2, 3, error).unwrap());
            }
        }
        if let Some(dispatch) = dispatch {
            assert_eq!(
                q.reply(token, 2, 3, reply(&dispatch, b"late")),
                Err(DriverError::Stale)
            );
        }
        let done = consume(&mut q);
        match case {
            0 => assert_eq!(done.outcome, ReadOutcome::CanceledUnsent),
            1 => assert_eq!(done.outcome, ReadOutcome::PossiblySent),
            2 => assert_eq!(
                done.outcome,
                ReadOutcome::Deadline {
                    possibly_sent: true
                }
            ),
            _ => assert!(matches!(
                done.outcome,
                ReadOutcome::Remote { result: -2, .. }
            )),
        }
        let output = done.read_into.unwrap();
        assert_eq!(output.initialized(), 0);
        assert_eq!(output.delivery(), None);
        assert_eq!(output.buffer(), &[0xa5; 48]);
        let buffer = output.into_buffer();
        assert_eq!(buffer.as_ptr(), pointer);
        assert_eq!(q.poll_into(&mut [None]), 0);
    }
}

#[test]
fn retry_preserves_destination_and_rejects_old_session_and_oversized_reply() {
    let mut q = ReadQueue::with_retry_limit(1, 64, 0, 2).unwrap();
    let request = request();
    let pointer = request.buffer.as_ptr();
    let token = q.submit_read_into(request).unwrap();
    let first = q.dispatch(token, route(3)).unwrap();
    let invalid = reply(&first, b"too long for read destination");
    assert_eq!(
        q.reply(token, 2, 3, invalid),
        Err(DriverError::InvalidReply)
    );
    assert!(q.is_pending(token));
    q.retry(token).unwrap();
    let next = q.dispatch(token, route(4)).unwrap();
    assert_eq!(
        q.reply(token, 2, 3, reply(&first, b"stale")),
        Err(DriverError::Stale)
    );
    assert!(q.reply(token, 2, 4, reply(&next, b"new")).unwrap());
    let output = consume(&mut q).read_into.unwrap();
    assert_eq!(output.data(), b"new");
    let buffer = output.into_buffer();
    assert_eq!(buffer.as_ptr(), pointer);
}
