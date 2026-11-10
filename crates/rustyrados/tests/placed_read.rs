// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
#![cfg(feature = "registered-memory")]

use bytes::Bytes;
use denc::types::PgT;
use opwire::MOSDOpReply;
use rustyrados::{
    DriverError, PlacedReadReply, PoolRoute, ReadDispatch, ReadIntoPolicy, ReadIntoRequest,
    ReadOutcome, ReadQueue, ReadRequest, ReadRoute, ReplyAction, Target,
};

fn request() -> ReadRequest {
    ReadRequest {
        target: Target {
            pool: 7,
            object: b"placed-read".to_vec(),
            namespace: vec![],
            locator: vec![],
        },
        offset: 10,
        length: 16,
    }
}

fn route() -> ReadRoute {
    ReadRoute {
        osd: 2,
        base_pool: 7,
        direct_read: false,
        session: 3,
        pg: PgT { pool: 7, seed: 4 },
        hash: 55,
        epoch: 9,
        features: 0,
        generation: 1,
        pool: PoolRoute::Replicated,
    }
}

fn reply(dispatch: &ReadDispatch, initialized: usize) -> MOSDOpReply {
    let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
    let mut extent = reply.ops[0].extent();
    extent.length = initialized as u64;
    reply.ops[0].set_extent(extent);
    reply.user_version = 123;
    reply
}

fn placed(reply: MOSDOpReply) -> PlacedReadReply {
    PlacedReadReply::try_from(reply).unwrap()
}

#[test]
fn placed_short_and_eof_publish_length_without_an_inline_payload() {
    for initialized in [5, 0] {
        let mut queue = ReadQueue::new(1, 64, 0).unwrap();
        let token = queue.submit(request()).unwrap();
        let dispatch = queue.dispatch(token, route()).unwrap();
        // Model boundary: the transport supplies the authenticated reply only
        // after the matching window retired and its receipt was verified.
        let action = unsafe {
            queue.reply_placed_for_recovery(
                token,
                2,
                3,
                placed(reply(&dispatch, initialized)),
                initialized,
                true,
            )
        };
        assert_eq!(action, Ok(ReplyAction::Completed));
        let mut output = [None];
        assert_eq!(queue.poll_into(&mut output), 1);
        let completion = output[0].take().unwrap();
        assert_eq!(completion.token, token);
        assert!(matches!(completion.outcome, ReadOutcome::RemotePlaced {
            result: 0, op_result: 0, user_version: 123, initialized: count, verified: true
        } if count == initialized));
        assert_eq!(queue.charged_bytes(), 0);
    }
}

#[test]
fn placed_reply_rejects_wrong_extent_inline_bytes_and_stale_retry() {
    let mut queue = ReadQueue::new(1, 64, 0).unwrap();
    let token = queue.submit(request()).unwrap();
    let dispatch = queue.dispatch(token, route()).unwrap();
    let mut wrong_extent = reply(&dispatch, 5);
    let mut extent = wrong_extent.ops[0].extent();
    extent.length = 6;
    wrong_extent.ops[0].set_extent(extent);
    assert_eq!(
        unsafe { queue.reply_placed_for_recovery(token, 2, 3, placed(wrong_extent), 5, true) },
        Err(DriverError::InvalidReply)
    );
    let mut inline = reply(&dispatch, 5);
    inline.ops[0].outdata = Bytes::from_static(b"copy!");
    assert!(PlacedReadReply::try_from(inline).is_err());
    let mut stale = reply(&dispatch, 5);
    stale.retry_attempt += 1;
    assert_eq!(
        unsafe { queue.reply_placed_for_recovery(token, 2, 3, placed(stale), 5, true) },
        Err(DriverError::Stale)
    );
    assert_eq!(queue.poll_into(&mut [None]), 0);
    queue.cancel(token).unwrap();
}

#[test]
fn placed_remote_error_publishes_no_initialized_bytes() {
    let mut queue = ReadQueue::new(1, 64, 0).unwrap();
    let token = queue.submit(request()).unwrap();
    let dispatch = queue.dispatch(token, route()).unwrap();
    let mut error = reply(&dispatch, 0);
    error.result = -2;
    error.ops[0].rval = -2;
    assert_eq!(
        unsafe { queue.reply_placed_for_recovery(token, 2, 3, placed(error.clone()), 1, true) },
        Err(DriverError::InvalidReply)
    );
    assert_eq!(
        unsafe { queue.reply_placed_for_recovery(token, 2, 3, placed(error), 0, true) },
        Ok(ReplyAction::Completed)
    );
    let mut output = [None];
    assert_eq!(queue.poll_into(&mut output), 1);
    assert!(matches!(
        output[0].take().unwrap().outcome,
        ReadOutcome::RemotePlaced {
            result: -2,
            op_result: -2,
            initialized: 0,
            ..
        }
    ));
}

#[test]
fn staged_read_cannot_be_completed_as_a_registered_lease() {
    let mut queue = ReadQueue::new(1, 64, 0).unwrap();
    let token = queue
        .submit_read_into(ReadIntoRequest {
            read: request(),
            buffer: vec![0; 16],
            buffer_offset: 0,
            policy: ReadIntoPolicy::AllowStaging,
        })
        .unwrap();
    let dispatch = queue.dispatch(token, route()).unwrap();
    assert_eq!(
        unsafe {
            queue.reply_placed_for_recovery(token, 2, 3, placed(reply(&dispatch, 5)), 5, true)
        },
        Err(DriverError::InvalidReply)
    );
    queue.cancel(token).unwrap();
}

#[test]
fn placed_eagain_retains_the_logical_read_for_a_fenced_retry() {
    let mut queue = ReadQueue::with_retry_limit(1, 64, 0, 2).unwrap();
    let token = queue.submit(request()).unwrap();
    queue.set_deadline_us(token, 1_000, 1_000).unwrap();
    let first = queue.dispatch(token, route()).unwrap();
    let mut again = reply(&first, 0);
    again.result = -11;
    again.ops[0].rval = -11;
    assert_eq!(
        unsafe { queue.reply_placed_for_recovery(token, 2, 3, placed(again.clone()), 0, true) },
        Ok(ReplyAction::Recover)
    );
    assert_eq!(queue.poll_into(&mut [None]), 0);
    queue.retry(token).unwrap();
    let next = queue.dispatch(token, route()).unwrap();
    assert_eq!(next.message.retry_attempt, 1);
    assert_eq!(
        unsafe { queue.reply_placed_for_recovery(token, 2, 3, placed(again), 0, true) },
        Err(DriverError::Stale)
    );
    assert_eq!(
        unsafe { queue.reply_placed_for_recovery(token, 2, 3, placed(reply(&next, 7)), 7, true) },
        Ok(ReplyAction::Completed)
    );
    let mut output = [None];
    assert_eq!(queue.poll_into(&mut output), 1);
    assert!(matches!(
        output[0].take().unwrap().outcome,
        ReadOutcome::RemotePlaced {
            result: 0,
            initialized: 7,
            ..
        }
    ));
}
