// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Pinned image-header notifications; journal notifications use another protocol.

/// Connected client instance and live header-watch identity, not auth user name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LockClientId {
    pub instance: u64,
    pub watch_cookie: u64,
}

/// One validated image-header notification. Ownership hints never grant a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderNotify {
    HeaderUpdate,
    Acquired(LockClientId),
    Released(LockClientId),
    Request { client: LockClientId, force: bool },
    Other(u32),
}

/// Invalid framing must not be mistaken for the empty legacy HeaderUpdate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyDecodeError {
    Truncated,
    Incompatible,
}

impl std::fmt::Display for NotifyDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated header notification"),
            Self::Incompatible => f.write_str("incompatible header notification"),
        }
    }
}
impl std::error::Error for NotifyDecodeError {}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], NotifyDecodeError> {
    let end = cursor.checked_add(N).ok_or(NotifyDecodeError::Truncated)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(NotifyDecodeError::Truncated)?;
    let value = value.try_into().map_err(|_| NotifyDecodeError::Truncated)?;
    *cursor = end;
    Ok(value)
}

/// Decode within the declared frame body, accepting compatible future fields
/// and outer trailing bytes. Pre-v2 messages have an invalid zero client ID;
/// pre-v3 requests default force=false. Ceph bool decoding accepts any nonzero
/// byte. Only an entirely empty input is the legacy HeaderUpdate.
pub fn decode_header_notify(bytes: &[u8]) -> Result<HeaderNotify, NotifyDecodeError> {
    if bytes.is_empty() {
        return Ok(HeaderNotify::HeaderUpdate);
    }
    let header = bytes.get(..6).ok_or(NotifyDecodeError::Truncated)?;
    if header[1] > 1 {
        return Err(NotifyDecodeError::Incompatible);
    }
    let version = header[0];
    let length = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
    let end = 6usize
        .checked_add(length)
        .ok_or(NotifyDecodeError::Truncated)?;
    let body = bytes.get(6..end).ok_or(NotifyDecodeError::Truncated)?;
    let mut cursor = 0;
    let operation = u32::from_le_bytes(take(body, &mut cursor)?);
    if operation == 3 {
        return Ok(HeaderNotify::HeaderUpdate);
    }
    if operation > 2 {
        return Ok(HeaderNotify::Other(operation));
    }
    let client = if version >= 2 {
        LockClientId {
            instance: u64::from_le_bytes(take(body, &mut cursor)?),
            watch_cookie: u64::from_le_bytes(take(body, &mut cursor)?),
        }
    } else {
        LockClientId::default()
    };
    Ok(match operation {
        0 => HeaderNotify::Acquired(client),
        1 => HeaderNotify::Released(client),
        _ => HeaderNotify::Request {
            client,
            force: version >= 3 && take::<1>(body, &mut cursor)?[0] != 0,
        },
    })
}

/// Pinned modern HeaderUpdate sender frame; an empty receive buffer is legacy.
pub const HEADER_UPDATE_NOTIFY: [u8; 10] = [7, 1, 4, 0, 0, 0, 3, 0, 0, 0];

fn encode_lock_hint(operation: u32, client: LockClientId) -> [u8; 26] {
    let mut frame = [0; 26];
    frame[..6].copy_from_slice(&[7, 1, 20, 0, 0, 0]);
    frame[6..10].copy_from_slice(&operation.to_le_bytes());
    frame[10..18].copy_from_slice(&client.instance.to_le_bytes());
    frame[18..].copy_from_slice(&client.watch_cookie.to_le_bytes());
    frame
}

/// Advertise completed ownership preparation, without invalidating metadata.
pub fn encode_lock_acquired(client: LockClientId) -> [u8; 26] {
    encode_lock_hint(0, client)
}

/// Advertise a completed managed release; peers still need actual class lock.
pub fn encode_lock_released(client: LockClientId) -> [u8; 26] {
    encode_lock_hint(1, client)
}

/// Request a cooperative managed handoff from the current owner. The current
/// requester protocol always sends force=false; administrative breaking is a
/// separate operation. An owner response is never itself a grant of ownership.
pub fn encode_lock_request(client: LockClientId) -> [u8; 27] {
    let mut request = [0; 27];
    request[..26].copy_from_slice(&encode_lock_hint(2, client));
    request[2..6].copy_from_slice(&21u32.to_le_bytes());
    request
}

/// Invalid or absent ownership response in a completed RADOS notify aggregate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockOwnerReplyError {
    /// The outer ACK map or missed-watch vector was truncated or malformed.
    MalformedAggregate,
    /// No current watch supplied a nonempty owner response.
    MissingOwner,
    /// Distinct watches supplied more than one nonempty owner response.
    MultipleOwners,
    /// The selected nonempty owner response had invalid framing.
    MalformedResponse,
}
impl std::fmt::Display for LockOwnerReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MalformedAggregate => "malformed lock notify aggregate",
            Self::MissingOwner => "no lock owner response",
            Self::MultipleOwners => "multiple lock owner responses",
            Self::MalformedResponse => "malformed lock owner response",
        })
    }
}
impl std::error::Error for LockOwnerReplyError {}

/// Malformed outer ACK map or missed-watch vector, before reply selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyAggregateError;
impl std::fmt::Display for NotifyAggregateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed notify reply aggregate")
    }
}
impl std::error::Error for NotifyAggregateError {}

/// Quiesce notify failure. An application result, including a negative one,
/// is returned in Ok; it must not be confused with a retryable provider timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuiesceReplyError {
    Provider(i32),
    MalformedAggregate,
    MalformedResponse,
}
impl std::fmt::Display for QuiesceReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provider(status) => write!(f, "quiesce notify provider returned {status}"),
            Self::MalformedAggregate => f.write_str("malformed quiesce notify aggregate"),
            Self::MalformedResponse => f.write_str("malformed quiesce response"),
        }
    }
}
impl std::error::Error for QuiesceReplyError {}

// Pinned Ceph Linux error numbers on this protocol, independent of host libc.
const NOTIFY_TIMED_OUT: i32 = -110;
const QUIESCE_NOT_SUPPORTED: i32 = -95;

/// Borrowed, validated notification aggregate. Decoding replaces duplicate ACK
/// identities and orders by instance/cookie, skipping compatible outer tails.
/// Keep the provider's buffer alive until this value is dropped.
///
/// Staged decoding allows the sender to report per-attempt progress AFTER outer
/// decoding but BEFORE status/inner-response classification. It does not imply
/// successful quiesce or grant image ownership.
#[derive(Debug)]
pub struct NotifyReply<'a> {
    provider_result: i32,
    replies: std::collections::BTreeMap<(u64, u64), &'a [u8]>,
}
impl<'a> NotifyReply<'a> {
    /// Decode for provider success or timeout. Other nonzero statuses are
    /// retained without inspecting bytes. A malformed outer aggregate overrides
    /// provider timeout; malformed inner responses are not interpreted here.
    pub fn decode(provider_result: i32, bytes: &'a [u8]) -> Result<Self, NotifyAggregateError> {
        let replies = if provider_result == 0 || provider_result == NOTIFY_TIMED_OUT {
            decode_notify_acks(bytes)?
        } else {
            std::collections::BTreeMap::new()
        };
        Ok(Self {
            provider_result,
            replies,
        })
    }

    /// Evaluate all watchers for a quiesce attempt. Empty/unsupported replies
    /// preserve the running result. The first negative or malformed response
    /// stops ordered evaluation; otherwise the last nonignored result wins,
    /// including positive results. This is not the single-owner selection rule.
    ///
    /// Provider timeout skips inner replies and is an error eligible for retry;
    /// an application timeout is Ok(-110) and must finish the attempt normally.
    pub fn quiesce_result(&self) -> Result<i32, QuiesceReplyError> {
        if self.provider_result != 0 {
            return Err(QuiesceReplyError::Provider(self.provider_result));
        }
        let mut result = 0;
        for response in self.replies.values().filter(|payload| !payload.is_empty()) {
            let next =
                decode_notify_response(response).ok_or(QuiesceReplyError::MalformedResponse)?;
            if next != QUIESCE_NOT_SUPPORTED {
                result = next;
                if result < 0 {
                    break;
                }
            }
        }
        Ok(result)
    }
}

/// Decode and select a quiesce result without an intervening progress callback.
/// Senders reporting attempt progress use NotifyReply's staged interface.
pub fn decode_quiesce_reply(provider_result: i32, bytes: &[u8]) -> Result<i32, QuiesceReplyError> {
    NotifyReply::decode(provider_result, bytes)
        .map_err(|_| QuiesceReplyError::MalformedAggregate)?
        .quiesce_result()
}

/// Select the sole nonempty owner response from a provider's ACK aggregate.
/// Call only for notify success or notify timeout: another provider error must
/// be returned before inspecting these bytes. A valid owner result overrides
/// notify timeout and unrelated missed watches. It still does not grant a lock.
///
/// Parsing borrows payloads and bounds declared counts before allocations.
/// Repeated ACK identities replace earlier payloads, including empty payloads;
/// duplicate missed identities and compatible trailing bytes are accepted.
pub fn decode_lock_owner_reply(bytes: &[u8]) -> Result<i32, LockOwnerReplyError> {
    let replies = decode_notify_acks(bytes).map_err(|_| LockOwnerReplyError::MalformedAggregate)?;
    let mut owners = replies.values().filter(|payload| !payload.is_empty());
    let response = owners.next().ok_or(LockOwnerReplyError::MissingOwner)?;
    if owners.next().is_some() {
        return Err(LockOwnerReplyError::MultipleOwners);
    }
    decode_notify_response(response).ok_or(LockOwnerReplyError::MalformedResponse)
}

fn decode_notify_acks(
    bytes: &[u8],
) -> Result<std::collections::BTreeMap<(u64, u64), &[u8]>, NotifyAggregateError> {
    use denc::Decoder;
    use std::collections::BTreeMap;
    let malformed = |_| NotifyAggregateError;
    let mut decoder = Decoder::new(bytes);
    let count = decoder.u32().map_err(malformed)? as usize;
    // Every ACK needs two u64s and a payload-length word; leave the final
    // missed-vector count. Never reserve from an unchecked wire count.
    if decoder.remaining() < 4 || count > (decoder.remaining() - 4) / 20 {
        return Err(NotifyAggregateError);
    }
    let mut replies = BTreeMap::new();
    for _ in 0..count {
        let key = (
            decoder.u64().map_err(malformed)?,
            decoder.u64().map_err(malformed)?,
        );
        replies.insert(key, decoder.bytes().map_err(malformed)?);
    }
    let missed = decoder.u32().map_err(malformed)? as usize;
    if missed > decoder.remaining() / 16 {
        return Err(NotifyAggregateError);
    }
    decoder.take(missed * 16).map_err(malformed)?;
    Ok(replies)
}

fn decode_notify_response(response: &[u8]) -> Option<i32> {
    let header = response.get(..6)?;
    if header[1] > 1 {
        return None;
    }
    let length = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
    let body = response
        .get(6..)
        .and_then(|tail| tail.get(..length))
        .and_then(|body| body.get(..4))?;
    Some(i32::from_le_bytes([body[0], body[1], body[2], body[3]]))
}

/// Encode the framed signed response used for HeaderUpdate and owner replies.
pub fn encode_notify_response(result: i32) -> [u8; 10] {
    let mut response = [1, 1, 4, 0, 0, 0, 0, 0, 0, 0];
    response[6..].copy_from_slice(&result.to_le_bytes());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(version: u8, operation: u32, payload: &[u8]) -> Vec<u8> {
        let mut value = vec![version, 1];
        value.extend_from_slice(&(4u32 + payload.len() as u32).to_le_bytes());
        value.extend_from_slice(&operation.to_le_bytes());
        value.extend_from_slice(payload);
        value
    }

    fn identity() -> Vec<u8> {
        let mut payload = 4u64.to_le_bytes().to_vec();
        payload.extend_from_slice(&7u64.to_le_bytes());
        payload
    }

    fn aggregate(acks: &[((u64, u64), &[u8])], missed: &[(u64, u64)]) -> Vec<u8> {
        let mut encoded = (acks.len() as u32).to_le_bytes().to_vec();
        for ((instance, cookie), payload) in acks {
            encoded.extend_from_slice(&instance.to_le_bytes());
            encoded.extend_from_slice(&cookie.to_le_bytes());
            encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            encoded.extend_from_slice(payload);
        }
        encoded.extend_from_slice(&(missed.len() as u32).to_le_bytes());
        for (instance, cookie) in missed {
            encoded.extend_from_slice(&instance.to_le_bytes());
            encoded.extend_from_slice(&cookie.to_le_bytes());
        }
        encoded
    }

    #[test]
    fn quiesce_combines_all_acks_and_preserves_last_nonignored_positive_result() {
        let zero = encode_notify_response(0);
        let seven = encode_notify_response(7);
        let eleven = encode_notify_response(11);
        let unsupported = encode_notify_response(QUIESCE_NOT_SUPPORTED);
        assert_eq!(decode_quiesce_reply(0, &aggregate(&[], &[])), Ok(0));
        assert_eq!(
            decode_quiesce_reply(0, &aggregate(&[((9, 1), &seven), ((1, 8), &eleven),], &[])),
            Ok(7)
        ); // key order, not wire arrival order
        assert_eq!(
            decode_quiesce_reply(0, &aggregate(&[((1, 2), &seven), ((1, 3), &zero),], &[])),
            Ok(0)
        );
        let mut bytes = aggregate(
            &[((1, 2), &seven), ((1, 3), &unsupported), ((1, 4), &[])],
            &[(99, 1), (99, 1)],
        );
        bytes.extend(b"compatible outer tail");
        assert_eq!(decode_quiesce_reply(0, &bytes), Ok(7));
    }

    #[test]
    fn quiesce_replaces_duplicates_and_stops_on_first_ordered_negative_or_bad_response() {
        let success = encode_notify_response(7);
        let failure = encode_notify_response(-5);
        let unsupported = encode_notify_response(QUIESCE_NOT_SUPPORTED);
        let malformed = [1];
        assert_eq!(
            decode_quiesce_reply(
                0,
                &aggregate(&[((1, 2), &malformed), ((1, 2), &success),], &[])
            ),
            Ok(7)
        );
        assert_eq!(
            decode_quiesce_reply(0, &aggregate(&[((1, 2), &success), ((1, 2), &[]),], &[])),
            Ok(0)
        );
        assert_eq!(
            decode_quiesce_reply(
                0,
                &aggregate(&[((9, 1), &malformed), ((1, 2), &failure),], &[])
            ),
            Ok(-5)
        );
        for earlier in [success, unsupported] {
            assert_eq!(
                decode_quiesce_reply(
                    0,
                    &aggregate(&[((1, 2), &earlier), ((9, 1), &malformed),], &[])
                ),
                Err(QuiesceReplyError::MalformedResponse)
            );
        }
        assert_eq!(
            decode_quiesce_reply(
                0,
                &aggregate(&[((1, 2), &malformed), ((9, 1), &failure),], &[])
            ),
            Err(QuiesceReplyError::MalformedResponse)
        );
    }

    #[test]
    fn quiesce_distinguishes_transport_timeout_outer_failure_and_application_timeout() {
        let malformed_inner = aggregate(&[((1, 2), &[1])], &[]);
        for status in [-5, -30, -108] {
            assert_eq!(
                decode_quiesce_reply(status, &[]),
                Err(QuiesceReplyError::Provider(status))
            );
            assert_eq!(
                decode_quiesce_reply(status, &malformed_inner),
                Err(QuiesceReplyError::Provider(status))
            );
        }
        assert_eq!(
            decode_quiesce_reply(NOTIFY_TIMED_OUT, &malformed_inner),
            Err(QuiesceReplyError::Provider(NOTIFY_TIMED_OUT))
        );
        assert_eq!(
            decode_quiesce_reply(NOTIFY_TIMED_OUT, &[]),
            Err(QuiesceReplyError::MalformedAggregate)
        );
        let application_timeout = encode_notify_response(NOTIFY_TIMED_OUT);
        let bytes = aggregate(&[((1, 2), &application_timeout)], &[]);
        assert_eq!(decode_quiesce_reply(0, &bytes), Ok(NOTIFY_TIMED_OUT));
        assert_eq!(
            decode_quiesce_reply(NOTIFY_TIMED_OUT, &bytes),
            Err(QuiesceReplyError::Provider(NOTIFY_TIMED_OUT))
        );
        let staged = NotifyReply::decode(0, &malformed_inner).unwrap();
        // Outer decoding succeeded. The caller can report attempt progress
        // before this inner error becomes the terminal quiesce result.
        assert_eq!(
            staged.quiesce_result(),
            Err(QuiesceReplyError::MalformedResponse)
        );
        assert_eq!(
            decode_quiesce_reply(0, &malformed_inner),
            Err(QuiesceReplyError::MalformedResponse)
        );
    }

    #[test]
    fn quiesce_frame_boundaries_and_outer_counts_are_checked_independently() {
        for version in [0, 1, 255] {
            for compat in [0, 1] {
                let response = [version, compat, 6, 0, 0, 0, 123, 0, 0, 0, 55, 66, 77];
                assert_eq!(
                    decode_quiesce_reply(0, &aggregate(&[((1, 2), &response)], &[])),
                    Ok(123)
                );
            }
        }
        for response in [
            vec![1, 2, 4, 0, 0, 0, 0, 0, 0, 0],
            vec![1, 1, 3, 0, 0, 0, 0, 0, 0, 0],
            vec![1, 1, 5, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert_eq!(
                decode_quiesce_reply(0, &aggregate(&[((1, 2), &response)], &[])),
                Err(QuiesceReplyError::MalformedResponse)
            );
        }
        let response = encode_notify_response(-5);
        let bytes = aggregate(&[((1, 2), &response)], &[(3, 4)]);
        for end in 0..bytes.len() {
            for status in [0, NOTIFY_TIMED_OUT] {
                assert_eq!(
                    decode_quiesce_reply(status, &bytes[..end]),
                    Err(QuiesceReplyError::MalformedAggregate)
                );
            }
        }
        assert_eq!(
            decode_quiesce_reply(0, &[255; 8]),
            Err(QuiesceReplyError::MalformedAggregate)
        );
    }

    #[test]
    fn request_uses_current_identity_and_never_sets_force() {
        let client = LockClientId {
            instance: 42,
            watch_cookie: 99,
        };
        assert_eq!(
            encode_lock_request(client),
            [
                7, 1, 21, 0, 0, 0, 2, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            decode_header_notify(&encode_lock_request(client)),
            Ok(HeaderNotify::Request {
                client,
                force: false
            })
        );
    }

    #[test]
    fn owner_reply_ignores_empty_acks_and_unrelated_duplicate_misses() {
        let refusal = [1, 1, 4, 0, 0, 0, 226, 255, 255, 255]; // signed -30
        let mut reply = aggregate(&[((9, 4), &[]), ((2, 8), &refusal)], &[(7, 3), (7, 3)]);
        reply.extend_from_slice(b"aggregate tail");
        assert_eq!(decode_lock_owner_reply(&reply), Ok(-30));
        assert_eq!(
            decode_lock_owner_reply(&aggregate(&[], &[])),
            Err(LockOwnerReplyError::MissingOwner)
        );
        assert_eq!(
            decode_lock_owner_reply(&aggregate(&[((1, 2), &[])], &[(1, 2)])),
            Err(LockOwnerReplyError::MissingOwner)
        );
    }

    #[test]
    fn owner_reply_duplicate_keys_replace_in_wire_order() {
        let success = [1, 1, 4, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            decode_lock_owner_reply(&aggregate(&[((2, 3), &success), ((2, 3), &[]),], &[])),
            Err(LockOwnerReplyError::MissingOwner)
        );
        assert_eq!(
            decode_lock_owner_reply(&aggregate(&[((2, 3), &[]), ((2, 3), &success),], &[])),
            Ok(0)
        );
        assert_eq!(
            decode_lock_owner_reply(&aggregate(&[((2, 3), &success), ((2, 4), &success),], &[])),
            Err(LockOwnerReplyError::MultipleOwners)
        );
    }

    #[test]
    fn owner_response_accepts_compatible_versions_and_declared_and_physical_tails() {
        for version in [0, 1, 255] {
            for compat in [0, 1] {
                let response = [version, compat, 6, 0, 0, 0, 123, 0, 0, 0, 55, 66, 77];
                assert_eq!(
                    decode_lock_owner_reply(&aggregate(&[((1, 2), &response)], &[])),
                    Ok(123)
                );
            }
        }
        for response in [
            vec![1, 2, 4, 0, 0, 0, 0, 0, 0, 0],
            vec![1, 1, 3, 0, 0, 0, 0, 0, 0, 0],
            vec![1, 1, 5, 0, 0, 0, 0, 0, 0, 0],
            vec![1],
        ] {
            assert_eq!(
                decode_lock_owner_reply(&aggregate(&[((1, 2), &response)], &[])),
                Err(LockOwnerReplyError::MalformedResponse)
            );
        }
    }

    #[test]
    fn truncated_outer_counts_and_payloads_fail_before_owner_selection() {
        let reply = aggregate(&[((1, 2), &[1, 1, 4, 0, 0, 0, 0, 0, 0, 0])], &[(3, 4)]);
        for length in 0..reply.len() {
            assert_eq!(
                decode_lock_owner_reply(&reply[..length]),
                Err(LockOwnerReplyError::MalformedAggregate),
                "prefix={length}"
            );
        }
        assert_eq!(
            decode_lock_owner_reply(&[255; 8]),
            Err(LockOwnerReplyError::MalformedAggregate)
        );
        let mut missed = 0u32.to_le_bytes().to_vec();
        missed.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode_lock_owner_reply(&missed),
            Err(LockOwnerReplyError::MalformedAggregate)
        );
    }

    #[test]
    fn sender_frames_distinguish_metadata_from_ownership_hints() {
        let client = LockClientId {
            instance: 4,
            watch_cookie: 7,
        };
        let acquired = encode_lock_acquired(client);
        assert_eq!(
            acquired,
            [
                7, 1, 20, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        let mut released = acquired;
        released[6] = 1;
        assert_eq!(encode_lock_released(client), released);
        assert_eq!(
            decode_header_notify(&acquired),
            Ok(HeaderNotify::Acquired(client))
        );
        assert_eq!(
            decode_header_notify(&released),
            Ok(HeaderNotify::Released(client))
        );
        assert_eq!(
            decode_header_notify(&HEADER_UPDATE_NOTIFY),
            Ok(HeaderNotify::HeaderUpdate)
        );
        let wide = LockClientId {
            instance: u64::MAX,
            watch_cookie: 1 << 63,
        };
        assert_eq!(
            decode_header_notify(&encode_lock_acquired(wide)),
            Ok(HeaderNotify::Acquired(wide))
        );
    }

    #[test]
    fn response_success_and_negative_result_use_the_signed_wire_frame() {
        assert_eq!(encode_notify_response(0), [1, 1, 4, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            encode_notify_response(-30),
            [1, 1, 4, 0, 0, 0, 0xe2, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn managed_events_keep_identity_and_do_not_become_metadata_updates() {
        let client = LockClientId {
            instance: 4,
            watch_cookie: 7,
        };
        assert_eq!(
            decode_header_notify(&frame(7, 0, &identity())),
            Ok(HeaderNotify::Acquired(client))
        );
        assert_eq!(
            decode_header_notify(&frame(7, 1, &identity())),
            Ok(HeaderNotify::Released(client))
        );
        let mut payload = identity();
        payload.push(2);
        assert_eq!(
            decode_header_notify(&frame(7, 2, &payload)),
            Ok(HeaderNotify::Request {
                client,
                force: true
            })
        );
        assert_eq!(decode_header_notify(&[]), Ok(HeaderNotify::HeaderUpdate));
        assert_eq!(
            decode_header_notify(&frame(7, 3, &[])),
            Ok(HeaderNotify::HeaderUpdate)
        );
        assert_eq!(
            decode_header_notify(&frame(7, 999, &[])),
            Ok(HeaderNotify::Other(999))
        );
    }

    #[test]
    fn older_versions_only_consume_fields_introduced_by_that_version() {
        for version in [0, 1] {
            assert_eq!(
                decode_header_notify(&frame(version, 2, &[1; 24])),
                Ok(HeaderNotify::Request {
                    client: LockClientId::default(),
                    force: false
                })
            );
        }
        let mut payload = identity();
        payload.push(1);
        assert_eq!(
            decode_header_notify(&frame(2, 2, &payload)),
            Ok(HeaderNotify::Request {
                client: LockClientId {
                    instance: 4,
                    watch_cookie: 7
                },
                force: false,
            })
        );
    }

    #[test]
    fn physical_trailing_bytes_cannot_rescue_a_short_declared_body() {
        let mut value = frame(7, 0, &[]);
        value.extend_from_slice(&identity());
        assert_eq!(
            decode_header_notify(&value),
            Err(NotifyDecodeError::Truncated)
        );
        let mut value = frame(7, 2, &identity());
        value.push(1);
        assert_eq!(
            decode_header_notify(&value),
            Err(NotifyDecodeError::Truncated)
        );
    }

    #[test]
    fn compatible_future_and_outer_trailing_fields_are_ignored() {
        let mut payload = identity();
        payload.extend_from_slice(&[0, 8, 9, 10]);
        let mut value = frame(250, 2, &payload);
        value.extend_from_slice(&[0xff; 10]);
        assert_eq!(
            decode_header_notify(&value),
            Ok(HeaderNotify::Request {
                client: LockClientId {
                    instance: 4,
                    watch_cookie: 7
                },
                force: false,
            })
        );
        value[1] = 2;
        assert_eq!(
            decode_header_notify(&value),
            Err(NotifyDecodeError::Incompatible)
        );
    }

    #[test]
    fn truncated_nonempty_messages_are_never_legacy_updates() {
        let mut payload = identity();
        payload.push(1);
        let value = frame(7, 2, &payload);
        for end in 1..value.len() {
            assert_eq!(
                decode_header_notify(&value[..end]),
                Err(NotifyDecodeError::Truncated)
            );
        }
        assert_eq!(
            decode_header_notify(&[7, 1, 255, 255, 255, 255]),
            Err(NotifyDecodeError::Truncated)
        );
    }
}
