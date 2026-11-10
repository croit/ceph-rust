// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Strict borrowed daemon-command results, RC181. Status is arbitrary bytes.
use denc::{Decoder, Error, Result};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandReplyView<'a> {
    pub result: i32,
    pub status: &'a [u8],
    pub data: &'a [u8],
}
impl<'a> CommandReplyView<'a> {
    pub fn decode(
        version: u16,
        compat: u16,
        front: &'a [u8],
        middle: &[u8],
        data: &'a [u8],
    ) -> Result<Self> {
        if version != 1 || compat > 1 || !middle.is_empty() {
            return Err(Error::BadValue("daemon command reply framing"));
        }
        let mut d = Decoder::new(front);
        let reply = Self {
            result: d.i32()?,
            status: d.bytes()?,
            data,
        };
        if !d.is_empty() {
            return Err(Error::TrailingBytes(d.remaining()));
        }
        Ok(reply)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_binary_status_data_signed_result_and_exact_front() {
        let front = [243, 255, 255, 255, 3, 0, 0, 0, 0, 255, 128];
        let data = [7, 0, 254];
        let reply = CommandReplyView::decode(1, 0, &front, &[], &data).unwrap();
        assert_eq!(
            reply,
            CommandReplyView {
                result: -13,
                status: &[0, 255, 128],
                data: &data
            }
        );
        assert_eq!(reply.status.as_ptr(), front[8..].as_ptr());
        for n in 0..front.len() {
            assert!(CommandReplyView::decode(1, 1, &front[..n], &[], &data).is_err());
        }
        for (v, c, m) in [
            (0, 0, &[][..]),
            (2, 1, &[][..]),
            (1, 2, &[][..]),
            (1, 1, &[0][..]),
        ] {
            assert!(CommandReplyView::decode(v, c, &front, m, &data).is_err());
        }
        let mut trailing = front.to_vec();
        trailing.push(0);
        assert!(CommandReplyView::decode(1, 1, &trailing, &[], &[]).is_err());
    }
}
