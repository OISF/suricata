/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use nom7::bytes::streaming::{tag, take};
use nom7::number::streaming::{le_u16, le_u32, le_u64};
use nom7::IResult;

#[derive(Debug,PartialEq, Eq)]
pub struct Smb3TransformRecord<'a> {
    pub session_id: u64,
    pub enc_algo: u16,
    pub enc_data: &'a[u8],
}

pub fn parse_smb3_transform_record(i: &[u8]) -> IResult<&[u8], Smb3TransformRecord<'_>> {
    let (i, _) = tag(b"\xfdSMB")(i)?;
    let (i, _signature) = take(16_usize)(i)?;
    let (i, _nonce) = take(16_usize)(i)?;
    let (i, msg_size) = le_u32(i)?;
    let (i, _reserved) = le_u16(i)?;
    let (i, enc_algo) = le_u16(i)?;
    let (i, session_id) = le_u64(i)?;
    let (i, enc_data) = take(msg_size)(i)?;
    let record = Smb3TransformRecord {
        session_id,
        enc_algo,
        enc_data,
    };
    Ok((i, record))
}

#[cfg(test)]
mod tests {
    use super::*;
	#[test]
	fn test_parse_smb3_transform_record() {
        // https://raw.githubusercontent.com/bro/bro/master/testing/btest/Traces/smb/smb3.pcap
        let data = hex::decode("fd534d42188d39cea4b1e3f640aff5d0b1569852c0bd665516dbb4b499507f000000000069000000000001003d00009400480000d9f8a66572b40c621bea6f5922a412a8eb2e3cc2af9ce26a277e75898cb523b9eb49ef660a6a1a09368fadd6a58e893e08eb3b7c068bdb74b6cd38e9ed1a2559cefb2ebc2172fd86c08a1a636eb851f20bf53a242f4cfaf7ab44e77291073ad492d6297c3d3a67757c").unwrap();
        let result = parse_smb3_transform_record(&data).unwrap();
        let record: Smb3TransformRecord = result.1;
        assert_eq!(record.session_id, 79167320227901);
        assert_eq!(record.enc_algo, 1);
        assert_eq!(record.enc_data.len(), 105);
    }
}
