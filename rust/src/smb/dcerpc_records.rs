/* Copyright (C) 2017 Open Information Security Foundation
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

use crate::common::nom7::bits;
use crate::smb::error::SmbError;
use nom7::bits::streaming::take as take_bits;
use nom7::bytes::streaming::take;
use nom7::combinator::{cond, rest};
use nom7::multi::count;
use nom7::number::Endianness;
use nom7::number::streaming::{be_u16, le_u8, le_u16, le_u32, u16, u32};
use nom7::sequence::tuple;
use nom7::{Err, IResult};

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcResponseRecord<'a> {
    pub data: &'a[u8],
}

/// parse a packet type 'response' DCERPC record. Implemented
/// as function to be able to pass the fraglen in.
pub fn parse_dcerpc_response_record(i:&[u8], frag_len: u16 )
    -> IResult<&[u8], DceRpcResponseRecord, SmbError>
{
    if frag_len < 24 {
        return Err(Err::Error(SmbError::RecordTooSmall));
    }
    let (i, _) = take(8_usize)(i)?;
    let (i, data) = take(frag_len - 24)(i)?;
    let record = DceRpcResponseRecord { data };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcRequestRecord<'a> {
    pub opnum: u16,
    pub context_id: u16,
    pub data: &'a[u8],
}

/// parse a packet type 'request' DCERPC record. Implemented
/// as function to be able to pass the fraglen in.
pub fn parse_dcerpc_request_record(i:&[u8], frag_len: u16, little: bool)
    -> IResult<&[u8], DceRpcRequestRecord, SmbError>
{
    if frag_len < 24 {
        return Err(Err::Error(SmbError::RecordTooSmall));
    }
    let (i, _) = take(4_usize)(i)?;
    let endian = if little { Endianness::Little } else { Endianness::Big };
    let (i, context_id) = u16(endian)(i)?;
    let (i, opnum) = u16(endian)(i)?;
    let (i, data) = take(frag_len - 24)(i)?;
    let record = DceRpcRequestRecord { opnum, context_id, data };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcBindIface<'a> {
    pub iface: &'a[u8],
    pub ver: u16,
    pub ver_min: u16,
}

pub fn parse_dcerpc_bind_iface(i: &[u8]) -> IResult<&[u8], DceRpcBindIface> {
    let (i, _ctx_id) = le_u16(i)?;
    let (i, _num_trans_items) = le_u8(i)?;
    let (i, _) = take(1_usize)(i)?; // reserved
    let (i, interface) = take(16_usize)(i)?;
    let (i, ver) = le_u16(i)?;
    let (i, ver_min) = le_u16(i)?;
    let (i, _) = take(20_usize)(i)?;
    let res = DceRpcBindIface {
        iface:interface,
        ver,
        ver_min,
    };
    Ok((i, res))
}

pub fn parse_dcerpc_bind_iface_big(i: &[u8]) -> IResult<&[u8], DceRpcBindIface> {
    let (i, _ctx_id) = le_u16(i)?;
    let (i, _num_trans_items) = le_u8(i)?;
    let (i, _) = take(1_usize)(i)?; // reserved
    let (i, interface) = take(16_usize)(i)?;
    let (i, ver_min) = be_u16(i)?;
    let (i, ver) = be_u16(i)?;
    let (i, _) = take(20_usize)(i)?;
    let res = DceRpcBindIface {
        iface:interface,
        ver,
        ver_min,
    };
    Ok((i, res))
}

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcBindRecord<'a> {
    pub num_ctx_items: u8,
    pub ifaces: Vec<DceRpcBindIface<'a>>,
}

pub fn parse_dcerpc_bind_record(i: &[u8]) -> IResult<&[u8], DceRpcBindRecord> {
    let (i, _max_xmit_frag) = le_u16(i)?;
    let (i, _max_recv_frag) = le_u16(i)?;
    let (i, _assoc_group) = take(4_usize)(i)?;
    let (i, num_ctx_items) = le_u8(i)?;
    let (i, _) = take(3_usize)(i)?; // reserved
    let (i, ifaces) = count(parse_dcerpc_bind_iface, num_ctx_items as usize)(i)?;
    let record = DceRpcBindRecord {
        num_ctx_items,
        ifaces,
    };
    Ok((i, record))
}

pub fn parse_dcerpc_bind_record_big(i: &[u8]) -> IResult<&[u8], DceRpcBindRecord> {
    let (i, _max_xmit_frag) = be_u16(i)?;
    let (i, _max_recv_frag) = be_u16(i)?;
    let (i, _assoc_group) = take(4_usize)(i)?;
    let (i, num_ctx_items) = le_u8(i)?;
    let (i, _) = take(3_usize)(i)?; // reserved
    let (i, ifaces) = count(parse_dcerpc_bind_iface_big, num_ctx_items as usize)(i)?;
    let record = DceRpcBindRecord {
        num_ctx_items,
        ifaces,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcBindAckResult<'a> {
    pub ack_result: u16,
    pub ack_reason: u16,
    pub transfer_syntax: &'a[u8],
    pub syntax_version: u32,
}

pub fn parse_dcerpc_bindack_result(i: &[u8]) -> IResult<&[u8], DceRpcBindAckResult> {
    let (i, ack_result) = le_u16(i)?;
    let (i, ack_reason) = le_u16(i)?;
    let (i, transfer_syntax) = take(16_usize)(i)?;
    let (i, syntax_version) = le_u32(i)?;
    let res = DceRpcBindAckResult {
        ack_result,
        ack_reason,
        transfer_syntax,
        syntax_version,
    };
    Ok((i, res))
}

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcBindAckRecord<'a> {
    pub num_results: u8,
    pub results: Vec<DceRpcBindAckResult<'a>>,
}

pub fn parse_dcerpc_bindack_record(i: &[u8]) -> IResult<&[u8], DceRpcBindAckRecord> {
    let (i, _max_xmit_frag) = le_u16(i)?;
    let (i, _max_recv_frag) = le_u16(i)?;
    let (i, _assoc_group) = take(4_usize)(i)?;
    let (i, sec_addr_len) = le_u16(i)?;
    let (i, _) = take(sec_addr_len)(i)?;
    let topad = sec_addr_len.wrapping_add(2) % 4;
    let (i, _) = cond(topad != 0, take(4 - topad))(i)?;
    let (i, num_results) = le_u8(i)?;
    let (i, _) = take(3_usize)(i)?; // padding
    let (i, results) = count(parse_dcerpc_bindack_result, num_results as usize)(i)?;
    let record = DceRpcBindAckRecord {
        num_results,
        results,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcRecord<'a> {
    pub version_major: u8,
    pub version_minor: u8,

    pub first_frag: bool,
    pub last_frag: bool,

    pub frag_len: u16,

    pub little_endian: bool,

    pub packet_type: u8,

    pub call_id: u32,
    pub data: &'a[u8],
}

fn parse_dcerpc_flags1(i:&[u8]) -> IResult<&[u8],(u8,u8,u8)> {
    bits(tuple((
        take_bits(6u8),
        take_bits(1u8),   // last (1)
        take_bits(1u8),
    )))(i)
}

fn parse_dcerpc_flags2(i:&[u8]) -> IResult<&[u8],(u32,u32,u32)> {
    bits(tuple((
       take_bits(3u32),
       take_bits(1u32),     // endianness
       take_bits(28u32),
    )))(i)
}

pub fn parse_dcerpc_record(i: &[u8]) -> IResult<&[u8], DceRpcRecord> {
    let (i, version_major) = le_u8(i)?;
    let (i, version_minor) = le_u8(i)?;
    let (i, packet_type) = le_u8(i)?;
    let (i, packet_flags) = parse_dcerpc_flags1(i)?;
    let (i, data_rep) = parse_dcerpc_flags2(i)?;
    let endian = if data_rep.1 == 0 { Endianness::Big } else { Endianness::Little };
    let (i, frag_len) = u16(endian)(i)?;
    let (i, _auth) = u16(endian)(i)?;
    let (i, call_id) = u32(endian)(i)?;
    let (i, data) = rest(i)?;
    let record = DceRpcRecord {
        version_major,
        version_minor,
        packet_type,
        first_frag: packet_flags.2 == 1,
        last_frag: packet_flags.1 == 1,
        frag_len,
        little_endian: data_rep.1 == 1,
        call_id,
        data,
    };
    Ok((i, record))
}
