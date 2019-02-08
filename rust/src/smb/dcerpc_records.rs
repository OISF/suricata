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

use nom;
use nom::{rest, le_u8, be_u16, le_u16, le_u32, IResult, ErrorKind, Endianness};

#[derive(Debug,PartialEq)]
pub struct DceRpcResponseRecord<'a> {
    pub data: &'a[u8],
}

/// parse a packet type 'response' DCERPC record. Implemented
/// as function to be able to pass the fraglen in.
pub fn parse_dcerpc_response_record(i:&[u8], frag_len: u16 )
    -> IResult<&[u8], DceRpcResponseRecord>
{
    if frag_len < 24 {
        return Err(nom::Err::Error(error_position!(i,ErrorKind::Custom(128))));
    }
    do_parse!(i,
                take!(8)
            >>  data:take!(frag_len - 24)
            >> (DceRpcResponseRecord {
                    data:data,
               })
    )
}

#[derive(Debug,PartialEq)]
pub struct DceRpcRequestRecord<'a> {
    pub opnum: u16,
    pub data: &'a[u8],
}

/// parse a packet type 'request' DCERPC record. Implemented
/// as function to be able to pass the fraglen in.
pub fn parse_dcerpc_request_record(i:&[u8], frag_len: u16, little: bool)
    -> IResult<&[u8], DceRpcRequestRecord>
{
    if frag_len < 24 {
        return Err(nom::Err::Error(error_position!(i,ErrorKind::Custom(128))));
    }
    do_parse!(i,
                take!(6)
            >>  endian: value!(if little { Endianness::Little } else { Endianness::Big })
            >>  opnum: u16!(endian)
            >>  data:take!(frag_len - 24)
            >> (DceRpcRequestRecord {
                    opnum:opnum,
                    data:data,
               })
    )
}

#[derive(Debug,PartialEq)]
pub struct DceRpcBindIface<'a> {
    pub iface: &'a[u8],
    pub ver: u16,
    pub ver_min: u16,
}

named!(pub parse_dcerpc_bind_iface<DceRpcBindIface>,
    do_parse!(
            _ctx_id: le_u16
        >>  _num_trans_items: le_u8
        >>  take!(1) // reserved
        >>  interface: take!(16)
        >>  ver: le_u16
        >>  ver_min: le_u16
        >>  take!(20)
        >> (DceRpcBindIface {
                iface:interface,
                ver:ver,
                ver_min:ver_min,
            })
));

named!(pub parse_dcerpc_bind_iface_big<DceRpcBindIface>,
    do_parse!(
            _ctx_id: le_u16
        >>  _num_trans_items: le_u8
        >>  take!(1) // reserved
        >>  interface: take!(16)
        >>  ver_min: be_u16
        >>  ver: be_u16
        >>  take!(20)
        >> (DceRpcBindIface {
                iface:interface,
                ver:ver,
                ver_min:ver_min,
            })
));

#[derive(Debug,PartialEq)]
pub struct DceRpcBindRecord<'a> {
    pub num_ctx_items: u8,
    pub ifaces: Vec<DceRpcBindIface<'a>>,
}

named!(pub parse_dcerpc_bind_record<DceRpcBindRecord>,
    do_parse!(
            _max_xmit_frag: le_u16
        >>  _max_recv_frag: le_u16
        >>  _assoc_group: take!(4)
        >>  num_ctx_items: le_u8
        >>  take!(3) // reserved
        >>  ifaces: count!(parse_dcerpc_bind_iface, num_ctx_items as usize)
        >> (DceRpcBindRecord {
                num_ctx_items:num_ctx_items,
                ifaces:ifaces,
           })
));

named!(pub parse_dcerpc_bind_record_big<DceRpcBindRecord>,
    do_parse!(
            _max_xmit_frag: be_u16
        >>  _max_recv_frag: be_u16
        >>  _assoc_group: take!(4)
        >>  num_ctx_items: le_u8
        >>  take!(3) // reserved
        >>  ifaces: count!(parse_dcerpc_bind_iface_big, num_ctx_items as usize)
        >> (DceRpcBindRecord {
                num_ctx_items:num_ctx_items,
                ifaces:ifaces,
           })
));

#[derive(Debug,PartialEq)]
pub struct DceRpcBindAckResult<'a> {
    pub ack_result: u16,
    pub ack_reason: u16,
    pub transfer_syntax: &'a[u8],
    pub syntax_version: u32,
}

named!(pub parse_dcerpc_bindack_result<DceRpcBindAckResult>,
    do_parse!(
            ack_result: le_u16
        >>  ack_reason: le_u16
        >>  transfer_syntax: take!(16)
        >>  syntax_version: le_u32
        >> (DceRpcBindAckResult {
                ack_result:ack_result,
                ack_reason:ack_reason,
                transfer_syntax:transfer_syntax,
                syntax_version:syntax_version,
            })
));

#[derive(Debug,PartialEq)]
pub struct DceRpcBindAckRecord<'a> {
    pub num_results: u8,
    pub results: Vec<DceRpcBindAckResult<'a>>,
}

named!(pub parse_dcerpc_bindack_record<DceRpcBindAckRecord>,
    do_parse!(
            _max_xmit_frag: le_u16
        >>  _max_recv_frag: le_u16
        >>  _assoc_group: take!(4)
        >>  sec_addr_len: le_u16
        >>  take!(sec_addr_len)
        >>  cond!((sec_addr_len+2) % 4 != 0, take!(4 - (sec_addr_len+2) % 4))
        >>  num_results: le_u8
        >>  take!(3) // padding
        >>  results: count!(parse_dcerpc_bindack_result, num_results as usize)
        >> (DceRpcBindAckRecord {
                num_results:num_results,
                results:results,
           })
));

#[derive(Debug,PartialEq)]
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

named!(pub parse_dcerpc_record<DceRpcRecord>,
    do_parse!(
            version_major: le_u8
        >>  version_minor: le_u8
        >>  packet_type: le_u8
        >>  packet_flags: bits!(tuple!(
               take_bits!(u8, 6),
               take_bits!(u8, 1),   // last (1)
               take_bits!(u8, 1)))  // first (2)
        >>  data_rep: bits!(tuple!(
                take_bits!(u32, 3),
                take_bits!(u32, 1),     // endianess
                take_bits!(u32, 28)))
        >>  endian: value!(if data_rep.1 == 0 { Endianness::Big } else { Endianness::Little })
        >>  frag_len: u16!(endian)
        >>  _auth: u16!(endian)
        >>  call_id: u32!(endian)
        >>  data:rest
        >> (DceRpcRecord {
                version_major:version_major,
                version_minor:version_minor,
                packet_type:packet_type,
                first_frag:packet_flags.2==1,
                last_frag:packet_flags.1==1,
                frag_len: frag_len,
                little_endian:data_rep.1==1,
                call_id:call_id,
                data:data,
           })
));
