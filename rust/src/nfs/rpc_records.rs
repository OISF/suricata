/* Copyright (C) 2017-2022 Open Information Security Foundation
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

//! Nom parsers for RPCv2

use crate::common::nom7::bits;
use nom7::bits::streaming::take as take_bits;
use nom7::bytes::streaming::take;
use nom7::combinator::{cond, rest, verify};
use nom7::error::{make_error, ErrorKind};
use nom7::multi::length_data;
use nom7::number::streaming::be_u32;
use nom7::sequence::tuple;
use nom7::{Err, IResult};

pub const RPC_MAX_MACHINE_SIZE: u32 = 256; // Linux kernel defines 64.
pub const RPC_MAX_CREDS_SIZE: u32 = 4096; // Linux kernel defines 400.
pub const RPC_MAX_VERIFIER_SIZE: u32 = 4096; // Linux kernel defines 400.

#[derive(Debug, PartialEq, Eq)]
pub enum RpcRequestCreds<'a> {
    Unix(RpcRequestCredsUnix<'a>),
    GssApi(RpcRequestCredsGssApi<'a>),
    Unknown(&'a [u8]),
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcRequestCredsUnix<'a> {
    pub stamp: u32,
    pub machine_name_len: u32,
    pub machine_name_buf: &'a [u8],
    pub uid: u32,
    pub gid: u32,
    pub aux_gids: Option<Vec<u32>>,
    // list of gids
}

//named!(parse_rpc_creds_unix_aux_gids<Vec<u32>>,
//    many0!(be_u32)
//);

fn parse_rpc_request_creds_unix(i: &[u8]) -> IResult<&[u8], RpcRequestCreds<'_>> {
    let (i, stamp) = be_u32(i)?;
    let (i, machine_name_len) = verify(be_u32, |&size| size < RPC_MAX_MACHINE_SIZE)(i)?;
    let (i, machine_name_buf) = take(machine_name_len as usize)(i)?;
    let (i, uid) = be_u32(i)?;
    let (i, gid) = be_u32(i)?;
    // let (i, aux_gids) = parse_rpc_creds_unix_aux_gids(i)?;
    let creds = RpcRequestCreds::Unix(RpcRequestCredsUnix {
        stamp,
        machine_name_len,
        machine_name_buf,
        uid,
        gid,
        aux_gids: None,
    });
    Ok((i, creds))
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcRequestCredsGssApi<'a> {
    pub version: u32,
    pub procedure: u32,
    pub seq_num: u32,
    pub service: u32,

    pub ctx: &'a [u8],
}

fn parse_rpc_request_creds_gssapi(i: &[u8]) -> IResult<&[u8], RpcRequestCreds<'_>> {
    let (i, version) = be_u32(i)?;
    let (i, procedure) = be_u32(i)?;
    let (i, seq_num) = be_u32(i)?;
    let (i, service) = be_u32(i)?;
    let (i, ctx) = length_data(be_u32)(i)?;
    let creds = RpcRequestCreds::GssApi(RpcRequestCredsGssApi {
        version,
        procedure,
        seq_num,
        service,
        ctx,
    });
    Ok((i, creds))
}

fn parse_rpc_request_creds_unknown(i: &[u8]) -> IResult<&[u8], RpcRequestCreds<'_>> {
    Ok((&[], RpcRequestCreds::Unknown(i)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcGssApiIntegrity<'a> {
    pub seq_num: u32,
    pub data: &'a [u8],
}

// Parse the GSSAPI Integrity envelope to get to the
// data we care about.
pub fn parse_rpc_gssapi_integrity(i: &[u8]) -> IResult<&[u8], RpcGssApiIntegrity<'_>> {
    let (i, len) = verify(be_u32, |&size| size < RPC_MAX_CREDS_SIZE)(i)?;
    let (i, seq_num) = be_u32(i)?;
    let (i, data) = take(len as usize)(i)?;
    let res = RpcGssApiIntegrity { seq_num, data };
    Ok((i, res))
}

/// Outcome of locating the v4 compound to scan inside a possibly
/// RPCSEC_GSS integrity wrapped prog_data.
#[derive(Debug, PartialEq, Eq)]
pub enum GssCompoundScan<'a> {
    /// Scan this compound data (unwrapped, or no wrapper at all).
    Compound(&'a [u8]),
    /// The integrity envelope is not fully buffered yet; it declares less than
    /// RPC_MAX_CREDS_SIZE bytes, so the record completes before the scan is definitive.
    EnvelopeIncomplete,
    /// The claimed envelope length fails the bounds check: definitive malformed
    /// (the full record path rejects it the same way).
    EnvelopeMalformed,
    /// RPCSEC_GSS privacy (0, 3): the compound is encrypted, so there is
    /// nothing to scan either way; it is opaque, not malformed.
    Opaque,
}

/// `gss` is the request's RPCSEC_GSS credential combination (header on the
/// request side, xidmap on the response; None: non-GSS). Only (0, 2) is
/// unwrapped, (0, 3) is opaque; another GSS combination is definitive
/// malformed, never Incomplete
pub fn gss_compound_scan_data(gss: Option<(u32, u32)>, prog_data: &[u8]) -> GssCompoundScan<'_> {
    match gss {
        None => GssCompoundScan::Compound(prog_data),
        // rpc_gss_svc_none (RFC 2203): no integrity/privacy wrap
        Some((0, 1)) => GssCompoundScan::Compound(prog_data),
        Some((0, 2)) => match parse_rpc_gssapi_integrity(prog_data) {
            Ok((_rem, ref rec)) => GssCompoundScan::Compound(rec.data),
            Err(Err::Incomplete(_)) => GssCompoundScan::EnvelopeIncomplete,
            Err(_) => GssCompoundScan::EnvelopeMalformed,
        },
        // rpc_gss_svc_privacy: the payload is encrypted, in both directions
        Some((0, 3)) => GssCompoundScan::Opaque,
        Some(_) => GssCompoundScan::EnvelopeMalformed,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcPacketHeader {
    pub frag_is_last: bool,
    pub frag_len: u32,
    pub xid: u32,
    pub msgtype: u32,
}

fn parse_bits(i: &[u8]) -> IResult<&[u8], (u8, u32)> {
    bits(tuple((
        take_bits(1u8),   // is_last
        take_bits(31u32), // len
    )))(i)
}

pub fn parse_rpc_packet_header(i: &[u8]) -> IResult<&[u8], RpcPacketHeader> {
    let (i, fraghdr) = verify(parse_bits, |v: &(u8, u32)| v.1 >= 24)(i)?;
    let (i, xid) = be_u32(i)?;
    let (i, msgtype) = verify(be_u32, |&v| v <= 1)(i)?;
    let hdr = RpcPacketHeader {
        frag_is_last: fraghdr.0 == 1,
        frag_len: fraghdr.1,
        xid,
        msgtype,
    };
    Ok((i, hdr))
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcReplyPacket<'a> {
    pub hdr: RpcPacketHeader,

    pub verifier_flavor: u32,
    pub verifier_len: u32,
    pub verifier: Option<&'a [u8]>,

    pub reply_state: u32,
    pub accept_state: u32,

    pub prog_data_size: u32,
    pub prog_data: &'a [u8],
}

// top of request packet, just to get to procedure
#[derive(Debug, PartialEq, Eq)]
pub struct RpcRequestPacketPartial {
    pub hdr: RpcPacketHeader,

    pub rpcver: u32,
    pub program: u32,
    pub progver: u32,
    pub procedure: u32,
}

pub fn parse_rpc_request_partial(i: &[u8]) -> IResult<&[u8], RpcRequestPacketPartial> {
    let (i, hdr) = parse_rpc_packet_header(i)?;
    let (i, rpcver) = be_u32(i)?;
    let (i, program) = be_u32(i)?;
    let (i, progver) = be_u32(i)?;
    let (i, procedure) = be_u32(i)?;
    let req = RpcRequestPacketPartial {
        hdr,
        rpcver,
        program,
        progver,
        procedure,
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcPacket<'a> {
    pub hdr: RpcPacketHeader,

    pub rpcver: u32,
    pub program: u32,
    pub progver: u32,
    pub procedure: u32,

    pub creds_flavor: u32,
    pub creds_len: u32,
    pub creds: RpcRequestCreds<'a>,

    pub verifier_flavor: u32,
    pub verifier_len: u32,
    pub verifier: &'a [u8],

    pub prog_data_size: u32,
    pub prog_data: &'a [u8],
}

/// Parse request RPC record.
///
/// Can be called from 2 paths:
///  1. we have all data -> do full parsing
///  2. we have partial data (large records) -> allow partial prog_data parsing
///
/// Arguments:
/// * `complete`: do full parsing, including of `prog_data`
///
pub fn parse_rpc(start_i: &[u8], complete: bool) -> IResult<&[u8], RpcPacket<'_>> {
    let (i, hdr) = parse_rpc_packet_header(start_i)?;
    let rec_size = hdr.frag_len as usize + 4;

    let (i, rpcver) = be_u32(i)?;
    let (i, program) = be_u32(i)?;
    let (i, progver) = be_u32(i)?;
    let (i, procedure) = be_u32(i)?;

    let (i, creds_flavor) = be_u32(i)?;
    let (i, creds_len) = verify(be_u32, |&size| size < RPC_MAX_CREDS_SIZE)(i)?;
    let (i, creds_buf) = take(creds_len as usize)(i)?;
    let (_, creds) = match creds_flavor {
        1 => parse_rpc_request_creds_unix(creds_buf)?,
        6 => parse_rpc_request_creds_gssapi(creds_buf)?,
        _ => parse_rpc_request_creds_unknown(creds_buf)?,
    };

    let (i, verifier_flavor) = be_u32(i)?;
    let (i, verifier_len) = verify(be_u32, |&size| size < RPC_MAX_VERIFIER_SIZE)(i)?;
    let (i, verifier) = take(verifier_len as usize)(i)?;

    let consumed = start_i.len() - i.len();
    if consumed > rec_size {
        return Err(Err::Error(make_error(i, ErrorKind::LengthValue)));
    }

    let data_size: u32 = (rec_size - consumed) as u32;
    let (i, prog_data) = if !complete {
        rest(i)?
    } else {
        take(data_size)(i)?
    };

    let packet = RpcPacket {
        hdr,

        rpcver,
        program,
        progver,
        procedure,

        creds_flavor,
        creds_len,
        creds,

        verifier_flavor,
        verifier_len,
        verifier,

        prog_data_size: data_size,
        prog_data,
    };
    Ok((i, packet))
}

/// Parse reply RPC record.
///
/// Can be called from 2 paths:
///  1. we have all data -> do full parsing
///  2. we have partial data (large records) -> allow partial prog_data parsing
///
/// Arguments:
/// * `complete`: do full parsing, including of `prog_data`
///
pub fn parse_rpc_reply(start_i: &[u8], complete: bool) -> IResult<&[u8], RpcReplyPacket<'_>> {
    let (i, hdr) = parse_rpc_packet_header(start_i)?;
    let rec_size = hdr.frag_len + 4;

    let (i, reply_state) = verify(be_u32, |&v| v <= 1)(i)?;

    let (i, verifier_flavor) = be_u32(i)?;
    let (i, verifier_len) = verify(be_u32, |&size| size < RPC_MAX_VERIFIER_SIZE)(i)?;
    let (i, verifier) = cond(verifier_len > 0, take(verifier_len as usize))(i)?;

    let (i, accept_state) = be_u32(i)?;

    let consumed = start_i.len() - i.len();
    if consumed > rec_size as usize {
        return Err(Err::Error(make_error(i, ErrorKind::LengthValue)));
    }

    let data_size: u32 = (rec_size as usize - consumed) as u32;
    let (i, prog_data) = if !complete {
        rest(i)?
    } else {
        take(data_size)(i)?
    };
    let packet = RpcReplyPacket {
        hdr,

        verifier_flavor,
        verifier_len,
        verifier,

        reply_state,
        accept_state,

        prog_data_size: data_size,
        prog_data,
    };
    Ok((i, packet))
}

/// Checked RFC 5531 record-marker header: the marker must claim the whole
/// datagram (the record ends at the datagram boundary, the marker excluded)
/// and carry the last-fragment bit; any mismatch -> None (unmarked).
fn parse_rpc_udp_record_marked_header(i: &[u8]) -> Option<RpcPacketHeader> {
    if i.len() < 8 {
        return None;
    }
    let (rem, fraghdr) = parse_bits(i).ok()?;
    if fraghdr.0 != 1 || fraghdr.1 < 24 || fraghdr.1 as usize != rem.len() {
        return None;
    }
    let (rem, xid) = be_u32::<_, ()>(rem).ok()?;
    let (_, msgtype) = verify(be_u32::<_, ()>, |&v| v <= 1)(rem).ok()?;
    Some(RpcPacketHeader {
        frag_is_last: fraghdr.0 == 1,
        frag_len: fraghdr.1,
        xid,
        msgtype,
    })
}

pub fn parse_rpc_udp_packet_header(i: &[u8]) -> IResult<&[u8], RpcPacketHeader> {
    // An ONC/UDP datagram is normally unmarked: the xid is the first word
    // (RFC 5531 defines record marking for byte-stream transports). Some
    // servers do mark them, so the marked layout is attempted second, only
    // when the unmarked one fails (for a marked datagram the word at offset 4
    // is the real xid, so it is not a valid msgtype). Trying marked first
    // would misparse an unmarked reply whose xid equals its own length.
    let (rem, xid) = be_u32(i)?;
    let msgtype: IResult<&[u8], u32> = verify(be_u32, |&v| v <= 1)(rem);
    match msgtype {
        Ok((rem, msgtype)) => {
            let hdr = RpcPacketHeader {
                frag_is_last: false,
                frag_len: 0,

                xid,
                msgtype,
            };
            Ok((rem, hdr))
        }
        Err(_) => match parse_rpc_udp_record_marked_header(i) {
            Some(hdr) => {
                // marker + xid + msgtype consumed; the record ends at the
                // datagram boundary (enforced by the helper)
                Ok((&i[12..], hdr))
            }
            None => Err(Err::Error(make_error(i, ErrorKind::Verify))),
        },
    }
}

pub fn parse_rpc_udp_request(i: &[u8]) -> IResult<&[u8], RpcPacket<'_>> {
    let (i, hdr) = parse_rpc_udp_packet_header(i)?;

    let (i, rpcver) = be_u32(i)?;
    let (i, program) = be_u32(i)?;
    let (i, progver) = be_u32(i)?;
    let (i, procedure) = be_u32(i)?;

    let (i, creds_flavor) = be_u32(i)?;
    let (i, creds_len) = verify(be_u32, |&size| size < RPC_MAX_CREDS_SIZE)(i)?;
    let (i, creds_buf) = take(creds_len as usize)(i)?;
    let (_, creds) = match creds_flavor {
        1 => parse_rpc_request_creds_unix(creds_buf)?,
        6 => parse_rpc_request_creds_gssapi(creds_buf)?,
        _ => parse_rpc_request_creds_unknown(creds_buf)?,
    };

    let (i, verifier_flavor) = be_u32(i)?;
    let (i, verifier_len) = verify(be_u32, |&size| size < RPC_MAX_VERIFIER_SIZE)(i)?;
    let (i, verifier) = take(verifier_len as usize)(i)?;

    let data_size: u32 = i.len() as u32;
    let (i, prog_data) = rest(i)?;
    let packet = RpcPacket {
        hdr,

        rpcver,
        program,
        progver,
        procedure,

        creds_flavor,
        creds_len,
        creds,

        verifier_flavor,
        verifier_len,
        verifier,

        prog_data_size: data_size,
        prog_data,
    };
    Ok((i, packet))
}

pub fn parse_rpc_udp_reply(i: &[u8]) -> IResult<&[u8], RpcReplyPacket<'_>> {
    let (i, hdr) = parse_rpc_udp_packet_header(i)?;

    let (i, verifier_flavor) = be_u32(i)?;
    let (i, verifier_len) = verify(be_u32, |&size| size < RPC_MAX_VERIFIER_SIZE)(i)?;
    let (i, verifier) = cond(verifier_len > 0, take(verifier_len as usize))(i)?;

    let (i, reply_state) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, accept_state) = be_u32(i)?;

    let data_size: u32 = i.len() as u32;
    let (i, prog_data) = rest(i)?;
    let packet = RpcReplyPacket {
        hdr,

        verifier_flavor,
        verifier_len,
        verifier,

        reply_state,
        accept_state,

        prog_data_size: data_size,
        prog_data,
    };
    Ok((i, packet))
}

#[cfg(test)]
mod tests {
    use crate::nfs::rpc_records::*;
    use nom7::Err::Incomplete;
    use nom7::Needed;

    #[test]
    fn test_partial_input_too_short() {
        let buf: &[u8] = &[
            0x80, 0x00, 0x00, 0x9c, // flags
            0x8e, 0x28, 0x02, 0x7e, // xid
        ];

        let r = parse_rpc_request_partial(buf);
        match r {
            Err(Incomplete(s)) => {
                assert_eq!(s, Needed::new(4));
            }
            _ => {
                panic!("failed {:?}", r);
            }
        }
    }
    #[test]
    fn test_partial_input_ok() {
        let buf: &[u8] = &[
            0x80, 0x00, 0x00, 0x9c, // flags
            0x8e, 0x28, 0x02, 0x7e, // xid
            0x00, 0x00, 0x00, 0x01, // msgtype
            0x00, 0x00, 0x00, 0x02, // rpcver
            0x00, 0x00, 0x00, 0x03, // program
            0x00, 0x00, 0x00, 0x04, // progver
            0x00, 0x00, 0x00, 0x05, // procedure
        ];
        let expected = RpcRequestPacketPartial {
            hdr: RpcPacketHeader {
                frag_is_last: true,
                frag_len: 156,
                xid: 2384986750,
                msgtype: 1,
            },
            rpcver: 2,
            program: 3,
            progver: 4,
            procedure: 5,
        };
        let r = parse_rpc_request_partial(buf);
        match r {
            Ok((rem, hdr)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(hdr, expected);
            }
            _ => {
                panic!("failed {:?}", r);
            }
        }
    }

    #[test]
    fn test_gss_compound_scan_data_unwrap() {
        // (0, 2): the envelope is unwrapped, the compound is what scans
        let compound: &[u8] = &[0x00, 0x00, 0x00, 0x01]; // a compound head
        let mut envelope: Vec<u8> = Vec::new();
        envelope.extend_from_slice(&((compound.len()) as u32).to_be_bytes()); // len
        envelope.extend_from_slice(&1u32.to_be_bytes()); // seqnum
        envelope.extend_from_slice(compound); // data
        let r = gss_compound_scan_data(Some((0, 2)), &envelope[..]);
        match r {
            GssCompoundScan::Compound(d) => assert_eq!(d, compound),
            _ => panic!("unexpected {:?}", r),
        }
    }

    #[test]
    fn test_gss_compound_scan_data_service_none() {
        // (0, 1): rpc_gss_svc_none (RFC 2203) -- the data is not
        // wrapped, the raw compound is scanned as-is
        let prog: &[u8] = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
        assert_eq!(
            gss_compound_scan_data(Some((0, 1)), prog),
            GssCompoundScan::Compound(prog)
        );
    }

    #[test]
    fn test_gss_compound_scan_data_privacy() {
        // rpc_gss_svc_privacy: encrypted, opaque to the scan
        let prog: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            gss_compound_scan_data(Some((0, 3)), prog),
            GssCompoundScan::Opaque
        );
    }

    #[test]
    fn test_gss_compound_scan_data_no_wrapper() {
        // non-GSS requests: prog_data is scanned as-is
        let prog: &[u8] = &[0x00, 0x00, 0x00, 0x02];
        assert_eq!(
            gss_compound_scan_data(None, prog),
            GssCompoundScan::Compound(prog)
        );
        // a GSS combination the full record path does not unwrap: definitive
        // malformed (the full path rejects it the same way), never Incomplete
        assert_eq!(
            gss_compound_scan_data(Some((1, 0)), prog),
            GssCompoundScan::EnvelopeMalformed
        );
    }

    #[test]
    fn test_gss_compound_scan_data_envelope_incomplete() {
        // the envelope claims 100 bytes, only 4 are buffered: bounded
        // incomplete, not a reject
        let mut envelope: Vec<u8> = Vec::new();
        envelope.extend_from_slice(&100u32.to_be_bytes());
        envelope.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            gss_compound_scan_data(Some((0, 2)), &envelope[..]),
            GssCompoundScan::EnvelopeIncomplete
        );
    }

    #[test]
    fn test_gss_compound_scan_data_envelope_malformed() {
        // the envelope claims more than the bounds check allows:
        // definitive malformed, as the full record path decides
        let mut envelope: Vec<u8> = Vec::new();
        envelope.extend_from_slice(&RPC_MAX_CREDS_SIZE.to_be_bytes());
        envelope.extend_from_slice(&1u32.to_be_bytes());
        envelope.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            gss_compound_scan_data(Some((0, 2)), &envelope[..]),
            GssCompoundScan::EnvelopeMalformed
        );
    }

    #[test]
    fn test_udp_header_unmarked_reply_claim_plausible_falls_back() {
        // xid 0x80000030: the implied claim (48) is plausible, but the
        // datagram is longer than the claim -> unmarked reply layout
        // (xid 0x80000030, msgtype 1).
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0x8000_0030u32.to_be_bytes()); // xid
        buf.extend_from_slice(&1u32.to_be_bytes()); // msgtype 1 (reply)
        buf.extend_from_slice(&0u32.to_be_bytes()); // reply_state OK
        buf.extend_from_slice(&0u32.to_be_bytes()); // verf flavor
        buf.extend_from_slice(&0u32.to_be_bytes()); // verf length
        buf.extend_from_slice(&0u32.to_be_bytes()); // accept_stat
        buf.extend_from_slice(&[0u8; 32]); // prog_data
        let r = parse_rpc_udp_packet_header(&buf);
        match r {
            Ok((rem, hdr)) => {
                assert_eq!(rem.len(), buf.len() - 8);
                assert!(!hdr.frag_is_last);
                assert_eq!(hdr.frag_len, 0);
                assert_eq!(hdr.xid, 0x8000_0030);
                assert_eq!(hdr.msgtype, 1);
            }
            _ => panic!("failed {:?}", r),
        }
    }

    #[test]
    fn test_udp_header_unmarked_request_claim_at_boundary_falls_back() {
        // xid 0x80000030: the implied claim (48) ends exactly at the
        // datagram boundary, so the marked attempt is tried; its
        // msgtype word is the unmarked rpcvers (2) -> mismatch, fall
        // back to the unmarked layout.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0x8000_0030u32.to_be_bytes()); // xid
        buf.extend_from_slice(&0u32.to_be_bytes()); // msgtype 0 (request)
        buf.extend_from_slice(&2u32.to_be_bytes()); // rpcvers
        buf.extend_from_slice(&100003u32.to_be_bytes()); // program
        buf.extend_from_slice(&3u32.to_be_bytes()); // progver
        buf.extend_from_slice(&1u32.to_be_bytes()); // procedure
        buf.extend_from_slice(&[0u8; 28]); // auth + prog_data
        assert_eq!(buf.len(), 52);
        let r = parse_rpc_udp_packet_header(&buf);
        match r {
            Ok((rem, hdr)) => {
                assert_eq!(rem.len(), 44);
                assert!(!hdr.frag_is_last);
                assert_eq!(hdr.xid, 0x8000_0030);
                assert_eq!(hdr.msgtype, 0);
            }
            _ => panic!("failed {:?}", r),
        }
    }

    #[test]
    fn test_udp_header_marked_claim_not_at_boundary_falls_back() {
        // claim 36 but 34 bytes follow the marker: the record does not
        // end at the datagram boundary -> unmarked layout.
        let buf: &[u8] = &[
            0x80, 0x00, 0x00, 0x24, // marker, claim 36
            0x00, 0x00, 0x00, 0x00, // msgtype 0 (unmarked)
            0x00, 0x00, 0x00, 0x02, // rpcvers
            0x00, 0x01, 0x86, 0xA3, // program 100003
            0x00, 0x00, 0x00, 0x03, // progver
            0x00, 0x00, 0x00, 0x01, // procedure
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];
        // the claim (36) does not end at the datagram boundary
        assert_eq!(buf.len() - 4, 48);
        let r = parse_rpc_udp_packet_header(buf);
        match r {
            Ok((rem, hdr)) => {
                assert_eq!(rem.len(), buf.len() - 8);
                assert!(!hdr.frag_is_last);
                assert_eq!(hdr.frag_len, 0);
                assert_eq!(hdr.xid, 0x8000_0024);
                assert_eq!(hdr.msgtype, 0);
            }
            _ => panic!("failed {:?}", r),
        }
    }

    #[test]
    fn test_udp_header_record_marked() {
        // RFC 5531 record marker: is_last=1, len=36 (fits the datagram),
        // then xid + msgtype at offset 4.
        let buf: &[u8] = &[
            0x80, 0x00, 0x00, 0x24, // marker, claim 36
            0x12, 0x34, 0x56, 0x78, // xid
            0x00, 0x00, 0x00, 0x00, // msgtype 0
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, // 28 bytes after xid+msgtype
        ];
        let r = parse_rpc_udp_packet_header(buf);
        match r {
            Ok((rem, hdr)) => {
                assert_eq!(rem.len(), 28);
                assert!(hdr.frag_is_last);
                assert_eq!(hdr.frag_len, 36);
                assert_eq!(hdr.xid, 0x12345678);
                assert_eq!(hdr.msgtype, 0);
            }
            _ => panic!("failed {:?}", r),
        }
    }

    #[test]
    fn test_udp_header_marked_claim_beyond_datagram_falls_back() {
        // Claim of 65535 cannot be met by a 16-byte datagram: this is an
        // unmarked datagram whose xid has the top bit set. The header
        // must be parsed unmarked (xid at offset 0).
        let buf: &[u8] = &[
            0x80, 0xFF, 0xFF, 0xFE, // xid with top bit set
            0x00, 0x00, 0x00, 0x00, // msgtype 0
            0x00, 0x00, 0x00, 0x02, // rpcver
            0x00, 0x01, 0x86, 0xA3, // program 100003
        ];
        let r = parse_rpc_udp_packet_header(buf);
        match r {
            Ok((rem, hdr)) => {
                assert_eq!(rem.len(), 8);
                assert!(!hdr.frag_is_last);
                assert_eq!(hdr.frag_len, 0);
                assert_eq!(hdr.xid, 0x80FFFFFE);
                assert_eq!(hdr.msgtype, 0);
            }
            _ => panic!("failed {:?}", r),
        }
    }

    #[test]
    fn test_udp_header_unmarked_small_claim_falls_back() {
        // xid 0x80000005: the 31-bit "claim" is 5, below the minimal
        // record size of 24 -> unmarked layout.
        let buf: &[u8] = &[
            0x80, 0x00, 0x00, 0x05, // xid
            0x00, 0x00, 0x00, 0x01, // msgtype 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let r = parse_rpc_udp_packet_header(buf);
        match r {
            Ok((rem, hdr)) => {
                assert_eq!(rem.len(), 16);
                assert!(!hdr.frag_is_last);
                assert_eq!(hdr.xid, 0x80000005);
                assert_eq!(hdr.msgtype, 1);
            }
            _ => panic!("failed {:?}", r),
        }
    }
}
