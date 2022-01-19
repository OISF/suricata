/* Copyright (C) 2019 Open Information Security Foundation
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

// Author: Zach Kelly <zach.kelly@lmco.com>

//! RDP parser
//!
//! References:
//! * rdp-spec: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/>
//! * t.123-spec: <https://www.itu.int/rec/T-REC-T.123-200701-I/en>
//! * t.125-spec: <https://www.itu.int/rec/T-REC-T.125-199802-I/en>
//! * x.224-spec: <https://www.itu.int/rec/T-REC-X.224-199511-I/en>
//! * x.691-spec: <https://www.itu.int/rec/T-REC-X.691/en>

use crate::common::nom7::{bits, take_until_and_consume};
use crate::rdp::error::RdpError;
use crate::rdp::util::{le_slice_to_string, parse_per_length_determinant, utf7_slice_to_string};
use crate::rdp::windows;
use nom7::bits::streaming::take as take_bits;
use nom7::bytes::streaming::{tag, take};
use nom7::combinator::{map, map_opt, map_res, opt, verify};
use nom7::error::{make_error, ErrorKind};
use nom7::multi::length_data;
use nom7::number::streaming::{be_u16, be_u8, le_u16, le_u32, le_u8};
use nom7::sequence::tuple;
use nom7::{Err, IResult};

/// constrains dimension to a range, per spec
/// rdp-spec, section 2.2.1.3.2 Client Core Data
fn millimeters_to_opt(x: u32) -> Option<u32> {
    if x >= 10 && x <= 10_000 {
        Some(x)
    } else {
        None
    }
}

/// constrains desktop scale to a range, per spec
/// rdp-spec, section 2.2.1.3.2 Client Core Data
fn desktop_scale_to_opt(x: u32) -> Option<u32> {
    if x >= 100 && x <= 500 {
        Some(x)
    } else {
        None
    }
}

/// constrains device scale to a set of valid values, per spec
/// rdp-spec, section 2.2.1.3.2 Client Core Data
fn device_scale_to_opt(x: u32) -> Option<u32> {
    if x == 100 || x == 140 || x == 180 {
        Some(x)
    } else {
        None
    }
}

// ================

/// t.123-spec, section 8
#[derive(Clone, Debug, PartialEq)]
pub enum TpktVersion {
    T123 = 0x3,
}

/// t.123-spec, section 8
#[derive(Clone, Debug, PartialEq)]
pub struct T123Tpkt {
    pub child: T123TpktChild,
}

/// variants that a t.123 tpkt can hold
#[derive(Clone, Debug, PartialEq)]
pub enum T123TpktChild {
    X224ConnectionRequest(X224ConnectionRequest),
    X224ConnectionConfirm(X224ConnectionConfirm),
    Data(X223Data),
    Raw(Vec<u8>),
}

// ================

/// x.224-spec, sections 13.3.3, 13.4.3, 13.7.3
#[derive(Clone, Debug, PartialEq)]
pub enum X224Type {
    ConnectionConfirm = 0xd,
    ConnectionRequest = 0xe,
    Data = 0xf,
}

/// x.224-spec, section 13.3
// rdp-spec, section 2.2.1.1
#[derive(Clone, Debug, PartialEq)]
pub struct X224ConnectionRequest {
    pub cdt: u8,
    pub dst_ref: u16,
    pub src_ref: u16,
    pub class: u8,
    pub options: u8,
    pub cookie: Option<RdpCookie>,
    pub negotiation_request: Option<NegotiationRequest>,
    pub data: Vec<u8>,
}

/// rdp-spec, section 2.2.1.1.1
#[derive(Clone, Debug, PartialEq)]
pub struct RdpCookie {
    pub mstshash: String,
}

/// rdp-spec, sections 2.2.1.1.1, 2.2.1.2.1, 2.2.1.2.2
#[derive(Clone, Debug, PartialEq)]
pub enum X224ConnectionRequestType {
    NegotiationRequest = 0x1,
    NegotiationResponse = 0x2,
    NegotiationFailure = 0x3,
}

/// rdp-spec, section 2.2.1.1.1
#[derive(Clone, Debug, PartialEq)]
pub struct NegotiationRequest {
    pub flags: NegotiationRequestFlags,
    pub protocols: ProtocolFlags,
}

// rdp-spec, section 2.2.1.1.1
bitflags! {
    #[derive(Default)]
    pub struct NegotiationRequestFlags: u8 {
        const RESTRICTED_ADMIN_MODE_REQUIRED = 0x1;
        const REDIRECTED_AUTHENTICATION_MODE_REQUIRED = 0x2;
        const CORRELATION_INFO_PRESENT = 0x8;
    }
}

/// rdp-spec, section 2.2.1.1.1
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum Protocol {
    ProtocolRdp = 0x0,
    ProtocolSsl = 0x1,
    ProtocolHybrid = 0x2,
    ProtocolRdsTls = 0x4,
    ProtocolHybridEx = 0x8,
}

// rdp-spec, section 2.2.1.1.1
bitflags! {
    pub struct ProtocolFlags: u32 {
        const PROTOCOL_RDP = Protocol::ProtocolRdp as u32;
        const PROTOCOL_SSL = Protocol::ProtocolSsl as u32;
        const PROTOCOL_HYBRID = Protocol::ProtocolHybrid as u32;
        const PROTOCOL_RDSTLS = Protocol::ProtocolRdsTls as u32;
        const PROTOCOL_HYBRID_EX = Protocol::ProtocolHybridEx as u32;
    }
}

/// rdp-spec, section 2.2.1.2
/// x.224-spec, section 13.3
#[derive(Clone, Debug, PartialEq)]
pub struct X224ConnectionConfirm {
    pub cdt: u8,
    pub dst_ref: u16,
    pub src_ref: u16,
    pub class: u8,
    pub options: u8,
    pub negotiation_from_server: Option<NegotiationFromServer>,
}

/// variants of a server negotiation
#[derive(Clone, Debug, PartialEq)]
pub enum NegotiationFromServer {
    Response(NegotiationResponse),
    Failure(NegotiationFailure),
}

/// rdp-spec, section 2.2.1.1.1
#[derive(Clone, Debug, PartialEq)]
pub struct NegotiationResponse {
    pub flags: NegotiationResponseFlags,
    pub protocol: Protocol,
}

// rdp-spec, section 2.2.1.2.1
bitflags! {
    #[derive(Default)]
    pub struct NegotiationResponseFlags: u8 {
        const EXTENDED_CLIENT_DATA_SUPPORTED = 0x1;
        const DYNVC_GFX_PROTOCOL_SUPPORTED = 0x2;
        const NEGRSP_FLAG_RESERVED = 0x4;
        const RESTRICTED_ADMIN_MODE_SUPPORTED = 0x8;
        const REDIRECTED_AUTHENTICATION_MODE_SUPPORTED = 0x10;
    }
}

/// rdp-spec, section 2.2.1.1.1
#[derive(Clone, Debug, PartialEq)]
pub struct NegotiationFailure {
    pub code: NegotiationFailureCode,
}

/// rdp-spec, section 2.2.1.2.2
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum NegotiationFailureCode {
    SslRequiredByServer = 0x1,
    SslNotAllowedByServer = 0x2,
    SslCertNotOnServer = 0x3,
    InconsistentFlags = 0x4,
    HybridRequiredByServer = 0x5,
    SslWithUserAuthRequiredByServer = 0x6,
}

// ================

/// x224-spec, section 13.7
#[derive(Clone, Debug, PartialEq)]
pub struct X223Data {
    pub child: X223DataChild,
}

/// variants that an x.223 data message can hold
#[derive(Clone, Debug, PartialEq)]
pub enum X223DataChild {
    McsConnectRequest(McsConnectRequest),
    McsConnectResponse(McsConnectResponse),
    Raw(Vec<u8>),
}

/// t.125-spec, section 7, part 2
#[derive(Clone, Debug, PartialEq)]
pub enum T125Type {
    T125TypeMcsConnectRequest = 0x65,  // 101
    T125TypeMcsConnectResponse = 0x66, // 102
}

/// rdp-spec, section 2.2.1.3.2
#[derive(Clone, Debug, PartialEq)]
pub struct McsConnectRequest {
    pub children: Vec<McsConnectRequestChild>,
}

/// variants that an mcs connection message can hold
#[derive(Clone, Debug, PartialEq)]
pub enum McsConnectRequestChild {
    CsClientCore(CsClientCoreData),
    CsNet(CsNet),
    CsUnknown(CsUnknown),
}

/// rdp-spec, section 2.2.1.3.1
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum CsType {
    Core = 0xc001,
    Net = 0xc003,
}

/// rdp-spec, section 2.2.1.3.2
#[derive(Clone, Debug, PartialEq)]
pub struct CsClientCoreData {
    pub version: Option<RdpClientVersion>,
    pub desktop_width: u16,
    pub desktop_height: u16,
    pub color_depth: Option<ColorDepth>,
    pub sas_sequence: Option<SasSequence>,
    pub keyboard_layout: u32, // see windows::lcid_to_string
    pub client_build: windows::OperatingSystem,
    pub client_name: String,
    pub keyboard_type: Option<KeyboardType>,
    pub keyboard_subtype: u32,
    pub keyboard_function_key: u32,
    pub ime_file_name: String,
    // optional fields
    pub post_beta2_color_depth: Option<PostBeta2ColorDepth>,
    pub client_product_id: Option<u16>,
    pub serial_number: Option<u32>,
    pub high_color_depth: Option<HighColorDepth>,
    pub supported_color_depth: Option<SupportedColorDepth>,
    pub early_capability_flags: Option<EarlyCapabilityFlags>,
    pub client_dig_product_id: Option<String>,
    pub connection_hint: Option<ConnectionHint>,
    pub server_selected_protocol: Option<ProtocolFlags>,
    pub desktop_physical_width: Option<u32>,
    pub desktop_physical_height: Option<u32>,
    pub desktop_orientation: Option<DesktopOrientation>,
    pub desktop_scale_factor: Option<u32>,
    pub device_scale_factor: Option<u32>,
}

/// rdp-spec, section 2.2.1.3.2 Client Core Data
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
#[allow(non_camel_case_types)]
pub enum RdpClientVersion {
    V4 = 0x80001,
    V5_V8_1 = 0x80004,
    V10_0 = 0x80005,
    V10_1 = 0x80006,
    V10_2 = 0x80007,
    V10_3 = 0x80008,
    V10_4 = 0x80009,
    V10_5 = 0x8000a,
    V10_6 = 0x8000b,
    V10_7 = 0x8000c,
}

/// rdp-spec, section 2.2.1.3.2 Client Core Data
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum ColorDepth {
    RnsUdColor4Bpp = 0xca00,
    RnsUdColor8Bpp = 0xca01,
}

/// rdp-spec, section 2.2.1.3.2 Client Core Data
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum SasSequence {
    RnsUdSasDel = 0xaa03,
}

// for keyboard layout, see windows::lcid_to_string

/// rdp-spec, section 2.2.1.3.2 Client Core Data
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum KeyboardType {
    KbXt = 0x1,
    KbIco = 0x2,
    KbAt = 0x3,
    KbEnhanced = 0x4,
    Kb1050 = 0x5,
    Kb9140 = 0x6,
    KbJapanese = 0x7,
}

/// rdp-spec, section 2.2.1.3.2 Client Core Data
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum PostBeta2ColorDepth {
    RnsUdColorNotProvided = 0x0,
    RnsUdColor4Bpp = 0xca00,
    RnsUdColor8Bpp = 0xca01,
    RnsUdColor16Bpp555 = 0xca02,
    RnsUdColor16Bpp565 = 0xca03,
    RnsUdColor24Bpp = 0xca04,
}

/// rdp-spec, section 2.2.1.3.2 Client Core Data
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum HighColorDepth {
    HighColorNotProvided = 0x0,
    HighColor4Bpp = 0x4,
    HighColor8Bpp = 0x8,
    HighColor15Bpp = 0xf,
    HighColor16Bpp = 0x10,
    HighColor24Bpp = 0x18,
}

// rdp-spec, section 2.2.1.3.2 Client Core Data
bitflags! {
    #[derive(Default)]
    pub struct SupportedColorDepth: u16 {
        const RNS_UD_24_BPP_SUPPORT = 0x1;
        const RNS_UD_16_BPP_SUPPORT = 0x2;
        const RNS_UD_15_BPP_SUPPORT = 0x4;
        const RNS_UD_32_BPP_SUPPORT = 0x8;
    }
}

// rdp-spec, section 2.2.1.3.2 Client Core Data
bitflags! {
    #[derive(Default)]
    pub struct EarlyCapabilityFlags: u16 {
        const RNS_UD_CS_SUPPORT_ERRINFO_PDF = 0x1;
        const RNS_UD_CS_WANT_32BPP_SESSION = 0x2;
        const RNS_UD_CS_SUPPORT_STATUSINFO_PDU = 0x4;
        const RNS_UD_CS_STRONG_ASYMMETRIC_KEYS = 0x8;
        const RNS_UD_CS_UNUSED = 0x10;
        const RNS_UD_CS_VALID_CONNECTION_TYPE = 0x20;
        const RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU = 0x40;
        const RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT = 0x80;
        const RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL = 0x100;
        const RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE = 0x200;
        const RNS_UD_CS_SUPPORT_HEARTBEAT_PDU = 0x400;
    }
}

/// rdp-spec, section 2.2.1.3.2 Client Core Data, `connectionType`
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum ConnectionHint {
    ConnectionHintNotProvided = 0x0,
    ConnectionHintModem = 0x1,
    ConnectionHintBroadbandLow = 0x2,
    ConnectionHintSatellite = 0x3,
    ConnectionHintBroadbandHigh = 0x4,
    ConnectionHintWan = 0x5,
    ConnectionHintLan = 0x6,
    ConnectionHintAutoDetect = 0x7,
}

/// rdp-spec, section 2.2.1.3.2 Client Core Data
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq)]
pub enum DesktopOrientation {
    OrientationLandscape = 0,
    OrientationPortrait = 90,          // 0x5a
    OrientationLandscapeFlipped = 180, // 0xb4
    OrientationPortraitFlipped = 270,  // 0x10e
}

/// rdp-spec, section 2.2.1.3.4
#[derive(Clone, Debug, PartialEq)]
pub struct CsNet {
    pub channels: Vec<String>,
}

/// generic structure
/// cf. rdp-spec, section 2.2.1.3.4
#[derive(Clone, Debug, PartialEq)]
pub struct CsUnknown {
    pub typ: u16,
    pub data: Vec<u8>,
}

/// rdp-spec, section 2.2.1.4
#[derive(Clone, Debug, PartialEq)]
pub struct McsConnectResponse {}

// ==================

/// parser for t.123 and children
/// t.123-spec, section 8
pub fn parse_t123_tpkt(input: &[u8]) -> IResult<&[u8], T123Tpkt, RdpError> {
    let (i1, _version) = verify(be_u8, |&x| x == TpktVersion::T123 as u8)(input)?;
    let (i2, _reserved) = be_u8(i1)?;
    // less u8, u8, u16
    let (i3, sz) = map_opt(be_u16, |x: u16| x.checked_sub(4))(i2)?;
    let (i4, data) = take(sz)(i3)?;

    let opt1: Option<T123TpktChild> = {
        match opt(parse_x224_connection_request_class_0)(data) {
            Ok((_remainder, opt)) => opt.map(T123TpktChild::X224ConnectionRequest),
            Err(e) => return Err(e),
        }
    };

    let opt2: Option<T123TpktChild> = match opt1 {
        Some(x) => Some(x),
        None => match opt(parse_x224_connection_confirm_class_0)(data) {
            Ok((_remainder, opt)) => opt.map(T123TpktChild::X224ConnectionConfirm),
            Err(e) => return Err(e),
        },
    };

    let opt3: Option<T123TpktChild> = match opt2 {
        Some(x) => Some(x),
        None => match opt(parse_x223_data_class_0)(data) {
            Ok((_remainder, opt)) => opt.map(T123TpktChild::Data),
            Err(e) => return Err(e),
        },
    };
    let child: T123TpktChild = match opt3 {
        Some(x) => x,
        None => T123TpktChild::Raw(data.to_vec()),
    };

    return Ok((i4, T123Tpkt { child }));
}

fn take_4_4_bits(input: &[u8]) -> IResult<&[u8], (u8, u8), RdpError> {
    map(be_u8, |b| (b >> 4, b & 0xf))(input)
}

fn parse_class_options(i: &[u8]) -> IResult<&[u8], (u8, u8)> {
    bits(
        tuple((
            verify(take_bits(4u8), |&x| x <= 4),
            verify(take_bits(4u8), |&x| x <= 3)
        ))
    )(i)
}

/// rdp-spec, section 2.2.1.1
fn parse_x224_connection_request(input: &[u8]) -> IResult<&[u8], X224ConnectionRequest, RdpError> {
    let (i1, length) = verify(be_u8, |&x| x != 0xff)(input)?; // 0xff is reserved
    let (i2, cr_cdt) = take_4_4_bits(i1)?;
    if cr_cdt.0 != X224Type::ConnectionRequest as u8 {
        return Err(Err::Error(make_error(i1, ErrorKind::Verify)));
    }
    if !(cr_cdt.1 == 0 || cr_cdt.1 == 1) {
        return Err(Err::Error(make_error(i1, ErrorKind::Verify)));
    }
    let (i3, dst_ref) = verify(be_u16, |&x| x == 0)(i2)?;
    let (i4, src_ref) = be_u16(i3)?;
    let (i5, class_options) = parse_class_options(i4).map_err(Err::convert)?;
    // less cr_cdt (u8), dst_ref (u16), src_ref (u16), class_options (u8)
    if !(length >= 6) {
        return Err(Err::Error(make_error(i1, ErrorKind::Verify)));
    }
    let i6 = i5;
    let sz = length - 6;

    //
    // optionally find cookie and/or negotiation request
    //

    let (i7, data) = {
        if sz > 0 {
            take(sz)(i6)?
        } else {
            (i6, &[][..])
        }
    };

    let (j1, cookie) = {
        if data.len() > 0 {
            match opt(parse_rdp_cookie)(data) {
                Ok((remainder, opt)) => (remainder, opt),
                Err(e) => return Err(e),
            }
        } else {
            (&[][..], None)
        }
    };

    let (j2, negotiation_request) = {
        if j1.len() > 0 {
            match opt(parse_negotiation_request)(j1) {
                Ok((remainder, opt)) => (remainder, opt),
                Err(e) => return Err(e),
            }
        } else {
            (&[][..], None)
        }
    };

    return Ok((
        i7,
        X224ConnectionRequest {
            cdt: cr_cdt.1,
            dst_ref,
            src_ref,
            class: class_options.0,
            options: class_options.1,
            cookie,
            negotiation_request,
            data: j2.to_vec(),
        },
    ));
}

/// rdp-spec, section 2.2.1.1
/// "An X.224 Class 0 Connection Request TPDU, as specified in [X224] section 13.3."
fn parse_x224_connection_request_class_0(
    input: &[u8],
) -> IResult<&[u8], X224ConnectionRequest, RdpError> {
    let (i1, x224) = parse_x224_connection_request(input)?;
    if x224.class == 0 && x224.options == 0 {
        Ok((i1, x224))
    } else {
        Err(Err::Error(RdpError::NotX224Class0Error))
    }
}

// rdp-spec, section 2.2.1.1.1
fn parse_rdp_cookie(i: &[u8]) -> IResult<&[u8], RdpCookie, RdpError> {
    let (i, _key) = tag(b"Cookie: ")(i)?;
    let (i, _name) = tag(b"mstshash=")(i)?;
    let (i, bytes) = take_until_and_consume(b"\r\n")(i)?;
    // let (i, s) = map_res(value!(bytes), std::str::from_utf8)(i)?;
    let s = std::str::from_utf8(bytes).map_err(|_| Err::Error(make_error(bytes, ErrorKind::MapRes)))?;
    let cookie = RdpCookie{ mstshash: String::from(s) };
    Ok((i, cookie))
}

// rdp-spec, section 2.2.1.1.1
fn parse_negotiation_request(i: &[u8]) -> IResult<&[u8], NegotiationRequest, RdpError> {
    let (i, _typ) = verify(le_u8, |&x| x == X224ConnectionRequestType::NegotiationRequest as u8)(i)?;
    let (i, flags) = map_opt(le_u8, NegotiationRequestFlags::from_bits)(i)?;
    // u8, u8, u16, and u32 give _length of 8
    let (i, _length) = verify(le_u16, |&x| x == 8)(i)?;
    let (i, protocols) = map_opt(le_u32, ProtocolFlags::from_bits)(i)?;
    Ok((i, NegotiationRequest { flags, protocols }))
}

/// rdp-spec, section 2.2.1.2
/// x.224-spec, section 13.3
fn parse_x224_connection_confirm(input: &[u8]) -> IResult<&[u8], X224ConnectionConfirm, RdpError> {
    let (i1, length) = verify(be_u8, |&x| x != 0xff)(input)?; // 0xff is reserved
    let (i2, cr_cdt) = take_4_4_bits(i1)?;
    if cr_cdt.0 != X224Type::ConnectionConfirm as u8 {
        return Err(Err::Error(make_error(i1, ErrorKind::Verify)));
    }
    if !(cr_cdt.1 == 0 || cr_cdt.1 == 1) {
        return Err(Err::Error(make_error(i1, ErrorKind::Verify)));
    }
    let (i3, dst_ref) = verify(be_u16, |&x| x == 0)(i2)?;
    let (i4, src_ref) = be_u16(i3)?;
    let (i5, class_options) = parse_class_options(i4).map_err(Err::convert)?;

    // less cr_cdt (u8), dst_ref (u16), src_ref (u16), class_options (u8)
    if !(length >= 6) {
        return Err(Err::Error(make_error(i1, ErrorKind::Verify)));
    }
    let i6 = i5;
    let sz = length - 6;

    // a negotiation message from the server might be absent (sz == 0)
    let (i7, negotiation_from_server) = {
        if sz > 0 {
            let (i7, data) = take(sz)(i6)?;

            // it will be one of a response message or a failure message
            let opt1: Option<NegotiationFromServer> = match opt(parse_negotiation_response)(data) {
                Ok((_remainder, opt)) => opt.map(NegotiationFromServer::Response),
                Err(e) => return Err(e),
            };
            let opt2: Option<NegotiationFromServer> = match opt1 {
                Some(x) => Some(x),
                None => match opt(parse_negotiation_failure)(data) {
                    Ok((_remainder, opt)) => opt.map(NegotiationFromServer::Failure),
                    Err(e) => return Err(e),
                },
            };
            (i7, opt2)
        } else {
            (i6, None)
        }
    };

    return Ok((
        i7,
        X224ConnectionConfirm {
            cdt: cr_cdt.1,
            dst_ref,
            src_ref,
            class: class_options.0,
            options: class_options.1,
            negotiation_from_server,
        },
    ));
}

/// rdp-spec, section 2.2.1.2
/// "An X.224 Class 0 Connection Confirm TPDU, as specified in [X224] section 13.4."
fn parse_x224_connection_confirm_class_0(
    input: &[u8],
) -> IResult<&[u8], X224ConnectionConfirm, RdpError> {
    let (i1, x224) = parse_x224_connection_confirm(input)?;
    if x224.class == 0 && x224.options == 0 {
        Ok((i1, x224))
    } else {
        // x.224, but not a class 0 x.224 message
        Err(Err::Error(RdpError::NotX224Class0Error))
    }
}

// rdp-spec, section 2.2.1.1.1
fn parse_negotiation_response(i: &[u8]) -> IResult<&[u8], NegotiationResponse, RdpError> {
    let (i, _typ) = verify(le_u8, |&x| x == X224ConnectionRequestType::NegotiationResponse as u8)(i)?;
    let (i, flags) = map_opt(le_u8, NegotiationResponseFlags::from_bits)(i)?;
    // u8, u8, u16, and u32 give _length of 8
    let (i, _length) = verify(le_u16, |&x| x == 8)(i)?;
    let (i, protocol) = map_opt(le_u32, num::FromPrimitive::from_u32)(i)?;
    Ok((i, NegotiationResponse { flags, protocol }))
}

// rdp-spec, section 2.2.1.1.1
fn parse_negotiation_failure(i: &[u8]) -> IResult<&[u8], NegotiationFailure, RdpError> {
    let (i, _typ) = verify(le_u8, |&x| x == X224ConnectionRequestType::NegotiationFailure as u8)(i)?;
    let (i, _flags) = le_u8(i)?;
    // u8, u8, u16, and u32 give _length of 8
    let (i, _length) = verify(le_u16, |&x| x == 8)(i)?;
    let (i, code) = map_opt(le_u32, num::FromPrimitive::from_u32)(i)?;
    Ok((i, NegotiationFailure { code }))
}

/// x224-spec, section 13.7
fn parse_x223_data_class_0(input: &[u8]) -> IResult<&[u8], X223Data, RdpError> {
    fn parser(i: &[u8]) -> IResult<&[u8], (u8, u8, u8)> {
        bits(
            tuple((
                verify(take_bits(4u8), |&x| x == 0xf),
                verify(take_bits(3u8), |&x| x == 0),
                verify(take_bits(1u8), |&x| x == 0)
            ))
        )(i)
    }
    let (i1, _length) = verify(be_u8, |&x| x == 2)(input)?;
    let (i2, _dt_x_roa) = parser(i1).map_err(Err::convert)?;
    let (i3, _eot) = verify(be_u8, |&x| x == 0x80)(i2)?;

    //
    // optionally find exactly one of the child messages
    //

    let opt1: Option<X223DataChild> = match opt(parse_mcs_connect)(i3) {
        Ok((_remainder, opt)) => opt.map(X223DataChild::McsConnectRequest),
        Err(e) => return Err(e),
    };

    let opt2: Option<X223DataChild> = match opt1 {
        Some(x) => Some(x),
        None => match opt(parse_mcs_connect_response)(i3) {
            Ok((_remainder, opt)) => opt.map(X223DataChild::McsConnectResponse),
            Err(e) => return Err(e),
        },
    };

    let child: X223DataChild = match opt2 {
        Some(x) => x,
        None => X223DataChild::Raw(i3.to_vec()),
    };

    return Ok((&[], X223Data { child }));
}

/// rdp-spec, section 2.2.1.3.2
fn parse_mcs_connect(input: &[u8]) -> IResult<&[u8], McsConnectRequest, RdpError> {
    let (i1, _ber_type) = verify(
        le_u8,
        // BER: 0b01=application, 0b1=non-primitive, 0b11111
        |&x| x == 0x7f
    )(input)?;
    let (i2, _t125_type) = verify(le_u8, |&x| x
        == T125Type::T125TypeMcsConnectRequest as u8)(i1)?;

    // skip to, and consume, H.221 client-to-server key
    let (i3, _skipped) = take_until_and_consume(b"Duca")(i2)?;

    let (i4, data) = length_data(parse_per_length_determinant)(i3)?;
    let mut remainder: &[u8] = data;
    let mut children = Vec::new();

    // repeatedly attempt to parse optional CsClientCoreData, CsNet, and CsUnknown
    // until data buffer is exhausted
    loop {
        remainder = match opt(parse_cs_client_core_data)(remainder) {
            Ok((rem, o)) => match o {
                // found CsClientCoreData
                Some(core_data) => {
                    children.push(McsConnectRequestChild::CsClientCore(core_data));
                    rem
                }
                None => match opt(parse_cs_net)(remainder) {
                    // found CsNet
                    Ok((rem, o)) => match o {
                        Some(net) => {
                            children.push(McsConnectRequestChild::CsNet(net));
                            rem
                        }
                        None => {
                            match opt(parse_cs_unknown)(remainder) {
                                // was able to parse CsUnknown
                                Ok((rem, o)) => match o {
                                    Some(unknown) => {
                                        children.push(McsConnectRequestChild::CsUnknown(unknown));
                                        rem
                                    }
                                    None => {
                                        break;
                                    }
                                },
                                Err(Err::Incomplete(i)) => {
                                    return Err(Err::Incomplete(i))
                                }
                                Err(Err::Failure(_)) | Err(Err::Error(_)) => break,
                            }
                        }
                    },
                    Err(Err::Incomplete(i)) => return Err(Err::Incomplete(i)),
                    Err(Err::Failure(_)) | Err(Err::Error(_)) => break,
                },
            },
            Err(Err::Incomplete(i)) => return Err(Err::Incomplete(i)),
            Err(Err::Failure(_)) | Err(Err::Error(_)) => break,
        };
        if remainder.len() == 0 {
            break;
        }
    }

    return Ok((i4, McsConnectRequest { children }));
}

/// rdp-spec, section 2.2.1.3.2
fn parse_cs_client_core_data(input: &[u8]) -> IResult<&[u8], CsClientCoreData> {
    let (i1, _typ) = verify(le_u16, |&x| x == CsType::Core as u16)(input)?;
    // less u16, u16
    let (i2, sz) = map_opt(le_u16, |x: u16| x.checked_sub(4))(i1)?;
    let (i3, data) = take(sz)(i2)?;
    let (j1, version) = map(le_u32, num::FromPrimitive::from_u32)(data)?;
    let (j2, desktop_width) = le_u16(j1)?;
    let (j3, desktop_height) = le_u16(j2)?;
    let (j4, color_depth) = map(le_u16, num::FromPrimitive::from_u16)(j3)?;
    let (j5, sas_sequence) = map(le_u16, num::FromPrimitive::from_u16)(j4)?;
    let (j6, keyboard_layout) = le_u32(j5)?;
    let (j7, client_build) = map(le_u32, windows::build_number_to_os)(j6)?;
    let (j8, client_name) = map_res(take(32_usize), le_slice_to_string)(j7)?;
    let (j9, keyboard_type) = map(le_u32, num::FromPrimitive::from_u32)(j8)?;
    let (j10, keyboard_subtype) = le_u32(j9)?;
    let (j11, keyboard_function_key) = le_u32(j10)?;
    let (j12, ime_file_name) = map_res(take(64_usize), le_slice_to_string)(j11)?;

    //
    // optional fields below (but each requires the previous)
    //

    let (j13, post_beta2_color_depth) =
        match opt(map_opt(le_u16, num::FromPrimitive::from_u16))(j12) as IResult<&[u8], _> {
            Ok((rem, obj)) => (rem, obj),
            _ => (j12, None),
        };

    let (j14, client_product_id) = match post_beta2_color_depth {
        None => (j13, None),
        Some(_) => match opt(le_u16)(j13) as IResult<&[u8], _> {
            Ok((rem, obj)) => (rem, obj),
            _ => (j13, None),
        },
    };

    let (j15, serial_number) = match client_product_id {
        None => (j14, None),
        Some(_) => match opt(le_u32)(j14) as IResult<&[u8], _> {
            Ok((rem, obj)) => (rem, obj),
            _ => (j14, None),
        },
    };

    let (j16, high_color_depth) = match serial_number {
        None => (j15, None),
        Some(_) => {
            match opt(map_opt(le_u16, num::FromPrimitive::from_u16))(j15) as IResult<&[u8], _> {
                Ok((rem, obj)) => (rem, obj),
                _ => (j15, None),
            }
        }
    };

    let (j17, supported_color_depth) = match high_color_depth {
        None => (j16, None),
        Some(_) => {
            match opt(map_opt(le_u16, SupportedColorDepth::from_bits))(j16) as IResult<&[u8], _> {
                Ok((rem, obj)) => (rem, obj),
                _ => (j16, None),
            }
        }
    };

    let (j18, early_capability_flags) = match supported_color_depth {
        None => (j17, None),
        Some(_) => {
            match opt(map_opt(le_u16, EarlyCapabilityFlags::from_bits))(j17) as IResult<&[u8], _>
            {
                Ok((rem, obj)) => (rem, obj),
                _ => (j17, None),
            }
        }
    };

    let (j19, client_dig_product_id) = match early_capability_flags {
        None => (j18, None),
        Some(_) => {
            match opt(map_res(take(64usize), le_slice_to_string))(j18) as IResult<&[u8], _> {
                Ok((rem, obj)) => (rem, obj),
                _ => (j18, None),
            }
        }
    };

    let (j20, connection_hint) = match client_dig_product_id {
        None => (j19, None),
        Some(_) => {
            match opt(map_opt(le_u8, num::FromPrimitive::from_u8))(j19) as IResult<&[u8], _> {
                Ok((rem, obj)) => (rem, obj),
                _ => (j19, None),
            }
        }
    };

    let (j21, pad) = match connection_hint {
        None => (j20, None),
        Some(_) => match opt(take(1usize))(j20) as IResult<&[u8], _> {
            Ok((rem, obj)) => (rem, obj),
            _ => (j20, None),
        },
    };

    let (j22, server_selected_protocol) = match pad {
        None => (j21, None),
        Some(_) => {
            match opt(map_opt(le_u32, ProtocolFlags::from_bits))(j21) as IResult<&[u8], _> {
                Ok((rem, obj)) => (rem, obj),
                _ => (j21, None),
            }
        }
    };

    let (j23, desktop_physical_width) = match server_selected_protocol {
        None => (j22, None),
        Some(_) => match opt(map_opt(le_u32, millimeters_to_opt))(j22) as IResult<&[u8], _> {
            Ok((rem, obj)) => (rem, obj),
            _ => (j22, None),
        },
    };

    let (j24, desktop_physical_height) = match desktop_physical_width {
        None => (j23, None),
        Some(_) => match opt(map_opt(le_u32, millimeters_to_opt))(j23) as IResult<&[u8], _> {
            Ok((rem, obj)) => (rem, obj),
            _ => (j23, None),
        },
    };

    let (j25, desktop_orientation) = match desktop_physical_height {
        None => (j24, None),
        Some(_) => {
            match opt(map_opt(le_u16, num::FromPrimitive::from_u16))(j24) as IResult<&[u8], _> {
                Ok((rem, obj)) => (rem, obj),
                _ => (j24, None),
            }
        }
    };

    let (j26, desktop_scale_factor) = match desktop_orientation {
        None => (j25, None),
        Some(_) => match opt(map_opt(le_u32, desktop_scale_to_opt))(j25) as IResult<&[u8], _> {
            Ok((rem, obj)) => (rem, obj),
            _ => (j25, None),
        },
    };

    let (_j27, device_scale_factor) = match desktop_scale_factor {
        None => (j26, None),
        Some(_) => match opt(map_opt(le_u32, device_scale_to_opt))(j26) as IResult<&[u8], _> {
            Ok((rem, obj)) => (rem, obj),
            _ => (j26, None),
        },
    };

    return Ok((
        i3,
        CsClientCoreData {
            version,
            desktop_width,
            desktop_height,
            color_depth,
            sas_sequence,
            keyboard_layout,
            client_build,
            client_name,
            keyboard_type,
            keyboard_subtype,
            keyboard_function_key,
            ime_file_name,
            post_beta2_color_depth,
            client_product_id,
            serial_number,
            high_color_depth,
            supported_color_depth,
            early_capability_flags,
            client_dig_product_id,
            connection_hint,
            server_selected_protocol,
            desktop_physical_width,
            desktop_physical_height,
            desktop_orientation,
            desktop_scale_factor,
            device_scale_factor,
        },
    ));
}

/// rdp-spec, section 2.2.1.3.4
fn parse_cs_net(input: &[u8]) -> IResult<&[u8], CsNet> {
    let (i1, _typ) = verify(le_u16, |&x| x == CsType::Net as u16)(input)?;
    // less _typ (u16), this length indicator (u16), count (u32)
    let (i2, sz) = map_opt(le_u16, |x: u16| x.checked_sub(8))(i1)?;
    let (i3, count) = le_u32(i2)?;
    let (i4, data) = take(sz)(i3)?;

    let mut remainder: &[u8] = data;
    let mut channels = Vec::new();

    for _index in 0..count {
        // a channel name is 8 bytes, section 2.2.1.3.4.1
        let (j1, name) = map_res(take(8_usize), utf7_slice_to_string)(remainder)?;
        channels.push(name);
        // options (u32) are discarded for now
        let (j2, _options) = le_u32(j1)?;
        remainder = j2;
    }

    return Ok((i4, CsNet { channels }));
}

// generic CS structure parse
// cf. rdp-spec, section 2.2.1.3.4
fn parse_cs_unknown(i: &[u8]) -> IResult<&[u8], CsUnknown> {
    let (i, typ) = map_opt(le_u16, |x| {
        let opt: Option<CsType> = num::FromPrimitive::from_u16(x);
        match opt {
            // an unknown type must not be present in CsType
            Some(_) => None,
            None => Some(x),
        }
    })(i)?;
    // less u16, u16
    let (i, sz) = map_opt(le_u16, |x: u16| x.checked_sub(4))(i)?;
    let (i, data) = take(sz)(i)?;
    Ok((i, CsUnknown { typ, data: data.to_vec() }))
}

// rdp-spec, section 2.2.1.4
fn parse_mcs_connect_response(i: &[u8]) -> IResult<&[u8], McsConnectResponse, RdpError> {
    let (i, _ber_type) = verify(
        le_u8,
        // BER: 0b01=application, 0b1=non-primitive, 0b11111
        |&x| x == 0x7f)(i)?;
    let (i, _t125_type) = verify(le_u8, |&x| x == T125Type::T125TypeMcsConnectResponse as u8)(i)?;
    Ok((i, McsConnectResponse {}))
}

#[cfg(test)]
mod tests_cookie_21182 {
    use crate::rdp::parser::*;

    static BYTES: [u8; 37] = [
        0x03, 0x00, 0x00, 0x25, 0x20, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6f, 0x6f, 0x6b,
        0x69, 0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d, 0x75, 0x73,
        0x65, 0x72, 0x31, 0x32, 0x33, 0x0d, 0x0a,
    ];

    #[test]
    fn test_t123_x224_cookie() {
        let t123_bytes = &BYTES[..];
        let t123_tpkt: T123Tpkt = T123Tpkt {
            child: T123TpktChild::X224ConnectionRequest(X224ConnectionRequest {
                cdt: 0,
                dst_ref: 0,
                src_ref: 0,
                class: 0,
                options: 0,
                cookie: Some(RdpCookie {
                    mstshash: String::from("user123"),
                }),
                negotiation_request: None,
                data: Vec::new(),
            }),
        };
        assert_eq!(Ok((&[][..], t123_tpkt)), parse_t123_tpkt(t123_bytes));
    }
}

#[cfg(test)]
mod tests_negotiate_49350 {
    use crate::rdp::parser::*;

    static BYTES: [u8; 20] = [
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff,
    ];
    static TPKT_BEGIN: usize = 0;
    static X224_BEGIN: usize = TPKT_BEGIN + 4;
    static NEG_REQ_BEGIN: usize = X224_BEGIN + 7;
    static NEG_REQ_END: usize = NEG_REQ_BEGIN + 8;
    static X224_END: usize = NEG_REQ_END;
    static TPKT_END: usize = X224_END;
    static PADDING_BEGIN: usize = TPKT_END;

    #[test]
    fn test_t123_x224_negotiate() {
        let t123_bytes = &BYTES[TPKT_BEGIN..];
        let t123_tpkt: T123Tpkt = T123Tpkt {
            child: T123TpktChild::X224ConnectionRequest(X224ConnectionRequest {
                cdt: 0,
                dst_ref: 0,
                src_ref: 0,
                class: 0,
                options: 0,
                cookie: None,
                negotiation_request: Some(NegotiationRequest {
                    flags: NegotiationRequestFlags::empty(),
                    protocols: ProtocolFlags::PROTOCOL_RDP,
                }),
                data: Vec::new(),
            }),
        };
        assert_eq!(
            Ok((&BYTES[PADDING_BEGIN..][..], t123_tpkt)),
            parse_t123_tpkt(t123_bytes)
        )
    }
}

#[cfg(test)]
mod tests_core_49350 {
    use crate::rdp::parser::*;

    static BYTES: [u8; 429] = [
        0x03, 0x00, 0x01, 0xac, 0x02, 0xf0, 0x80, 0x7f, 0x65, 0x82, 0x01, 0xa0, 0x04, 0x01, 0x01,
        0x04, 0x01, 0x01, 0x01, 0x01, 0xff, 0x30, 0x19, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02,
        0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0xff,
        0x02, 0x01, 0x02, 0x30, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02,
        0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0x04, 0x20, 0x02, 0x01, 0x02,
        0x30, 0x1c, 0x02, 0x02, 0xff, 0xff, 0x02, 0x02, 0xfc, 0x17, 0x02, 0x02, 0xff, 0xff, 0x02,
        0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02,
        0x04, 0x82, 0x01, 0x3f, 0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x81, 0x36, 0x00, 0x08,
        0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 0x44, 0x75, 0x63, 0x61, 0x81, 0x28, 0x01, 0xc0, 0xd8,
        0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x05, 0x00, 0x03, 0x01, 0xca, 0x03, 0xaa, 0x09, 0x04,
        0x00, 0x00, 0x71, 0x17, 0x00, 0x00, 0x53, 0x00, 0x45, 0x00, 0x52, 0x00, 0x56, 0x00, 0x45,
        0x00, 0x52, 0x00, 0x2d, 0x00, 0x58, 0x00, 0x59, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xca, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x0f, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0xc0, 0x0c, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0xc0, 0x0c, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xc0, 0x38,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x72, 0x64, 0x70, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x80, 0x72, 0x64, 0x70, 0x73, 0x6e, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x64,
        0x72, 0x64, 0x79, 0x6e, 0x76, 0x63, 0x00, 0x00, 0x00, 0x80, 0xc0, 0x63, 0x6c, 0x69, 0x70,
        0x72, 0x64, 0x72, 0x00, 0x00, 0x00, 0xa0, 0xc0, 0xff,
    ];
    static TPKT_BEGIN: usize = 0;
    static X223_BEGIN: usize = TPKT_BEGIN + 4;
    static MCS_CONNECT_BEGIN: usize = X223_BEGIN + 3;
    static MCS_CONNECT_END: usize = MCS_CONNECT_BEGIN + 421;
    static X223_END: usize = MCS_CONNECT_END;
    static TPKT_END: usize = X223_END;
    static PADDING_BEGIN: usize = TPKT_END;

    #[test]
    fn test_t123_x223_connect_core() {
        let t123_bytes = &BYTES[TPKT_BEGIN..];
        let core_data = CsClientCoreData {
            version: Some(RdpClientVersion::V5_V8_1),
            desktop_width: 1280,
            desktop_height: 768,
            color_depth: Some(ColorDepth::RnsUdColor8Bpp),
            sas_sequence: Some(SasSequence::RnsUdSasDel),
            keyboard_layout: 0x409,
            client_build: windows::OperatingSystem {
                build: windows::Build::Vista_6001,
                suffix: windows::Suffix::Sp1,
            },
            client_name: String::from("SERVER-XYZ"),
            keyboard_type: Some(KeyboardType::KbEnhanced),
            keyboard_subtype: 0,
            keyboard_function_key: 12,
            ime_file_name: String::from(""),
            post_beta2_color_depth: Some(PostBeta2ColorDepth::RnsUdColor8Bpp),
            client_product_id: Some(1),
            serial_number: Some(0),
            high_color_depth: Some(HighColorDepth::HighColor8Bpp),
            supported_color_depth: Some(
                SupportedColorDepth::RNS_UD_15_BPP_SUPPORT
                    | SupportedColorDepth::RNS_UD_16_BPP_SUPPORT
                    | SupportedColorDepth::RNS_UD_24_BPP_SUPPORT
                    | SupportedColorDepth::RNS_UD_32_BPP_SUPPORT,
            ),
            early_capability_flags: Some(
                EarlyCapabilityFlags::RNS_UD_CS_SUPPORT_ERRINFO_PDF
                    | EarlyCapabilityFlags::RNS_UD_CS_STRONG_ASYMMETRIC_KEYS,
            ),
            client_dig_product_id: Some(String::from("")),
            connection_hint: Some(ConnectionHint::ConnectionHintNotProvided),
            server_selected_protocol: Some(ProtocolFlags::PROTOCOL_RDP),
            desktop_physical_width: None,
            desktop_physical_height: None,
            desktop_orientation: None,
            desktop_scale_factor: None,
            device_scale_factor: None,
        };
        let mut children = Vec::new();
        children.push(McsConnectRequestChild::CsClientCore(core_data));
        children.push(McsConnectRequestChild::CsUnknown(CsUnknown {
            typ: 0xc004,
            data: BYTES[0x160..0x160 + 0x8].to_vec(),
        }));
        children.push(McsConnectRequestChild::CsUnknown(CsUnknown {
            typ: 0xc002,
            data: BYTES[0x16c..0x16c + 0x8].to_vec(),
        }));
        let mut channels = Vec::new();
        channels.push(String::from("rdpdr"));
        channels.push(String::from("rdpsnd"));
        channels.push(String::from("drdynvc"));
        channels.push(String::from("cliprdr"));
        children.push(McsConnectRequestChild::CsNet(CsNet { channels }));
        let t123_tpkt: T123Tpkt = T123Tpkt {
            child: T123TpktChild::Data(X223Data {
                child: X223DataChild::McsConnectRequest(McsConnectRequest { children }),
            }),
        };
        assert_eq!(
            Ok((&BYTES[PADDING_BEGIN..][..], t123_tpkt)),
            parse_t123_tpkt(t123_bytes)
        );
    }
}

#[cfg(test)]
mod tests_x223_response_49350 {
    use crate::rdp::parser::*;

    // changed offset 9 from 0x65 to 0x66 so it is no longer an mcs connect
    static BYTES: [u8; 9] = [0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x7f, 0x66];

    #[test]
    fn test_x223_response() {
        let t123_bytes = &BYTES[..];
        assert_eq!(
            Ok((
                &[][..],
                T123Tpkt {
                    child: T123TpktChild::Data(X223Data {
                        child: X223DataChild::McsConnectResponse(McsConnectResponse {}),
                    })
                }
            )),
            parse_t123_tpkt(t123_bytes)
        )
    }
}

#[cfg(test)]
mod tests_t123_raw_49350 {
    use crate::rdp::parser::*;

    // changed offset 4 from 0x02 to 0x03 so it is no longer an X223 data object
    static BYTES: [u8; 9] = [0x03, 0x00, 0x00, 0x09, 0x03, 0xf0, 0x80, 0x7f, 0x65];

    #[test]
    fn test_t123_raw() {
        let t123_bytes = &BYTES[..];
        assert_eq!(
            Ok((
                &[][..],
                T123Tpkt {
                    child: T123TpktChild::Raw(BYTES[4..].to_vec())
                }
            )),
            parse_t123_tpkt(t123_bytes)
        )
    }
}

#[cfg(test)]
mod tests_x224_raw_49350 {
    use crate::rdp::parser::*;

    // changed offset 11 from 0x01 to 0x02 so it is not a known X224 payload type
    static BYTES: [u8; 19] = [
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_x224_raw() {
        let t123_bytes = &BYTES[..];
        assert_eq!(
            Ok((
                &[][..],
                T123Tpkt {
                    child: T123TpktChild::X224ConnectionRequest(X224ConnectionRequest {
                        cdt: 0,
                        dst_ref: 0,
                        src_ref: 0,
                        class: 0,
                        options: 0,
                        cookie: None,
                        negotiation_request: None,
                        data: BYTES[11..].to_vec(),
                    })
                }
            )),
            parse_t123_tpkt(t123_bytes)
        )
    }
}

#[cfg(test)]
mod tests_x223_raw_49350 {
    use crate::rdp::parser::*;

    // changed offset 9 from 0x65 to 0xff so it is no longer an mcs connect
    static BYTES: [u8; 9] = [0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x7f, 0xff];

    #[test]
    fn test_x223_raw() {
        let t123_bytes = &BYTES[..];
        assert_eq!(
            Ok((
                &[][..],
                T123Tpkt {
                    child: T123TpktChild::Data(X223Data {
                        child: X223DataChild::Raw(BYTES[7..].to_vec()),
                    })
                }
            )),
            parse_t123_tpkt(t123_bytes)
        )
    }
}

#[cfg(test)]
mod tests_negotiate_incomplete_49350 {
    use crate::rdp::parser::*;
    use nom7::Needed;

    static BYTES: [u8; 19] = [
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    static TPKT_BEGIN: usize = 0;
    static X224_BEGIN: usize = TPKT_BEGIN + 4;
    static NEG_REQ_BEGIN: usize = X224_BEGIN + 7;
    static NEG_REQ_END: usize = NEG_REQ_BEGIN + 8;
    static X224_END: usize = NEG_REQ_END;
    static TPKT_END: usize = X224_END;

    #[test]
    fn test_t123_incomplete() {
        let t123_bytes = &BYTES[TPKT_BEGIN..TPKT_END - 1];
        assert_eq!(
            // fails: map_opt!(i2, be_u16, |x: u16| x.checked_sub(4))?
            Err(Err::Incomplete(Needed::new(1))),
            parse_t123_tpkt(t123_bytes)
        )
    }

    #[test]
    fn test_x224_incomplete() {
        let x224_bytes = &BYTES[X224_BEGIN..X224_END - 1];
        assert_eq!(
            // fails: expr_opt!(i5, length.checked_sub(6))?
            // not counting a u8 length read, which was also successful
            Err(Err::Incomplete(Needed::new( 1))),
            parse_x224_connection_request_class_0(x224_bytes)
        )
    }

    #[test]
    fn test_negotiate_incomplete() {
        let neg_req_bytes = &BYTES[NEG_REQ_BEGIN..NEG_REQ_END - 1];
        assert_eq!(
            // fails: map_opt!(le_u32, num::FromPrimitive::from_u32)?
            Err(Err::Incomplete(Needed::new(1))),
            parse_negotiation_request(neg_req_bytes)
        )
    }
}

#[cfg(test)]
mod tests_core_incomplete_49350 {
    use crate::rdp::parser::*;
    use nom7::Needed;

    static BYTES: [u8; 428] = [
        0x03, 0x00, 0x01, 0xac, 0x02, 0xf0, 0x80, 0x7f, 0x65, 0x82, 0x01, 0xa0, 0x04, 0x01, 0x01,
        0x04, 0x01, 0x01, 0x01, 0x01, 0xff, 0x30, 0x19, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02,
        0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0xff,
        0x02, 0x01, 0x02, 0x30, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02,
        0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0x04, 0x20, 0x02, 0x01, 0x02,
        0x30, 0x1c, 0x02, 0x02, 0xff, 0xff, 0x02, 0x02, 0xfc, 0x17, 0x02, 0x02, 0xff, 0xff, 0x02,
        0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02,
        0x04, 0x82, 0x01, 0x3f, 0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x81, 0x36, 0x00, 0x08,
        0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 0x44, 0x75, 0x63, 0x61, 0x81, 0x28, 0x01, 0xc0, 0xd8,
        0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x05, 0x00, 0x03, 0x01, 0xca, 0x03, 0xaa, 0x09, 0x04,
        0x00, 0x00, 0x71, 0x17, 0x00, 0x00, 0x53, 0x00, 0x45, 0x00, 0x52, 0x00, 0x56, 0x00, 0x45,
        0x00, 0x52, 0x00, 0x2d, 0x00, 0x58, 0x00, 0x59, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xca, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x0f, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0xc0, 0x0c, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0xc0, 0x0c, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xc0, 0x38,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x72, 0x64, 0x70, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x80, 0x72, 0x64, 0x70, 0x73, 0x6e, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x64,
        0x72, 0x64, 0x79, 0x6e, 0x76, 0x63, 0x00, 0x00, 0x00, 0x80, 0xc0, 0x63, 0x6c, 0x69, 0x70,
        0x72, 0x64, 0x72, 0x00, 0x00, 0x00, 0xa0, 0xc0,
    ];
    static X223_BEGIN: usize = 4;
    static MCS_CONNECT_BEGIN: usize = X223_BEGIN + 3;
    static MCS_CONNECT_END: usize = MCS_CONNECT_BEGIN + 421;
    static _X223_END: usize = MCS_CONNECT_END;

    #[test]
    fn test_x223_incomplete() {
        let x223_bytes = &BYTES[X223_BEGIN..X223_BEGIN + 2];
        assert_eq!(
            // fails: verify!(i2, be_u8, |x| x == 0x80)?
            Err(Err::Incomplete(Needed::new(1))),
            parse_x223_data_class_0(x223_bytes)
        )
    }

    #[test]
    fn test_connect_incomplete() {
        let connect_bytes = &BYTES[MCS_CONNECT_BEGIN..MCS_CONNECT_END - 1];
        assert_eq!(
            // fails: length_data!(i3, parse_per_length_determinant)?
            // which reads the length (2) but not the full data (0x128)
            Err(Err::Incomplete(Needed::new(1))),
            parse_mcs_connect(connect_bytes)
        )
    }
}
