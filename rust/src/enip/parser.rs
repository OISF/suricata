/* Copyright (C) 2023 Open Information Security Foundation
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

use nom7::bytes::streaming::take;
use nom7::error::{make_error, ErrorKind};
use nom7::multi::count;
use nom7::number::streaming::{le_u16, le_u32, le_u64, le_u8};
use nom7::IResult;

use super::constant::EnipCommand;
use crate::detect::EnumString;

#[derive(Clone, Debug, Default)]
pub struct EnipHeader {
    pub cmd: u16,
    pub pdulen: u16,
    pub session: u32,
    pub status: u32,
    pub context: u64,
    pub options: u32,
}

pub fn parse_enip_header(i: &[u8]) -> IResult<&[u8], EnipHeader> {
    let (i, cmd) = le_u16(i)?;
    let (i, pdulen) = le_u16(i)?;
    let (i, session) = le_u32(i)?;
    let (i, status) = le_u32(i)?;
    let (i, context) = le_u64(i)?;
    let (i, options) = le_u32(i)?;
    Ok((
        i,
        EnipHeader {
            cmd,
            pdulen,
            session,
            status,
            context,
            options,
        },
    ))
}

pub fn parse_enip_list_interfaces(i: &[u8]) -> IResult<&[u8], Vec<u16>> {
    let (i, nb) = le_u16(i)?;
    let (i, r) = count(le_u16, nb.into())(i)?;
    Ok((i, r))
}

#[derive(Clone, Debug, Default)]
pub enum EnipPayload {
    #[default]
    Unparsed,
    Cip(EnipCIP),
    ListIdentity(Vec<EnipCipItem>),
    ListServices(Vec<EnipCipItem>),
    ListInterfaces(Vec<EnipCipItem>),
    RegisterSession(EnipRegisterSession),
}

#[derive(Clone, Debug, Default)]
pub struct EnipRegisterSession {
    pub protocol_version: u16,
    pub options: u16,
}

#[derive(Clone, Debug, Default)]
pub struct EnipCipPathSegment {
    pub segment_type: u8,
    pub value: u32,
}

#[derive(Clone, Debug, Default)]
pub struct EnipCipRequestGetAttributeList {
    pub attr_list: Vec<u16>,
}

#[derive(Clone, Debug, Default)]
pub struct EnipCipRequestSetAttributeList {
    pub first_attr: Option<u16>,
}

#[derive(Clone, Debug, Default)]
pub struct EnipCipReqRespMultipleService {
    pub offset_from_cip: usize,
    pub offset_list: Vec<u16>,
    pub packet_list: Vec<CipData>,
    pub size_list: Vec<usize>,
}

#[derive(Clone, Debug, Default)]
pub enum EnipCipRequestPayload {
    #[default]
    Unhandled,
    GetAttributeList(EnipCipRequestGetAttributeList),
    SetAttributeList(EnipCipRequestSetAttributeList),
    Multiple(EnipCipReqRespMultipleService),
}

#[derive(Clone, Debug, Default)]
pub struct EnipCipRequest {
    pub path: Vec<EnipCipPathSegment>,
    pub payload: EnipCipRequestPayload,
}

#[derive(Clone, Debug, Default)]
pub enum EnipCipResponsePayload {
    #[default]
    Unhandled,
    Multiple(EnipCipReqRespMultipleService),
}

#[derive(Clone, Debug, Default)]
pub struct EnipCipResponse {
    pub status: u8,
    pub status_extended: Vec<u8>,
    pub payload: EnipCipResponsePayload,
}

#[derive(Clone, Debug, Default)]
pub enum CipDir {
    #[default]
    None,
    Request(EnipCipRequest),
    Response(EnipCipResponse),
}

#[derive(Clone, Debug, Default)]
pub struct CipData {
    pub service: u8,
    pub cipdir: CipDir,
}

pub fn cip_segment_type_string(p: u8) -> Option<&'static str> {
    match p >> 2 {
        8 => Some("class"),
        9 => Some("instance"),
        12 => Some("attribute"),
        _ => None,
    }
}

pub fn parse_cip_path_segment(i: &[u8]) -> IResult<&[u8], EnipCipPathSegment> {
    let (i, segment_type) = le_u8(i)?;
    if segment_type >> 5 != 1 {
        // we only handle logical segment
        return Err(nom7::Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, value) = match segment_type & 3 {
        0 => {
            let (i, v) = le_u8(i)?;
            Ok((i, v as u32))
        }
        1 => {
            let (i, _pad) = le_u8(i)?;
            let (i, v) = le_u16(i)?;
            Ok((i, v as u32))
        }
        2 => {
            let (i, _pad) = le_u8(i)?;
            le_u32(i)
        }
        // There may be more cases to handle
        _ => Err(nom7::Err::Error(make_error(i, ErrorKind::Switch))),
    }?;
    return Ok((
        i,
        EnipCipPathSegment {
            segment_type,
            value,
        },
    ));
}

pub fn parse_cip_path(i: &[u8]) -> IResult<&[u8], (Vec<EnipCipPathSegment>, usize)> {
    let (i, nb) = le_u8(i)?;
    let (i, data) = take(2 * (nb as usize))(i)?;
    let consumed = 1 + 2 * (nb as usize);
    let mut rem = data;
    let mut segments = Vec::new();
    while !rem.is_empty() {
        let (rem2, seg) = parse_cip_path_segment(rem)?;
        segments.push(seg);
        rem = rem2;
    }
    return Ok((i, (segments, consumed)));
}

pub const CIP_GET_ATTR_LIST: u8 = 3;
pub const CIP_SET_ATTR_LIST: u8 = 4;
pub const CIP_MULTIPLE_SERVICE: u8 = 0xa;

pub fn parse_cip_request_get_attr_list(i: &[u8]) -> IResult<&[u8], EnipCipRequestGetAttributeList> {
    let (i, nb) = le_u16(i)?;
    let (i, attr_list) = count(le_u16, nb.into())(i)?;
    Ok((i, EnipCipRequestGetAttributeList { attr_list }))
}

pub fn parse_cip_request_set_attr_list(i: &[u8]) -> IResult<&[u8], EnipCipRequestSetAttributeList> {
    let (i, nb) = le_u16(i)?;
    if nb > 0 {
        let (i, first_attr) = le_u16(i)?;
        // do not parse further because attribute data is class specific
        return Ok((
            i,
            EnipCipRequestSetAttributeList {
                first_attr: Some(first_attr),
            },
        ));
    }
    return Ok((i, EnipCipRequestSetAttributeList { first_attr: None }));
}

pub fn parse_cip_reqresp_multiple(
    i: &[u8], offset_from_cip: usize,
) -> IResult<&[u8], EnipCipReqRespMultipleService> {
    let start = i;
    let (i, nb) = le_u16(i)?;
    let (i, offset_list) = count(le_u16, nb.into())(i)?;
    let mut packet_list = Vec::new();
    let mut size_list = Vec::new();
    let mut rem = i;
    for j in 0..nb as usize {
        if (offset_list[j] as usize) < start.len() {
            let (rem2, packet) = parse_cip_multi(&start[offset_list[j] as usize..])?;
            packet_list.push(packet);
            size_list.push(start[offset_list[j] as usize..].len() - rem2.len());
            rem = rem2;
        } else {
            return Err(nom7::Err::Error(make_error(i, ErrorKind::LengthValue)));
        }
    }
    Ok((
        rem,
        EnipCipReqRespMultipleService {
            offset_from_cip,
            offset_list,
            packet_list,
            size_list,
        },
    ))
}

pub fn parse_cip_request(i: &[u8], service: u8, multi: bool) -> IResult<&[u8], EnipCipRequest> {
    let (i, (path, offset_from_cip)) = parse_cip_path(i)?;
    let (i, payload) = match service {
        CIP_GET_ATTR_LIST => {
            let (i, ga) = parse_cip_request_get_attr_list(i)?;
            Ok((i, EnipCipRequestPayload::GetAttributeList(ga)))
        }
        CIP_SET_ATTR_LIST => {
            let (i, sa) = parse_cip_request_set_attr_list(i)?;
            Ok((i, EnipCipRequestPayload::SetAttributeList(sa)))
        }
        CIP_MULTIPLE_SERVICE if multi => {
            // adding one byte for the cip service
            let (i, m) = parse_cip_reqresp_multiple(i, offset_from_cip + 1)?;
            Ok((i, EnipCipRequestPayload::Multiple(m)))
        }
        _ => Ok((i, EnipCipRequestPayload::Unhandled)),
    }?;
    return Ok((i, EnipCipRequest { path, payload }));
}

pub fn parse_cip_response(i: &[u8], service: u8, multi: bool) -> IResult<&[u8], EnipCipResponse> {
    let (i, _reserved) = le_u8(i)?;
    let (i, status) = le_u8(i)?;
    let (i, status_ext_nb) = le_u8(i)?;
    let (i, status_extended) = take(status_ext_nb as usize)(i)?;
    let offset_from_cip = 4 + (status_ext_nb as usize);
    let (i, payload) = match service {
        // CIP_GET_ATTR_LIST : need to parse attribute value variant, based on cip class
        CIP_MULTIPLE_SERVICE if multi => {
            let (i, m) = parse_cip_reqresp_multiple(i, offset_from_cip)?;
            Ok((i, EnipCipResponsePayload::Multiple(m)))
        }
        _ => Ok((i, EnipCipResponsePayload::Unhandled)),
    }?;

    return Ok((
        i,
        EnipCipResponse {
            status,
            payload,
            status_extended: status_extended.to_vec(),
        },
    ));
}

pub fn parse_cip_base(i: &[u8]) -> IResult<&[u8], CipData> {
    parse_cip(i, true)
}

pub fn parse_cip_multi(i: &[u8]) -> IResult<&[u8], CipData> {
    // have only one level of recursion
    parse_cip(i, false)
}

pub fn parse_cip(i: &[u8], multi: bool) -> IResult<&[u8], CipData> {
    let (i, service) = le_u8(i)?;
    let (i, cipdir) = if service & 0x80 == 0 {
        let (i, req) = parse_cip_request(i, service, multi)?;
        Ok((i, CipDir::Request(req)))
    } else {
        let (i, resp) = parse_cip_response(i, service & 0x7F, multi)?;
        Ok((i, CipDir::Response(resp)))
    }?;
    return Ok((
        i,
        CipData {
            service: service & 0x7F,
            cipdir,
        },
    ));
}

#[derive(Clone, Debug, Default)]
pub struct EnipItemData {
    pub seq_num: Option<u16>,
    pub cip: CipData,
}

#[derive(Clone, Debug, Default)]
pub struct EnipItemIdentity {
    pub protocol_version: u16,
    pub vendor_id: u16,
    pub device_type: u16,
    pub product_code: u16,
    pub revision_major: u8,
    pub revision_minor: u8,
    pub status: u16,
    pub serial: u32,
    pub product_name: Vec<u8>,
    pub state: u8,
}

#[derive(Clone, Debug, Default)]
pub enum EnipItemPayload {
    #[default]
    Unparsed,
    Data(EnipItemData),
    Identity(EnipItemIdentity),
    Services(EnipItemServices),
}

#[derive(Clone, Debug, Default)]
pub struct EnipCipItem {
    pub item_type: u16,
    pub item_length: u16,
    pub cip_offset: usize,
    pub start: usize,
    pub payload: EnipItemPayload,
}

pub const ENIP_ITEM_TYPE_CONNECTED_DATA: u16 = 0xb1;
pub const ENIP_ITEM_TYPE_UNCONNECTED_DATA: u16 = 0xb2;
pub const ENIP_ITEM_TYPE_IDENTITY: u16 = 0xc;
pub const ENIP_ITEM_TYPE_SERVICES: u16 = 0x100;

pub fn parse_cip_identity(i: &[u8]) -> IResult<&[u8], EnipItemIdentity> {
    let (i, protocol_version) = le_u16(i)?;
    let (i, _sock_addr) = take(16_usize)(i)?;
    let (i, vendor_id) = le_u16(i)?;
    let (i, device_type) = le_u16(i)?;
    let (i, product_code) = le_u16(i)?;
    let (i, revision_major) = le_u8(i)?;
    let (i, revision_minor) = le_u8(i)?;
    let (i, status) = le_u16(i)?;
    let (i, serial) = le_u32(i)?;
    let (i, prod_name_len) = le_u8(i)?;
    let (i, product_name) = take(prod_name_len as usize)(i)?;
    let (i, state) = le_u8(i)?;

    return Ok((
        i,
        EnipItemIdentity {
            protocol_version,
            vendor_id,
            device_type,
            product_code,
            revision_major,
            revision_minor,
            status,
            serial,
            product_name: product_name.to_vec(),
            state,
        },
    ));
}

#[derive(Clone, Debug, Default)]
pub struct EnipItemServices {
    pub protocol_version: u16,
    pub capabilities: u16,
    pub service_name: Vec<u8>,
}

pub fn parse_enip_services(i: &[u8]) -> IResult<&[u8], EnipItemServices> {
    let (i, protocol_version) = le_u16(i)?;
    let (i, capabilities) = le_u16(i)?;
    let (i, service_name) = take(16_usize)(i)?;
    return Ok((
        i,
        EnipItemServices {
            protocol_version,
            capabilities,
            service_name: service_name.to_vec(),
        },
    ));
}

pub fn parse_enip_cip_item(i: &[u8], start: usize) -> IResult<&[u8], EnipCipItem> {
    let (i, item_type) = le_u16(i)?;
    let (i, item_length) = le_u16(i)?;
    let mut cip_offset = start + 4;
    let (i, data) = take(item_length as usize)(i)?;
    let (_, payload) = match item_type {
        ENIP_ITEM_TYPE_IDENTITY => {
            let (_, li) = parse_cip_identity(data)?;
            Ok((data, EnipItemPayload::Identity(li)))
        }
        ENIP_ITEM_TYPE_SERVICES => {
            let (_, ls) = parse_enip_services(data)?;
            Ok((data, EnipItemPayload::Services(ls)))
        }
        ENIP_ITEM_TYPE_CONNECTED_DATA => {
            let (data, seq_num) = le_u16(data)?;
            cip_offset += 2;
            let (_, cip) = parse_cip_base(data)?;
            Ok((
                data,
                EnipItemPayload::Data(EnipItemData {
                    seq_num: Some(seq_num),
                    cip,
                }),
            ))
        }
        ENIP_ITEM_TYPE_UNCONNECTED_DATA => {
            let (_, cip) = parse_cip_base(data)?;
            Ok((
                data,
                EnipItemPayload::Data(EnipItemData { seq_num: None, cip }),
            ))
        }
        _ => Ok((data, EnipItemPayload::Unparsed)),
    }?;
    Ok((
        i,
        EnipCipItem {
            item_type,
            item_length,
            cip_offset,
            start,
            payload,
        },
    ))
}

#[derive(Clone, Debug, Default)]
pub struct EnipCIP {
    pub handle: u32,
    pub timeout: u16,
    pub items: Vec<EnipCipItem>,
}

pub fn parse_enip_cip_items(i: &[u8]) -> IResult<&[u8], Vec<EnipCipItem>> {
    let (i, nb) = le_u16(i)?;
    let mut start = 26; // ENIP_HEADER_LEN + fields parsed
    let mut items = Vec::new();
    let mut rem = i;
    for _j in 0..nb {
        let (rem2, item) = parse_enip_cip_item(rem, start)?;
        items.push(item);
        start += rem.len() - rem2.len();
        rem = rem2;
    }
    Ok((i, items))
}

pub fn parse_enip_cip(i: &[u8]) -> IResult<&[u8], EnipCIP> {
    let (i, handle) = le_u32(i)?;
    let (i, timeout) = le_u16(i)?;
    let (i, nb) = le_u16(i)?;
    let mut start = 32; // ENIP_HEADER_LEN + fields parsed
    let mut items = Vec::new();
    let mut rem = i;
    for _j in 0..nb {
        let (rem2, item) = parse_enip_cip_item(rem, start)?;
        items.push(item);
        start += rem.len() - rem2.len();
        rem = rem2;
    }
    Ok((
        i,
        EnipCIP {
            handle,
            timeout,
            items,
        },
    ))
}

pub fn parse_enip_register_session(i: &[u8]) -> IResult<&[u8], EnipRegisterSession> {
    let (i, protocol_version) = le_u16(i)?;
    let (i, options) = le_u16(i)?;
    Ok((
        i,
        EnipRegisterSession {
            protocol_version,
            options,
        },
    ))
}

#[derive(Clone, Debug, Default)]
pub struct EnipPdu {
    pub header: EnipHeader,
    pub payload: EnipPayload,
    pub invalid: bool,
}

pub fn parse_enip_pdu(i: &[u8]) -> IResult<&[u8], EnipPdu> {
    let (i, header) = parse_enip_header(i)?;
    let (i, data) = take(header.pdulen as usize)(i)?;
    let mut invalid = false;
    match EnipCommand::from_u(header.cmd) {
        Some(EnipCommand::RegisterSession) => {
            if let Ok((_, rs)) = parse_enip_register_session(data) {
                return Ok((
                    i,
                    EnipPdu {
                        header,
                        payload: EnipPayload::RegisterSession(rs),
                        invalid,
                    },
                ));
            } else {
                //used to set event
                invalid = true;
            }
        }
        Some(EnipCommand::ListServices) if header.pdulen > 0 => {
            // request is empty, response has data
            if let Ok((_, li)) = parse_enip_cip_items(data) {
                return Ok((
                    i,
                    EnipPdu {
                        header,
                        payload: EnipPayload::ListServices(li),
                        invalid,
                    },
                ));
            } else {
                invalid = true;
            }
        }
        Some(EnipCommand::ListInterfaces) if header.pdulen > 0 => {
            // request is empty, response has data
            if let Ok((_, li)) = parse_enip_cip_items(data) {
                return Ok((
                    i,
                    EnipPdu {
                        header,
                        payload: EnipPayload::ListInterfaces(li),
                        invalid,
                    },
                ));
            } else {
                invalid = true;
            }
        }
        Some(EnipCommand::ListIdentity) if header.pdulen > 0 => {
            // request is empty, response has data
            if let Ok((_, li)) = parse_enip_cip_items(data) {
                return Ok((
                    i,
                    EnipPdu {
                        header,
                        payload: EnipPayload::ListIdentity(li),
                        invalid,
                    },
                ));
            } else {
                invalid = true;
            }
        }
        Some(EnipCommand::SendRRData) | Some(EnipCommand::SendUnitData) => {
            if let Ok((_, cip)) = parse_enip_cip(data) {
                return Ok((
                    i,
                    EnipPdu {
                        header,
                        payload: EnipPayload::Cip(cip),
                        invalid,
                    },
                ));
            } else {
                //used to set event
                invalid = true;
            }
        }
        _ => {}
    }
    Ok((
        i,
        EnipPdu {
            header,
            payload: EnipPayload::Unparsed,
            invalid,
        },
    ))
}

pub fn enip_pdu_get_items(pdu: &EnipPdu) -> &[EnipCipItem] {
    match &pdu.payload {
        EnipPayload::ListIdentity(li) => {
            return li;
        }
        EnipPayload::ListInterfaces(li) => {
            return li;
        }
        EnipPayload::ListServices(ls) => {
            return ls;
        }
        EnipPayload::Cip(cip) => {
            return &cip.items;
        }
        _ => {
            return &[];
        }
    }
}
