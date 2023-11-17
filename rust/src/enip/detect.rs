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

use nom7::character::complete::{char, digit1, space0};
use nom7::combinator::{map_opt, opt, verify};
use nom7::error::{make_error, ErrorKind};
use nom7::IResult;

use std::ffi::c_void;

use crate::enip::constant::{EnipCommand, EnipStatus};
use crate::enip::enip::EnipTransaction;
use crate::enip::parser::{
    CipData, CipDir, EnipCipRequestPayload, EnipCipResponsePayload, EnipItemPayload, EnipPayload,
    CIP_MULTIPLE_SERVICE,
};

use crate::detect::uint::{detect_match_uint, detect_parse_uint_enum, DetectUintData};

use crate::core::Direction;

use std::ffi::CStr;

#[no_mangle]
pub unsafe extern "C" fn SCEnipParseCommand(
    raw: *const std::os::raw::c_char,
) -> *mut DetectUintData<u16> {
    let raw: &CStr = CStr::from_ptr(raw); //unsafe
    if let Ok(s) = raw.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u16, EnipCommand>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCEnipParseStatus(
    raw: *const std::os::raw::c_char,
) -> *mut DetectUintData<u32> {
    let raw: &CStr = CStr::from_ptr(raw); //unsafe
    if let Ok(s) = raw.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u32, EnipStatus>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetCommand(
    tx: &mut EnipTransaction, direction: u8, value: *mut u16,
) -> bool {
    let direction: Direction = direction.into();
    if direction == Direction::ToServer {
        if let Some(req) = &tx.request {
            *value = req.header.cmd;
            return true;
        }
    } else if let Some(resp) = &tx.response {
        *value = resp.header.cmd;
        return true;
    }
    return false;
}

#[derive(Clone, Debug, Default)]
pub struct DetectCipServiceData {
    pub service: u8,
    pub class: Option<u32>,
    pub attribute: Option<u32>,
}

fn enip_parse_cip_service(i: &str) -> IResult<&str, DetectCipServiceData> {
    let (i, _) = space0(i)?;
    let (i, service) = verify(map_opt(digit1, |s: &str| s.parse::<u8>().ok()), |&v| {
        v < 0x80
    })(i)?;
    let mut class = None;
    let mut attribute = None;
    let (i, _) = space0(i)?;
    let (i, comma) = opt(char(','))(i)?;
    let mut input = i;
    if comma.is_some() {
        let (i, _) = space0(i)?;
        let (i, class1) = map_opt(digit1, |s: &str| s.parse::<u32>().ok())(i)?;
        class = Some(class1);
        let (i, _) = space0(i)?;
        let (i, comma) = opt(char(','))(i)?;
        input = i;
        if comma.is_some() {
            let (i, _) = space0(i)?;
            let (i, negation) = opt(char('!'))(i)?;
            let (i, attr1) = map_opt(digit1, |s: &str| s.parse::<u32>().ok())(i)?;
            if negation.is_none() {
                attribute = Some(attr1);
            }
            input = i;
        }
    }
    let (i, _) = space0(input)?;
    if !i.is_empty() {
        return Err(nom7::Err::Error(make_error(i, ErrorKind::NonEmpty)));
    }
    return Ok((
        i,
        DetectCipServiceData {
            service,
            class,
            attribute,
        },
    ));
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_parse_cip_service(
    raw: *const std::os::raw::c_char,
) -> *mut c_void {
    let raw: &CStr = CStr::from_ptr(raw); //unsafe
    if let Ok(s) = raw.to_str() {
        if let Ok((_, ctx)) = enip_parse_cip_service(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_cip_service_free(ctx: *mut c_void) {
    std::mem::drop(Box::from_raw(ctx as *mut DetectCipServiceData));
}

fn enip_cip_has_attribute(cipdir: &CipDir, attr: u32) -> std::os::raw::c_int {
    if let CipDir::Request(req) = cipdir {
        for seg in req.path.iter() {
            if seg.segment_type >> 2 == 12 && seg.value == attr {
                return 1;
            }
        }
        match &req.payload {
            EnipCipRequestPayload::GetAttributeList(ga) => {
                for attrg in ga.attr_list.iter() {
                    if attr == (*attrg).into() {
                        return 1;
                    }
                }
            }
            EnipCipRequestPayload::SetAttributeList(sa) => {
                if let Some(val) = sa.first_attr {
                    if attr == val.into() {
                        return 1;
                    }
                }
            }
            _ => {}
        }
    }
    return 0;
}

fn enip_cip_has_class(cipdir: &CipDir, class: u32) -> bool {
    if let CipDir::Request(req) = cipdir {
        for seg in req.path.iter() {
            if seg.segment_type >> 2 == 8 && seg.value == class {
                return true;
            }
        }
    }
    return false;
}

fn enip_cip_match_service(d: &CipData, ctx: &DetectCipServiceData) -> std::os::raw::c_int {
    if d.service == ctx.service {
        if let Some(class) = ctx.class {
            if enip_cip_has_class(&d.cipdir, class) {
                if let Some(attr) = ctx.attribute {
                    return enip_cip_has_attribute(&d.cipdir, attr);
                } //else
                return 1;
            } //else
            return 0;
        } //else
        return 1;
    } else if d.service == CIP_MULTIPLE_SERVICE {
        match &d.cipdir {
            CipDir::Request(req) => {
                if let EnipCipRequestPayload::Multiple(m) = &req.payload {
                    for p in m.packet_list.iter() {
                        if enip_cip_match_service(p, ctx) == 1 {
                            return 1;
                        }
                    }
                }
            }
            CipDir::Response(resp) => {
                if let EnipCipResponsePayload::Multiple(m) = &resp.payload {
                    for p in m.packet_list.iter() {
                        if enip_cip_match_service(p, ctx) == 1 {
                            return 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    return 0;
}

fn enip_tx_has_cip_service(
    tx: &mut EnipTransaction, direction: Direction, ctx: &DetectCipServiceData,
) -> std::os::raw::c_int {
    let pduo = if direction == Direction::ToServer {
        &tx.request
    } else {
        &tx.response
    };
    if let Some(pdu) = pduo {
        if let EnipPayload::Cip(c) = &pdu.payload {
            for item in c.items.iter() {
                if let EnipItemPayload::Data(d) = &item.payload {
                    return enip_cip_match_service(&d.cip, ctx);
                }
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_has_cip_service(
    tx: &mut EnipTransaction, direction: u8, ctx: *const c_void,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, DetectCipServiceData);
    return enip_tx_has_cip_service(tx, direction.into(), ctx);
}

fn enip_cip_match_status(d: &CipData, ctx: &DetectUintData<u8>) -> std::os::raw::c_int {
    if let CipDir::Response(resp) = &d.cipdir {
        if detect_match_uint(ctx, resp.status) {
            return 1;
        }
        if let EnipCipResponsePayload::Multiple(m) = &resp.payload {
            for p in m.packet_list.iter() {
                if enip_cip_match_status(p, ctx) == 1 {
                    return 1;
                }
            }
        }
    }
    return 0;
}

fn enip_tx_has_cip_status(
    tx: &mut EnipTransaction, ctx: &DetectUintData<u8>,
) -> std::os::raw::c_int {
    if let Some(pdu) = &tx.response {
        if let EnipPayload::Cip(c) = &pdu.payload {
            for item in c.items.iter() {
                if let EnipItemPayload::Data(d) = &item.payload {
                    return enip_cip_match_status(&d.cip, ctx);
                }
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_has_cip_status(
    tx: &mut EnipTransaction, ctx: *const c_void,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return enip_tx_has_cip_status(tx, ctx);
}

fn enip_cip_match_extendedstatus(d: &CipData, ctx: &DetectUintData<u16>) -> std::os::raw::c_int {
    if let CipDir::Response(resp) = &d.cipdir {
        if resp.status_extended.len() == 2 {
            let val = ((resp.status_extended[1] as u16) << 8) | (resp.status_extended[0] as u16);
            if detect_match_uint(ctx, val) {
                return 1;
            }
        }
        if let EnipCipResponsePayload::Multiple(m) = &resp.payload {
            for p in m.packet_list.iter() {
                if enip_cip_match_extendedstatus(p, ctx) == 1 {
                    return 1;
                }
            }
        }
    }
    return 0;
}

fn enip_tx_has_cip_extendedstatus(
    tx: &mut EnipTransaction, ctx: &DetectUintData<u16>,
) -> std::os::raw::c_int {
    if let Some(pdu) = &tx.response {
        if let EnipPayload::Cip(c) = &pdu.payload {
            for item in c.items.iter() {
                if let EnipItemPayload::Data(d) = &item.payload {
                    return enip_cip_match_extendedstatus(&d.cip, ctx);
                }
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_has_cip_extendedstatus(
    tx: &mut EnipTransaction, ctx: *const c_void,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    return enip_tx_has_cip_extendedstatus(tx, ctx);
}

fn enip_get_status(tx: &mut EnipTransaction, direction: Direction) -> Option<u32> {
    if direction == Direction::ToServer {
        if let Some(req) = &tx.request {
            return Some(req.header.status);
        }
    } else if let Some(resp) = &tx.response {
        return Some(resp.header.status);
    }
    return None;
}

fn enip_cip_match_segment(
    d: &CipData, ctx: &DetectUintData<u32>, segment_type: u8,
) -> std::os::raw::c_int {
    if let CipDir::Request(req) = &d.cipdir {
        for seg in req.path.iter() {
            if seg.segment_type >> 2 == segment_type && detect_match_uint(ctx, seg.value) {
                return 1;
            }
        }
        if let EnipCipRequestPayload::Multiple(m) = &req.payload {
            for p in m.packet_list.iter() {
                if enip_cip_match_segment(p, ctx, segment_type) == 1 {
                    return 1;
                }
            }
        }
    }
    return 0;
}

fn enip_tx_has_cip_segment(
    tx: &mut EnipTransaction, ctx: &DetectUintData<u32>, segment_type: u8,
) -> std::os::raw::c_int {
    if let Some(pdu) = &tx.request {
        if let EnipPayload::Cip(c) = &pdu.payload {
            for item in c.items.iter() {
                if let EnipItemPayload::Data(d) = &item.payload {
                    return enip_cip_match_segment(&d.cip, ctx, segment_type);
                }
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_has_cip_class(
    tx: &mut EnipTransaction, ctx: *const c_void,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    return enip_tx_has_cip_segment(tx, ctx, 8);
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_has_cip_instance(
    tx: &mut EnipTransaction, ctx: *const c_void,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    return enip_tx_has_cip_segment(tx, ctx, 9);
}

fn enip_cip_match_attribute(d: &CipData, ctx: &DetectUintData<u32>) -> std::os::raw::c_int {
    if let CipDir::Request(req) = &d.cipdir {
        for seg in req.path.iter() {
            if seg.segment_type >> 2 == 12 && detect_match_uint(ctx, seg.value) {
                return 1;
            }
        }
        match &req.payload {
            EnipCipRequestPayload::GetAttributeList(ga) => {
                for attrg in ga.attr_list.iter() {
                    if detect_match_uint(ctx, (*attrg).into()) {
                        return 1;
                    }
                }
            }
            EnipCipRequestPayload::SetAttributeList(sa) => {
                if let Some(val) = sa.first_attr {
                    if detect_match_uint(ctx, val.into()) {
                        return 1;
                    }
                }
            }
            EnipCipRequestPayload::Multiple(m) => {
                for p in m.packet_list.iter() {
                    if enip_cip_match_attribute(p, ctx) == 1 {
                        return 1;
                    }
                }
            }
            _ => {}
        }
    }
    return 0;
}

fn enip_tx_has_cip_attribute(
    tx: &mut EnipTransaction, ctx: &DetectUintData<u32>,
) -> std::os::raw::c_int {
    if let Some(pdu) = &tx.request {
        if let EnipPayload::Cip(c) = &pdu.payload {
            for item in c.items.iter() {
                if let EnipItemPayload::Data(d) = &item.payload {
                    return enip_cip_match_attribute(&d.cip, ctx);
                }
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_has_cip_attribute(
    tx: &mut EnipTransaction, ctx: *const c_void,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    return enip_tx_has_cip_attribute(tx, ctx);
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetStatus(
    tx: &mut EnipTransaction, direction: u8, value: *mut u32,
) -> bool {
    if let Some(x) = enip_get_status(tx, direction.into()) {
        *value = x;
        return true;
    }
    return false;
}

fn enip_tx_get_protocol_version(tx: &mut EnipTransaction, direction: Direction) -> Option<u16> {
    if direction == Direction::ToServer {
        if let Some(req) = &tx.request {
            if let EnipPayload::RegisterSession(rs) = &req.payload {
                return Some(rs.protocol_version);
            }
        }
    } else if let Some(resp) = &tx.response {
        match &resp.payload {
            EnipPayload::RegisterSession(rs) => {
                return Some(rs.protocol_version);
            }
            EnipPayload::ListServices(lsp) if !lsp.is_empty() => {
                if let EnipItemPayload::Services(ls) = &lsp[0].payload {
                    return Some(ls.protocol_version);
                }
            }
            EnipPayload::ListIdentity(lip) if !lip.is_empty() => {
                if let EnipItemPayload::Identity(li) = &lip[0].payload {
                    return Some(li.protocol_version);
                }
            }
            _ => {}
        }
    }
    return None;
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetProtocolVersion(
    tx: &mut EnipTransaction, direction: u8, value: *mut u16,
) -> bool {
    if let Some(val) = enip_tx_get_protocol_version(tx, direction.into()) {
        *value = val;
        return true;
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetCapabilities(
    tx: &mut EnipTransaction, value: *mut u16,
) -> bool {
    if let Some(ref response) = tx.response {
        if let EnipPayload::ListServices(lsp) = &response.payload {
            if !lsp.is_empty() {
                if let EnipItemPayload::Services(ls) = &lsp[0].payload {
                    *value = ls.capabilities;
                    return true;
                }
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetRevision(
    tx: &mut EnipTransaction, value: *mut u16,
) -> bool {
    if let Some(ref response) = tx.response {
        if let EnipPayload::ListIdentity(lip) = &response.payload {
            if !lip.is_empty() {
                if let EnipItemPayload::Identity(li) = &lip[0].payload {
                    *value = ((li.revision_major as u16) << 8) | (li.revision_minor as u16);
                    return true;
                }
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetIdentityStatus(
    tx: &mut EnipTransaction, value: *mut u16,
) -> bool {
    if let Some(ref response) = tx.response {
        if let EnipPayload::ListIdentity(lip) = &response.payload {
            if !lip.is_empty() {
                if let EnipItemPayload::Identity(li) = &lip[0].payload {
                    *value = li.status;
                    return true;
                }
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetState(tx: &mut EnipTransaction, value: *mut u8) -> bool {
    if let Some(ref response) = tx.response {
        if let EnipPayload::ListIdentity(lip) = &response.payload {
            if !lip.is_empty() {
                if let EnipItemPayload::Identity(li) = &lip[0].payload {
                    *value = li.state;
                    return true;
                }
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetSerial(
    tx: &mut EnipTransaction, value: *mut u32,
) -> bool {
    if let Some(ref response) = tx.response {
        if let EnipPayload::ListIdentity(lip) = &response.payload {
            if !lip.is_empty() {
                if let EnipItemPayload::Identity(li) = &lip[0].payload {
                    *value = li.serial;
                    return true;
                }
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetProductCode(
    tx: &mut EnipTransaction, value: *mut u16,
) -> bool {
    if let Some(ref response) = tx.response {
        if let EnipPayload::ListIdentity(lip) = &response.payload {
            if !lip.is_empty() {
                if let EnipItemPayload::Identity(li) = &lip[0].payload {
                    *value = li.product_code;
                    return true;
                }
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetDeviceType(
    tx: &mut EnipTransaction, value: *mut u16,
) -> bool {
    if let Some(ref response) = tx.response {
        if let EnipPayload::ListIdentity(lip) = &response.payload {
            if !lip.is_empty() {
                if let EnipItemPayload::Identity(li) = &lip[0].payload {
                    *value = li.device_type;
                    return true;
                }
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn ScEnipTxGetVendorId(
    tx: &mut EnipTransaction, value: *mut u16,
) -> bool {
    if let Some(ref response) = tx.response {
        if let EnipPayload::ListIdentity(lip) = &response.payload {
            if !lip.is_empty() {
                if let EnipItemPayload::Identity(li) = &lip[0].payload {
                    *value = li.vendor_id;
                    return true;
                }
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_get_product_name(
    tx: &EnipTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ref response) = tx.response {
        if let EnipPayload::ListIdentity(lip) = &response.payload {
            if !lip.is_empty() {
                if let EnipItemPayload::Identity(li) = &lip[0].payload {
                    *buffer = li.product_name.as_ptr();
                    *buffer_len = li.product_name.len() as u32;
                    return 1;
                }
            }
        }
    }

    *buffer = std::ptr::null();
    *buffer_len = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_get_service_name(
    tx: &EnipTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ref response) = tx.response {
        if let EnipPayload::ListServices(lsp) = &response.payload {
            if !lsp.is_empty() {
                if let EnipItemPayload::Services(ls) = &lsp[0].payload {
                    *buffer = ls.service_name.as_ptr();
                    *buffer_len = ls.service_name.len() as u32;
                    return 1;
                }
            }
        }
    }

    *buffer = std::ptr::null();
    *buffer_len = 0;
    return 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test of some valid data.
    #[test]
    fn test_enip_parse_cip_service() {
        let buf1 = "12";
        let (remainder, csd) = enip_parse_cip_service(buf1).unwrap();
        // Check the first message.
        assert_eq!(csd.service, 12);
        assert_eq!(csd.class, None);
        assert_eq!(remainder.len(), 0);

        // with spaces and all values
        let buf2 = "12 , 123 , 45678";
        let (remainder, csd) = enip_parse_cip_service(buf2).unwrap();
        // Check the first message.
        assert_eq!(csd.service, 12);
        assert_eq!(csd.class, Some(123));
        assert_eq!(csd.attribute, Some(45678));
        assert_eq!(remainder.len(), 0);

        // too big for service
        let buf3 = "202";
        assert!(enip_parse_cip_service(buf3).is_err());

        // non numerical after comma
        let buf4 = "123,toto";
        assert!(enip_parse_cip_service(buf4).is_err());

        // too many commas/values
        let buf5 = "1,2,3,4";
        assert!(enip_parse_cip_service(buf5).is_err());

        // too many commas/values
        let buf6 = "1,2,!3";
        let (remainder, csd) = enip_parse_cip_service(buf6).unwrap();
        // Check the first message.
        assert_eq!(csd.service, 1);
        assert_eq!(csd.class, Some(2));
        assert_eq!(csd.attribute, None);
        assert_eq!(remainder.len(), 0);
    }
}
