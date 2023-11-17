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

use nom7::branch::alt;
use nom7::character::complete::{char, digit1, space0};
use nom7::combinator::{map_opt, opt, verify};
use nom7::error::{make_error, ErrorKind};
use nom7::IResult;

use std::ffi::c_void;

use crate::enip::enip::EnipTransaction;
use crate::enip::parser::{
    CipDir, EnipItemPayload, EnipPayload, ENIP_CIP_PATH_ATTR_16BIT, ENIP_CIP_PATH_ATTR_8BIT,
    ENIP_CIP_PATH_CLASS_16BIT, ENIP_CIP_PATH_CLASS_8BIT, ENIP_CMD_CANCEL, ENIP_CMD_INDICATE_STATUS,
    ENIP_CMD_LIST_IDENTITY, ENIP_CMD_LIST_INTERFACES, ENIP_CMD_LIST_SERVICES, ENIP_CMD_NOP,
    ENIP_CMD_REGISTER_SESSION, ENIP_CMD_SEND_RRDATA, ENIP_CMD_SEND_UNIT_DATA,
    ENIP_CMD_UNREGISTER_SESSION,
};

use crate::core::Direction;

use std::ffi::CStr;

fn enip_detect_parse_u16(i: &str) -> IResult<&str, u16> {
    let (i, r) = map_opt(digit1, |s: &str| s.parse::<u16>().ok())(i)?;
    return Ok((i, r));
}

fn enip_parse_command_string(i: &str) -> IResult<&str, u16> {
    let su = i.to_uppercase();
    let su_slice: &str = &su;
    match su_slice {
        "NOP" => Ok((i, ENIP_CMD_NOP)),
        "LISTSERVICES" => Ok((i, ENIP_CMD_LIST_SERVICES)),
        "LISTIDENTITY" => Ok((i, ENIP_CMD_LIST_IDENTITY)),
        "LISTINTERFACES" => Ok((i, ENIP_CMD_LIST_INTERFACES)),
        "REGISTERSESSION" => Ok((i, ENIP_CMD_REGISTER_SESSION)),
        "UNREGISTERSESSION" => Ok((i, ENIP_CMD_UNREGISTER_SESSION)),
        "SENDRRDATA" => Ok((i, ENIP_CMD_SEND_RRDATA)),
        "SENDUNITDATA" => Ok((i, ENIP_CMD_SEND_UNIT_DATA)),
        "INDICATESTATUS" => Ok((i, ENIP_CMD_INDICATE_STATUS)),
        "CANCEL" => Ok((i, ENIP_CMD_CANCEL)),
        _ => Err(nom7::Err::Error(nom7::error::make_error(
            i,
            nom7::error::ErrorKind::MapOpt,
        ))),
    }
}

fn enip_parse_command(i: &str) -> IResult<&str, u16> {
    let (i, v) = alt((enip_detect_parse_u16, enip_parse_command_string))(i)?;
    return Ok((i, v));
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_parse_command(
    raw: *const std::os::raw::c_char, value: *mut u16,
) -> bool {
    let raw2: &CStr = CStr::from_ptr(raw); //unsafe
    if let Ok(s) = raw2.to_str() {
        if let Ok((_, v)) = enip_parse_command(s) {
            *value = v;
            return true;
        }
    }
    return false;
}

fn enip_tx_is_cmd(
    tx: &mut EnipTransaction, direction: Direction, value: u16,
) -> std::os::raw::c_int {
    if direction == Direction::ToServer {
        if let Some(req) = &tx.request {
            if req.header.cmd == value {
                return 1;
            }
        }
    } else if let Some(resp) = &tx.response {
        if resp.header.cmd == value {
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_is_cmd(
    tx: *mut std::os::raw::c_void, direction: u8, value: u16,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, EnipTransaction);
    return enip_tx_is_cmd(tx, direction.into(), value);
}

#[derive(Clone, Debug, Default)]
pub struct DetectCipServiceData {
    pub service: u8,
    pub class: Option<u16>,
    pub attribute: Option<u16>,
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
        let (i, class1) = map_opt(digit1, |s: &str| s.parse::<u16>().ok())(i)?;
        class = Some(class1);
        let (i, _) = space0(i)?;
        let (i, comma) = opt(char(','))(i)?;
        input = i;
        if comma.is_some() {
            let (i, _) = space0(i)?;
            let (i, negation) = opt(char('!'))(i)?;
            let (i, attr1) = map_opt(digit1, |s: &str| s.parse::<u16>().ok())(i)?;
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
    let raw2: &CStr = CStr::from_ptr(raw); //unsafe
    if let Ok(s) = raw2.to_str() {
        if let Ok((_, ctx)) = enip_parse_cip_service(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_cip_service_free(ctx: *mut c_void) {
    std::mem::drop(Box::from_raw(ctx));
}

fn enip_cip_has_attribute(cipdir: &CipDir, class: u16) -> std::os::raw::c_int {
    if let CipDir::Request(req) = cipdir {
        for seg in req.path.iter() {
            match seg.segment_type {
                ENIP_CIP_PATH_ATTR_8BIT | ENIP_CIP_PATH_ATTR_16BIT => {
                    if seg.value == class {
                        return 1;
                    }
                }
                _ => {}
            }
        }
    }
    return 0;
}

fn enip_cip_has_class(cipdir: &CipDir, class: u16) -> bool {
    if let CipDir::Request(req) = cipdir {
        for seg in req.path.iter() {
            match seg.segment_type {
                ENIP_CIP_PATH_CLASS_8BIT | ENIP_CIP_PATH_CLASS_16BIT if seg.value == class => {
                    return true;
                }
                _ => {}
            }
        }
    }
    return false;
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
        if let EnipPayload::CIP(c) = &pdu.payload {
            for item in c.items.iter() {
                if let EnipItemPayload::Data(d) = &item.payload {
                    if d.cip.service == ctx.service {
                        if let Some(class) = ctx.class {
                            if enip_cip_has_class(&d.cip.cipdir, class) {
                                if let Some(attr) = ctx.attribute {
                                    return enip_cip_has_attribute(&d.cip.cipdir, attr);
                                } //else
                                return 1;
                            } //else
                            return 0;
                        } //else
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_has_cip_service(
    tx: *mut std::os::raw::c_void, direction: u8, ctx: *const c_void,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, EnipTransaction);
    let ctx = cast_pointer!(ctx, DetectCipServiceData);
    return enip_tx_has_cip_service(tx, direction.into(), ctx);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test of some valid data.
    #[test]
    fn test_enip_parse_cip_service() {
        let buf1 = "12";
        let r1 = enip_parse_cip_service(buf1);
        match r1 {
            Ok((remainder, csd)) => {
                // Check the first message.
                assert_eq!(csd.service, 12);
                assert_eq!(csd.class, None);
                assert_eq!(remainder.len(), 0);
            }
            Err(_) => {
                panic!("Result should not be an error.");
            }
        }

        // with spaces and all values
        let buf2 = "12 , 123 , 45678";
        let r2 = enip_parse_cip_service(buf2);
        match r2 {
            Ok((remainder, csd)) => {
                // Check the first message.
                assert_eq!(csd.service, 12);
                assert_eq!(csd.class, Some(123));
                assert_eq!(csd.attribute, Some(45678));
                assert_eq!(remainder.len(), 0);
            }
            Err(_) => {
                panic!("Result should not be an error.");
            }
        }

        // too big for service
        let buf3 = "202";
        let r3 = enip_parse_cip_service(buf3);
        match r3 {
            Ok((_, _)) => {
                panic!("Result should be an error.");
            }
            Err(_) => {}
        }

        // non numerical after comma
        let buf4 = "123,toto";
        let r4 = enip_parse_cip_service(buf4);
        match r4 {
            Ok((_, _)) => {
                panic!("Result should be an error.");
            }
            Err(_) => {}
        }

        // too many commas/values
        let buf5 = "1,2,3,4";
        let r5 = enip_parse_cip_service(buf5);
        match r5 {
            Ok((_, _)) => {
                panic!("Result should be an error.");
            }
            Err(_) => {}
        }

        // too many commas/values
        let buf6 = "1,2,!3";
        let r6 = enip_parse_cip_service(buf6);
        match r6 {
            Ok((remainder, csd)) => {
                // Check the first message.
                assert_eq!(csd.service, 1);
                assert_eq!(csd.class, Some(2));
                assert_eq!(csd.attribute, None);
                assert_eq!(remainder.len(), 0);
            }
            Err(_) => {
                panic!("Result should not be an error.");
            }
        }
    }
}
