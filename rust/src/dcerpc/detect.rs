/* Copyright (C) 2020 Open Information Security Foundation
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

use super::dcerpc::{
    DCERPCState, DCERPCTransaction, DCERPC_TYPE_REQUEST, DCERPC_TYPE_RESPONSE,
    DCERPC_UUID_ENTRY_FLAG_FF,
};
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use uuid::Uuid;

pub const DETECT_DCE_IFACE_OP_NONE: u8 = 0;
pub const DETECT_DCE_IFACE_OP_LT: u8 = 1;
pub const DETECT_DCE_IFACE_OP_GT: u8 = 2;
pub const DETECT_DCE_IFACE_OP_EQ: u8 = 3;
pub const DETECT_DCE_IFACE_OP_NE: u8 = 4;

pub const DETECT_DCE_OPNUM_RANGE_UNINITIALIZED: u32 = 100000;

#[derive(Debug)]
pub struct DCEIfaceData {
    pub if_uuid: Vec<u8>,
    pub op: u8,
    pub version: u16,
    pub any_frag: u8,
}

#[derive(Debug)]
pub struct DCEOpnumRange {
    pub range1: u32,
    pub range2: u32,
}

impl DCEOpnumRange {
    pub fn new() -> DCEOpnumRange {
        return DCEOpnumRange {
            range1: DETECT_DCE_OPNUM_RANGE_UNINITIALIZED,
            range2: DETECT_DCE_OPNUM_RANGE_UNINITIALIZED,
        };
    }
}

#[derive(Debug)]
pub struct DCEOpnumData {
    pub data: Vec<DCEOpnumRange>,
}

fn extract_op_version(opver: &str) -> Result<(u8, u16), ()> {
    if !opver.is_char_boundary(1){
        return Err(());
    }
    let (op, version) = opver.split_at(1);
    let opval: u8 = match op {
        ">" => DETECT_DCE_IFACE_OP_GT,
        "<" => DETECT_DCE_IFACE_OP_LT,
        "=" => DETECT_DCE_IFACE_OP_EQ,
        "!" => DETECT_DCE_IFACE_OP_NE,
        _ => DETECT_DCE_IFACE_OP_NONE,
    };

    let version: u16 = match version.parse::<u16>() {
        Ok(res) => res,
        _ => {
            return Err(());
        }
    };
    if opval == DETECT_DCE_IFACE_OP_NONE
        || (opval == DETECT_DCE_IFACE_OP_LT && version == std::u16::MIN)
        || (opval == DETECT_DCE_IFACE_OP_GT && version == std::u16::MAX)
    {
        return Err(());
    }

    Ok((opval, version))
}

fn match_iface_version(version: u16, if_data: &DCEIfaceData) -> bool {
    match if_data.op {
        DETECT_DCE_IFACE_OP_LT => version < if_data.version,
        DETECT_DCE_IFACE_OP_GT => version > if_data.version,
        DETECT_DCE_IFACE_OP_EQ => version == if_data.version,
        DETECT_DCE_IFACE_OP_NE => version != if_data.version,
        _ => {
            return true;
        }
    }
}

fn match_backuuid(
    tx: &mut DCERPCTransaction, state: &mut DCERPCState, if_data: &mut DCEIfaceData,
) -> u8 {
    let mut ret = 0;
    if let Some(ref bindack) = state.bindack {
        for uuidentry in bindack.accepted_uuid_list.iter() {
            ret = 1;
            // if any_frag is not enabled, we need to match only against the first fragment
            if if_data.any_frag == 0 && (uuidentry.flags & DCERPC_UUID_ENTRY_FLAG_FF == 0) {
                SCLogDebug!("any frag not enabled");
                continue;
            }
            // if the uuid has been rejected(uuidentry->result == 1), we skip to the next uuid
            if uuidentry.result != 0 {
                SCLogDebug!("Skipping to next UUID");
                continue;
            }

            for i in 0..16 {
                if if_data.if_uuid[i] != uuidentry.uuid[i] {
                    SCLogDebug!("Iface UUID and BINDACK Accepted UUID does not match");
                    ret = 0;
                    break;
                }
            }
            let ctxid = tx.get_req_ctxid();
            ret = ret & ((uuidentry.ctxid == ctxid) as u8);
            if ret == 0 {
                SCLogDebug!("CTX IDs/UUIDs do not match");
                continue;
            }

            if if_data.op != DETECT_DCE_IFACE_OP_NONE
                && !match_iface_version(uuidentry.version, if_data)
            {
                SCLogDebug!("Interface version did not match");
                ret &= 0;
            }

            if ret == 1 {
                return 1;
            }
        }
    }

    return ret;
}

fn parse_iface_data(arg: &str) -> Result<DCEIfaceData, ()> {
    let split_args: Vec<&str> = arg.split(',').collect();
    let mut op_version = (0, 0);
    let mut any_frag: u8 = 0;
    let if_uuid = match Uuid::parse_str(split_args[0]) {
        Ok(res) => res.as_bytes().to_vec(),
        _ => {
            return Err(());
        }
    };

    match split_args.len() {
        1 => {}
        2 => match split_args[1] {
            "any_frag" => {
                any_frag = 1;
            }
            _ => {
                op_version = match extract_op_version(split_args[1]) {
                    Ok((op, ver)) => (op, ver),
                    _ => {
                        return Err(());
                    }
                };
            }
        },
        3 => {
            op_version = match extract_op_version(split_args[1]) {
                Ok((op, ver)) => (op, ver),
                _ => {
                    return Err(());
                }
            };
            if split_args[2] != "any_frag" {
                return Err(());
            }
            any_frag = 1;
        }
        _ => {
            return Err(());
        }
    }

    Ok(DCEIfaceData {
        if_uuid: if_uuid,
        op: op_version.0,
        version: op_version.1,
        any_frag: any_frag,
    })
}

fn convert_str_to_u32(arg: &str) -> Result<u32, ()> {
    match arg.parse::<u32>() {
        Ok(res) => Ok(res),
        _ => Err(()),
    }
}

fn parse_opnum_data(arg: &str) -> Result<DCEOpnumData, ()> {
    let split_args: Vec<&str> = arg.split(',').collect();
    let mut dce_opnum_data: Vec<DCEOpnumRange> = Vec::new();
    for range in split_args.iter() {
        let mut opnum_range = DCEOpnumRange::new();
        let split_range: Vec<&str> = range.split('-').collect();
        let split_len = split_range.len();

        if (split_len > 0 && convert_str_to_u32(split_range[0]).is_err())
            || (split_len > 1 && convert_str_to_u32(split_range[1]).is_err())
        {
            return Err(());
        }
        match split_len {
            1 => {
                opnum_range.range1 = convert_str_to_u32(split_range[0]).unwrap();
            }
            2 => {
                let range1 = convert_str_to_u32(split_range[0]).unwrap();
                let range2 = convert_str_to_u32(split_range[1]).unwrap();
                if range2 < range1 {
                    return Err(());
                }
                opnum_range.range1 = range1;
                opnum_range.range2 = range2;
            }
            _ => {
                return Err(());
            }
        }
        dce_opnum_data.push(opnum_range);
    }

    Ok(DCEOpnumData {
        data: dce_opnum_data,
    })
}

#[no_mangle]
pub extern "C" fn rs_dcerpc_iface_match(
    tx: &mut DCERPCTransaction, state: &mut DCERPCState, if_data: &mut DCEIfaceData,
) -> u8 {
    let first_req_seen = tx.get_first_req_seen();
    if first_req_seen == 0 {
        return 0;
    }

    match state.get_hdr_type() {
        Some(x) => match x {
            DCERPC_TYPE_REQUEST | DCERPC_TYPE_RESPONSE => {}
            _ => {
                return 0;
            }
        },
        None => {
            return 0;
        }
    };

    return match_backuuid(tx, state, if_data);
}

#[no_mangle]
pub unsafe extern "C" fn rs_dcerpc_iface_parse(carg: *const c_char) -> *mut c_void {
    if carg.is_null() {
        return std::ptr::null_mut();
    }
    let arg = match CStr::from_ptr(carg).to_str() {
        Ok(arg) => arg,
        _ => {
            return std::ptr::null_mut();
        }
    };

    match parse_iface_data(&arg) {
        Ok(detect) => std::mem::transmute(Box::new(detect)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_dcerpc_iface_free(ptr: *mut c_void) {
    if ptr != std::ptr::null_mut() {
        let _: Box<DCEIfaceData> = std::mem::transmute(ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_dcerpc_opnum_match(
    tx: &mut DCERPCTransaction, opnum_data: &mut DCEOpnumData,
) -> u8 {
    let first_req_seen = tx.get_first_req_seen();
    if first_req_seen == 0 {
        return 0;
    }
    let opnum = tx.get_req_opnum();
    for range in opnum_data.data.iter() {
        if range.range2 == DETECT_DCE_OPNUM_RANGE_UNINITIALIZED {
            if range.range1 == opnum as u32 {
                return 1;
            }
        } else if range.range1 <= opnum as u32 && range.range2 >= opnum as u32 {
            return 1;
        }
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_dcerpc_opnum_parse(carg: *const c_char) -> *mut c_void {
    if carg.is_null() {
        return std::ptr::null_mut();
    }
    let arg = match CStr::from_ptr(carg).to_str() {
        Ok(arg) => arg,
        _ => {
            return std::ptr::null_mut();
        }
    };

    match parse_opnum_data(&arg) {
        Ok(detect) => std::mem::transmute(Box::new(detect)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_dcerpc_opnum_free(ptr: *mut c_void) {
    if ptr != std::ptr::null_mut() {
        let _: Box<DCEOpnumData> = std::mem::transmute(ptr);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_extract_op_version() {
        let op_version = "<1";
        assert_eq!(
            Ok((DETECT_DCE_IFACE_OP_LT, 1)),
            extract_op_version(op_version)
        );

        let op_version = ">10";
        assert_eq!(
            Ok((DETECT_DCE_IFACE_OP_GT, 10)),
            extract_op_version(op_version)
        );

        let op_version = "=45";
        assert_eq!(
            Ok((DETECT_DCE_IFACE_OP_EQ, 45)),
            extract_op_version(op_version)
        );

        let op_version = "!0";
        assert_eq!(
            Ok((DETECT_DCE_IFACE_OP_NE, 0)),
            extract_op_version(op_version)
        );

        let op_version = "@1";
        assert_eq!(true, extract_op_version(op_version).is_err());

        let op_version = "";
        assert_eq!(
            Err(()),
            extract_op_version(op_version)
        );

    }

    #[test]
    fn test_match_iface_version() {
        let iface_data = DCEIfaceData {
            if_uuid: Vec::new(),
            op: 3,
            version: 10,
            any_frag: 0,
        };
        let version = 10;
        assert_eq!(true, match_iface_version(version, &iface_data));

        let version = 2;
        assert_eq!(false, match_iface_version(version, &iface_data));
    }

    #[test]
    fn test_parse_iface_data() {
        let arg = "12345678-1234-1234-1234-123456789ABC";
        let iface_data = parse_iface_data(arg).unwrap();
        let expected_uuid = Ok(String::from("12345678-1234-1234-1234-123456789ABC").to_lowercase());
        let uuid = Uuid::from_slice(iface_data.if_uuid.as_slice());
        let uuid = uuid.map(|uuid| uuid.to_hyphenated().to_string());
        assert_eq!(expected_uuid, uuid);

        let arg = "12345678-1234-1234-1234-123456789ABC,>1";
        let iface_data = parse_iface_data(arg).unwrap();
        let expected_uuid = Ok(String::from("12345678-1234-1234-1234-123456789ABC").to_lowercase());
        let uuid = Uuid::from_slice(iface_data.if_uuid.as_slice());
        let uuid = uuid.map(|uuid| uuid.to_hyphenated().to_string());
        assert_eq!(expected_uuid, uuid);
        assert_eq!(DETECT_DCE_IFACE_OP_GT, iface_data.op);
        assert_eq!(1, iface_data.version);

        let arg = "12345678-1234-1234-1234-123456789ABC,any_frag";
        let iface_data = parse_iface_data(arg).unwrap();
        let expected_uuid = Ok(String::from("12345678-1234-1234-1234-123456789ABC").to_lowercase());
        let uuid = Uuid::from_slice(iface_data.if_uuid.as_slice());
        let uuid = uuid.map(|uuid| uuid.to_hyphenated().to_string());
        assert_eq!(expected_uuid, uuid);
        assert_eq!(DETECT_DCE_IFACE_OP_NONE, iface_data.op);
        assert_eq!(1, iface_data.any_frag);
        assert_eq!(0, iface_data.version);

        let arg = "12345678-1234-1234-1234-123456789ABC,!10,any_frag";
        let iface_data = parse_iface_data(arg).unwrap();
        let expected_uuid = Ok(String::from("12345678-1234-1234-1234-123456789ABC").to_lowercase());
        let uuid = Uuid::from_slice(iface_data.if_uuid.as_slice());
        let uuid = uuid.map(|uuid| uuid.to_hyphenated().to_string());
        assert_eq!(expected_uuid, uuid);
        assert_eq!(DETECT_DCE_IFACE_OP_NE, iface_data.op);
        assert_eq!(1, iface_data.any_frag);
        assert_eq!(10, iface_data.version);

        let arg = "12345678-1234-1234-1234-123456789ABC,>1,ay_frag";
        let iface_data = parse_iface_data(arg);
        assert_eq!(iface_data.is_err(), true);

        let arg = "12345678-1234-1234-1234-12345679ABC,>1,any_frag";
        let iface_data = parse_iface_data(arg);
        assert_eq!(iface_data.is_err(), true);

        let arg = "12345678-1234-1234-134-123456789ABC,>1,any_frag";
        let iface_data = parse_iface_data(arg);
        assert_eq!(iface_data.is_err(), true);

        let arg = "12345678-123-124-1234-123456789ABC,>1,any_frag";
        let iface_data = parse_iface_data(arg);
        assert_eq!(iface_data.is_err(), true);

        let arg = "1234568-1234-1234-1234-123456789ABC,>1,any_frag";
        let iface_data = parse_iface_data(arg);
        assert_eq!(iface_data.is_err(), true);

        let arg = "12345678-1234-1234-1234-123456789ABC,>65536,any_frag";
        let iface_data = parse_iface_data(arg);
        assert_eq!(iface_data.is_err(), true);

        let arg = "12345678-1234-1234-1234-123456789ABC,>=1,any_frag";
        let iface_data = parse_iface_data(arg);
        assert_eq!(iface_data.is_err(), true);

        let arg = "12345678-1234-1234-1234-123456789ABC,<0,any_frag";
        let iface_data = parse_iface_data(arg);
        assert_eq!(iface_data.is_err(), true);

        let arg = "12345678-1234-1234-1234-123456789ABC,>65535,any_frag";
        let iface_data = parse_iface_data(arg);
        assert_eq!(iface_data.is_err(), true);
    }

    #[test]
    fn test_parse_opnum_data() {
        let arg = "12";
        let opnum_data = parse_opnum_data(arg).unwrap();
        assert_eq!(1, opnum_data.data.len());
        assert_eq!(12, opnum_data.data[0].range1);
        assert_eq!(
            DETECT_DCE_OPNUM_RANGE_UNINITIALIZED,
            opnum_data.data[0].range2
        );

        let arg = "12,24";
        let opnum_data = parse_opnum_data(arg).unwrap();
        assert_eq!(2, opnum_data.data.len());
        assert_eq!(12, opnum_data.data[0].range1);
        assert_eq!(24, opnum_data.data[1].range1);

        let arg = "12,12-24";
        let opnum_data = parse_opnum_data(arg).unwrap();
        assert_eq!(2, opnum_data.data.len());
        assert_eq!(12, opnum_data.data[0].range1);
        assert_eq!(12, opnum_data.data[1].range1);
        assert_eq!(24, opnum_data.data[1].range2);

        let arg = "12-14,12,121,62-78";
        let opnum_data = parse_opnum_data(arg).unwrap();
        assert_eq!(4, opnum_data.data.len());
        assert_eq!(12, opnum_data.data[0].range1);
        assert_eq!(14, opnum_data.data[0].range2);
        assert_eq!(121, opnum_data.data[2].range1);
        assert_eq!(78, opnum_data.data[3].range2);

        let arg = "12,26,62,61,6513-6666";
        let opnum_data = parse_opnum_data(arg).unwrap();
        assert_eq!(5, opnum_data.data.len());
        assert_eq!(61, opnum_data.data[3].range1);
        assert_eq!(6513, opnum_data.data[4].range1);

        let arg = "12,26,62,61,6513--";
        let opnum_data = parse_opnum_data(arg);
        assert_eq!(true, opnum_data.is_err());

        let arg = "12-14,12,121,62-8";
        let opnum_data = parse_opnum_data(arg);
        assert_eq!(true, opnum_data.is_err());
    }
}
