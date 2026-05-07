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
    DCERPCState, DCERPCTransaction, ALPROTO_DCERPC, DCERPC_TYPE_REQUEST, DCERPC_TYPE_RESPONSE,
    DCERPC_UUID_ENTRY_FLAG_FF,
};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{detect_match_uint, detect_parse_uint, DetectUintData};
use crate::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use crate::smb::detect::{smb_tx_get_stub_data, smb_tx_match_dce_iface, smb_tx_match_dce_opnum};
use crate::smb::smb::ALPROTO_SMB;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, DetectEngineTransforms, Flow, InspectionBuffer,
    SCDetectBufferSetActiveList, SCDetectHelperBufferMpmRegister,
    SCDetectHelperBufferProgressRegister, SCDetectHelperKeywordAliasRegister,
    SCDetectHelperKeywordRegister, SCDetectRegisterMpmGeneric, SCDetectSignatureSetAppProto,
    SCFlowGetAppProtocol, SCInspectionBufferGet, SCInspectionBufferSetupAndApplyTransforms,
    SCSigMatchAppendSMToList, SCSigTableAppLiteElmt, SigMatchCtx, Signature,
};
use uuid::Uuid;

pub const DETECT_DCE_OPNUM_RANGE_UNINITIALIZED: u32 = 100000;

#[derive(Debug)]
pub struct DCEIfaceData {
    pub if_uuid: Vec<u8>,
    pub du16: Option<DetectUintData<u16>>,
    pub any_frag: u8,
}

#[derive(Debug)]
pub struct DCEOpnumRange {
    pub range1: u32,
    pub range2: u32,
}

impl Default for DCEOpnumRange {
    fn default() -> Self {
        Self::new()
    }
}

impl DCEOpnumRange {
    pub fn new() -> Self {
        Self {
            range1: DETECT_DCE_OPNUM_RANGE_UNINITIALIZED,
            range2: DETECT_DCE_OPNUM_RANGE_UNINITIALIZED,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DCEOpnumDataRanges {
    pub data: Vec<DCEOpnumRange>,
}

#[derive(Debug)]
pub(crate) enum DCEOpnumData {
    Ranges(DCEOpnumDataRanges),
    Num(DetectUintData<u16>),
}

fn match_backuuid(
    tx: &DCERPCTransaction, state: &mut DCERPCState, if_data: &mut DCEIfaceData,
) -> c_int {
    if !state.interface_uuids.is_empty() {
        for uuidentry in &state.interface_uuids {
            // if any_frag is not enabled, we need to match only against the first fragment
            if if_data.any_frag == 0 && (uuidentry.flags & DCERPC_UUID_ENTRY_FLAG_FF == 0) {
                SCLogDebug!("any frag not enabled");
                continue;
            }
            // if the uuid has been rejected(uuidentry->result == 1), we skip to the next uuid
            if !uuidentry.acked || uuidentry.result != 0 {
                SCLogDebug!("Skipping to next UUID");
                continue;
            }

            let mut same = true;
            for i in 0..16 {
                if if_data.if_uuid[i] != uuidentry.uuid[i] {
                    SCLogDebug!("Iface UUID and BINDACK Accepted UUID does not match");
                    same = false;
                    break;
                }
            }
            if !same {
                continue;
            }
            let ctxid = tx.get_req_ctxid();
            if uuidentry.ctxid != ctxid {
                SCLogDebug!("CTX IDs/UUIDs do not match");
                continue;
            }

            if let Some(x) = &if_data.du16 {
                if !detect_match_uint(x, uuidentry.version) {
                    SCLogDebug!("Interface version did not match");
                    continue
                }
            }

            return 1;
        }
    }

    return 0;
}

fn parse_iface_data(arg: &str) -> Result<DCEIfaceData, ()> {
    let split_args: Vec<&str> = arg.split(',').collect();
    let mut du16 = None;
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
                match detect_parse_uint(split_args[1]) {
                    Ok((_, x)) => du16 = Some(x),
                    _ => {
                        return Err(());
                    }
                };
            }
        },
        3 => {
            match detect_parse_uint(split_args[1]) {
                Ok((_, x)) => du16 = Some(x),
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
        if_uuid,
        du16,
        any_frag,
    })
}

fn convert_str_to_u32(arg: &str) -> Result<u32, ()> {
    match arg.parse::<u32>() {
        Ok(res) => Ok(res),
        _ => Err(()),
    }
}

fn parse_opnum_data_ranges(arg: &str) -> Result<DCEOpnumData, ()> {
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

    Ok(DCEOpnumData::Ranges(DCEOpnumDataRanges {
        data: dce_opnum_data,
    }))
}

fn parse_opnum_data(arg: &str) -> Result<DCEOpnumData, ()> {
    if let Ok(r) = parse_opnum_data_ranges(arg) {
        return Ok(r);
    }
    if let Ok((_, du16)) = detect_parse_uint::<u16>(arg) {
        return Ok(DCEOpnumData::Num(du16));
    }
    return Err(());
}

unsafe fn dcerpc_tx_match_dce_iface(
    tx: *mut c_void, state: *mut c_void, if_data: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, DCERPCTransaction);
    let state = cast_pointer!(state, DCERPCState);
    let if_data = cast_pointer!(if_data, DCEIfaceData);

    let first_req_seen = tx.get_first_req_seen();
    if first_req_seen == 0 {
        return 0;
    }

    if !(tx.req_cmd == DCERPC_TYPE_REQUEST || tx.resp_cmd == DCERPC_TYPE_RESPONSE) {
        return 0;
    }

    return match_backuuid(tx, state, if_data);
}

unsafe extern "C" fn dcerpc_iface_match(
    _de: *mut DetectEngineThreadCtx, f: *mut crate::flow::Flow, _flags: u8, state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    if SCFlowGetAppProtocol(f) == ALPROTO_DCERPC {
        return dcerpc_tx_match_dce_iface(tx, state, ctx);
    }
    if smb_tx_match_dce_iface(state, tx, ctx) != 1 {
        return 0;
    }

    return 1;
}

unsafe fn dcerpc_iface_parse(carg: *const c_char) -> *mut c_void {
    let arg = match CStr::from_ptr(carg).to_str() {
        Ok(arg) => arg,
        _ => {
            return std::ptr::null_mut();
        }
    };

    match parse_iface_data(arg) {
        Ok(detect) => Box::into_raw(Box::new(detect)) as *mut _,
        Err(_) => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn dcerpc_iface_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DCERPC) != 0 {
        return -1;
    }
    let ctx = dcerpc_iface_parse(raw);
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_DCERPC_IFACE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_DCERPC_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        dcerpc_iface_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn dcerpc_iface_free(_de: *mut DetectEngineCtx, ptr: *mut c_void) {
    if !ptr.is_null() {
        std::mem::drop(Box::from_raw(ptr as *mut DCEIfaceData));
    }
}

unsafe extern "C" fn dcerpc_tx_match_dce_opnum(tx: *mut c_void, ctx: *const SigMatchCtx) -> c_int {
    let tx = cast_pointer!(tx, DCERPCTransaction);
    let opnum_data = cast_pointer!(ctx, DCEOpnumData);

    let first_req_seen = tx.get_first_req_seen();
    if first_req_seen == 0 {
        return 0;
    }
    let opnum = tx.get_req_opnum();
    match opnum_data {
        DCEOpnumData::Num(ref num_data) => {
            if detect_match_uint(num_data, opnum) {
                return 1;
            }
        }
        DCEOpnumData::Ranges(ref ranges_data) => {
            for range in ranges_data.data.iter() {
                if range.range2 == DETECT_DCE_OPNUM_RANGE_UNINITIALIZED {
                    if range.range1 == opnum as u32 {
                        return 1;
                    }
                } else if range.range1 <= opnum as u32 && range.range2 >= opnum as u32 {
                    return 1;
                }
            }
        }
    }

    0
}

unsafe extern "C" fn dcerpc_opnum_parse(carg: *const c_char) -> *mut c_void {
    if let Ok(arg) = CStr::from_ptr(carg).to_str() {
        return match parse_opnum_data(arg) {
            Ok(detect) => Box::into_raw(Box::new(detect)) as *mut _,
            Err(_) => std::ptr::null_mut(),
        };
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn dcerpc_opnum_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DCERPC) != 0 {
        return -1;
    }
    let ctx = dcerpc_opnum_parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_DCERPC_OPNUM_KW_ID,
        ctx as *mut SigMatchCtx,
        G_DCERPC_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        dcerpc_opnum_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn dcerpc_opnum_match(
    _de: *mut DetectEngineThreadCtx, f: *mut crate::flow::Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    if SCFlowGetAppProtocol(f) == ALPROTO_DCERPC {
        return dcerpc_tx_match_dce_opnum(tx, ctx);
    }
    if smb_tx_match_dce_opnum(tx, ctx) != 1 {
        return 0;
    }

    return 1;
}

unsafe extern "C" fn dcerpc_opnum_free(_de: *mut DetectEngineCtx, ptr: *mut c_void) {
    if !ptr.is_null() {
        std::mem::drop(Box::from_raw(ptr as *mut DCEOpnumData));
    }
}

unsafe extern "C" fn dcerpc_stub_data_setup(
    de_ctx: *mut DetectEngineCtx, s: *mut Signature, _str: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de_ctx, s, G_DCERPC_STUB_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub const DETECT_CI_FLAGS_DCE_LE: u8 = 1 << 2;
pub const DETECT_CI_FLAGS_DCE_BE: u8 = 1 << 3;


unsafe extern "C" fn dcerpc_tx_get_stub_data(
    det_ctx: *mut DetectEngineThreadCtx, transforms: *const DetectEngineTransforms,
    _flow: *mut Flow, dir: u8, tx: *mut c_void, list_id: c_int,
) -> *mut InspectionBuffer {
    let tx = cast_pointer!(tx, DCERPCTransaction);
    let buffer = SCInspectionBufferGet(det_ctx, list_id);
    if !(*buffer).initialized {
        let (data, data_len) = if (dir & STREAM_TOSERVER) != 0 {
            (
                tx.stub_data_buffer_ts.as_ptr(),
                tx.stub_data_buffer_ts.len() as u32,
            )
        } else {
            (
                tx.stub_data_buffer_tc.as_ptr(),
                tx.stub_data_buffer_tc.len() as u32,
            )
        };
        if tx.endianness > 0 {
            (*buffer).flags |= DETECT_CI_FLAGS_DCE_LE;
        } else {
            (*buffer).flags |= DETECT_CI_FLAGS_DCE_BE;
        }

        SCInspectionBufferSetupAndApplyTransforms(
            det_ctx, list_id, buffer, data, data_len, transforms,
        );
    }
    return buffer;
}

static mut G_DCERPC_OPNUM_KW_ID: u16 = 0;
static mut G_DCERPC_GENERIC_BUFFER_ID: c_int = 0;
static mut G_DCERPC_IFACE_KW_ID: u16 = 0;
static mut G_DCERPC_STUB_BUFFER_ID: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn SCDetectDcerpcRegister() {
    let kw = SCSigTableAppLiteElmt {
        name: b"dcerpc.opnum\0".as_ptr() as *const libc::c_char,
        desc: b"match on one or many operation numbers within the interface in a DCERPC header\0"
            .as_ptr() as *const libc::c_char,
        url: b"/rules/dcerpc-keywords.html#dcerpc-opnum\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(dcerpc_opnum_match),
        Setup: Some(dcerpc_opnum_setup),
        Free: Some(dcerpc_opnum_free),
        flags: 0,
    };
    G_DCERPC_OPNUM_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_DCERPC_GENERIC_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"dce_generic\0".as_ptr() as *const libc::c_char,
        ALPROTO_DCERPC,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    _ = SCDetectHelperBufferProgressRegister(
        b"dce_generic\0".as_ptr() as *const libc::c_char,
        ALPROTO_SMB,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    SCDetectHelperKeywordAliasRegister(
        G_DCERPC_OPNUM_KW_ID,
        b"dce_opnum\0".as_ptr() as *const libc::c_char,
    );

    let kw = SCSigTableAppLiteElmt {
        name: b"dcerpc.iface\0".as_ptr() as *const libc::c_char,
        desc: b"match on the value of the interface UUID in a DCERPC header\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/dcerpc-keywords.html#dcerpc-iface\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(dcerpc_iface_match),
        Setup: Some(dcerpc_iface_setup),
        Free: Some(dcerpc_iface_free),
        flags: 0,
    };
    G_DCERPC_IFACE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    SCDetectHelperKeywordAliasRegister(
        G_DCERPC_IFACE_KW_ID,
        b"dce_iface\0".as_ptr() as *const libc::c_char,
    );

    let kw_stub = SigTableElmtStickyBuffer {
        name: String::from("dcerpc.stub_data"),
        desc: String::from("match on the stub data in a DCERPC packet"),
        url: String::from("/rules/dcerpc-keywords.html#dcerpc-stub-data"),
        setup: dcerpc_stub_data_setup,
    };
    let stub_kw_id = helper_keyword_register_sticky_buffer(&kw_stub);

    G_DCERPC_STUB_BUFFER_ID = SCDetectRegisterMpmGeneric(
        b"dce_stub_data\0".as_ptr() as *const libc::c_char,
        b"dcerpc stub data\0".as_ptr() as *const libc::c_char,
        ALPROTO_DCERPC,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(dcerpc_tx_get_stub_data),
    );
    G_DCERPC_STUB_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"dce_stub_data\0".as_ptr() as *const libc::c_char,
        b"dcerpc stub data\0".as_ptr() as *const libc::c_char,
        ALPROTO_SMB,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(smb_tx_get_stub_data),
    );
    SCDetectHelperKeywordAliasRegister(
        stub_kw_id,
        b"dce_stub_data\0".as_ptr() as *const libc::c_char,
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::detect::uint::DetectUintMode;

    fn extract_op_version(i: &str) -> Result<(DetectUintMode, u16), ()> {
        match detect_parse_uint(i) {
            Ok((_, d)) => return Ok((d.mode, d.arg1)),
            _ => {
                return Err(());
            }
        }
    }
    #[test]
    fn test_extract_op_version() {
        let op_version = "<1";
        assert_eq!(
            Ok((DetectUintMode::DetectUintModeLt, 1)),
            extract_op_version(op_version)
        );

        let op_version = ">10";
        assert_eq!(
            Ok((DetectUintMode::DetectUintModeGt, 10)),
            extract_op_version(op_version)
        );

        let op_version = "=45";
        assert_eq!(
            Ok((DetectUintMode::DetectUintModeEqual, 45)),
            extract_op_version(op_version)
        );

        let op_version = "!0";
        assert_eq!(
            Ok((DetectUintMode::DetectUintModeNe, 0)),
            extract_op_version(op_version)
        );

        let op_version = "@1";
        assert!(extract_op_version(op_version).is_err());

        let op_version = "";
        assert_eq!(Err(()), extract_op_version(op_version));
    }

    #[test]
    fn test_match_iface_version() {
        let iface_data = DetectUintData::<u16> {
            mode: DetectUintMode::DetectUintModeEqual,
            arg1: 10,
            arg2: 0,
        };
        let version: u16 = 10;
        assert!(detect_match_uint(&iface_data, version));

        let version: u16 = 2;
        assert!(!detect_match_uint(&iface_data, version));
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
        let du16 = iface_data.du16.unwrap();
        assert_eq!(DetectUintMode::DetectUintModeGt, du16.mode);
        assert_eq!(1, du16.arg1);

        let arg = "12345678-1234-1234-1234-123456789ABC,any_frag";
        let iface_data = parse_iface_data(arg).unwrap();
        let expected_uuid = Ok(String::from("12345678-1234-1234-1234-123456789ABC").to_lowercase());
        let uuid = Uuid::from_slice(iface_data.if_uuid.as_slice());
        let uuid = uuid.map(|uuid| uuid.to_hyphenated().to_string());
        assert_eq!(expected_uuid, uuid);
        assert!(iface_data.du16.is_none());
        assert_eq!(1, iface_data.any_frag);

        let arg = "12345678-1234-1234-1234-123456789ABC,!10,any_frag";
        let iface_data = parse_iface_data(arg).unwrap();
        let expected_uuid = Ok(String::from("12345678-1234-1234-1234-123456789ABC").to_lowercase());
        let uuid = Uuid::from_slice(iface_data.if_uuid.as_slice());
        let uuid = uuid.map(|uuid| uuid.to_hyphenated().to_string());
        assert_eq!(expected_uuid, uuid);
        assert_eq!(1, iface_data.any_frag);
        let du16 = iface_data.du16.unwrap();
        assert_eq!(DetectUintMode::DetectUintModeNe, du16.mode);
        assert_eq!(10, du16.arg1);

        let arg = "12345678-1234-1234-1234-123456789ABC,>1,ay_frag";
        let iface_data = parse_iface_data(arg);
        assert!(iface_data.is_err());

        let arg = "12345678-1234-1234-1234-12345679ABC,>1,any_frag";
        let iface_data = parse_iface_data(arg);
        assert!(iface_data.is_err());

        let arg = "12345678-1234-1234-134-123456789ABC,>1,any_frag";
        let iface_data = parse_iface_data(arg);
        assert!(iface_data.is_err());

        let arg = "12345678-123-124-1234-123456789ABC,>1,any_frag";
        let iface_data = parse_iface_data(arg);
        assert!(iface_data.is_err());

        let arg = "1234568-1234-1234-1234-123456789ABC,>1,any_frag";
        let iface_data = parse_iface_data(arg);
        assert!(iface_data.is_err());

        let arg = "12345678-1234-1234-1234-123456789ABC,>65536,any_frag";
        let iface_data = parse_iface_data(arg);
        assert!(iface_data.is_err());

        let arg = "12345678-1234-1234-1234-123456789ABC,>=0,any_frag";
        let iface_data = parse_iface_data(arg);
        assert!(iface_data.is_err());

        let arg = "12345678-1234-1234-1234-123456789ABC,<0,any_frag";
        let iface_data = parse_iface_data(arg);
        assert!(iface_data.is_err());

        let arg = "12345678-1234-1234-1234-123456789ABC,>65535,any_frag";
        let iface_data = parse_iface_data(arg);
        assert!(iface_data.is_err());
    }

    #[test]
    fn test_parse_opnum_data() {
        let arg = "12";
        let opnum_data = parse_opnum_data(arg).unwrap();
        let DCEOpnumData::Ranges(opnum_data) = opnum_data else {
            panic!("Result should have been ranges.");
        };
        assert_eq!(1, opnum_data.data.len());
        assert_eq!(12, opnum_data.data[0].range1);
        assert_eq!(
            DETECT_DCE_OPNUM_RANGE_UNINITIALIZED,
            opnum_data.data[0].range2
        );

        let arg = "12,24";
        let opnum_data = parse_opnum_data(arg).unwrap();
        let DCEOpnumData::Ranges(opnum_data) = opnum_data else {
            panic!("Result should have been ranges.");
        };
        assert_eq!(2, opnum_data.data.len());
        assert_eq!(12, opnum_data.data[0].range1);
        assert_eq!(24, opnum_data.data[1].range1);

        let arg = "12,12-24";
        let opnum_data = parse_opnum_data(arg).unwrap();
        let DCEOpnumData::Ranges(opnum_data) = opnum_data else {
            panic!("Result should have been ranges.");
        };
        assert_eq!(2, opnum_data.data.len());
        assert_eq!(12, opnum_data.data[0].range1);
        assert_eq!(12, opnum_data.data[1].range1);
        assert_eq!(24, opnum_data.data[1].range2);

        let arg = "12-14,12,121,62-78";
        let opnum_data = parse_opnum_data(arg).unwrap();
        let DCEOpnumData::Ranges(opnum_data) = opnum_data else {
            panic!("Result should have been ranges.");
        };
        assert_eq!(4, opnum_data.data.len());
        assert_eq!(12, opnum_data.data[0].range1);
        assert_eq!(14, opnum_data.data[0].range2);
        assert_eq!(121, opnum_data.data[2].range1);
        assert_eq!(78, opnum_data.data[3].range2);

        let arg = "12,26,62,61,6513-6666";
        let opnum_data = parse_opnum_data(arg).unwrap();
        let DCEOpnumData::Ranges(opnum_data) = opnum_data else {
            panic!("Result should have been ranges.");
        };
        assert_eq!(5, opnum_data.data.len());
        assert_eq!(61, opnum_data.data[3].range1);
        assert_eq!(6513, opnum_data.data[4].range1);

        let arg = "12,26,62,61,6513--";
        let opnum_data = parse_opnum_data(arg);
        assert!(opnum_data.is_err());

        let arg = "12-14,12,121,62-8";
        let opnum_data = parse_opnum_data(arg);
        assert!(opnum_data.is_err());
    }
}
