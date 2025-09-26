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

// written by Pierre Chifflier  <chifflier@wzdftpd.net>

use suricata_sys::sys::AppProtoEnum::ALPROTO_NFS;
use suricata_sys::sys::{
    AppProto, DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectHelperBufferRegister,
    SCDetectHelperKeywordRegister, SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList,
    SCSigTableAppLiteElmt, SigMatchCtx, Signature,
};

use super::nfs::{NFSTransaction, NFSTransactionTypeData};
use super::types::{NfsProc3, NfsProc4};
use crate::core::STREAM_TOSERVER;
use crate::detect::uint::{
    detect_match_uint, detect_parse_uint_enum, detect_parse_uint_inclusive, DetectUintData,
    SCDetectU32Free,
};
use crate::detect::{SIGMATCH_INFO_ENUM_UINT, SIGMATCH_INFO_MULTI_UINT, SIGMATCH_INFO_UINT32};

use std::ffi::{c_int, CStr};
use std::os::raw::c_void;

static mut G_NFS_PROCEDURE_KW_ID: u16 = 0;
static mut G_NFS_PROCEDURE_BUFFER_ID: c_int = 0;

struct DetectNfsProcedureDataVersion {
    v3: Option<DetectUintData<u32>>,
    v4: Option<DetectUintData<u32>>,
}

enum DetectNfsProcedureData {
    VersionLiteral(DetectNfsProcedureDataVersion),
    Num(DetectUintData<u32>),
}

fn nfs_procedure_parse_aux(s: &str) -> Option<DetectNfsProcedureData> {
    if let Ok((_, ctx)) = detect_parse_uint_inclusive::<u32>(s) {
        return Some(DetectNfsProcedureData::Num(ctx));
    }
    let v3 = detect_parse_uint_enum::<u32, NfsProc3>(s);
    let v4 = detect_parse_uint_enum::<u32, NfsProc4>(s);
    if v3.is_none() && v4.is_none() {
        return None;
    }
    return Some(DetectNfsProcedureData::VersionLiteral(
        DetectNfsProcedureDataVersion { v3, v4 },
    ));
}

unsafe extern "C" fn nfs_procedure_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u32> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = nfs_procedure_parse_aux(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn nfs_procedure_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_NFS as AppProto) != 0 {
        return -1;
    }
    let ctx = nfs_procedure_parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_NFS_PROCEDURE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_NFS_PROCEDURE_BUFFER_ID,
    )
    .is_null()
    {
        nfs_procedure_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

fn nfs_procedure_match_val(proc: u32, nfs_version: u16, ctx: &DetectNfsProcedureData) -> bool {
    match ctx {
        DetectNfsProcedureData::VersionLiteral(ver) => {
            if nfs_version < 4 {
                if let Some(du32v3) = &ver.v3 {
                    return detect_match_uint(du32v3, proc);
                }
            } else if let Some(du32v4) = &ver.v4 {
                return detect_match_uint(du32v4, proc);
            }
            return false;
        }
        DetectNfsProcedureData::Num(du32) => {
            return detect_match_uint(du32, proc);
        }
    }
}

fn nfs_procedure_match_aux(tx: &NFSTransaction, ctx: &DetectNfsProcedureData) -> c_int {
    // first try tx.procedure
    if nfs_procedure_match_val(tx.procedure, tx.nfs_version, ctx) {
        return 1;
    }

    if !tx.is_file_tx {
        return 0;
    }

    /* file tx handling follows */
    if let Some(NFSTransactionTypeData::FILE(ref tdf)) = tx.type_data {
        for proc in &tdf.file_additional_procs {
            if nfs_procedure_match_val(*proc, tx.nfs_version, ctx) {
                return 1;
            }
        }
    }
    return 0;
}

unsafe extern "C" fn nfs_procedure_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, NFSTransaction);
    let ctx = cast_pointer!(ctx, DetectNfsProcedureData);
    return nfs_procedure_match_aux(tx, ctx);
}

unsafe extern "C" fn nfs_procedure_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    SCDetectU32Free(ctx);
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectNfsProcedureRegister() {
    let kw = SCSigTableAppLiteElmt {
        name: b"nfs_procedure\0".as_ptr() as *const libc::c_char,
        desc: b"match NFS procedure\0".as_ptr() as *const libc::c_char,
        url: b"/rules/nfs-keywords.html#procedure\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(nfs_procedure_match),
        Setup: Some(nfs_procedure_setup),
        Free: Some(nfs_procedure_free),
        flags: SIGMATCH_INFO_UINT32 | SIGMATCH_INFO_MULTI_UINT | SIGMATCH_INFO_ENUM_UINT,
    };
    G_NFS_PROCEDURE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_NFS_PROCEDURE_BUFFER_ID = SCDetectHelperBufferRegister(
        b"nfs_procedure\0".as_ptr() as *const libc::c_char,
        ALPROTO_NFS as AppProto,
        STREAM_TOSERVER,
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::detect::uint::DetectUintMode;

    #[test]
    fn nfs_procedure_parse_test() {
        let ctx = nfs_procedure_parse_aux("1430000000").unwrap();
        if let DetectNfsProcedureData::Num(ctx) = ctx {
            assert_eq!(ctx.arg1, 1430000000);
            assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);
        } else {
            panic!("not right enum");
        }

        let ctx = nfs_procedure_parse_aux(">1430000000").unwrap();
        if let DetectNfsProcedureData::Num(ctx) = ctx {
            assert_eq!(ctx.arg1, 1430000000);
            assert_eq!(ctx.mode, DetectUintMode::DetectUintModeGt);
        } else {
            panic!("not right enum");
        }

        let ctx = nfs_procedure_parse_aux("<1430000000").unwrap();
        if let DetectNfsProcedureData::Num(ctx) = ctx {
            assert_eq!(ctx.arg1, 1430000000);
            assert_eq!(ctx.mode, DetectUintMode::DetectUintModeLt);
        } else {
            panic!("not right enum");
        }

        let ctx = nfs_procedure_parse_aux("1430000001<>1470000000").unwrap();
        if let DetectNfsProcedureData::Num(ctx) = ctx {
            assert_eq!(ctx.arg1, 1430000000);
            assert_eq!(ctx.arg2, 1470000001);
            assert_eq!(ctx.mode, DetectUintMode::DetectUintModeRange);
        } else {
            panic!("not right enum");
        }

        assert!(nfs_procedure_parse_aux("A").is_none());
        assert!(nfs_procedure_parse_aux(">1430000000<>1470000000").is_none());
        assert!(nfs_procedure_parse_aux("1430000000<>").is_none());
        assert!(nfs_procedure_parse_aux("<>1430000000").is_none());
        assert!(nfs_procedure_parse_aux("").is_none());
        assert!(nfs_procedure_parse_aux(" ").is_none());
        assert!(nfs_procedure_parse_aux("1490000000<>1430000000").is_none());

        let ctx = nfs_procedure_parse_aux("1430000001 <> 1490000000").unwrap();
        if let DetectNfsProcedureData::Num(ctx) = ctx {
            assert_eq!(ctx.arg1, 1430000000);
            assert_eq!(ctx.arg2, 1490000001);
            assert_eq!(ctx.mode, DetectUintMode::DetectUintModeRange);
        } else {
            panic!("not right enum");
        }

        let ctx = nfs_procedure_parse_aux("> 1430000000 ").unwrap();
        if let DetectNfsProcedureData::Num(ctx) = ctx {
            assert_eq!(ctx.arg1, 1430000000);
            assert_eq!(ctx.mode, DetectUintMode::DetectUintModeGt);
        } else {
            panic!("not right enum");
        }

        let ctx = nfs_procedure_parse_aux("<   1490000000 ").unwrap();
        if let DetectNfsProcedureData::Num(ctx) = ctx {
            assert_eq!(ctx.arg1, 1490000000);
            assert_eq!(ctx.mode, DetectUintMode::DetectUintModeLt);
        } else {
            panic!("not right enum");
        }

        let ctx = nfs_procedure_parse_aux("   1490000000 ").unwrap();
        if let DetectNfsProcedureData::Num(ctx) = ctx {
            assert_eq!(ctx.arg1, 1490000000);
            assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);
        } else {
            panic!("not right enum");
        }
    }
}
