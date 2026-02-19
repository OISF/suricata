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

// Author: Frank Honza <frank.honza@dcso.de>

use super::ike::ALPROTO_IKE;
use super::ipsec_parser::IkeV2Transform;
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{detect_match_uint, DetectUintData, SCDetectU8Free, SCDetectU8Parse};
use crate::detect::{
    helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer, SIGMATCH_INFO_UINT8,
};
use crate::ike::ike::*;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectHelperBufferRegister, SCDetectHelperKeywordRegister,
    SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList, SCSigTableAppLiteElmt, Signature,
};

#[no_mangle]
pub extern "C" fn SCIkeStateGetNonce(
    tx: &IKETransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    debug_validate_bug_on!(buffer.is_null() || buffer_len.is_null());

    if tx.ike_version == 1 && !tx.hdr.ikev1_header.nonce.is_empty() {
        let p = &tx.hdr.ikev1_header.nonce;
        unsafe {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
        }
        return 1;
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn SCIkeStateGetKeyExchange(
    tx: &IKETransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    debug_validate_bug_on!(buffer.is_null() || buffer_len.is_null());

    if tx.ike_version == 1 && !tx.hdr.ikev1_header.key_exchange.is_empty() {
        let p = &tx.hdr.ikev1_header.key_exchange;
        unsafe {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
        }
        return 1;
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCIkeTxGetVendor(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, i: u32, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, IKETransaction);
    if tx.ike_version == 1 && i < tx.hdr.ikev1_header.vendor_ids.len() as u32 {
        *len = tx.hdr.ikev1_header.vendor_ids[i as usize].len() as u32;
        *buf = tx.hdr.ikev1_header.vendor_ids[i as usize].as_ptr();
        return true;
    }

    *buf = ptr::null();
    *len = 0;

    return false;
}

#[no_mangle]
pub extern "C" fn SCIkeStateGetSaAttribute(
    tx: &IKETransaction, sa_type: *const std::os::raw::c_char, value: *mut u32,
) -> u8 {
    debug_validate_bug_on!(value.is_null());
    let mut ret_val = 0;
    let mut ret_code = 0;
    let sa_type_s: Result<_, _>;

    unsafe { sa_type_s = CStr::from_ptr(sa_type).to_str() }
    SCLogDebug!("{:#?}", sa_type_s);

    if let Ok(sa) = sa_type_s {
        if tx.ike_version == 1 {
            if !tx.hdr.ikev1_transforms.is_empty() {
                // there should be only one chosen server_transform, check event
                if let Some(server_transform) = tx.hdr.ikev1_transforms.first() {
                    for attr in server_transform {
                        if attr.attribute_type.to_string() == sa {
                            if let Some(numeric_value) = attr.numeric_value {
                                ret_val = numeric_value;
                                ret_code = 1;
                                break;
                            }
                        }
                    }
                }
            }
        } else if tx.ike_version == 2 {
            for attr in tx.hdr.ikev2_transforms.iter() {
                match attr {
                    IkeV2Transform::Encryption(e) => {
                        if sa == "alg_enc" {
                            ret_val = e.0 as u32;
                            ret_code = 1;
                            break;
                        }
                    }
                    IkeV2Transform::Auth(e) => {
                        if sa == "alg_auth" {
                            ret_val = e.0 as u32;
                            ret_code = 1;
                            break;
                        }
                    }
                    IkeV2Transform::PRF(ref e) => {
                        if sa == "alg_prf" {
                            ret_val = e.0 as u32;
                            ret_code = 1;
                            break;
                        }
                    }
                    IkeV2Transform::DH(ref e) => {
                        if sa == "alg_dh" {
                            ret_val = e.0 as u32;
                            ret_code = 1;
                            break;
                        }
                    }
                    _ => (),
                }
            }
        }
    }

    unsafe {
        *value = ret_val;
    }
    return ret_code;
}

#[no_mangle]
pub unsafe extern "C" fn SCIkeStateGetKeyExchangePayloadLength(
    tx: &IKETransaction, value: *mut u32,
) -> u8 {
    debug_validate_bug_on!(value.is_null());

    if tx.ike_version == 1 && !tx.hdr.ikev1_header.key_exchange.is_empty() {
        *value = tx.hdr.ikev1_header.key_exchange.len() as u32;
        return 1;
    }

    *value = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCIkeStateGetNoncePayloadLength(
    tx: &IKETransaction, value: *mut u32,
) -> u8 {
    debug_validate_bug_on!(value.is_null());

    if tx.ike_version == 1 && !tx.hdr.ikev1_header.nonce.is_empty() {
        *value = tx.hdr.ikev1_header.nonce.len() as u32;
        return 1;
    }

    *value = 0;
    return 0;
}

unsafe extern "C" fn ike_tx_get_spi_initiator(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, IKETransaction);
    *buffer = tx.hdr.spi_initiator.as_ptr();
    *buffer_len = tx.hdr.spi_initiator.len() as u32;
    return true;
}

unsafe extern "C" fn ike_tx_get_spi_responder(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, IKETransaction);
    *buffer = tx.hdr.spi_responder.as_ptr();
    *buffer_len = tx.hdr.spi_responder.len() as u32;
    return true;
}

unsafe extern "C" fn ike_detect_exchtype_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IKE) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_IKE_EXCHTYPE_KW_ID,
        ctx as *mut suricata_sys::sys::SigMatchCtx,
        G_IKE_EXCHTYPE_BUFFER_ID,
    )
    .is_null()
    {
        ike_detect_exchtype_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ike_detect_exchtype_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut crate::flow::Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const suricata_sys::sys::SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, IKETransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    let mut exch_type: u8 = 0;
    let found = if tx.ike_version == 1 {
        if let Some(r) = tx.hdr.ikev1_header.exchange_type {
            exch_type = r;
            true
        } else {
            false
        }
    } else if tx.ike_version == 2 {
        exch_type = tx.hdr.ikev2_header.exch_type.0;
        true
    } else {
        false
    };
    if found && detect_match_uint(ctx, exch_type) {
        return 1;
    }
    return 0;
}

unsafe extern "C" fn ike_detect_exchtype_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

static mut G_IKE_SPI_INITIATOR_BUFFER_ID: c_int = 0;
static mut G_IKE_SPI_RESPONDER_BUFFER_ID: c_int = 0;
static mut G_IKE_EXCHTYPE_KW_ID: u16 = 0;
static mut G_IKE_EXCHTYPE_BUFFER_ID: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn SCDetectIkeRegister() {
    // Inline registration for ike.exchtype keyword
    let kw = SCSigTableAppLiteElmt {
        name: b"ike.exchtype\0".as_ptr() as *const libc::c_char,
        desc: b"match IKE exchange type\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ike-keywords.html#ike-exchtype\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(ike_detect_exchtype_match),
        Setup: Some(ike_detect_exchtype_setup),
        Free: Some(ike_detect_exchtype_free),
        flags: SIGMATCH_INFO_UINT8,
    };
    G_IKE_EXCHTYPE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_IKE_EXCHTYPE_BUFFER_ID = SCDetectHelperBufferRegister(
        b"ike.exchtype\0".as_ptr() as *const libc::c_char,
        ALPROTO_IKE,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
    let kw_initiator = SigTableElmtStickyBuffer {
        name: String::from("ike.init_spi"),
        desc: String::from("sticky buffer to match on the IKE spi initiator"),
        url: String::from("/rules/ike-keywords.html#ike-init_spi"),
        setup: ike_spi_initiator_setup,
    };
    helper_keyword_register_sticky_buffer(&kw_initiator);
    G_IKE_SPI_INITIATOR_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"ike_init_spi\0".as_ptr() as *const libc::c_char,
        b"ike init spi\0".as_ptr() as *const libc::c_char,
        ALPROTO_IKE,
        STREAM_TOSERVER,
        Some(ike_tx_get_spi_initiator),
    );

    let kw_responder = SigTableElmtStickyBuffer {
        name: String::from("ike.resp_spi"),
        desc: String::from("sticky buffer to match on the IKE spi responder"),
        url: String::from("/rules/ike-keywords.html#ike-resp_spi"),
        setup: ike_spi_responder_setup,
    };
    helper_keyword_register_sticky_buffer(&kw_responder);
    G_IKE_SPI_RESPONDER_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"ike_resp_spi\0".as_ptr() as *const libc::c_char,
        b"ike resp spi\0".as_ptr() as *const libc::c_char,
        ALPROTO_IKE,
        STREAM_TOCLIENT,
        Some(ike_tx_get_spi_responder),
    );
}

unsafe extern "C" fn ike_spi_initiator_setup(
    de_ctx: *mut DetectEngineCtx, s: *mut Signature, _str: *const c_char,
) -> c_int {
    if SCDetectBufferSetActiveList(de_ctx, s, G_IKE_SPI_INITIATOR_BUFFER_ID) < 0 {
        return -1;
    }

    if SCDetectSignatureSetAppProto(s, ALPROTO_IKE) < 0 {
        return -1;
    }

    return 0;
}

unsafe extern "C" fn ike_spi_responder_setup(
    de_ctx: *mut DetectEngineCtx, s: *mut Signature, _str: *const c_char,
) -> c_int {
    if SCDetectBufferSetActiveList(de_ctx, s, G_IKE_SPI_RESPONDER_BUFFER_ID) < 0 {
        return -1;
    }

    if SCDetectSignatureSetAppProto(s, ALPROTO_IKE) < 0 {
        return -1;
    }

    return 0;
}
