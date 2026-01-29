/* Copyright (C) 2021 Open Information Security Foundation
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

use super::quic::ALPROTO_QUIC;
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use crate::quic::quic::QuicTransaction;
use std::os::raw::{c_int, c_void};
use std::ptr;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectSignatureSetAppProto, Signature,
};

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetUa(
    tx: &QuicTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ua) = &tx.ua {
        *buffer = ua.as_ptr();
        *buffer_len = ua.len() as u32;
        1
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;
        0
    }
}

unsafe extern "C" fn quic_tx_get_sni(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if let Some(sni) = &tx.sni {
        *buffer = sni.as_ptr();
        *buffer_len = sni.len() as u32;
        true
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetJa3(
    tx: &QuicTransaction, dir: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    if tx.client {
        if dir & STREAM_TOSERVER == 0 {
            return false;
        }
    } else if dir & STREAM_TOCLIENT == 0 {
        return false;
    }
    if let Some(ja3) = &tx.ja3 {
        *buffer = ja3.as_ptr();
        *buffer_len = ja3.len() as u32;
        return true;
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetJa4(
    tx: &QuicTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ja4) = &tx.ja4 {
        *buffer = ja4.as_ref().as_ptr();
        *buffer_len = ja4.as_ref().len() as u32;
        1
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;
        0
    }
}

unsafe extern "C" fn quic_tx_get_version(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if tx.header.flags.is_long {
        let s = &tx.header.version_buf;
        *buffer = s.as_ptr();
        *buffer_len = s.len() as u32;
        true
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetCyuHash(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, i: u32, buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if (i as usize) < tx.cyu.len() {
        let cyu = &tx.cyu[i as usize];

        let p = &cyu.hash;

        *buffer = p.as_ptr();
        *buffer_len = p.len() as u32;

        true
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;

        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetCyuString(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, i: u32, buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if (i as usize) < tx.cyu.len() {
        let cyu = &tx.cyu[i as usize];

        let p = &cyu.string;

        *buffer = p.as_ptr();
        *buffer_len = p.len() as u32;
        true
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;

        false
    }
}

unsafe extern "C" fn quic_version_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_QUIC) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_QUIC_VERSION_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn quic_sni_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_QUIC) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_QUIC_SNI_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

static mut G_QUIC_VERSION_BUFFER_ID: c_int = 0;
static mut G_QUIC_SNI_BUFFER_ID: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn SCDetectQuicRegister() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("quic.version"),
        desc: String::from("match Quic version"),
        url: String::from("/rules/quic-keywords.html#quic-version"),
        setup: quic_version_setup,
    };
    helper_keyword_register_sticky_buffer(&kw);
    G_QUIC_VERSION_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"quic_version\0".as_ptr() as *const libc::c_char,
        b"quic version\0".as_ptr() as *const libc::c_char,
        ALPROTO_QUIC,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(quic_tx_get_version),
    );

    let kw = SigTableElmtStickyBuffer {
        name: String::from("quic.sni"),
        desc: String::from("match Quic sni"),
        url: String::from("/rules/quic-keywords.html#quic-sni"),
        setup: quic_sni_setup,
    };
    helper_keyword_register_sticky_buffer(&kw);
    G_QUIC_SNI_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"quic_sni\0".as_ptr() as *const libc::c_char,
        b"quic sni\0".as_ptr() as *const libc::c_char,
        ALPROTO_QUIC,
        STREAM_TOSERVER,
        Some(quic_tx_get_sni),
    );
}
