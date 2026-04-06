/* Copyright (C) 2026 Open Information Security Foundation
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

//! Detection utils.

use std::ffi::{c_int, CString};
use suricata_sys::sys::{
    DetectEngineCtx, SCDetectHelperKeywordRegister, SCDetectHelperKeywordSetCleanCString,
    SCSigTableAppLiteElmt, Signature, SIGMATCH_INFO_MULTI_BUFFER, SIGMATCH_INFO_STICKY_BUFFER,
    SIGMATCH_NOOPT,
};

/// Rust app-layer light version of SigTableElmt for simple sticky buffer
pub struct SigTableElmtStickyBuffer {
    /// keyword name
    pub name: String,
    /// keyword description
    pub desc: String,
    /// keyword documentation url
    pub url: String,
    /// function callback to parse and setup keyword in rule
    pub setup: unsafe extern "C" fn(
        de: *mut DetectEngineCtx,
        s: *mut Signature,
        raw: *const std::os::raw::c_char,
    ) -> c_int,
}

fn helper_keyword_register_buffer_flags(kw: &SigTableElmtStickyBuffer, flags: u32) -> u16 {
    let name = CString::new(kw.name.as_bytes()).unwrap().into_raw();
    let desc = CString::new(kw.desc.as_bytes()).unwrap().into_raw();
    let url = CString::new(kw.url.as_bytes()).unwrap().into_raw();
    let st = SCSigTableAppLiteElmt {
        name,
        desc,
        url,
        Setup: Some(kw.setup),
        flags,
        AppLayerTxMatch: None,
        Free: None,
    };
    unsafe {
        let r = SCDetectHelperKeywordRegister(&st);
        SCDetectHelperKeywordSetCleanCString(r);
        r
    }
}

pub fn helper_keyword_register_multi_buffer(kw: &SigTableElmtStickyBuffer) -> u16 {
    helper_keyword_register_buffer_flags(
        kw,
        SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_INFO_MULTI_BUFFER,
    )
}

pub fn helper_keyword_register_sticky_buffer(kw: &SigTableElmtStickyBuffer) -> u16 {
    helper_keyword_register_buffer_flags(kw, SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER)
}
