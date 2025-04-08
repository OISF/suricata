/* Copyright (C) 2024-2025 Open Information Security Foundation
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

//! Module for transforms

use std::os::raw::{c_char, c_int, c_void};

pub mod casechange;
pub mod compress_whitespace;
pub mod domain;
pub mod dotprefix;
pub mod hash;
pub mod http_headers;
pub mod strip_whitespace;
pub mod urldecode;
pub mod xor;

#[repr(C)]
#[allow(non_snake_case)]
pub struct SCTransformTableElmt {
    pub name: *const c_char,
    pub desc: *const c_char,
    pub url: *const c_char,
    pub flags: u16,
    pub Setup: unsafe extern "C" fn(de: *mut c_void, s: *mut c_void, raw: *const c_char) -> c_int,
    pub Free: Option<unsafe extern "C" fn(de: *mut c_void, ptr: *mut c_void)>,
    pub Transform: unsafe extern "C" fn(_det: *mut c_void, inspect_buf: *mut c_void, options: *mut c_void),
    pub TransformValidate:
        Option<unsafe extern "C" fn(content: *const u8, len: u16, context: *mut c_void) -> bool>,
}

/// cbindgen:ignore
extern "C" {
    pub fn DetectSignatureAddTransform(
        s: *mut c_void, transform_id: c_int, ctx: *mut c_void,
    ) -> c_int;
    pub fn InspectionBufferPtr(buf: *const c_void) -> *const u8;
    pub fn InspectionBufferLength(buf: *const c_void) -> u32;
    pub fn InspectionBufferCopy(ibuf: *const c_void, buf: *const u8, buf_len: u32);
    pub fn DetectHelperTransformRegister(kw: *const SCTransformTableElmt) -> c_int;
    pub fn InspectionBufferCheckAndExpand(ibuf: *const c_void, buf_len: u32) -> *mut u8;
    pub fn InspectionBufferTruncate(ibuf: *const c_void, buf_len: u32);
}
