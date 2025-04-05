/* Copyright (C) 2025 Open Information Security Foundation
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

use crate::detect::SIGMATCH_NOOPT;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, InspectionBuffer, SCDetectHelperTransformRegister,
    SCDetectSignatureAddTransform, SCTransformTableElmt, Signature, SCInspectionBufferCheckAndExpand,
    SCInspectionBufferTruncate,
};

use std::os::raw::{c_int, c_void};
use std::ptr;

static mut G_TRANSFORM_DOMAIN_ID: c_int = 0;
static mut G_TRANSFORM_TLD_ID: c_int = 0;

unsafe extern "C" fn domain_setup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_DOMAIN_ID, ptr::null_mut());
}

fn get_domain(input: &[u8], output: &mut [u8]) -> u32 {
    if let Some(domain) = psl::domain(input) {
        let domain = domain.as_bytes();
        let len = domain.len();
        output[0..len].copy_from_slice(domain);
        return domain.len() as u32;
    }
    0
}

unsafe extern "C" fn domain_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, _ctx: *mut c_void,
) {
    let input = (*buffer).inspect;
    let input_len = (*buffer).inspect_len;
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = SCInspectionBufferCheckAndExpand(buffer, input_len);
    if output.is_null() {
        // allocation failure
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, input_len as usize);

    let output_len = get_domain(input, output);

    SCInspectionBufferTruncate(buffer, output_len);
}

unsafe extern "C" fn tld_setup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_TLD_ID, ptr::null_mut());
}

fn get_tld(input: &[u8], output: &mut [u8]) -> u32 {
    if let Some(domain) = psl::domain(input) {
        let tldb = domain.suffix().as_bytes();
        let len = tldb.len();
        let domain = tldb;
        output[0..len].copy_from_slice(domain);
        return domain.len() as u32;
    }
    0
}

unsafe extern "C" fn tld_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, _ctx: *mut c_void,
) {
    let input = (*buffer).inspect;
    let input_len = (*buffer).inspect_len;
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = SCInspectionBufferCheckAndExpand(buffer, input_len);
    if output.is_null() {
        // allocation failure
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, input_len as usize);

    let output_len = get_tld(input, output);

    SCInspectionBufferTruncate(buffer, output_len);
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectTransformDomainRegister() {
    let kw = SCTransformTableElmt {
        name: b"domain\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer to extract the domain\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#domain\0".as_ptr() as *const libc::c_char,
        Setup: Some(domain_setup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(domain_transform),
        Free: None,
        TransformValidate: None,
        TransformId: None,
    };
    unsafe {
        G_TRANSFORM_DOMAIN_ID = SCDetectHelperTransformRegister(&kw);
        if G_TRANSFORM_DOMAIN_ID < 0 {
            SCLogWarning!("Failed registering transform domain");
        }
    }

    let kw = SCTransformTableElmt {
        name: b"tld\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer to extract the tld\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#tld\0".as_ptr() as *const libc::c_char,
        Setup: Some(tld_setup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(tld_transform),
        Free: None,
        TransformValidate: None,
        TransformId: None,
    };
    unsafe {
        G_TRANSFORM_TLD_ID = SCDetectHelperTransformRegister(&kw);
        if G_TRANSFORM_TLD_ID < 0 {
            SCLogWarning!("Failed registering transform tld");
        }
    }
}
