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

// Author: Jeff Lucovsky <jlucovsky@oisf.net>

use std::ffi::{c_char, c_uchar};
use std::net::Ipv6Addr;

/// Writes the compressed IPv6 string into `out_buf`, which has length `out_len`.
/// Returns the number of bytes written (excluding the null terminator),
/// or 0 on error (invalid addr pointer, buffer too small, etc.)
#[no_mangle]
pub unsafe extern "C" fn SCIPv6Compress(
    addr: *const c_uchar, // pointer to 16-byte IPv6
    out_buf: *mut c_char, // out buffer allocated by caller
    out_len: usize,       // size of out buffer
) -> usize {
    if addr.is_null() || out_buf.is_null() || out_len == 0 {
        return 0;
    }

    // get 16-byte IPv6 address
    let fixed = std::ptr::read_unaligned(addr as *const [u8; 16]);
    let ipv6 = Ipv6Addr::from(fixed);

    let ipv6_str = ipv6.to_string();
    // Sufficient room?
    if ipv6_str.len() + 1 > out_len {
        return 0;
    }
    // Copy string + NULL termination
    let len = ipv6_str.len();
    crate::ffi::strings::copy_to_c_char(ipv6_str, out_buf, out_len);
    len
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::os::raw::{c_char, c_uchar};

    struct CompressedResult {
        string: String,
    }

    fn call_compresser(bytes: &[u8; 16]) -> Option<CompressedResult> {
        let mut out = vec![0u8; 64];
        let len = unsafe {
            SCIPv6Compress(
                bytes.as_ptr() as *const c_uchar,
                out.as_mut_ptr() as *mut c_char,
                out.len(),
            )
        };

        if len == 0 {
            return None;
        }

        let s = String::from_utf8(out[..len].to_vec()).unwrap();
        Some(CompressedResult { string: s })
    }

    #[test]
    fn test_ipv6_compress_success_zero_addr() {
        let addr = [0u8; 16];
        let out = call_compresser(&addr).unwrap();
        assert_eq!(out.string, "::");
        assert_eq!(out.string.len(), 2);
    }

    #[test]
    fn test_ipv6_compress_success_loopback() {
        let mut addr = [0u8; 16];
        addr[15] = 1; // ::1
        let out = call_compresser(&addr).unwrap();
        assert_eq!(out.string, "::1");
        assert_eq!(out.string.len(), 3);
    }

    #[test]
    fn test_ipv6_compress_success_normal_addr() {
        let addr = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let out = call_compresser(&addr).unwrap();
        assert_eq!(out.string, "2001:db8::1");
        assert_eq!(out.string.len(), 11);
    }

    #[test]
    fn test_ipv6_compress_success_ipv4_mapped() {
        let addr: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1];
        let out = call_compresser(&addr).unwrap();
        assert_eq!(out.string, "::ffff:192.168.0.1");
        assert_eq!(out.string.len(), 18);
    }

    #[test]
    fn test_ipv6_compress_success_no_zero_compression() {
        // 2001:db8:1:2:3:4:5:6 (fully expanded, no zero-run)
        let addr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
            0x00, 0x06,
        ];
        let out = call_compresser(&addr).unwrap();
        assert_eq!(out.string, "2001:db8:1:2:3:4:5:6");
        assert_eq!(out.string.len(), 20);
    }

    #[test]
    fn test_ipv6_compress_fail_null_addr() {
        let mut out = vec![0u8; 64];
        let len =
            unsafe { SCIPv6Compress(std::ptr::null(), out.as_mut_ptr() as *mut c_char, out.len()) };
        assert_eq!(len, 0);
    }

    #[test]
    fn test_ipv6_compress_fail_null_out_buf() {
        let addr = [0u8; 16];
        let len =
            unsafe { SCIPv6Compress(addr.as_ptr() as *const c_uchar, std::ptr::null_mut(), 64) };
        assert_eq!(len, 0);
    }

    #[test]
    fn test_ipv6_compress_fail_out_buf_too_small() {
        let addr = [0u8; 16];
        // "::" is 2 bytes + NUL = 3, so give only length 2
        let mut out = vec![0u8; 2];
        let len = unsafe {
            SCIPv6Compress(
                addr.as_ptr() as *const c_uchar,
                out.as_mut_ptr() as *mut c_char,
                out.len(),
            )
        };
        assert_eq!(len, 0);
    }

    #[test]
    fn test_ipv6_compress_fail_exactly_one_byte_short() {
        let addr = [0u8; 16];
        let compressed = "::";
        let needed = compressed.len() + 1; // for NUL
        let mut out = vec![0u8; needed - 1]; // one byte too small
        let len = unsafe {
            SCIPv6Compress(
                addr.as_ptr() as *const c_uchar,
                out.as_mut_ptr() as *mut c_char,
                out.len(),
            )
        };
        assert_eq!(len, 0);
    }

    #[test]
    fn test_ipv6_compress_writes_nul_terminator() {
        let addr = [0u8; 16];
        let mut out = vec![0u8; 64];
        let len = unsafe {
            SCIPv6Compress(
                addr.as_ptr() as *const c_uchar,
                out.as_mut_ptr() as *mut c_char,
                out.len(),
            )
        };
        assert!(len > 0);
        assert_eq!(out[len], 0);
    }
}
