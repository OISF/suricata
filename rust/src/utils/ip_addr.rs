use std::ffi::{c_char, c_uchar};
use std::net::Ipv6Addr;

/// Writes the shortened IPv6 string into `out_buf`, which has length `out_len`.
/// Returns the number of bytes written (excluding the null terminator),
/// or 0 on error (invalid addr pointer, buffer too small, etc.)
#[no_mangle]
pub unsafe extern "C" fn SCIPv6Shorten(
    addr: *const c_uchar,   // pointer to 16-byte IPv6
    out_buf: *mut c_char,   // out buffer allocated by caller
    out_len: usize          // size of out buffer
) -> usize {
    if addr.is_null() || out_buf.is_null() {
        return 0;
    }

    unsafe {
        // get 16-byte IPv6 address
        let bytes = std::slice::from_raw_parts(addr, 16);

        // Convert &[u8] → Ipv6Addr
        let ipv6 = match <&[u8; 16]>::try_from(bytes) {
            Ok(b) => Ipv6Addr::from(*b),
            Err(_) => return 0,
        };

        // RFC 5952 compressed format
        let ipv6_str = ipv6.to_string(); // produces Rust String

        // Sufficient room?
        if ipv6_str.len() + 1 > out_len {
            return 0;
        }

        // Copy string + NULL termination
        std::ptr::copy_nonoverlapping(
            ipv6_str.as_ptr(),
            out_buf as *mut u8,
            ipv6_str.len(),
        );

        //*out_buf.add(ipv6_str.len()) = 0;

        0
    }
}

