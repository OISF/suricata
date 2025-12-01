use std::ffi::{c_char, c_uchar};
use std::net::Ipv6Addr;

/// Writes the shortened IPv6 string into `out_buf`, which has length `out_len`.
/// Returns the number of bytes written (excluding the null terminator),
/// or 0 on error (invalid addr pointer, buffer too small, etc.)
#[no_mangle]
pub unsafe extern "C" fn SCIPv6Shorten(
    addr: *const c_uchar,   // pointer to 16-byte IPv6
    out_buf: *mut c_char,   // destination buffer allocated by caller
    out_len: usize          // size of destination buffer
) -> usize {
    if addr.is_null() || out_buf.is_null() {
        return 0;
    }

    unsafe {
        // Read 16-byte IPv6 address
        let src = std::slice::from_raw_parts(addr, 16);

        let mut raw = [0u8; 16];
        raw.copy_from_slice(src);

        let ipv6 = Ipv6Addr::from(raw);

        // RFC 5952 compressed representation
        let s = ipv6.to_string();

        // Need space for the string + '\0'
        let required = s.len() + 1;
        if required > out_len {
            return 0;  // buffer too small
        }

        // Copy characters
        std::ptr::copy_nonoverlapping(
            s.as_ptr(),
            out_buf as *mut u8,
            s.len()
        );

        // Null terminator
        *out_buf.add(s.len()) = 0;

        s.len()
    }
}

