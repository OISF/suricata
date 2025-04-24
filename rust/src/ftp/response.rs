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

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

#[repr(C)]
pub struct FTPResponseLine {
    code: *mut u8,     // Response code as a string (may be null)
    response: *mut u8, // Response string
    length: usize,     // Length of the response string
    truncated: bool,   // Uses TX/state value.
    total_size: usize, // Total allocated size in bytes
}

/// Parses a single FTP response line and returns an FTPResponseLine struct.
/// Handles response lines like:
/// - (single response) "530 Login incorrect"
/// - (single response, no code) "Login incorrect"
fn parse_response_line(input: &str) -> Option<FTPResponseLine> {
    // Find the first complete response line (delimited by `\r\n`)
    let mut split = input.splitn(2, "\r\n");
    let response_line = split.next().unwrap_or("").trim_end();

    if response_line.is_empty() {
        return None; // Ignore empty input
    }

    // Extract response code as a string
    let mut parts = response_line.splitn(2, ' ');
    let (code, response) = match (parts.next(), parts.next()) {
        (Some(num_str), Some(rest))
            if num_str.len() == 3 && num_str.chars().all(|c| c.is_ascii_digit()) =>
        {
            (num_str.to_string(), rest)
        }
        _ => ("".to_string(), response_line), // No valid numeric code found
    };

    // Convert response and code to C strings
    let c_code = CString::new(code).ok()?;
    let c_response = CString::new(response).ok()?;

    // Compute memory usage
    let total_size = std::mem::size_of::<FTPResponseLine>()
        + c_code.as_bytes_with_nul().len()
        + c_response.as_bytes_with_nul().len();

    Some(FTPResponseLine {
        code: c_code.into_raw() as *mut u8,
        response: c_response.into_raw() as *mut u8,
        length: response.len(),
        truncated: false,
        total_size,
    })
}

/// Parses an FTP response string and returns a pointer to an `FTPResponseLine` struct.
#[no_mangle]
pub unsafe extern "C" fn SCFTPParseResponseLine(
    input: *const c_char, length: usize,
) -> *mut FTPResponseLine {
    if input.is_null() || length == 0 {
        return ptr::null_mut();
    }

    let slice = slice::from_raw_parts(input as *const u8, length);

    let input_str = String::from_utf8_lossy(slice);

    match parse_response_line(&input_str) {
        Some(response) => Box::into_raw(Box::new(response)),
        None => ptr::null_mut(),
    }
}

/// Frees the memory allocated for an `FTPResponseLine` struct.
#[no_mangle]
pub unsafe extern "C" fn SCFTPFreeResponseLine(response: *mut FTPResponseLine) {
    if response.is_null() {
        return;
    }

    let response = Box::from_raw(response);

    if !response.code.is_null() {
        let _ = CString::from_raw(response.code as *mut c_char);
    }

    if !response.response.is_null() {
        let _ = CString::from_raw(response.response as *mut c_char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_parse_valid_response() {
        let input = "220 Welcome to FTP\r\n";
        let parsed = parse_response_line(input).unwrap();

        let code_cstr = unsafe { CStr::from_ptr(parsed.code as *mut c_char) };
        let code_str = code_cstr.to_str().unwrap();
        assert_eq!(code_str, "220");
        let response_cstr = unsafe { CStr::from_ptr(parsed.response as *mut c_char) };
        let response_str = response_cstr.to_str().unwrap();
        assert_eq!(response_str, "Welcome to FTP");
        assert_eq!(parsed.length, "Welcome to FTP".len());
    }

    #[test]
    fn test_parse_response_without_code() {
        let input = "Some random text\r\n";
        let parsed = parse_response_line(input).unwrap();

        let code_cstr = unsafe { CStr::from_ptr(parsed.code as *mut c_char) };
        let code_str = code_cstr.to_str().unwrap();
        assert_eq!(code_str, "");

        let response_cstr = unsafe { CStr::from_ptr(parsed.response as *mut c_char) };
        let response_str = response_cstr.to_str().unwrap();
        assert_eq!(response_str, "Some random text");
        assert_eq!(parsed.length, "Some random text".len());
    }

    #[test]
    fn test_parse_response_with_extra_whitespace() {
        let input = "331  Password required  \r\n";
        let parsed = parse_response_line(input).unwrap();

        let code_cstr = unsafe { CStr::from_ptr(parsed.code as *mut c_char) };
        let code_str = code_cstr.to_str().unwrap();
        assert_eq!(code_str, "331");
        let response_cstr = unsafe { CStr::from_ptr(parsed.response as *mut c_char) };
        let response_str = response_cstr.to_str().unwrap();
        assert_eq!(response_str, " Password required");
        assert_eq!(parsed.length, " Password required".len());
    }

    #[test]
    fn test_parse_response_with_trailing_newlines() {
        let input = "220 Hello FTP Server\n";
        let parsed = parse_response_line(input).unwrap();

        let code_cstr = unsafe { CStr::from_ptr(parsed.code as *mut c_char) };
        let code_str = code_cstr.to_str().unwrap();
        assert_eq!(code_str, "220");
        let response_cstr = unsafe { CStr::from_ptr(parsed.response as *mut c_char) };
        let response_str = response_cstr.to_str().unwrap();
        assert_eq!(response_str, "Hello FTP Server");
        assert_eq!(parsed.length, "Hello FTP Server".len());
    }

    #[test]
    fn test_parse_empty_input() {
        let input = "";
        assert!(parse_response_line(input).is_none());
    }

    #[test]
    fn test_parse_only_newline() {
        let input = "\n";
        assert!(parse_response_line(input).is_none());
    }

    #[test]
    fn test_parse_malformed_code() {
        let input = "99 Incorrect code\r\n";
        let parsed = parse_response_line(input).unwrap();

        let code_cstr = unsafe { CStr::from_ptr(parsed.code as *mut c_char) };
        let code_str = code_cstr.to_str().unwrap();
        assert_eq!(code_str, "");
        let response_cstr = unsafe { CStr::from_ptr(parsed.response as *mut c_char) };
        let response_str = response_cstr.to_str().unwrap();
        assert_eq!(response_str, "99 Incorrect code");
        assert_eq!(parsed.length, "99 Incorrect code".len());
    }

    #[test]
    fn test_parse_non_ascii_characters() {
        let input = "500 '🌍 ABOR': unknown command\r\n";
        let parsed = parse_response_line(input).unwrap();

        let code_cstr = unsafe { CStr::from_ptr(parsed.code as *mut c_char) };
        let code_str = code_cstr.to_str().unwrap();
        assert_eq!(code_str, "500");

        let response_cstr = unsafe { CStr::from_ptr(parsed.response as *mut c_char) };
        let response_str = response_cstr.to_str().unwrap();
        assert_eq!(response_str, "'🌍 ABOR': unknown command");
        assert_eq!(parsed.length, "'🌍 ABOR': unknown command".len());
    }
}
