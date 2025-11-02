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

use std::os::raw::c_char;
use std::ptr;
use std::slice;

#[repr(C)]
pub struct FTPResponseLine {
    code: *mut u8,      // Response code as a string (may be null)
    response: *mut u8,  // Response string
    length: usize,      // Length of the response string
    code_length: usize, // Length of the response code string
    truncated: bool,    // Uses TX/state value.
    total_size: usize,  // Total allocated size in bytes
}

/// Parses a single FTP response line and returns an FTPResponseLine struct.
/// Handles response lines like:
/// - (single response) "530 Login incorrect"
/// - (single response, no code) "Login incorrect"
fn parse_response_line(input: &str) -> Option<FTPResponseLine> {
    // Split the input on the first \r\n to get the response line
    let response_line = input.split("\r\n").next().unwrap_or("").trim_end();

    if response_line.is_empty() {
        return None;
    }

    // Try to split off the 3-digit FTP status code
    let (code_str, response_str) = match response_line.split_once(' ') {
        Some((prefix, rest)) if prefix.len() == 3 && prefix.chars().all(|c| c.is_ascii_digit()) => {
            (prefix, rest)
        }
        _ => ("", response_line),
    };

    let code_bytes = code_str.as_bytes().to_vec();
    let response_bytes = response_str.as_bytes().to_vec();

    let code_len = code_bytes.len();
    let response_len = response_bytes.len();

    let total_size = std::mem::size_of::<FTPResponseLine>() + code_len + response_len;

    Some(FTPResponseLine {
        code: Box::into_raw(code_bytes.into_boxed_slice()) as *mut u8,
        response: Box::into_raw(response_bytes.into_boxed_slice()) as *mut u8,
        length: response_len,
        code_length: code_len,
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

    if !response.response.is_null() {
        let _ = Vec::from_raw_parts(
            response.code,
            response.code_length,
            response.code_length,
        );
    }

    if !response.response.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            response.response,
            response.length,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_response() {
        let input = "220 Welcome to FTP\r\n";
        let parsed = parse_response_line(input).unwrap();

        let code_slice = unsafe { slice::from_raw_parts(parsed.code, parsed.code_length) };
        let code_str = std::str::from_utf8(code_slice).expect("Invalid UTF-8");
        assert_eq!(code_str, "220");
        let response_slice = unsafe { slice::from_raw_parts(parsed.response, parsed.length) };
        let response_str = std::str::from_utf8(response_slice).expect("Invalid UTF-8");
        assert_eq!(response_str, "Welcome to FTP");
        assert_eq!(parsed.length, "Welcome to FTP".len());
    }

    #[test]
    fn test_parse_response_without_code() {
        let input = "Some random text\r\n";
        let parsed = parse_response_line(input).unwrap();

        let code_slice = unsafe { slice::from_raw_parts(parsed.code, parsed.code_length) };
        let code_str = std::str::from_utf8(code_slice).expect("Invalid UTF-8");
        assert_eq!(code_str, "");

        let response_slice = unsafe { slice::from_raw_parts(parsed.response, parsed.length) };
        let response_str = std::str::from_utf8(response_slice).expect("Invalid UTF-8");
        assert_eq!(response_str, "Some random text");
        assert_eq!(parsed.length, "Some random text".len());
    }

    #[test]
    fn test_parse_response_with_extra_whitespace() {
        let input = "331  Password required  \r\n";
        let parsed = parse_response_line(input).unwrap();

        let code_slice = unsafe { slice::from_raw_parts(parsed.code, parsed.code_length) };
        let code_str = std::str::from_utf8(code_slice).expect("Invalid UTF-8");
        assert_eq!(code_str, "331");
        let response_slice = unsafe { slice::from_raw_parts(parsed.response, parsed.length) };
        let response_str = std::str::from_utf8(response_slice).expect("Invalid UTF-8");
        assert_eq!(response_str, " Password required");
        assert_eq!(parsed.length, " Password required".len());
    }

    #[test]
    fn test_parse_response_with_trailing_newlines() {
        let input = "220 Hello FTP Server\n";
        let parsed = parse_response_line(input).unwrap();

        let code_slice = unsafe { slice::from_raw_parts(parsed.code, parsed.code_length) };
        let code_str = std::str::from_utf8(code_slice).expect("Invalid UTF-8");
        assert_eq!(code_str, "220");
        let response_slice = unsafe { slice::from_raw_parts(parsed.response, parsed.length) };
        let response_str = std::str::from_utf8(response_slice).expect("Invalid UTF-8");
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

        let code_slice = unsafe { slice::from_raw_parts(parsed.code, parsed.code_length) };
        let code_str = std::str::from_utf8(code_slice).expect("Invalid UTF-8");
        assert_eq!(code_str, "");
        let response_slice = unsafe { slice::from_raw_parts(parsed.response, parsed.length) };
        let response_str = std::str::from_utf8(response_slice).expect("Invalid UTF-8");
        assert_eq!(response_str, "99 Incorrect code");
        assert_eq!(parsed.length, "99 Incorrect code".len());
    }

    #[test]
    fn test_parse_non_ascii_characters() {
        let input = "500 '🌍 ABOR': unknown command\r\n";
        let parsed = parse_response_line(input).unwrap();

        let code_slice = unsafe { slice::from_raw_parts(parsed.code, parsed.code_length) };
        let code_str = std::str::from_utf8(code_slice).expect("Invalid UTF-8");
        assert_eq!(code_str, "500");

        let response_slice = unsafe { slice::from_raw_parts(parsed.response, parsed.length) };
        let response_str = std::str::from_utf8(response_slice).expect("Invalid UTF-8");
        assert_eq!(response_str, "'🌍 ABOR': unknown command");
        assert_eq!(parsed.length, "'🌍 ABOR': unknown command".len());
    }
}
