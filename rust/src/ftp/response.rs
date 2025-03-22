use std::ffi::{c_char, CString};
use std::ptr;
use std::slice;

/// Struct representing a single response line
#[repr(C)]
pub struct FTPResponseLine {
    code: i32,             // 3-digit numeric code (optional)
    response: *mut c_char, // Response string
    length: usize,
}

/// Struct representing all parsed response lines
#[repr(C)]
pub struct FTPResponse {
    lines: *mut FTPResponseLine, // Array of response lines
    count: usize,                // Number of lines
    truncated: bool,
    total_size: usize,
}

/// Parses FTP response lines into a vector of `FTPResponseLine` and tracks memory usage
fn parse_response_lines(input: &str) -> (Vec<FTPResponseLine>, usize) {
    let mut total_size = std::mem::size_of::<Vec<FTPResponseLine>>(); // Track vector size

    let lines: Vec<FTPResponseLine> = input
        .lines()
        .filter_map(|line| {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() {
                return None;
            }

            let mut parts = line.splitn(2, ' ');
            let (code, response) = match (parts.next(), parts.next()) {
                (Some(num_str), Some(rest))
                    if num_str.len() == 3 && num_str.chars().all(|c| c.is_ascii_digit()) =>
                {
                    (num_str.parse::<i32>().unwrap_or(-1), rest)
                }
                _ => (-1, line),
            };

            let c_response = CString::new(response).unwrap_or_else(|_| CString::new("").unwrap());

            // Update memory usage
            total_size += std::mem::size_of::<FTPResponseLine>(); // Struct size
            total_size += c_response.as_bytes_with_nul().len(); // CString size

            Some(FTPResponseLine {
                code,
                response: c_response.into_raw(), // Leak CString to pass to C safely
                length: response.len(),
            })
        })
        .collect();

    (lines, total_size)
}

/// Parses an FTP response string and returns a pointer to an `FTPResponse` struct
#[no_mangle]
pub unsafe extern "C" fn SCParseFTPResponseLine(
    input: *const c_char, length: usize,
) -> *mut FTPResponse {
    if input.is_null() || length == 0 {
        return ptr::null_mut();
    }

    // Read input as a byte slice
    let slice = slice::from_raw_parts(input as *const u8, length);

    // Truncate at null byte if present
    let slice = match slice.iter().position(|&b| b == 0) {
        Some(pos) => &slice[..pos],
        None => slice,
    };

    // Convert bytes to string, handling non-UTF-8 safely
    let input_str = String::from_utf8_lossy(slice);

    // Parse the response lines
    let (mut parsed_lines, total_size) = parse_response_lines(&input_str);
    let response_array = parsed_lines.as_mut_ptr();

    // Allocate response struct
    let response_struct = Box::new(FTPResponse {
        lines: response_array,
        count: parsed_lines.len(),
        truncated: false,
        total_size,
    });

    // Prevent Rust from freeing parsed_lines
    std::mem::forget(parsed_lines);

    Box::into_raw(response_struct)
}

/// Frees the memory allocated for an `FTPResponse`
#[no_mangle]
pub unsafe extern "C" fn SCFreeFTPResponse(response: *mut FTPResponse) {
    if response.is_null() {
        return;
    }

    let boxed_response = Box::from_raw(response);

    // Free each response line
    let lines_slice = slice::from_raw_parts_mut(boxed_response.lines, boxed_response.count);
    for line in lines_slice {
        if !line.response.is_null() {
            drop(CString::from_raw(line.response));
        }
    }

    // Free the response array
    drop(Vec::from_raw_parts(
        boxed_response.lines,
        boxed_response.count,
        boxed_response.count,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn free_parsed_lines(parsed: Vec<FTPResponseLine>) {
        for line in parsed {
            unsafe {
                let _ = CString::from_raw(line.response);
            }
        }
    }
    #[test]
    fn test_parse_valid_lines() {
        let input = "330 this is line 1\r\n444 this is line 2\n555 another line";
        let (parsed, _) = parse_response_lines(input);

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].code, 330);
        assert_eq!(parsed[0].length, "this is line 1".len());
        assert_eq!(
            unsafe { CStr::from_ptr(parsed[0].response).to_str().unwrap() },
            "this is line 1"
        );

        assert_eq!(parsed[1].code, 444);
        assert_eq!(parsed[1].length, "this is line 2".len());
        assert_eq!(
            unsafe { CStr::from_ptr(parsed[1].response).to_str().unwrap() },
            "this is line 2"
        );

        assert_eq!(parsed[2].code, 555);
        assert_eq!(parsed[2].length, "another line".len());
        assert_eq!(
            unsafe { CStr::from_ptr(parsed[2].response).to_str().unwrap() },
            "another line"
        );

        free_parsed_lines(parsed);
    }

    #[test]
    fn test_parse_empty_input() {
        let input = "";
        let (parsed, _) = parse_response_lines(input);
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_parse_malformed_lines() {
        let input = "invalid line\n123missing response\n45 short code\n777 correct response";
        let (parsed, _) = parse_response_lines(input);

        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].code, -1);
        assert_eq!(parsed[1].code, -1);
        assert_eq!(parsed[2].code, -1);
        assert_eq!(parsed[3].code, 777);
        assert_eq!(parsed[3].length, "correct response".len());
        assert_eq!(
            unsafe { CStr::from_ptr(parsed[3].response).to_str().unwrap() },
            "correct response"
        );

        free_parsed_lines(parsed);
    }

    #[test]
    fn test_parse_trailing_newlines() {
        let input = "123 first line\n456 second line\n";
        let (parsed, _) = parse_response_lines(input);

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].code, 123);
        assert_eq!(parsed[0].length, "first line".len());
        assert_eq!(
            unsafe { CStr::from_ptr(parsed[0].response).to_str().unwrap() },
            "first line"
        );

        assert_eq!(parsed[1].code, 456);
        assert_eq!(parsed[1].length, "second line".len());
        assert_eq!(
            unsafe { CStr::from_ptr(parsed[1].response).to_str().unwrap() },
            "second line"
        );

        free_parsed_lines(parsed);
    }

    #[test]
    fn test_mixed_numeric_and_non_numeric_lines() {
        let input = "220 FTP Ready\r\nSome random line\r\n331 Password required\r\n";
        let (parsed, _) = parse_response_lines(input);

        assert_eq!(parsed.len(), 3);

        assert_eq!(parsed[0].code, 220);
        assert_eq!(parsed[0].length, "FTP Ready".len());
        assert_eq!(
            unsafe { CStr::from_ptr(parsed[0].response).to_str().unwrap() },
            "FTP Ready"
        );

        assert_eq!(parsed[1].code, -1);
        assert_eq!(parsed[1].length, "Some random line".len());
        assert_eq!(
            unsafe { CStr::from_ptr(parsed[1].response).to_str().unwrap() },
            "Some random line"
        );

        assert_eq!(parsed[2].code, 331);
        assert_eq!(parsed[2].length, "Password required".len());
        assert_eq!(
            unsafe { CStr::from_ptr(parsed[2].response).to_str().unwrap() },
            "Password required"
        );

        free_parsed_lines(parsed);
    }

    #[test]
    fn test_parse_non_ascii_characters() {
        let input = "500 '\\362ABOR': command not understood.\r\n";
        let (parsed, _) = parse_response_lines(input);
        assert_eq!(parsed.len(), 1);

        assert_eq!(parsed[0].code, 500);
        assert_eq!(
            parsed[0].length,
            "'\\362ABOR': command not understood.".len()
        );
        assert_eq!(
            unsafe { CStr::from_ptr(parsed[0].response).to_str().unwrap() },
            "'\\362ABOR': command not understood."
        );

        free_parsed_lines(parsed);
    }
}
