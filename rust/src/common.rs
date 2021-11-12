use std::ffi::CString;
use std::os::raw::c_char;

pub mod nom7 {
    use nom7::bytes::streaming::{tag, take_until};
    use nom7::error::ParseError;
    use nom7::IResult;

    pub fn take_until_and_consume<'a, E: ParseError<&'a [u8]>>(t: &'a [u8])
         -> impl Fn(&'a [u8]) -> IResult<&'a [u8], &'a [u8], E>
    {
        move |i: &'a [u8]| {
            let t = t.clone();
            let (i, res) = take_until(t)(i)?;
            let (i, _) = tag(t)(i)?;
            Ok((i, res))
        }
    }
}

#[macro_export]
macro_rules! take_until_and_consume (
 ( $i:expr, $needle:expr ) => (
    {
      let input: &[u8] = $i;

      let (rem, res) = ::nom::take_until!(input, $needle)?;
      let (rem, _) = ::nom::take!(rem, $needle.len())?;
      Ok((rem, res))
    }
  );
);

#[cfg(not(feature = "debug-validate"))]
#[macro_export]
macro_rules! debug_validate_bug_on (
  ($item:expr) => {};
);

#[cfg(feature = "debug-validate")]
#[macro_export]
macro_rules! debug_validate_bug_on (
  ($item:expr) => {
    if $item {
        panic!("Condition check failed");
    }
  };
);

#[cfg(not(feature = "debug-validate"))]
#[macro_export]
macro_rules! debug_validate_fail (
  ($msg:expr) => {};
);

#[cfg(feature = "debug-validate")]
#[macro_export]
macro_rules! debug_validate_fail (
  ($msg:expr) => {
    // Wrap in a conditional to prevent unreachable code warning in caller.
    if true {
      panic!($msg);
    }
  };
);

/// Convert a String to C-compatible string
///
/// This function will consume the provided data and use the underlying bytes to construct a new
/// string, ensuring that there is a trailing 0 byte. This trailing 0 byte will be appended by this
/// function; the provided data should *not* contain any 0 bytes in it.
///
/// Returns a valid pointer, or NULL
pub fn rust_string_to_c(s: String) -> *mut c_char {
    CString::new(s)
        .map(|c_str| c_str.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Free a CString allocated by Rust (for ex. using `rust_string_to_c`)
///
/// # Safety
///
/// s must be allocated by rust, using `CString::new`
#[no_mangle]
pub unsafe extern "C" fn rs_cstring_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(CString::from_raw(s));
}

/// Convert an u8-array of data into a hexadecimal representation
pub fn to_hex(input: &[u8]) -> String {
    static CHARS: &'static [u8] = b"0123456789abcdef";

    return input.iter().map(
        |b| vec![char::from(CHARS[(b >>  4) as usize]), char::from(CHARS[(b & 0xf) as usize])]
    ).flatten().collect();
}
