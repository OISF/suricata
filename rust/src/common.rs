use super::build_slice;
use crate::jsonbuilder::HEX;
use std::ffi::CString;
use std::os::raw::c_char;

pub mod nom7 {
    use nom7::bytes::streaming::{tag, take_until};
    use nom7::error::{Error, ParseError};
    use nom7::ErrorConvert;
    use nom7::IResult;

    /// Reimplementation of `take_until_and_consume` for nom 7
    ///
    /// `take_until` does not consume the matched tag, and
    /// `take_until_and_consume` was removed in nom 7. This function
    /// provides an implementation (specialized for `&[u8]`).
    pub fn take_until_and_consume<'a, E: ParseError<&'a [u8]>>(
        t: &'a [u8],
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], &'a [u8], E> {
        move |i: &'a [u8]| {
            let (i, res) = take_until(t)(i)?;
            let (i, _) = tag(t)(i)?;
            Ok((i, res))
        }
    }

    /// Specialized version of the nom 7 `bits` combinator
    ///
    /// The `bits combinator has trouble inferring the transient error type
    /// used by the tuple parser, because the function is generic and any
    /// error type would be valid.
    /// Use an explicit error type (as described in
    /// https://docs.rs/nom/7.1.0/nom/bits/fn.bits.html) to solve this problem, and
    /// specialize this function for `&[u8]`.
    pub fn bits<'a, O, E, P>(parser: P) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
    where
        E: ParseError<&'a [u8]>,
        Error<(&'a [u8], usize)>: ErrorConvert<E>,
        P: FnMut((&'a [u8], usize)) -> IResult<(&'a [u8], usize), O, Error<(&'a [u8], usize)>>,
    {
        // use full path to disambiguate nom `bits` from this current function name
        nom7::bits::bits(parser)
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
    return input
        .iter()
        .map(|b| {
            vec![
                char::from(HEX[(b >> 4) as usize]),
                char::from(HEX[(b & 0xf) as usize]),
            ]
        })
        .flatten()
        .collect();
}

#[no_mangle]
pub unsafe extern "C" fn rs_to_hex(
    output: *mut u8, out_len: usize, input: *const u8, in_len: usize,
) {
    if out_len < 2 * in_len + 1 {
        return;
    }
    let islice = build_slice!(input, in_len);
    let oslice = std::slice::from_raw_parts_mut(output, 2 * in_len + 1);
    // only used from C
    for i in 0..islice.len() {
        oslice[2 * i] = HEX[(islice[i] >> 4) as usize];
        oslice[2 * i + 1] = HEX[(islice[i] & 0xf) as usize];
    }
    oslice[2 * islice.len()] = 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_to_hex_sep(
    output: *mut u8, out_len: usize, sep: u8, input: *const u8, in_len: usize,
) {
    if out_len < 3 * in_len {
        return;
    }
    let islice = build_slice!(input, in_len);
    let oslice = std::slice::from_raw_parts_mut(output, 3 * in_len);
    // only used from C
    for i in 0..islice.len() {
        oslice[3 * i] = HEX[(islice[i] >> 4) as usize];
        oslice[3 * i + 1] = HEX[(islice[i] & 0xf) as usize];
        oslice[3 * i + 2] = sep;
    }
    // overwrites last separator with final null char
    oslice[3 * islice.len() - 1] = 0;
}
