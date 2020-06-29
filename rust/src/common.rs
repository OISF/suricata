use std::ffi::CString;
use std::os::raw::c_char;

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
