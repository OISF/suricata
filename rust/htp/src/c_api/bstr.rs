use crate::bstr::Bstr;
use core::cmp::Ordering;
use std::{boxed::Box, ffi::CStr};

/// Allocate a zero-length bstring, reserving space for at least size bytes.
fn bstr_alloc(len: libc::size_t) -> *mut Bstr {
    let b = Bstr::with_capacity(len);
    let boxed = Box::new(b);
    Box::into_raw(boxed)
}

/// Deallocate the supplied bstring instance. Allows NULL on input.
/// # Safety
/// This function is unsafe because improper use may lead to memory problems. For example, a double-free may occur if the function is called twice on the same raw pointer.
#[no_mangle]
pub unsafe extern "C" fn bstr_free(b: *mut Bstr) {
    if !b.is_null() {
        drop(Box::from_raw(b));
    }
}

/// Return the length of the string
/// # Safety
/// x must be properly intialized: not NULL, dangling, or misaligned
#[no_mangle]
pub unsafe extern "C" fn bstr_len(x: *const Bstr) -> libc::size_t {
    (*x).len()
}

/// Return a pointer to the bstr payload
/// # Safety
/// x must be properly intialized: not NULL, dangling, or misaligned
#[no_mangle]
pub unsafe extern "C" fn bstr_ptr(x: *const Bstr) -> *mut libc::c_uchar {
    (*x).as_ptr() as *mut u8
}

/// Return the capacity of the string
/// # Safety
/// x must be properly intialized: not NULL, dangling, or misaligned
#[no_mangle]
pub unsafe extern "C" fn bstr_size(x: *const Bstr) -> libc::size_t {
    (*x).capacity()
}

/// Case-sensitive comparison of a bstring and a NUL-terminated string.
/// returns -1 if b is less than c
///          0 if b is equal to c
///          1 if b is greater than c
/// # Safety
/// b and c must be properly intialized: not NULL, dangling, or misaligned.
/// c must point to memory that contains a valid nul terminator byte at the end of the string
#[no_mangle]
pub unsafe extern "C" fn bstr_cmp_c(b: *const Bstr, c: *const libc::c_char) -> libc::c_int {
    let cs = CStr::from_ptr(c);
    match (*b).cmp_slice(cs.to_bytes()) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// Case-indensitive comparison of a bstring and a NUL-terminated string.
/// returns -1 if b is less than c
///          0 if b is equal to c
///          1 if b is greater than c
/// # Safety
/// b and c must be properly intialized: not NULL, dangling, or misaligned.
/// c must point to memory that contains a valid nul terminator byte at the end of the string
#[no_mangle]
pub unsafe extern "C" fn bstr_cmp_c_nocase(b: *const Bstr, c: *const libc::c_char) -> bool {
    let cs = CStr::from_ptr(c);
    (*b).cmp_nocase(cs.to_bytes())
}

/// Create a new bstring by copying the provided NUL-terminated string
/// # Safety
/// cstr must be properly intialized: not NULL, dangling, or misaligned.
/// cstr must point to memory that contains a valid nul terminator byte at the end of the string
#[no_mangle]
pub unsafe extern "C" fn bstr_dup_c(cstr: *const libc::c_char) -> *mut Bstr {
    let cs = CStr::from_ptr(cstr).to_bytes();
    let new = bstr_alloc(cs.len());
    (*new).add(cs);
    new
}

/// Create a new NUL-terminated string out of the provided bstring. If NUL bytes
/// are contained in the bstring, each will be replaced with "\0" (two characters).
/// The caller is responsible to keep track of the allocated memory area and free
/// it once it is no longer needed.
/// returns The newly created NUL-terminated string, or NULL in case of memory
///         allocation failure.
/// # Safety
/// b must be properly intialized and not dangling nor misaligned.
#[no_mangle]
pub unsafe extern "C" fn bstr_util_strdup_to_c(b: *const Bstr) -> *mut libc::c_char {
    if b.is_null() {
        return std::ptr::null_mut();
    }
    let src = std::slice::from_raw_parts(bstr_ptr(b), bstr_len(b));

    // Since the memory returned here is just a char* and the caller will
    // free() it we have to use malloc() here.
    // So we allocate enough space for doubled NULL bytes plus the trailing NULL.
    let mut null_count = 1;
    for byte in src {
        if *byte == 0 {
            null_count += 1;
        }
    }
    let newlen = bstr_len(b) + null_count;
    let mem = libc::malloc(newlen) as *mut libc::c_char;
    if mem.is_null() {
        return std::ptr::null_mut();
    }
    let dst: &mut [libc::c_char] = std::slice::from_raw_parts_mut(mem, newlen);
    let mut dst_idx = 0;
    for byte in src {
        if *byte == 0 {
            dst[dst_idx] = '\\' as libc::c_char;
            dst_idx += 1;
            dst[dst_idx] = '0' as libc::c_char;
        } else {
            dst[dst_idx] = *byte as libc::c_char;
        }
        dst_idx += 1;
    }
    dst[dst_idx] = 0;

    mem
}

#[cfg(test)]
mod test {
    use super::*;
    use std::ffi::CString;

    macro_rules! cstr {
        ( $x:expr ) => {{
            CString::new($x).unwrap()
        }};
    }

    #[test]
    fn Bstr_Alloc() {
        unsafe {
            let p1 = bstr_alloc(10);
            assert_eq!(10, bstr_size(p1));
            assert_eq!(0, bstr_len(p1));
            bstr_free(p1);
        }
    }

    #[test]
    fn Bstr_DupC() {
        unsafe {
            let p1 = bstr_dup_c(cstr!("arfarf").as_ptr());

            assert_eq!(6, bstr_size(p1));
            assert_eq!(6, bstr_len(p1));
            assert_eq!(
                0,
                libc::memcmp(
                    cstr!("arfarf").as_ptr() as *const core::ffi::c_void,
                    bstr_ptr(p1) as *const core::ffi::c_void,
                    6
                )
            );
            bstr_free(p1);
        }
    }

    #[test]
    fn Bstr_UtilDupToC() {
        unsafe {
            let s = Bstr::from(b"ABCDEFGHIJKL\x00NOPQRST" as &[u8]);
            let c = bstr_util_strdup_to_c(&s);
            let e = CString::new("ABCDEFGHIJKL\\0NOPQRST").unwrap();
            assert_eq!(0, libc::strcmp(e.as_ptr(), c));

            libc::free(c as *mut core::ffi::c_void);
        }
    }

    #[test]
    fn Bstr_CmpC() {
        unsafe {
            let p1 = Bstr::from("arfarf");
            assert_eq!(0, bstr_cmp_c(&p1, cstr!("arfarf").as_ptr()));
            assert_eq!(-1, bstr_cmp_c(&p1, cstr!("arfarf2").as_ptr()));
            assert_eq!(1, bstr_cmp_c(&p1, cstr!("arf").as_ptr()));
            assert_eq!(-1, bstr_cmp_c(&p1, cstr!("not equal").as_ptr()));
        }
    }
}
