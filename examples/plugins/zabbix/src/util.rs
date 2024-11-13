// Helper macros
use crate::suricata::{Level, SCLogMessage};

use std::ffi::CString;

macro_rules! ctor_pointer {
    ($ptr:ident, $ty:ty) => {
        &mut *($ptr as *mut $ty)
    };
}
pub(crate) use ctor_pointer;

// This macro returns the function name.
//
// This macro has been borrowed from https://github.com/popzxc/stdext-rs, which
// is released under the MIT license as there is currently no macro in Rust
// to provide the function name.
macro_rules! function {
    () => {{
        // Okay, this is ugly, I get it. However, this is the best we can get on a stable rust.
        fn __f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(__f);
        &name[..name.len() - 5]
    }};
}
pub(crate) use function;

macro_rules!SCLog {
    ($level:expr, $($arg:tt)*) => {
        $crate::util::sclog($level, file!(), line!(), crate::util::function!(),
                &(format!($($arg)*)));
    }
}

pub(crate) use SCLog;

pub fn sclog(level: Level, filename: &str, line: u32, function: &str, message: &str) {
    let filenamec = CString::new(filename).unwrap();
    let functionc = CString::new(function).unwrap();
    let modulec = CString::new("zabbix").unwrap();
    let messagec = CString::new(message).unwrap();
    unsafe {
        SCLogMessage(
            level as i32,
            filenamec.as_ptr(),
            line,
            (functionc).as_ptr(),
            (modulec).as_ptr(),
            (messagec).as_ptr(),
        );
    }
}
