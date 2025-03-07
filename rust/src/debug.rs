/* Copyright (C) 2017-2025 Open Information Security Foundation
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

//! Logging and debug utilities, like util-debug.c.

use std::{ffi::CString, path::Path};

use crate::core::SC;
use std::os::raw::c_char;

/// cbindgen:ignore
extern "C" {
    pub fn SCLogGetLogLevel() -> i32;
}

// Defined in util-debug.c
/// cbindgen:ignore
extern "C" {
    pub fn SCFatalErrorOnInitStatic(arg: *const c_char);
}

#[derive(Debug)]
#[repr(C)]
pub enum Level {
    NotSet = -1,
    _None = 0,
    Error,
    Warning,
    Notice,
    Info,
    _Perf,
    Config,
    #[cfg(feature = "debug")]
    Debug,
}

pub static mut LEVEL: i32 = Level::NotSet as i32;

/// Set the Rust context's idea of the log level.
///
/// This will be called during Suricata initialization with the
/// runtime log level.
#[no_mangle]
pub unsafe extern "C" fn SCSetRustLogLevel(level: i32) {
    LEVEL = level;
}

fn basename(filename: &str) -> &str {
    let path = Path::new(filename);
    if let Some(os_str) = path.file_name() {
        if let Some(basename) = os_str.to_str() {
            return basename;
        }
    }
    return filename;
}

pub fn fatalerror(message: &str) {
    unsafe {
        SCFatalErrorOnInitStatic(to_safe_cstring(message).as_ptr());
    }
}

pub fn sclog(level: Level, file: &str, line: u32, function: &str, message: &str) {
    let filename = basename(file);
    let noext = &filename[0..filename.len() - 3];
    sc_log_message(level, filename, line, function, noext, message);
}

/// SCLogMessage wrapper. If the Suricata C context is not registered
/// a more basic log format will be used (for example, when running
/// Rust unit tests).
pub fn sc_log_message(
    level: Level, filename: &str, line: std::os::raw::c_uint, function: &str, module: &str,
    message: &str,
) -> std::os::raw::c_int {
    unsafe {
        if let Some(c) = SC {
            return (c.SCLogMessage)(
                level as i32,
                to_safe_cstring(filename).as_ptr(),
                line,
                to_safe_cstring(function).as_ptr(),
                to_safe_cstring(module).as_ptr(),
                to_safe_cstring(message).as_ptr(),
            );
        }
    }

    // Fall back if the Suricata C context is not registered which is
    // the case when Rust unit tests are running.
    //
    // We don't log the time right now as I don't think it can be done
    // with Rust 1.7.0 without using an external crate. With Rust
    // 1.8.0 and newer we can unix UNIX_EPOCH.elapsed() to get the
    // unix time.
    println!("{}:{} <{:?}> -- {}", filename, line, level, message);
    return 0;
}

// Convert a &str into a CString by first stripping NUL bytes.
fn to_safe_cstring(val: &str) -> CString {
    let mut safe = Vec::with_capacity(val.len());
    for c in val.as_bytes() {
        if *c != 0 {
            safe.push(*c);
        }
    }
    match CString::new(safe) {
        Ok(cstr) => cstr,
        _ => CString::new("<failed to encode string>").unwrap(),
    }
}

// This macro returns the function name.
//
// This macro has been borrowed from https://github.com/popzxc/stdext-rs, which
// is released under the MIT license as there is currently no macro in Rust
// to provide the function name.
#[macro_export(local_inner_macros)]
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

#[macro_export]
macro_rules!do_log {
    ($level:expr, $($arg:tt)*) => {
        #[allow(unused_unsafe)]
        if unsafe { $crate::debug::LEVEL } >= $level as i32 {
            $crate::debug::sclog($level, file!(), line!(), $crate::function!(),
                  &(format!($($arg)*)));
        }
    }
}

#[macro_export]
macro_rules!SCLogError {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::debug::Level::Error, $($arg)*);
    };
}

#[macro_export]
macro_rules!SCLogWarning {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::debug::Level::Warning, $($arg)*);
    };
}

#[macro_export]
macro_rules!SCLogNotice {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::debug::Level::Notice, $($arg)*);
    }
}

#[macro_export]
macro_rules!SCLogInfo {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::debug::Level::Info, $($arg)*);
    }
}

#[macro_export]
macro_rules!SCLogPerf {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::debug::Level::Perf, $($arg)*);
    }
}

#[macro_export]
macro_rules!SCLogConfig {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::debug::Level::Config, $($arg)*);
    }
}

// Debug mode: call C SCLogDebug
#[cfg(feature = "debug")]
#[macro_export]
macro_rules!SCLogDebug {
    ($($arg:tt)*) => {
        do_log!($crate::debug::Level::Debug, $($arg)*);
    }
}

// SCLogDebug variation to use when not compiled with debug support.
//
// This macro will only use the parameters passed to prevent warnings
// about unused variables, but is otherwise the equivalent to a no-op.
#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! SCLogDebug {
    ($($arg:tt)*) => {};
}

#[macro_export]
macro_rules!SCFatalErrorOnInit {
    ($($arg:tt)*) => {
        $crate::debug::fatalerror(&format!($($arg)*));
    }
}

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

pub use suricata_core::debug_validate_fail;

#[macro_export]
macro_rules! unwrap_or_return (
    ($e:expr, $r:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => return $r,
        }
    };
);
