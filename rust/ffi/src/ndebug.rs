/* Copyright (C) 2017-2026 Open Information Security Foundation
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

use suricata_sys::sys::{SCError, SCLogMessage};
use suricata_sys::sys::{SCFatalErrorOnInitStatic, SCLogLevel};

/// The Suricata log-level.
///
/// This must be set on start-up of Suricata, as well as on plugin
/// initialization so the plugin inherits the same log-level as the
/// running Suricata.
pub static mut LEVEL: SCLogLevel = SCLogLevel::SC_LOG_NOTSET;

/// Set the Rust context's idea of the log level.
///
/// This will be called during Suricata initialization with the
/// runtime log level.
///
/// # Safety
///
/// This function writes to the global variable LEVEL. This variable
/// should not be read or written from multiple threads, so this is
/// best called before we spawn any threads.
pub unsafe fn set_log_level(level: SCLogLevel) {
    LEVEL = level;
}

fn basename(filename: &str) -> &str {
    let path = Path::new(filename);
    if let Some(os_str) = path.file_name() {
        if let Some(basename) = os_str.to_str() {
            return basename;
        }
    }
    filename
}

pub fn fatalerror(message: &str) {
    unsafe {
        SCFatalErrorOnInitStatic(to_safe_cstring(message).as_ptr());
    }
}

pub fn sclog(level: SCLogLevel, file: &str, line: u32, function: &str, message: &str) {
    let filename = basename(file);
    let noext = &filename[0..filename.len() - 3];
    log_message(level, filename, line, function, noext, message);
}

/// SCLogMessage wrapper.
pub fn log_message(
    level: SCLogLevel, filename: &str, line: std::os::raw::c_uint, function: &str, module: &str,
    message: &str,
) -> SCError {
    unsafe {
        SCLogMessage(
            level,
            to_safe_cstring(filename).as_ptr(),
            line,
            to_safe_cstring(function).as_ptr(),
            to_safe_cstring(module).as_ptr(),
            to_safe_cstring(message).as_ptr(),
        )
    }
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
macro_rules! do_log {
    ($level:expr, $($arg:tt)*) => {
        #[allow(unused_unsafe)]
        if unsafe { $crate::ndebug::LEVEL as i32 } >= $level as i32 {
            $crate::ndebug::sclog($level, file!(), line!(), $crate::function!(),
                  &(format!($($arg)*)));
        }
    }
}

#[macro_export]
macro_rules! SCLogError {
    ($($arg:tt)*) => {
        $crate::do_log!(suricata_sys::sys::SCLogLevel::SC_LOG_ERROR, $($arg)*);
    };
}

#[macro_export]
macro_rules! SCLogWarning {
    ($($arg:tt)*) => {
        $crate::do_log!(suricata_sys::sys::SCLogLevel::SC_LOG_WARNING, $($arg)*);
    };
}

#[macro_export]
macro_rules! SCLogNotice {
    ($($arg:tt)*) => {
        $crate::do_log!(suricata_sys::sys::SCLogLevel::SC_LOG_NOTICE, $($arg)*);
    }
}

#[macro_export]
macro_rules! SCLogInfo {
    ($($arg:tt)*) => {
        $crate::do_log!(suricata_sys::sys::SCLogLevel::SC_LOG_INFO, $($arg)*);
    }
}

#[macro_export]
macro_rules! SCLogPerf {
    ($($arg:tt)*) => {
        $crate::do_log!(suricata_sys::sys::SCLogLevel::SC_LOG_PERF, $($arg)*);
    }
}

#[macro_export]
macro_rules! SCLogConfig {
    ($($arg:tt)*) => {
        $crate::do_log!(suricata_sys::sys::SCLogLevel::SC_LOG_CONFIG, $($arg)*);
    }
}

// Debug mode: call C SCLogDebug
#[cfg(feature = "debug")]
#[macro_export]
macro_rules!SCLogDebug {
    ($($arg:tt)*) => {
        $crate::do_log!(suricata_sys::sys::SCLogLevel::SC_LOG_DEBUG, $($arg)*);
    }
}

// SCLogDebug variation to use when not compiled with debug
// support. This just swallows the arguments and doesn't output
// anything.
#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! SCLogDebug {
    ($($arg:tt)*) => {};
}

#[macro_export]
macro_rules! SCFatalErrorOnInit {
    ($($arg:tt)*) => {
        $crate::ndebug::fatalerror(&format!($($arg)*));
    }
}
