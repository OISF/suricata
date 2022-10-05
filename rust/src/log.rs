/* Copyright (C) 2017 Open Information Security Foundation
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

use std;
use std::ffi::CString;
use std::path::Path;

use crate::core::*;

#[derive(Debug)]
#[repr(C)]
pub enum Level {
    NotSet = -1,
    None = 0,
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Perf,
    Config,
    Debug,
}

pub static mut LEVEL: i32 = Level::NotSet as i32;

pub fn get_log_level() -> i32 {
    unsafe {
        LEVEL
    }
}

pub fn log_set_level(level: i32) {
    unsafe {
        LEVEL = level;
    }
}

#[no_mangle]
pub extern "C" fn rs_log_set_level(level: i32) {
    log_set_level(level);
}

fn basename(filename: &str) -> &str {
    let path = Path::new(filename);
    for os_str in path.file_name() {
        for basename in os_str.to_str() {
            return basename;
        }
    }
    filename
}

pub fn sclog(level: Level, file: &str, line: u32, function: &str,
         code: i32, message: &str)
{
    let filename = basename(file);
    sc_log_message(level,
                   filename,
                   line,
                   function,
                   code,
                   message);
}

// This macro returns the function name.
//
// This macro has been borrowed from https://github.com/popzxc/stdext-rs, which
// is released under the MIT license as there is currently no macro in Rust
// to provide the function name.
#[macro_export(local_inner_macros)]
macro_rules!function {
    () => {{
         // Okay, this is ugly, I get it. However, this is the best we can get on a stable rust.
         fn __f() {}
         fn type_name_of<T>(_: T) -> &'static str {
             std::any::type_name::<T>()
         }
         let name = type_name_of(__f);
         &name[..name.len() - 5]
    }}
}

#[macro_export]
macro_rules!do_log {
    ($level:expr, $code:expr, $($arg:tt)*) => {
        if $crate::log::get_log_level() >= $level as i32 {
            $crate::log::sclog($level, file!(), line!(), $crate::function!(), $code,
                  &(format!($($arg)*)));
        }
    }
}

#[macro_export]
macro_rules!SCLogError {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::log::Level::Error, 0, $($arg)*);
    };
}

#[macro_export]
macro_rules!SCLogNotice {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::log::Level::Notice, 0, $($arg)*);
    }
}

#[macro_export]
macro_rules!SCLogInfo {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::log::Level::Info, 0, $($arg)*);
    }
}

#[macro_export]
macro_rules!SCLogPerf {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::log::Level::Perf, 0, $($arg)*);
    }
}

#[macro_export]
macro_rules!SCLogConfig {
    ($($arg:tt)*) => {
        $crate::do_log!($crate::log::Level::Config, 0, $($arg)*);
    }
}

// Debug mode: call C SCLogDebug
#[cfg(feature = "debug")]
#[macro_export]
macro_rules!SCLogDebug {
    ($($arg:tt)*) => {
        do_log!($crate::log::Level::Debug, 0, $($arg)*);
    }
}

// SCLogDebug variation to use when not compiled with debug support.
//
// This macro will only use the parameters passed to prevent warnings
// about unused variables, but is otherwise the equivalent to a no-op.
#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules!SCLogDebug {
    ($($arg:tt)*) => ()
}

/// SCLogMessage wrapper. If the Suricata C context is not registered
/// a more basic log format will be used (for example, when running
/// Rust unit tests).
pub fn sc_log_message(level: Level,
                      filename: &str,
                      line: std::os::raw::c_uint,
                      function: &str,
                      code: std::os::raw::c_int,
                      message: &str) -> std::os::raw::c_int
{
    unsafe {
        if let Some(c) = SC {
            return (c.SCLogMessage)(
                level as i32,
                to_safe_cstring(filename).as_ptr(),
                line,
                to_safe_cstring(function).as_ptr(),
                code,
                to_safe_cstring(message).as_ptr());
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
    0
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
        _ => {
            CString::new("<failed to encode string>").unwrap()
        }
    }
}
