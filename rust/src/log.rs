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

#![cfg_attr(feature = "type_name", feature(core_intrinsics))]

extern crate libc;

use std::ffi::{CString};
use std::path::Path;

use core::*;

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

fn basename(filename: &str) -> &str {
    let path = Path::new(filename);
    for os_str in path.file_name() {
        for basename in os_str.to_str() {
            return basename;
        }
    }
    return filename;
}

pub fn sclog(level: Level, file: &str, line: u32, function: &str,
         code: i32, message: &str)
{
    let filename = basename(file);
    sc_log_message(level as i32,
                   CString::new(filename).unwrap().as_ptr(),
                   line,
                   CString::new(function).unwrap().as_ptr(),
                   code,
                   CString::new(message).unwrap().as_ptr());
}

// A macro which expends to the function name from which it was
// invoked.
#[cfg(feature = "type_name")]
macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            extern crate core;
            unsafe { core::intrinsics::type_name::<T>() }
        }
        let name = type_name_of(f);
        &name[6..name.len() - 4]
    }}
}

// A macro that expends to some static text when the underlying
// feature to get at the function name is not available.
#[cfg(not(feature = "type_name"))]
macro_rules! function {
    () => {{ "<rust>" }}
}

#[macro_export]
macro_rules!do_log {
    ($level:expr, $file:expr, $line:expr, $function:expr, $code:expr,
     $($arg:tt)*) => {
        if get_log_level() >= $level as i32 {
            sclog($level, $file, $line, $function, $code,
                  &(format!($($arg)*)));
        }
    }
}

#[macro_export]
macro_rules!SCLogNotice {
    ($($arg:tt)*) => {
        do_log!(Level::Notice, file!(), line!(), function!(), 0, $($arg)*);
    }
}

#[macro_export]
macro_rules!SCLogInfo {
    ($($arg:tt)*) => {
        do_log!(Level::Info, file!(), line!(), function!(), 0, $($arg)*);
    }
}

#[macro_export]
macro_rules!SCLogPerf {
    ($($arg:tt)*) => {
        do_log!(Level::Perf, file!(), line!(), function!(), 0, $($arg)*);
    }
}

#[macro_export]
macro_rules!SCLogConfig {
    ($($arg:tt)*) => {
        do_log!(Level::Config, file!(), line!(), function!(), 0, $($arg)*);
    }
}

#[macro_export]
macro_rules!SCLogDebug {
    ($($arg:tt)*) => {
        do_log!(Level::Debug, file!(), line!(), function!(), 0, $($arg)*);
    }
}

#[no_mangle]
pub extern "C" fn rs_log_set_level(level: i32) {
    unsafe {
        LEVEL = level;
    }
}
