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

use std::os::raw::c_char;
use std::os::raw::c_void;
use std::os::raw::c_int;
use std::ffi::{CString, CStr};
use std::ptr;
use std::str;
use nom7::{
    character::complete::{multispace0, not_line_ending},
    sequence::{preceded, tuple},
    number::complete::double,
    combinator::verify,
    IResult,
};

extern {
    fn ConfGet(key: *const c_char, res: *mut *const c_char) -> i8;
    fn ConfGetChildValue(conf: *const c_void, key: *const c_char,
                         vptr: *mut *const c_char) -> i8;
    fn ConfGetChildValueBool(conf: *const c_void, key: *const c_char,
                             vptr: *mut c_int) -> i8;
    fn ConfGetNode(key: *const c_char) -> *const c_void;
}

pub fn conf_get_node(key: &str) -> Option<ConfNode> {
    let key = if let Ok(key) = CString::new(key) {
        key
    } else {
        return None;
    };

    let node = unsafe { ConfGetNode(key.as_ptr()) };
    if node.is_null() {
        None
    } else {
        Some(ConfNode::wrap(node))
    }
}

// Return the string value of a configuration value.
pub fn conf_get(key: &str) -> Option<&str> {
    let mut vptr: *const c_char = ptr::null_mut();

    unsafe {
        let s = CString::new(key).unwrap();
        if ConfGet(s.as_ptr(), &mut vptr) != 1 {
            SCLogDebug!("Failed to find value for key {}", key);
            return None;
        }
    }

    if vptr.is_null() {
        return None;
    }

    let value = str::from_utf8(unsafe{
        CStr::from_ptr(vptr).to_bytes()
    }).unwrap();

    return Some(value);
}

// Return the value of key as a boolean. A value that is not set is
// the same as having it set to false.
pub fn conf_get_bool(key: &str) -> bool {
    match conf_get(key) {
        Some(val) => {
            match val {
                "1" | "yes" | "true" | "on" => {
                    return true;
                },
                _ => {},
            }
        },
        None => {},
    }

    return false;
}

/// Wrap a Suricata ConfNode and expose some of its methods with a
/// Rust friendly interface.
pub struct ConfNode {
    pub conf: *const c_void,
}

impl ConfNode {

    pub fn wrap(conf: *const c_void) -> Self {
        return Self { conf }
    }

    pub fn get_child_value(&self, key: &str) -> Option<&str> {
        let mut vptr: *const c_char = ptr::null_mut();

        unsafe {
            let s = CString::new(key).unwrap();
            if ConfGetChildValue(self.conf,
                                 s.as_ptr(),
                                 &mut vptr) != 1 {
                return None;
            }
        }

        if vptr.is_null() {
            return None;
        }

        let value = str::from_utf8(unsafe{
            CStr::from_ptr(vptr).to_bytes()
        }).unwrap();

        return Some(value);
    }

    pub fn get_child_bool(&self, key: &str) -> bool {
        let mut vptr: c_int = 0;

        unsafe {
            let s = CString::new(key).unwrap();
            if ConfGetChildValueBool(self.conf,
                                     s.as_ptr(),
                                     &mut vptr) != 1 {
                return false;
            }
        }

        if vptr == 1 {
            return true;
        }
        return false;
    }

}

const BYTE: u64       = 1;
const KILOBYTE: u64   = 1024;
const MEGABYTE: u64   = 1_048_576;
const GIGABYTE: u64   = 1_073_741_824;

/// Helper function to retrieve memory unit from a string slice
///
/// Return value: u64
///
/// # Arguments
///
/// * `unit` - A string slice possibly containing memory unit
fn get_memunit(unit: &str) -> u64 {
    let unit = &unit.to_lowercase()[..];
    match unit {
        "b"     => { BYTE }
        "kb"    => { KILOBYTE }
        "mb"    => { MEGABYTE }
        "gb"    => { GIGABYTE }
        _       => { 0 }
    }
}

/// Parses memory units from human readable form to machine readable
///
/// Return value:
///     Result => Ok(u64)
///            => Err(error string)
///
/// # Arguments
///
/// * `arg` - A string slice that holds the value parsed from the config
pub fn get_memval(arg: &str) -> Result<u64, &'static str> {
    let arg = arg.trim();
    let val: f64;
    let mut unit: &str;
    let mut parser = tuple((preceded(multispace0, double),
                        preceded(multispace0, verify(not_line_ending, |c: &str| c.len() < 3))));
    let r: IResult<&str, (f64, &str)> = parser(arg);
    if let Ok(r) = r {
        val = (r.1).0;
        unit = (r.1).1;
    } else {
        return Err("Error parsing the memory value");
    }
    if unit.is_empty() {
        unit = "B";
    }
    let unit = get_memunit(unit);
    if unit == 0 {
        return Err("Invalid memory unit");
    }
    let res = val * unit as f64;
    Ok(res as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memval_nospace() {
        let s = "10";
        let res = 10 ;
        assert_eq!(Ok(10), get_memval(s));

        let s = "10kb";
        assert_eq!(Ok(res * KILOBYTE), get_memval(s));

        let s = "10Kb";
        assert_eq!(Ok(res * KILOBYTE), get_memval(s));

        let s = "10KB";
        assert_eq!(Ok(res * KILOBYTE), get_memval(s));

        let s = "10mb";
        assert_eq!(Ok(res * MEGABYTE), get_memval(s));

        let s = "10gb";
        assert_eq!(Ok(res * GIGABYTE), get_memval(s));
    }

    #[test]
    fn test_memval_space_start() {
        let s = " 10";
        let res = 10 ;
        assert_eq!(Ok(res), get_memval(s));

        let s = " 10Kb";
        assert_eq!(Ok(res * KILOBYTE), get_memval(s));

        let s = "     10mb";
        assert_eq!(Ok(res * MEGABYTE), get_memval(s));

        let s = "        10Gb";
        assert_eq!(Ok(res * GIGABYTE), get_memval(s));

        let s = "   30b";
        assert_eq!(Ok(30), get_memval(s));
    }

    #[test]
    fn test_memval_space_end() {
        let s = " 10                  ";
        let res = 10 ;
        assert_eq!(Ok(res), get_memval(s));

        let s = "10Kb    ";
        assert_eq!(Ok(res * KILOBYTE), get_memval(s));

        let s = "10mb            ";
        assert_eq!(Ok(res * MEGABYTE), get_memval(s));

        let s = "        10Gb           ";
        assert_eq!(Ok(res * GIGABYTE), get_memval(s));

        let s = "   30b                    ";
        assert_eq!(Ok(30), get_memval(s));
    }

    #[test]
    fn test_memval_space_in_bw() {
        let s = " 10                  ";
        let res = 10 ;
        assert_eq!(Ok(res), get_memval(s));

        let s = "10 Kb    ";
        assert_eq!(Ok(res * KILOBYTE), get_memval(s));

        let s = "10 mb";
        assert_eq!(Ok(res * MEGABYTE), get_memval(s));

        let s = "        10 Gb           ";
        assert_eq!(Ok(res * GIGABYTE), get_memval(s));

        let s = "30 b";
        assert_eq!(Ok(30), get_memval(s));
    }

    #[test]
    fn test_memval_float_val() {
        let s = " 10.5                  ";
        assert_eq!(Ok(10), get_memval(s));

        let s = "10.8Kb    ";
        assert_eq!(Ok((10.8 * KILOBYTE as f64) as u64), get_memval(s));

        let s = "10.4 mb            ";
        assert_eq!(Ok((10.4 * MEGABYTE as f64) as u64), get_memval(s));

        let s = "        10.5Gb           ";
        assert_eq!(Ok((10.5 * GIGABYTE as f64) as u64), get_memval(s));

        let s = "   30.0 b                    ";
        assert_eq!(Ok(30), get_memval(s));
    }

    #[test]
    fn test_memval_erroneous_val() {
        let s = "5eb";
        assert_eq!(true, get_memval(s).is_err());

        let s = "5 1kb";
        assert_eq!(true, get_memval(s).is_err());

        let s = "61k b";
        assert_eq!(true, get_memval(s).is_err());

        let s = "8 8 k b";
        assert_eq!(true, get_memval(s).is_err());
    }
}
