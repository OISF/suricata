/* Copyright (C) 2023 Open Information Security Foundation
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

use nom7::bytes::complete::is_a;
use nom7::character::complete::{char, digit1};
use nom7::combinator::{map_opt, opt};
use nom7::IResult;

use std::ffi::CStr;

fn min_version_check<'a>(rv: &'a str, sv: &'a str) -> IResult<&'a str, bool> {
    let (sv, major_sv) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(sv)?;
    let (rv, _) = opt(is_a(" "))(rv)?;
    let (rv, major_rv) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(rv)?;
    if major_sv < major_rv {
        return Ok((rv, false));
    } else if major_sv > major_rv || rv.is_empty() {
        return Ok((rv, true));
    }

    let (sv, _) = char('.')(sv)?;
    let (sv, minor_sv) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(sv)?;
    let (rv, _) = char('.')(rv)?;
    let (rv, minor_rv) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(rv)?;
    if minor_sv < minor_rv {
        return Ok((rv, false));
    } else if minor_sv > minor_rv || rv.is_empty() {
        return Ok((rv, true));
    }

    let (sv, _) = char('.')(sv)?;
    let (sv, patch_sv) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(sv)?;
    let (rv, _) = char('.')(rv)?;
    let (rv, patch_rv) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(rv)?;
    if patch_sv < patch_rv {
        return Ok((rv, false));
    } else if patch_sv > patch_rv {
        return Ok((rv, true));
    }

    if sv.is_empty() && rv.is_empty() {
        return Ok((rv, true));
    }
    // do not deal yet -rc1 in 7.0.0-rc1
    return Ok((rv, false));
}

#[no_mangle]
pub unsafe extern "C" fn rs_min_version_check(
    rawstr: *const std::os::raw::c_char, suristr: *const std::os::raw::c_char,
) -> bool {
    let rulever: &CStr = CStr::from_ptr(rawstr); //unsafe
    if let Ok(rv) = rulever.to_str() {
        let suriver: &CStr = CStr::from_ptr(suristr); //unsafe
        if let Ok(sv) = suriver.to_str() {
            match min_version_check(rv, sv) {
                Ok((_, v)) => return v,
                _ => return false,
            }
        }
    }
    return false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_version_check() {
        match min_version_check("7", "6.0.11") {
            Ok((_, val)) => {
                assert_eq!(val, false);
            }
            Err(_) => {
                assert!(false);
            }
        }
        match min_version_check("6", "6.0.11") {
            Ok((_, val)) => {
                assert_eq!(val, true);
            }
            Err(_) => {
                assert!(false);
            }
        }
        match min_version_check("6", "7.0.0") {
            Ok((_, val)) => {
                assert_eq!(val, true);
            }
            Err(_) => {
                assert!(false);
            }
        }
        match min_version_check("6.0.11", "6.0.11") {
            Ok((_, val)) => {
                assert_eq!(val, true);
            }
            Err(_) => {
                assert!(false);
            }
        }
        match min_version_check("6.1", "6.0.11") {
            Ok((_, val)) => {
                assert_eq!(val, false);
            }
            Err(_) => {
                assert!(false);
            }
        }
        match min_version_check("6.1.0", "6.0.11") {
            Ok((_, val)) => {
                assert_eq!(val, false);
            }
            Err(_) => {
                assert!(false);
            }
        }
        match min_version_check("7.0.0", "7.0.0-rc1") {
            Ok((_, val)) => {
                assert_eq!(val, false);
            }
            Err(_) => {
                assert!(false);
            }
        }
        match min_version_check("7.0.0-tag", "7.0.0") {
            Ok((_, val)) => {
                assert_eq!(val, false);
            }
            Err(_) => {
                assert!(false);
            }
        }
        match min_version_check("toto", "7.0.0") {
            Ok((_, _)) => {
                assert!(false);
            }
            Err(_) => {}
        }
    }
}
