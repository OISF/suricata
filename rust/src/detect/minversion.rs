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

use nom7::character::complete::{char, digit1};
use nom7::combinator::map_opt;
use nom7::IResult;

use std::cmp::Ordering;
use std::ffi::CStr;

struct RuleVersion {
    major: u8,
    minor: Option<u8>,
    patch: Option<u8>,
}

struct SuricataVersion {
    major: u8,
    minor: u8,
    patch: u8,
}

fn parse_rule_version(rv: &str) -> IResult<&str, RuleVersion> {
    let (rv, major) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(rv)?;
    if rv.is_empty() {
        return Ok((
            rv,
            RuleVersion {
                major,
                minor: None,
                patch: None,
            },
        ));
    }
    let (rv, _) = char('.')(rv)?;
    let (rv, minor) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(rv)?;
    if rv.is_empty() {
        return Ok((
            rv,
            RuleVersion {
                major,
                minor: Some(minor),
                patch: None,
            },
        ));
    }
    let (rv, _) = char('.')(rv)?;
    let (rv, patch) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(rv)?;
    return Ok((
        rv,
        RuleVersion {
            major,
            minor: Some(minor),
            patch: Some(patch),
        },
    ));
}

fn parse_suricata_version(sv: &str) -> IResult<&str, SuricataVersion> {
    let (sv, major) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(sv)?;
    let (sv, _) = char('.')(sv)?;
    let (sv, minor) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(sv)?;
    let (sv, _) = char('.')(sv)?;
    let (sv, patch) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(sv)?;
    return Ok((
        sv,
        SuricataVersion {
            major,
            minor,
            patch,
        },
    ));
}

fn cmp_rule_suri_versions<'a>(
    rule_ver: &RuleVersion, rv_rem: &'a str, suri_ver: &SuricataVersion, sv_rem: &'a str,
) -> bool {
    match suri_ver.major.cmp(&rule_ver.major) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => {
            if let Some(minor) = rule_ver.minor {
                match suri_ver.minor.cmp(&minor) {
                    Ordering::Greater => true,
                    Ordering::Less => false,
                    Ordering::Equal => {
                        if let Some(patch) = rule_ver.patch {
                            match suri_ver.patch.cmp(&patch) {
                                Ordering::Greater => true,
                                Ordering::Less => false,
                                Ordering::Equal => sv_rem.is_empty() && rv_rem.is_empty(),
                            }
                        } else {
                            true
                        }
                    }
                }
            } else {
                // no minor in rule version
                true
            }
        }
    }
}

fn min_version_check<'a>(rv: &'a str, sv: &'a str) -> IResult<&'a str, bool> {
    let (rv_rem, rule_ver) = parse_rule_version(rv)?;
    let (sv_rem, suri_ver) = parse_suricata_version(sv)?;
    let r = cmp_rule_suri_versions(&rule_ver, rv_rem, &suri_ver, sv_rem);
    return Ok((rv_rem, r));
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
