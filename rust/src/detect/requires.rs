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

use std::{cmp::Ordering, ffi::CStr};

// std::ffi::{c_char, c_int} is recommended these days, but requires
// Rust 1.64.0.
use std::os::raw::{c_char, c_int};

use nom7::{
    branch::alt,
    bytes::complete::{tag, take_till, take_while},
    character::complete::{char, multispace0},
    combinator::map_res,
    sequence::preceded,
    IResult,
};

#[derive(Debug, Eq, PartialEq)]
enum VersionCompareOp {
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug, Eq, PartialEq)]
struct SuricataVersion {
    major: u8,
    minor: u8,
    patch: u8,
}

impl PartialOrd for SuricataVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SuricataVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                other => other,
            },
            other => other,
        }
    }
}

impl SuricataVersion {
    fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RuleRequireVersion {
    pub op: VersionCompareOp,
    pub version: SuricataVersion,
}

#[derive(Debug)]
struct Requires {
    pub features: Vec<String>,
    pub versions: Vec<RuleRequireVersion>,
}

impl Requires {
    fn new() -> Self {
        Self {
            features: vec![],
            versions: vec![],
        }
    }
}

fn parse_op_gt(input: &str) -> IResult<&str, VersionCompareOp> {
    let (input, _) = tag(">")(input)?;
    Ok((input, VersionCompareOp::Gt))
}

fn parse_op_gte(input: &str) -> IResult<&str, VersionCompareOp> {
    let (input, _) = tag(">=")(input)?;
    Ok((input, VersionCompareOp::Gte))
}

fn parse_op_lt(input: &str) -> IResult<&str, VersionCompareOp> {
    let (input, _) = tag("<")(input)?;
    Ok((input, VersionCompareOp::Lt))
}

fn parse_op_lte(input: &str) -> IResult<&str, VersionCompareOp> {
    let (input, _) = tag("<=")(input)?;
    Ok((input, VersionCompareOp::Lte))
}

fn parse_op(input: &str) -> IResult<&str, VersionCompareOp> {
    // Be careful of order, ie) attempt to parse >= before >.
    alt((parse_op_gte, parse_op_gt, parse_op_lte, parse_op_lt))(input)
}

/// Parse the next part of the version.
///
/// That is all chars up to eof, or the next '.' or '-'.
fn parse_next_version_part(input: &str) -> IResult<&str, u8> {
    map_res(take_till(|c| c == '.' || c == '-'), |s: &str| {
        s.parse::<u8>()
    })(input)
}

fn parse_version(input: &str) -> IResult<&str, SuricataVersion> {
    let (input, major) = parse_next_version_part(input)?;
    let (input, minor) = if input.is_empty() {
        (input, 0)
    } else {
        preceded(char('.'), parse_next_version_part)(input)?
    };
    let (input, patch) = if input.is_empty() {
        (input, 0)
    } else {
        preceded(char('.'), parse_next_version_part)(input)?
    };

    Ok((input, SuricataVersion::new(major, minor, patch)))
}

fn parse_requires(mut input: &str) -> IResult<&str, Requires> {
    let mut requires = Requires::new();

    while !input.is_empty() {
        let (rest, keyword) = preceded(multispace0, alt((tag("feature"), tag("version"))))(input)?;
        let (rest, value) = preceded(multispace0, take_till(|c: char| c == ','))(rest)?;

        match keyword {
            "feature" => {
                requires.features.push(value.trim().to_string());
            }
            "version" => {
                let (value, op) = preceded(multispace0, parse_op)(value)?;
                let (_, version) = preceded(multispace0, parse_version)(value)?;
                let require_version = RuleRequireVersion { op, version };
                requires.versions.push(require_version);
            }
            _ => {}
        }

        // Now consume any remaining "," or whitespace.
        let (rest, _) = take_while(|c: char| c == ',' || c.is_whitespace())(rest)?;
        input = rest;
    }
    Ok((input, requires))
}

static ERR_BAD_SURICATA_VERSION: &str = "Failed to parse running Suricata version\0";
static ERR_BAD_REQUIRES: &str = "Failed to parse requires expression\0";

fn parse_suricata_version(version: &CStr) -> Result<SuricataVersion, *mut c_char> {
    let version = version
        .to_str()
        .map_err(|_| ERR_BAD_SURICATA_VERSION.as_ptr() as *mut c_char)?;
    let (_, version) =
        parse_version(version).map_err(|_| ERR_BAD_SURICATA_VERSION.as_ptr() as *mut c_char)?;
    Ok(version)
}

#[derive(Debug, Eq, PartialEq)]
enum RequiresError {
    /// The Suricata version greater than (too new) than the required
    /// version.
    VersionGt,

    /// The Suricata version is less than (too old) than the required
    /// version.
    VersionLt,

    /// The running Suricata is missing a required feature.
    MissingFeature,
}

impl RequiresError {
    /// Return a pointer to a C compatible constant error message.
    const fn c_errmsg(&self) -> *const c_char {
        let msg = match self {
            RequiresError::VersionGt => "Suricata version great than required\0",
            RequiresError::VersionLt => "Suricata version less than required\0",
            RequiresError::MissingFeature => "Suricata missing a required feature\0",
        };
        msg.as_ptr() as *const c_char
    }
}

fn check_requires(
    requires: &Requires, suricata_version: &SuricataVersion,
) -> Result<(), RequiresError> {
    for version in &requires.versions {
        match version.op {
            VersionCompareOp::Gt => {
                if suricata_version <= &version.version {
                    return Err(RequiresError::VersionLt);
                }
            }
            VersionCompareOp::Gte => {
                if suricata_version < &version.version {
                    return Err(RequiresError::VersionLt);
                }
            }
            VersionCompareOp::Lt => {
                if suricata_version >= &version.version {
                    return Err(RequiresError::VersionGt);
                }
            }
            VersionCompareOp::Lte => {
                if suricata_version > &version.version {
                    return Err(RequiresError::VersionGt);
                }
            }
        }
    }

    for feature in &requires.features {
        if !crate::feature::requires(feature) {
            return Err(RequiresError::MissingFeature);
        }
    }

    Ok(())
}

/// Parse a "requires" rule option.
///
/// Return values:
///   *  0 - OK, rule should continue loading
///   * -1 - Error parsing the requires content
///   * -4 - Requirements not met, don't continue loading the rule, this
///          value is chosen so it can be passed back to the options parser
///          as its treated as a non-fatal silent error.
#[no_mangle]
pub unsafe extern "C" fn SCDetectCheckRequires(
    requires: *const c_char, suricata_version_string: *const c_char, errstr: *mut *const c_char,
) -> c_int {
    // First parse the running Suricata version.
    let suricata_version = match parse_suricata_version(CStr::from_ptr(suricata_version_string)) {
        Ok(version) => version,
        Err(err) => {
            *errstr = err;
            return -1;
        }
    };

    let requires = match CStr::from_ptr(requires).to_str().map(parse_requires) {
        Ok(Ok((_, requires))) => requires,
        _ => {
            *errstr = ERR_BAD_REQUIRES.as_ptr() as *mut c_char;
            return -1;
        }
    };

    match check_requires(&requires, &suricata_version) {
        Ok(()) => 0,
        Err(err) => {
            *errstr = err.c_errmsg();
            -4
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_suricata_version() {
        // 7.1.1 < 7.1.2
        assert!(SuricataVersion::new(7, 1, 1) < SuricataVersion::new(7, 1, 2));

        // 7.1.1 <= 7.1.2
        assert!(SuricataVersion::new(7, 1, 1) <= SuricataVersion::new(7, 1, 2));

        // 7.1.1 <= 7.1.1
        assert!(SuricataVersion::new(7, 1, 1) <= SuricataVersion::new(7, 1, 1));

        // NOT 7.1.1 < 7.1.1
        assert!(SuricataVersion::new(7, 1, 1) >= SuricataVersion::new(7, 1, 1));

        // 7.3.1 < 7.22.1
        assert!(SuricataVersion::new(7, 3, 1) < SuricataVersion::new(7, 22, 1));

        // 7.22.1 >= 7.3.4
        assert!(SuricataVersion::new(7, 22, 1) >= SuricataVersion::new(7, 3, 4));
    }

    #[test]
    fn test_parse_op() {
        assert_eq!(parse_op(">").unwrap().1, VersionCompareOp::Gt);
        assert_eq!(parse_op(">=").unwrap().1, VersionCompareOp::Gte);
        assert_eq!(parse_op("<").unwrap().1, VersionCompareOp::Lt);
        assert_eq!(parse_op("<=").unwrap().1, VersionCompareOp::Lte);

        assert!(parse_op("=").is_err());
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(
            parse_version("7").unwrap().1,
            SuricataVersion {
                major: 7,
                minor: 0,
                patch: 0,
            }
        );

        assert_eq!(
            parse_version("7.1").unwrap().1,
            SuricataVersion {
                major: 7,
                minor: 1,
                patch: 0,
            }
        );

        assert_eq!(
            parse_version("7.1.2").unwrap().1,
            SuricataVersion {
                major: 7,
                minor: 1,
                patch: 2,
            }
        );

        // Suricata pre-releases will have a suffix starting with a
        // '-', so make sure we accept those versions as well.
        assert_eq!(
            parse_version("8.0.0-dev").unwrap().1,
            SuricataVersion {
                major: 8,
                minor: 0,
                patch: 0,
            }
        );

        assert!(parse_version("7.1.2a").is_err());
        assert!(parse_version("a").is_err());
        assert!(parse_version("777").is_err());
        assert!(parse_version("product-1").is_err());
    }

    #[test]
    fn test_parse_requires() {
        let (_, requires) = parse_requires("  feature geoip").unwrap();
        assert_eq!(&requires.features[0], "geoip");

        let (_, requires) = parse_requires("  feature geoip,    feature    lua  ").unwrap();
        assert_eq!(&requires.features[0], "geoip");
        assert_eq!(&requires.features[1], "lua");

        let (_, requires) = parse_requires("version >=7").unwrap();
        assert_eq!(
            &requires.versions[0],
            &RuleRequireVersion {
                op: VersionCompareOp::Gte,
                version: SuricataVersion {
                    major: 7,
                    minor: 0,
                    patch: 0,
                }
            }
        );

        let (_, requires) = parse_requires("version >= 7.1").unwrap();
        assert_eq!(
            &requires.versions[0],
            &RuleRequireVersion {
                op: VersionCompareOp::Gte,
                version: SuricataVersion {
                    major: 7,
                    minor: 1,
                    patch: 0,
                }
            }
        );

        let (_, requires) = parse_requires("feature output::file-store, version >= 7.1.2").unwrap();
        assert_eq!(
            &requires.versions[0],
            &RuleRequireVersion {
                op: VersionCompareOp::Gte,
                version: SuricataVersion {
                    major: 7,
                    minor: 1,
                    patch: 2,
                }
            }
        );

        let (_, requires) =
            parse_requires("feature: geoip, version >= 7.1.2, version < 8").unwrap();
        assert_eq!(
            &requires.versions[0],
            &RuleRequireVersion {
                op: VersionCompareOp::Gte,
                version: SuricataVersion {
                    major: 7,
                    minor: 1,
                    patch: 2,
                }
            }
        );
        assert_eq!(
            &requires.versions[1],
            &RuleRequireVersion {
                op: VersionCompareOp::Lt,
                version: SuricataVersion {
                    major: 8,
                    minor: 0,
                    patch: 0,
                }
            }
        );
    }

    #[test]
    fn test_check_requires() {
        // Have 7.0.4, require >= 8.
        let suricata_version = SuricataVersion::new(7, 0, 4);
        let requires = parse_requires("version >= 8").unwrap().1;
        assert_eq!(
            check_requires(&requires, &suricata_version),
            Err(RequiresError::VersionLt)
        );

        // Have 7.0.4, require 7.0.3.
        let suricata_version = SuricataVersion::new(7, 0, 4);
        let requires = parse_requires("version >= 7.0.3").unwrap().1;
        assert_eq!(check_requires(&requires, &suricata_version), Ok(()));

        // Have 8.0.0, require >= 7.0.0 and < 8.0
        let suricata_version = SuricataVersion::new(8, 0, 0);
        let requires = parse_requires("version >= 7.0.0, version < 8").unwrap().1;
        assert_eq!(
            check_requires(&requires, &suricata_version),
            Err(RequiresError::VersionGt)
        );

        // Have 8.0.0, require >= 7.0.0 and < 9.0
        let suricata_version = SuricataVersion::new(8, 0, 0);
        let requires = parse_requires("version >= 7.0.0, version < 9").unwrap().1;
        assert_eq!(check_requires(&requires, &suricata_version), Ok(()));

        // Require feature foobar.
        let suricata_version = SuricataVersion::new(8, 0, 0);
        let requires = parse_requires("feature foobar").unwrap().1;
        assert_eq!(
            check_requires(&requires, &suricata_version),
            Err(RequiresError::MissingFeature)
        );

        // Require feature foobar, but this time we have the feature.
        let suricata_version = SuricataVersion::new(8, 0, 0);
        let requires = parse_requires("feature true_foobar").unwrap().1;
        assert_eq!(check_requires(&requires, &suricata_version), Ok(()));
    }
}
