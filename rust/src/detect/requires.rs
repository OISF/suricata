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

use std::collections::{HashSet, VecDeque};
use std::{cmp::Ordering, ffi::CStr};

// std::ffi::{c_char, c_int} is recommended these days, but requires
// Rust 1.64.0.
use std::os::raw::{c_char, c_int};

use nom7::bytes::complete::take_while;
use nom7::combinator::map;
use nom7::multi::{many1, separated_list1};
use nom7::sequence::tuple;
use nom7::{
    branch::alt,
    bytes::complete::{tag, take_till},
    character::complete::{char, multispace0},
    combinator::map_res,
    sequence::preceded,
    IResult,
};

#[derive(Debug, Eq, PartialEq)]
enum RequiresError {
    /// Suricata is greater than the required version.
    VersionGt,

    /// Suricata is less than the required version.
    VersionLt(SuricataVersion),

    /// The running Suricata is missing a required feature.
    MissingFeature(String),

    /// The Suricata version, of Suricata itself is bad and failed to parse.
    BadSuricataVersion,

    /// The requires expression is bad and failed to parse.
    BadRequires,

    /// MultipleVersions
    MultipleVersions,

    /// Passed in requirements not a valid UTF-8 string.
    Utf8Error,

    /// An unknown requirement was provided.
    UnknownRequirement(String),
}

impl RequiresError {
    /// Return a pointer to a C compatible constant error message.
    const fn c_errmsg(&self) -> *const c_char {
        let msg = match self {
            Self::VersionGt => "Suricata version greater than required\0",
            Self::VersionLt(_) => "Suricata version less than required\0",
            Self::MissingFeature(_) => "Suricata missing a required feature\0",
            Self::BadSuricataVersion => "Failed to parse running Suricata version\0",
            Self::BadRequires => "Failed to parse requires expression\0",
            Self::MultipleVersions => "Version may only be specified once\0",
            Self::Utf8Error => "Requires expression is not valid UTF-8\0",
            Self::UnknownRequirement(_) => "Unknown requirements\0",
        };
        msg.as_ptr() as *const c_char
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum VersionCompareOp {
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug, Clone, Eq, PartialEq)]
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

impl std::fmt::Display for SuricataVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
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

/// Parse a version expression.
///
/// Parse into a version expression into a nested array, for example:
///
///    version: >= 7.0.3 < 8 | >= 8.0.3
///
/// would result in something like:
///
/// [
///     [{op: gte, version: 7.0.3}, {op:lt, version: 8}],
///     [{op: gte, version: 8.0.3}],
/// ]
fn parse_version_expression(input: &str) -> IResult<&str, Vec<Vec<RuleRequireVersion>>> {
    let sep = preceded(multispace0, tag("|"));
    let inner_parser = many1(tuple((parse_op, parse_version)));
    let (input, versions) = separated_list1(sep, inner_parser)(input)?;

    let versions = versions
        .into_iter()
        .map(|versions| {
            versions
                .into_iter()
                .map(|(op, version)| RuleRequireVersion { op, version })
                .collect()
        })
        .collect();

    Ok((input, versions))
}

#[derive(Debug, Eq, PartialEq)]
struct RuleRequireVersion {
    pub op: VersionCompareOp,
    pub version: SuricataVersion,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct Requires {
    pub features: Vec<String>,

    /// The version expression.
    ///
    /// - All of the inner most must evaluate to true.
    /// - To pass, any of the outer must be true.
    pub version: Vec<Vec<RuleRequireVersion>>,

    /// Unknown parameters to requires.
    pub unknown: Vec<String>,
}

fn parse_op(input: &str) -> IResult<&str, VersionCompareOp> {
    preceded(
        multispace0,
        alt((
            map(tag(">="), |_| VersionCompareOp::Gte),
            map(tag(">"), |_| VersionCompareOp::Gt),
            map(tag("<="), |_| VersionCompareOp::Lte),
            map(tag("<"), |_| VersionCompareOp::Lt),
        )),
    )(input)
}

/// Parse the next part of the version.
///
/// That is all chars up to eof, or the next '.' or '-'.
fn parse_next_version_part(input: &str) -> IResult<&str, u8> {
    map_res(
        take_till(|c| c == '.' || c == '-' || c == ' '),
        |s: &str| s.parse::<u8>(),
    )(input)
}

/// Parse a version string into a SuricataVersion.
fn parse_version(input: &str) -> IResult<&str, SuricataVersion> {
    let (input, major) = preceded(multispace0, parse_next_version_part)(input)?;
    let (input, minor) = if input.is_empty() || input.starts_with(' ') {
        (input, 0)
    } else {
        preceded(char('.'), parse_next_version_part)(input)?
    };
    let (input, patch) = if input.is_empty() || input.starts_with(' ') {
        (input, 0)
    } else {
        preceded(char('.'), parse_next_version_part)(input)?
    };

    Ok((input, SuricataVersion::new(major, minor, patch)))
}

fn parse_key_value(input: &str) -> IResult<&str, (&str, &str)> {
    // Parse the keyword, any sequence of characters, numbers or "-" or "_".
    let (input, key) = preceded(
        multispace0,
        take_while(|c: char| c.is_alphanumeric() || c == '-' || c == '_'),
    )(input)?;
    let (input, value) = preceded(multispace0, take_till(|c: char| c == ','))(input)?;
    Ok((input, (key, value)))
}

fn parse_requires(mut input: &str) -> Result<Requires, RequiresError> {
    let mut requires = Requires::default();

    while !input.is_empty() {
        let (rest, (keyword, value)) =
            parse_key_value(input).map_err(|_| RequiresError::BadRequires)?;
        match keyword {
            "feature" => {
                requires.features.push(value.trim().to_string());
            }
            "version" => {
                if !requires.version.is_empty() {
                    return Err(RequiresError::MultipleVersions);
                }
                let (_, versions) =
                    parse_version_expression(value).map_err(|_| RequiresError::BadRequires)?;
                requires.version = versions;
            }
            _ => {
                // Unknown keyword, allow by warn in case we extend
                // this in the future.
                SCLogWarning!("Unknown requires keyword: {}", keyword);
                requires.unknown.push(format!("{} {}", keyword, value));
            }
        }

        // No consume any remaining ',' or whitespace.
        input = rest.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
    }
    Ok(requires)
}

fn parse_suricata_version(version: &CStr) -> Result<SuricataVersion, *const c_char> {
    let version = version
        .to_str()
        .map_err(|_| RequiresError::BadSuricataVersion.c_errmsg())?;
    let (_, version) =
        parse_version(version).map_err(|_| RequiresError::BadSuricataVersion.c_errmsg())?;
    Ok(version)
}

fn check_version(
    version: &RuleRequireVersion, suricata_version: &SuricataVersion,
) -> Result<(), RequiresError> {
    match version.op {
        VersionCompareOp::Gt => {
            if suricata_version <= &version.version {
                return Err(RequiresError::VersionLt(version.version.clone()));
            }
        }
        VersionCompareOp::Gte => {
            if suricata_version < &version.version {
                return Err(RequiresError::VersionLt(version.version.clone()));
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
    Ok(())
}

fn check_requires(
    requires: &Requires, suricata_version: &SuricataVersion, ignore_unknown: bool,
) -> Result<(), RequiresError> {
    if !ignore_unknown && !requires.unknown.is_empty() {
        return Err(RequiresError::UnknownRequirement(
            requires.unknown.join(","),
        ));
    }

    if !requires.version.is_empty() {
        let mut errs = VecDeque::new();
        let mut ok = 0;
        for or_versions in &requires.version {
            let mut err = None;
            for version in or_versions {
                if let Err(_err) = check_version(version, suricata_version) {
                    err = Some(_err);
                    break;
                }
            }
            if let Some(err) = err {
                errs.push_back(err);
            } else {
                ok += 1;
            }
        }
        if ok == 0 {
            return Err(errs.pop_front().unwrap());
        }
    }

    for feature in &requires.features {
        if !crate::feature::requires(feature) {
            return Err(RequiresError::MissingFeature(feature.to_string()));
        }
    }

    Ok(())
}

/// Status object to hold required features and the latest version of
/// Suricata required.
///
/// Full qualified name as it is exposed to C.
#[derive(Debug, Default)]
pub struct SCDetectRequiresStatus {
    min_version: Option<SuricataVersion>,
    features: HashSet<String>,

    /// Number of rules that didn't meet a feature.
    feature_count: u64,

    /// Number of rules where the Suricata version wasn't new enough.
    lt_count: u64,

    /// Number of rules where the Suricata version was too new.
    gt_count: u64,
}

#[no_mangle]
pub extern "C" fn SCDetectRequiresStatusNew() -> *mut SCDetectRequiresStatus {
    Box::into_raw(Box::default())
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectRequiresStatusFree(status: *mut SCDetectRequiresStatus) {
    if !status.is_null() {
        std::mem::drop(Box::from_raw(status));
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectRequiresStatusLog(
    status: &mut SCDetectRequiresStatus, suricata_version: *const c_char, tenant_id: u32,
) {
    let suricata_version = CStr::from_ptr(suricata_version)
        .to_str()
        .unwrap_or("<unknown>");

    let mut parts = vec![];
    if status.lt_count > 0 {
        let min_version = status
            .min_version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        let msg = format!(
            "{} {} skipped because the running Suricata version {} is less than {}",
            status.lt_count,
            if status.lt_count > 1 {
                "rules were"
            } else {
                "rule was"
            },
            suricata_version,
            &min_version
        );
        parts.push(msg);
    }
    if status.gt_count > 0 {
        let msg = format!(
            "{} {} for an older version Suricata",
            status.gt_count,
            if status.gt_count > 1 {
                "rules were skipped as they are"
            } else {
                "rule was skipped as it is"
            }
        );
        parts.push(msg);
    }
    if status.feature_count > 0 {
        let features = status
            .features
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        let msg = format!(
            "{}{} {} skipped because the running Suricata version does not have feature{}: [{}]",
            if tenant_id > 0 {
                format!("tenant id: {}  ", tenant_id)
            } else {
                String::new()
            },
            status.feature_count,
            if status.feature_count > 1 {
                "rules were"
            } else {
                "rule was"
            },
            if status.feature_count > 1 { "s" } else { "" },
            &features
        );
        parts.push(msg);
    }

    let msg = parts.join("; ");

    if status.lt_count > 0 {
        SCLogNotice!("{}", &msg);
    } else if status.gt_count > 0 || status.feature_count > 0 {
        SCLogInfo!("{}", &msg);
    }
}

/// Parse a "requires" rule option.
///
/// Return values:
///   *  0 - OK, rule should continue loading
///   * -1 - Error parsing the requires content
///   * -4 - Requirements not met, don't continue loading the rule, this
///     value is chosen so it can be passed back to the options parser
///     as its treated as a non-fatal silent error.
#[no_mangle]
pub unsafe extern "C" fn SCDetectCheckRequires(
    requires: *const c_char, suricata_version_string: *const c_char, errstr: *mut *const c_char,
    status: &mut SCDetectRequiresStatus, ignore_unknown: c_int,
) -> c_int {
    // First parse the running Suricata version.
    let suricata_version = match parse_suricata_version(CStr::from_ptr(suricata_version_string)) {
        Ok(version) => version,
        Err(err) => {
            *errstr = err;
            return -1;
        }
    };

    let requires = match CStr::from_ptr(requires)
        .to_str()
        .map_err(|_| RequiresError::Utf8Error)
        .and_then(parse_requires)
    {
        Ok(requires) => requires,
        Err(err) => {
            *errstr = err.c_errmsg();
            return -1;
        }
    };

    let ignore_unknown = ignore_unknown != 0;

    match check_requires(&requires, &suricata_version, ignore_unknown) {
        Ok(()) => 0,
        Err(err) => {
            match &err {
                RequiresError::VersionLt(version) => {
                    if let Some(min_version) = &status.min_version {
                        if version > min_version {
                            status.min_version = Some(version.clone());
                        }
                    } else {
                        status.min_version = Some(version.clone());
                    }
                    status.lt_count += 1;
                }
                RequiresError::MissingFeature(feature) => {
                    status.features.insert(feature.to_string());
                    status.feature_count += 1;
                }
                RequiresError::VersionGt => {
                    status.gt_count += 1;
                }
                RequiresError::UnknownRequirement(_) => {}
                _ => {}
            }
            *errstr = err.c_errmsg();
            return -4;
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
        let requires = parse_requires("  feature geoip").unwrap();
        assert_eq!(&requires.features[0], "geoip");

        let requires = parse_requires("  feature geoip,    feature    lua  ").unwrap();
        assert_eq!(&requires.features[0], "geoip");
        assert_eq!(&requires.features[1], "lua");

        let requires = parse_requires("version >=7").unwrap();
        assert_eq!(
            requires,
            Requires {
                features: vec![],
                version: vec![vec![RuleRequireVersion {
                    op: VersionCompareOp::Gte,
                    version: SuricataVersion {
                        major: 7,
                        minor: 0,
                        patch: 0,
                    }
                }]],
                unknown: vec![],
            }
        );

        let requires = parse_requires("version >= 7.1").unwrap();
        assert_eq!(
            requires,
            Requires {
                features: vec![],
                version: vec![vec![RuleRequireVersion {
                    op: VersionCompareOp::Gte,
                    version: SuricataVersion {
                        major: 7,
                        minor: 1,
                        patch: 0,
                    }
                }]],
                unknown: vec![],
            }
        );

        let requires = parse_requires("feature output::file-store, version >= 7.1.2").unwrap();
        assert_eq!(
            requires,
            Requires {
                features: vec!["output::file-store".to_string()],
                version: vec![vec![RuleRequireVersion {
                    op: VersionCompareOp::Gte,
                    version: SuricataVersion {
                        major: 7,
                        minor: 1,
                        patch: 2,
                    }
                }]],
                unknown: vec![],
            }
        );

        let requires = parse_requires("feature geoip, version >= 7.1.2 < 8").unwrap();
        assert_eq!(
            requires,
            Requires {
                features: vec!["geoip".to_string()],
                version: vec![vec![
                    RuleRequireVersion {
                        op: VersionCompareOp::Gte,
                        version: SuricataVersion {
                            major: 7,
                            minor: 1,
                            patch: 2,
                        },
                    },
                    RuleRequireVersion {
                        op: VersionCompareOp::Lt,
                        version: SuricataVersion {
                            major: 8,
                            minor: 0,
                            patch: 0,
                        }
                    }
                ]],
                unknown: vec![],
            }
        );
    }

    #[test]
    fn test_check_requires() {
        // Have 7.0.4, require >= 8.
        let suricata_version = SuricataVersion::new(7, 0, 4);
        let requires = parse_requires("version >= 8").unwrap();
        assert_eq!(
            check_requires(&requires, &suricata_version, false),
            Err(RequiresError::VersionLt(SuricataVersion {
                major: 8,
                minor: 0,
                patch: 0,
            })),
        );

        // Have 7.0.4, require 7.0.3.
        let suricata_version = SuricataVersion::new(7, 0, 4);
        let requires = parse_requires("version >= 7.0.3").unwrap();
        assert_eq!(check_requires(&requires, &suricata_version, false), Ok(()));

        // Have 8.0.0, require >= 7.0.0 and < 8.0
        let suricata_version = SuricataVersion::new(8, 0, 0);
        let requires = parse_requires("version >= 7.0.0 < 8").unwrap();
        assert_eq!(
            check_requires(&requires, &suricata_version, false),
            Err(RequiresError::VersionGt)
        );

        // Have 8.0.0, require >= 7.0.0 and < 9.0
        let suricata_version = SuricataVersion::new(8, 0, 0);
        let requires = parse_requires("version >= 7.0.0 < 9").unwrap();
        assert_eq!(check_requires(&requires, &suricata_version, false), Ok(()));

        // Require feature foobar.
        let suricata_version = SuricataVersion::new(8, 0, 0);
        let requires = parse_requires("feature foobar").unwrap();
        assert_eq!(
            check_requires(&requires, &suricata_version, false),
            Err(RequiresError::MissingFeature("foobar".to_string()))
        );

        // Require feature foobar, but this time we have the feature.
        let suricata_version = SuricataVersion::new(8, 0, 0);
        let requires = parse_requires("feature true_foobar").unwrap();
        assert_eq!(check_requires(&requires, &suricata_version, false), Ok(()));

        let suricata_version = SuricataVersion::new(8, 0, 1);
        let requires = parse_requires("version >= 7.0.3 < 8").unwrap();
        assert!(check_requires(&requires, &suricata_version, false).is_err());

        let suricata_version = SuricataVersion::new(7, 0, 1);
        let requires = parse_requires("version >= 7.0.3 < 8").unwrap();
        assert!(check_requires(&requires, &suricata_version, false).is_err());

        let suricata_version = SuricataVersion::new(7, 0, 3);
        let requires = parse_requires("version >= 7.0.3 < 8").unwrap();
        assert!(check_requires(&requires, &suricata_version, false).is_ok());

        let suricata_version = SuricataVersion::new(8, 0, 3);
        let requires = parse_requires("version >= 7.0.3 < 8 | >= 8.0.3").unwrap();
        assert!(check_requires(&requires, &suricata_version, false).is_ok());

        let suricata_version = SuricataVersion::new(8, 0, 2);
        let requires = parse_requires("version >= 7.0.3 < 8 | >= 8.0.3").unwrap();
        assert!(check_requires(&requires, &suricata_version, false).is_err());

        let suricata_version = SuricataVersion::new(7, 0, 2);
        let requires = parse_requires("version >= 7.0.3 < 8 | >= 8.0.3").unwrap();
        assert!(check_requires(&requires, &suricata_version, false).is_err());

        let suricata_version = SuricataVersion::new(7, 0, 3);
        let requires = parse_requires("version >= 7.0.3 < 8 | >= 8.0.3").unwrap();
        assert!(check_requires(&requires, &suricata_version, false).is_ok());

        // Example of something that requires a fix/feature that was
        // implemented in 7.0.5, 8.0.4, 9.0.3.
        let requires = parse_requires("version >= 7.0.5 < 8 | >= 8.0.4 < 9 | >= 9.0.3").unwrap();
        assert!(check_requires(&requires, &SuricataVersion::new(6, 0, 0), false).is_err());
        assert!(check_requires(&requires, &SuricataVersion::new(7, 0, 4), false).is_err());
        assert!(check_requires(&requires, &SuricataVersion::new(7, 0, 5), false).is_ok());
        assert!(check_requires(&requires, &SuricataVersion::new(8, 0, 3), false).is_err());
        assert!(check_requires(&requires, &SuricataVersion::new(8, 0, 4), false).is_ok());
        assert!(check_requires(&requires, &SuricataVersion::new(9, 0, 2), false).is_err());
        assert!(check_requires(&requires, &SuricataVersion::new(9, 0, 3), false).is_ok());
        assert!(check_requires(&requires, &SuricataVersion::new(10, 0, 0), false).is_ok());

        let requires = parse_requires("version >= 8 < 9").unwrap();
        assert!(check_requires(&requires, &SuricataVersion::new(6, 0, 0), false).is_err());
        assert!(check_requires(&requires, &SuricataVersion::new(7, 0, 0), false).is_err());
        assert!(check_requires(&requires, &SuricataVersion::new(8, 0, 0), false).is_ok());
        assert!(check_requires(&requires, &SuricataVersion::new(9, 0, 0), false).is_err());

        // Unknown keyword.
        let requires = parse_requires("feature true_lua, foo bar, version >= 7.0.3").unwrap();
        assert_eq!(
            requires,
            Requires {
                features: vec!["true_lua".to_string()],
                version: vec![vec![RuleRequireVersion {
                    op: VersionCompareOp::Gte,
                    version: SuricataVersion {
                        major: 7,
                        minor: 0,
                        patch: 3,
                    }
                }]],
                unknown: vec!["foo bar".to_string()],
            }
        );

        // This should not pass the requires check as it contains an
        // unknown requires keyword.
        //check_requires(&requires, &SuricataVersion::new(8, 0, 0)).unwrap();
        assert!(check_requires(&requires, &SuricataVersion::new(8, 0, 0), false).is_err());
    }

    #[test]
    fn test_parse_version_expression() {
        let version_str = ">= 7.0.3 < 8 | >= 8.0.3";
        let (rest, versions) = parse_version_expression(version_str).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            versions,
            vec![
                vec![
                    RuleRequireVersion {
                        op: VersionCompareOp::Gte,
                        version: SuricataVersion {
                            major: 7,
                            minor: 0,
                            patch: 3,
                        }
                    },
                    RuleRequireVersion {
                        op: VersionCompareOp::Lt,
                        version: SuricataVersion {
                            major: 8,
                            minor: 0,
                            patch: 0,
                        }
                    },
                ],
                vec![RuleRequireVersion {
                    op: VersionCompareOp::Gte,
                    version: SuricataVersion {
                        major: 8,
                        minor: 0,
                        patch: 3,
                    }
                },],
            ]
        );
    }

    #[test]
    fn test_requires_keyword() {
        let requires = parse_requires("keyword true_bar").unwrap();
        assert!(check_requires(&requires, &SuricataVersion::new(8, 0, 0), false).is_err());
    }
}
