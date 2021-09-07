/* Copyright (C) 2021 Open Information Security Foundation
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

const BASE: isize = 2;

/// enum to store currently allowed memory units in config,
/// can be easily expanded for more units
#[derive(Debug, Eq, PartialEq)]
pub enum MemUnit {
    B       = BASE.pow(0),
    KB      = BASE.pow(10),
    MB      = BASE.pow(20),
    GB      = BASE.pow(30),
    Unknown = 0,
 }

/// Helper function to retrieve memory unit from a string slice
///
/// Return value:
///     MemUnit enum type
///
/// # Arguments
///
/// * `unit` - A string slice possibly containg memory unit
///
/// # Examples
/// ```
/// use suricata_rust::memcap::{self, MemUnit};
///
/// let unit = "KB";
/// assert_eq!(MemUnit::KB, memcap::get_memunit(unit));
///
/// let unit = "mb";
/// assert_eq!(MemUnit::MB, memcap::get_memunit(unit));
///
/// let unit = "gB";
/// assert_eq!(MemUnit::GB, memcap::get_memunit(unit));
/// ```
pub fn get_memunit(unit: &str) -> MemUnit {
    let unit = &unit.to_lowercase()[..];
    match unit {
        "b"     => { MemUnit::B }
        "kb"    => { MemUnit::KB }
        "mb"    => { MemUnit::MB }
        "gb"    => { MemUnit::GB }
        _       => { MemUnit::Unknown }
    }
}

/// Parses memory units from human readable form to machine readable
///
/// Return value:
///     Result => Ok(f64)
///            => Err(error string)
///
/// # Arguments
///
/// * `arg` - A string slice that holds the value parsed from the config
///
/// # Examples
///
/// ```
/// use suricata_rust::memcap::{self, MemUnit};
///
/// let s = "5kb";
/// let res = (5 * 1024) as f64;
/// assert_eq!(Ok(res), memcap::parse(s));
///
/// let s = "10";
/// let res = 10 as f64;
/// assert_eq!(Ok(res), memcap::parse(s));
///
/// let s = "4hb";
/// assert_eq!(true, memcap::parse(s).is_err());
/// ```
pub fn parse(arg: &str) -> Result<f64, &'static str> {
    let arg = arg.trim();
    let mut val: &str = "";
    let mut unit: &str = "";
    let arg_vec: Vec<&str> = arg.split_whitespace().collect();
    let arg_vec_len = arg_vec.len();
    if arg_vec_len > 2 {
        return Err("Too many whitespaces");
    } else if arg_vec_len == 1 {
        val = arg.split(|c: char| c.is_alphabetic()).collect::<Vec<_>>()[0];
        let unit_vec = arg.split(|c: char| c.is_numeric()).collect::<Vec<_>>();
        unit = unit_vec.last().unwrap();
    } else if arg_vec_len == 2 {
        val = arg_vec[0];
        unit = arg_vec[1];
    }
    val = val.trim();
    unit = unit.trim();
    if unit.is_empty() {
        unit = "B";
    }
    let unit = get_memunit(unit) as u32;
    if unit == MemUnit::Unknown as u32 {
        return Err("Invalid memcap unit");
    }
    let unit = unit as f64;
    match val.parse::<f64>() {
        Ok(fval) => { Ok(fval * unit) }
        Err(_)   => { Err("Failed to evaluate the value") }
    }
}

#[cfg(test)]
mod tests {
    use crate::memcap::{self, MemUnit};

    #[test]
    fn test_nospace() {
        let ukb = MemUnit::KB as u32;
        let umb = MemUnit::MB as u32;
        let ugb = MemUnit::GB as u32;

        let s = "10";
        let res = 10 as f64;
        assert_eq!(Ok(10.0), memcap::parse(s));

        let s = "10kb";
        assert_eq!(Ok(res * ukb as f64), memcap::parse(s));

        let s = "10Kb";
        assert_eq!(Ok(res * ukb as f64), memcap::parse(s));

        let s = "10KB";
        assert_eq!(Ok(res * ukb as f64), memcap::parse(s));

        let s = "10mb";
        assert_eq!(Ok(res * umb as f64), memcap::parse(s));

        let s = "10gb";
        assert_eq!(Ok(res * ugb as f64), memcap::parse(s));
    }

    #[test]
    fn test_space_start() {
        let ukb = MemUnit::KB as u32;
        let umb = MemUnit::MB as u32;
        let ugb = MemUnit::GB as u32;

        let s = " 10";
        let res = 10 as f64;
        assert_eq!(Ok(res), memcap::parse(s));

        let s = " 10Kb";
        assert_eq!(Ok(res * ukb as f64), memcap::parse(s));

        let s = "     10mb";
        assert_eq!(Ok(res * umb as f64), memcap::parse(s));

        let s = "        10Gb";
        assert_eq!(Ok(res * ugb as f64), memcap::parse(s));

        let s = "   30b";
        assert_eq!(Ok(30.0), memcap::parse(s));
    }

    #[test]
    fn test_space_end() {
        let ukb = MemUnit::KB as u32;
        let umb = MemUnit::MB as u32;
        let ugb = MemUnit::GB as u32;

        let s = " 10                  ";
        let res = 10 as f64;
        assert_eq!(Ok(res), memcap::parse(s));

        let s = "10Kb    ";
        assert_eq!(Ok(res * ukb as f64), memcap::parse(s));

        let s = "10mb            ";
        assert_eq!(Ok(res * umb as f64), memcap::parse(s));

        let s = "        10Gb           ";
        assert_eq!(Ok(res * ugb as f64), memcap::parse(s));

        let s = "   30b                    ";
        assert_eq!(Ok(30.0), memcap::parse(s));
    }

    #[test]
    fn test_space_in_bw() {
        let ukb = MemUnit::KB as u32;
        let umb = MemUnit::MB as u32;
        let ugb = MemUnit::GB as u32;

        let s = " 10                  ";
        let res = 10 as f64;
        assert_eq!(Ok(res), memcap::parse(s));

        let s = "10 Kb    ";
        assert_eq!(Ok(res * ukb as f64), memcap::parse(s));

        let s = "10 mb";
        assert_eq!(Ok(res * umb as f64), memcap::parse(s));

        let s = "        10 Gb           ";
        assert_eq!(Ok(res * ugb as f64), memcap::parse(s));

        let s = "30 b";
        assert_eq!(Ok(30.0), memcap::parse(s));
    }

    #[test]
    fn test_float_val() {
        let ukb = MemUnit::KB as u32;
        let umb = MemUnit::MB as u32;
        let ugb = MemUnit::GB as u32;

        let s = " 10.5                  ";
        assert_eq!(Ok(10.5), memcap::parse(s));

        let s = "10.8Kb    ";
        assert_eq!(Ok(10.8 * ukb as f64), memcap::parse(s));

        let s = "10.4 mb            ";
        assert_eq!(Ok(10.4 * umb as f64), memcap::parse(s));

        let s = "        10.5Gb           ";
        assert_eq!(Ok(10.5 * ugb as f64), memcap::parse(s));

        let s = "   30.0 b                    ";
        assert_eq!(Ok(30.0), memcap::parse(s));
    }

    #[test]
    fn test_erroneous_val() {
        let s = "5eb";
        assert_eq!(true, memcap::parse(s).is_err());

        let s = "5 1kb";
        assert_eq!(true, memcap::parse(s).is_err());

        let s = "61k b";
        assert_eq!(true, memcap::parse(s).is_err());

        let s = "8 8 k b";
        assert_eq!(true, memcap::parse(s).is_err());
    }
}
