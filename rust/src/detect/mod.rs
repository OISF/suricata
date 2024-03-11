/* Copyright (C) 2022 Open Information Security Foundation
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

//! Module for rule parsing.

pub mod byte_extract;
pub mod byte_math;
pub mod error;
pub mod iprep;
pub mod parser;
pub mod requires;
pub mod stream_size;
pub mod uint;
pub mod uri;
pub mod tojson;

/// EnumString trait that will be implemented on enums that
/// derive StringEnum.
pub trait EnumString<T> {
    /// Return the enum variant of the given numeric value.
    fn from_u(v: T) -> Option<Self> where Self: Sized;

    /// Convert the enum variant to the numeric value.
    fn into_u(self) -> T;

    /// Return the string for logging the enum value.
    fn to_str(&self) -> &'static str;

    /// Get an enum variant from parsing a string.
    fn from_str(s: &str) -> Option<Self> where Self: Sized;
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
// endian <big|little|dce>
pub enum ByteEndian {
    BigEndian = 1,
    LittleEndian = 2,
    EndianDCE = 3,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ByteBase {
    BaseOct = 8,
    BaseDec = 10,
    BaseHex = 16,
}

fn get_string_value(value: &str) -> Result<ByteBase, ()> {
    let res = match value {
        "hex" => ByteBase::BaseHex,
        "oct" => ByteBase::BaseOct,
        "dec" => ByteBase::BaseDec,
        _ => return Err(()),
    };

    Ok(res)
}

fn get_endian_value(value: &str) -> Result<ByteEndian, ()> {
    let res = match value {
        "big" => ByteEndian::BigEndian,
        "little" => ByteEndian::LittleEndian,
        "dce" => ByteEndian::EndianDCE,
        _ => return Err(()),
    };

    Ok(res)
}

#[cfg(test)]
mod test {
    use super::*;
    use suricata_derive::EnumStringU8;

    #[derive(Clone, Debug, PartialEq, EnumStringU8)]
    #[repr(u8)]
    pub enum TestEnum {
        Zero = 0,
        BestValueEver = 42,
    }

    #[test]
    fn test_enum_string_u8() {
        assert_eq!(TestEnum::from_u(0), Some(TestEnum::Zero));
        assert_eq!(TestEnum::from_u(1), None);
        assert_eq!(TestEnum::from_u(42), Some(TestEnum::BestValueEver));
        assert_eq!(TestEnum::Zero.into_u(), 0);
        assert_eq!(TestEnum::BestValueEver.into_u(), 42);
        assert_eq!(TestEnum::Zero.to_str(), "zero");
        assert_eq!(TestEnum::BestValueEver.to_str(), "best_value_ever");
        assert_eq!(TestEnum::from_str("zero"), Some(TestEnum::Zero));
        assert_eq!(TestEnum::from_str("nope"), None);
        assert_eq!(TestEnum::from_str("best_value_ever"), Some(TestEnum::BestValueEver));
    }
}
