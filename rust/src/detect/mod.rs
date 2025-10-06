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
pub mod datasets;
pub mod entropy;
pub mod error;
pub mod float;
pub mod flow;
pub mod fragbits;
pub mod iprep;
pub mod parser;
pub mod requires;
pub mod stream_size;
pub mod tcp;
pub mod tojson;
pub mod transforms;
pub mod uint;
pub mod uri;
pub mod vlan;

use std::ffi::CString;
use std::os::raw::c_int;

use suricata_sys::sys::{
    DetectEngineCtx, SCDetectHelperKeywordRegister, SCDetectHelperKeywordSetCleanCString,
    SCSigTableAppLiteElmt, Signature,
};

/// EnumString trait that will be implemented on enums that
/// derive StringEnum.
pub trait EnumString<T> {
    /// Return the enum variant of the given numeric value.
    fn from_u(v: T) -> Option<Self>
    where
        Self: Sized;

    /// Convert the enum variant to the numeric value.
    fn into_u(self) -> T;

    /// Return the string for logging the enum value.
    fn to_str(&self) -> &'static str;

    /// Get an enum variant from parsing a string.
    fn from_str(s: &str) -> Option<Self>
    where
        Self: Sized;
}

/// Rust app-layer light version of SigTableElmt for simple sticky buffer
pub struct SigTableElmtStickyBuffer {
    /// keyword name
    pub name: String,
    /// keyword description
    pub desc: String,
    /// keyword documentation url
    pub url: String,
    /// function callback to parse and setup keyword in rule
    pub setup: unsafe extern "C" fn(
        de: *mut DetectEngineCtx,
        s: *mut Signature,
        raw: *const std::os::raw::c_char,
    ) -> c_int,
}

fn helper_keyword_register_buffer_flags(kw: &SigTableElmtStickyBuffer, flags: u32) -> u16 {
    let name = CString::new(kw.name.as_bytes()).unwrap().into_raw();
    let desc = CString::new(kw.desc.as_bytes()).unwrap().into_raw();
    let url = CString::new(kw.url.as_bytes()).unwrap().into_raw();
    let st = SCSigTableAppLiteElmt {
        name,
        desc,
        url,
        Setup: Some(kw.setup),
        flags,
        AppLayerTxMatch: None,
        Free: None,
    };
    unsafe {
        let r = SCDetectHelperKeywordRegister(&st);
        SCDetectHelperKeywordSetCleanCString(r);
        return r;
    }
}

pub fn helper_keyword_register_multi_buffer(kw: &SigTableElmtStickyBuffer) -> u16 {
    return helper_keyword_register_buffer_flags(
        kw,
        SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_INFO_MULTI_BUFFER,
    );
}

pub fn helper_keyword_register_sticky_buffer(kw: &SigTableElmtStickyBuffer) -> u16 {
    return helper_keyword_register_buffer_flags(kw, SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER);
}

#[repr(C)]
#[allow(non_snake_case)]
/// Names of SigTableElmt for release by rust
pub struct SCSigTableNamesElmt {
    /// keyword name
    pub name: *mut libc::c_char,
    /// keyword description
    pub desc: *mut libc::c_char,
    /// keyword documentation url
    pub url: *mut libc::c_char,
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectSigMatchNamesFree(kw: &mut SCSigTableNamesElmt) {
    let _ = CString::from_raw(kw.name);
    let _ = CString::from_raw(kw.desc);
    let _ = CString::from_raw(kw.url);
}

// TODO bindgen these
pub const SIGMATCH_NOOPT: u32 = 1; // BIT_U16(0) in detect.h
pub(crate) const SIGMATCH_OPTIONAL_OPT: u32 = 0x10; // BIT_U16(4) in detect.h
pub(crate) const SIGMATCH_QUOTES_MANDATORY: u32 = 0x40; // BIT_U16(6) in detect.h
pub const SIGMATCH_INFO_STICKY_BUFFER: u32 = 0x200; // BIT_U16(9)
pub const SIGMATCH_INFO_MULTI_BUFFER: u32 = 0x4000; // BIT_U16(14)
pub const SIGMATCH_INFO_UINT8: u32 = 0x8000; // BIT_U32(15)
pub const SIGMATCH_INFO_UINT16: u32 = 0x10000; // BIT_U32(16)
pub const SIGMATCH_INFO_UINT32: u32 = 0x20000; // BIT_U32(17)
pub const SIGMATCH_INFO_UINT64: u32 = 0x40000; // BIT_U32(18)
pub const SIGMATCH_INFO_MULTI_UINT: u32 = 0x80000; // BIT_U32(19)
pub const SIGMATCH_INFO_ENUM_UINT: u32 = 0x100000; // BIT_U32(20)
pub const SIGMATCH_INFO_BITFLAGS_UINT: u32 = 0x200000; // BIT_U32(21)

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

fn get_string_value(value: &str) -> Option<ByteBase> {
    let res = match value {
        "hex" => Some(ByteBase::BaseHex),
        "oct" => Some(ByteBase::BaseOct),
        "dec" => Some(ByteBase::BaseDec),
        _ => None,
    };

    res
}

fn get_endian_value(value: &str) -> Option<ByteEndian> {
    let res = match value {
        "big" => Some(ByteEndian::BigEndian),
        "little" => Some(ByteEndian::LittleEndian),
        "dce" => Some(ByteEndian::EndianDCE),
        _ => None,
    };

    res
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
        assert_eq!(
            TestEnum::from_str("best_value_ever"),
            Some(TestEnum::BestValueEver)
        );
    }

    #[derive(Clone, Debug, PartialEq, EnumStringU8)]
    #[repr(u8)]
    #[suricata(enum_string_style = "LOG_UPPERCASE")]
    pub enum TestEnumLogUppercase {
        Zero = 0,
        BestValueEver = 42,
    }

    #[test]
    fn test_enum_string_log_uppercase() {
        assert_eq!(TestEnumLogUppercase::Zero.to_str(), "ZERO");
        assert_eq!(
            TestEnumLogUppercase::BestValueEver.to_str(),
            "BESTVALUEEVER"
        );
        assert_eq!(
            TestEnumLogUppercase::from_str("zero"),
            Some(TestEnumLogUppercase::Zero)
        );
        assert_eq!(
            TestEnumLogUppercase::from_str("BEST_VALUE_EVER"),
            Some(TestEnumLogUppercase::BestValueEver)
        );
    }

    #[derive(Clone, Debug, PartialEq, EnumStringU8)]
    #[repr(u8)]
    #[suricata(enum_string_style = "UPPERCASE")]
    pub enum TestEnumUppercase {
        Zero = 0,
        BestValueEver = 42,
    }

    #[test]
    fn test_enum_string_uppercase() {
        assert_eq!(TestEnumUppercase::Zero.to_str(), "ZERO");
        assert_eq!(TestEnumUppercase::BestValueEver.to_str(), "BESTVALUEEVER");
        assert_eq!(
            TestEnumUppercase::from_str("zero"),
            Some(TestEnumUppercase::Zero)
        );
        assert_eq!(
            TestEnumUppercase::from_str("BESTVALUEEVER"),
            Some(TestEnumUppercase::BestValueEver)
        );
    }
}
