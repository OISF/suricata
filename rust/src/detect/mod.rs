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

use crate::core::AppProto;
use std::os::raw::{c_int, c_void};

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

#[repr(C)]
#[allow(non_snake_case)]
pub struct SCSigTableElmt {
    pub name: *const libc::c_char,
    pub desc: *const libc::c_char,
    pub url: *const libc::c_char,
    pub flags: u16,
    pub Setup: unsafe extern "C" fn(
        de: *mut c_void,
        s: *mut c_void,
        raw: *const std::os::raw::c_char,
    ) -> c_int,
    pub Free: Option<unsafe extern "C" fn(de: *mut c_void, ptr: *mut c_void)>,
    pub AppLayerTxMatch: Option<
        unsafe extern "C" fn(
            de: *mut c_void,
            f: *mut c_void,
            flags: u8,
            state: *mut c_void,
            tx: *mut c_void,
            sig: *const c_void,
            ctx: *const c_void,
        ) -> c_int,
    >,
}

pub(crate) const SIGMATCH_NOOPT: u16 = 1; // BIT_U16(0) in detect.h
pub(crate) const SIGMATCH_INFO_STICKY_BUFFER: u16 = 0x200; // BIT_U16(9)

extern {
    pub fn DetectBufferSetActiveList(de: *mut c_void, s: *mut c_void, bufid: c_int) -> c_int;
    pub fn DetectHelperGetData(
        de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
        tx: *const c_void, list_id: c_int,
        get_buf: unsafe extern "C" fn(*const c_void, u8, *mut *const u8, *mut u32) -> bool,
    ) -> *mut c_void;
    pub fn DetectHelperBufferMpmRegister(
        name: *const libc::c_char, desc: *const libc::c_char, alproto: AppProto, toclient: bool,
        toserver: bool,
        get_data: unsafe extern "C" fn(
            *mut c_void,
            *const c_void,
            *const c_void,
            u8,
            *const c_void,
            i32,
        ) -> *mut c_void,
    ) -> c_int;
    pub fn DetectHelperKeywordRegister(kw: *const SCSigTableElmt) -> c_int;
    pub fn DetectHelperBufferRegister(
        name: *const libc::c_char, alproto: AppProto, toclient: bool, toserver: bool,
    ) -> c_int;
    pub fn DetectSignatureSetAppProto(s: *mut c_void, alproto: AppProto) -> c_int;
    pub fn SigMatchAppendSMToList(
        de: *mut c_void, s: *mut c_void, kwid: c_int, ctx: *const c_void, bufid: c_int,
    ) -> *mut c_void;
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
        assert_eq!(TestEnum::from_str("best_value_ever"), Some(TestEnum::BestValueEver));
    }
}
