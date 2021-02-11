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

use super::modbus::ModbusTransaction;
use lazy_static::lazy_static;
use regex::Regex;
use sawp_modbus::{AccessType, CodeCategory, Data, FunctionCode, Message};
use std::ffi::CStr;
use std::ops::{Range, RangeInclusive};
use std::os::raw::{c_char, c_void};
use std::str::FromStr;

lazy_static! {
    static ref ACCESS_RE: Regex = Regex::new(
        "^\\s*\"?\\s*access\\s*(read|write)\
        \\s*(discretes|coils|input|holding)?\
        (?:,\\s*address\\s+([<>]?\\d+)(?:<>(\\d+))?\
        (?:,\\s*value\\s+([<>]?\\d+)(?:<>(\\d+))?)?)?\
        \\s*\"?\\s*$"
    )
    .unwrap();
    static ref FUNC_RE: Regex = Regex::new(
        "^\\s*\"?\\s*function\\s*(!?[A-z0-9]+)\
        (?:,\\s*subfunction\\s+(\\d+))?\\s*\"?\\s*$"
    )
    .unwrap();
    static ref UNIT_RE: Regex = Regex::new(
        "^\\s*\"?\\s*unit\\s+([<>]?\\d+)\
        (?:<>(\\d+))?(?:,\\s*(.*))?\\s*\"?\\s*$"
    )
    .unwrap();
}

#[derive(Debug, PartialEq)]
pub struct DetectModbusRust {
    category: Option<CodeCategory>,
    function: Option<FunctionCode>,
    subfunction: Option<u16>,
    access_type: Option<AccessType>,
    unit_id: Option<Range<u16>>,
    address: Option<Range<u16>>,
    value: Option<Range<u16>>,
}

/// TODO: remove these after regression testing commit
#[no_mangle]
pub extern "C" fn rs_modbus_get_category(modbus: *const DetectModbusRust) -> u8 {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.category.map(|val| val.bits()).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn rs_modbus_get_function(modbus: *const DetectModbusRust) -> u8 {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.function.map(|val| val as u8).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn rs_modbus_get_subfunction(modbus: *const DetectModbusRust) -> u16 {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.subfunction.unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn rs_modbus_get_has_subfunction(modbus: *const DetectModbusRust) -> bool {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.subfunction.is_some()
}

#[no_mangle]
pub extern "C" fn rs_modbus_get_access_type(modbus: *const DetectModbusRust) -> u8 {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.access_type.map(|val| val.bits()).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn rs_modbus_get_unit_id_min(modbus: *const DetectModbusRust) -> u16 {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.unit_id.as_ref().map(|val| val.start).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn rs_modbus_get_unit_id_max(modbus: *const DetectModbusRust) -> u16 {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.unit_id.as_ref().map(|val| val.end).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn rs_modbus_get_address_min(modbus: *const DetectModbusRust) -> u16 {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.address.as_ref().map(|val| val.start).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn rs_modbus_get_address_max(modbus: *const DetectModbusRust) -> u16 {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.address.as_ref().map(|val| val.end).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn rs_modbus_get_data_min(modbus: *const DetectModbusRust) -> u16 {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.value.as_ref().map(|val| val.start).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn rs_modbus_get_data_max(modbus: *const DetectModbusRust) -> u16 {
    let modbus = unsafe { modbus.as_ref() }.unwrap();
    modbus.value.as_ref().map(|val| val.end).unwrap_or(0)
}

impl Default for DetectModbusRust {
    fn default() -> Self {
        DetectModbusRust {
            category: None,
            function: None,
            subfunction: None,
            access_type: None,
            unit_id: None,
            address: None,
            value: None,
        }
    }
}

/// Compares a range from the alert signature to the transaction's unit_id/address/value
/// range. If the signature's range intersects with the transaction, it is a match and true is
/// returned.
fn check_match_range(sig_range: &Range<u16>, trans_range: RangeInclusive<u16>) -> bool {
    if sig_range.start == sig_range.end {
        sig_range.start >= *trans_range.start() && sig_range.start <= *trans_range.end()
    } else if sig_range.start == std::u16::MIN {
        sig_range.end > *trans_range.start()
    } else if sig_range.end == std::u16::MAX {
        sig_range.start < *trans_range.end()
    } else {
        sig_range.start < *trans_range.end() && *trans_range.start() < sig_range.end
    }
}

/// Compares a range from the alert signature to the transaction's unit_id/address/value.
/// If the signature's range intersects with the transaction, it is a match and true is
/// returned.
fn check_match(sig_range: &Range<u16>, value: u16) -> bool {
    if sig_range.start == sig_range.end {
        sig_range.start == value
    } else if sig_range.start == std::u16::MIN {
        sig_range.end > value
    } else if sig_range.end == std::u16::MAX {
        sig_range.start < value
    } else {
        sig_range.start < value && value < sig_range.end
    }
}

/// Gets the min/max range of an alert signature from the respective capture groups.
/// In the case where the max is not given, it is set based on the first char of the min str
/// which indicates what range we are looking for:
///     '<' = std::u16::MIN..min
///     '>' = min..std::u16::MAX
///     _ = min..min
/// If the max is given, the range returned is min..max
fn parse_range(min_str: &str, max_str: &str) -> Result<Range<u16>, ()> {
    if max_str.is_empty() {
        if let Some(sign) = min_str.chars().next() {
            match min_str[!sign.is_ascii_digit() as usize..].parse::<u16>() {
                Ok(num) => match sign {
                    '>' => Ok(num..std::u16::MAX),
                    '<' => Ok(std::u16::MIN..num),
                    _ => Ok(num..num),
                },
                Err(_) => {
                    SCLogError!("Invalid min number: {}", min_str);
                    Err(())
                }
            }
        } else {
            Err(())
        }
    } else {
        let min = match min_str.parse::<u16>() {
            Ok(num) => num,
            Err(_) => {
                SCLogError!("Invalid min number: {}", min_str);
                return Err(());
            }
        };

        let max = match max_str.parse::<u16>() {
            Ok(num) => num,
            Err(_) => {
                SCLogError!("Invalid max number: {}", max_str);
                return Err(());
            }
        };

        Ok(min..max)
    }
}

/// Intermediary function between the C code and the access type parsing function.
#[no_mangle]
pub unsafe extern "C" fn rs_modbus_parse_access(c_arg: *const c_char) -> *mut c_void {
    if c_arg.is_null() {
        return std::ptr::null_mut();
    }
    if let Ok(arg) = CStr::from_ptr(c_arg).to_str() {
        match parse_access(&arg) {
            Ok(detect) => return Box::into_raw(Box::new(detect)) as *mut c_void,
            Err(()) => return std::ptr::null_mut(),
        }
    }
    std::ptr::null_mut()
}

/// Intermediary function between the C code and the function code parsing function.
#[no_mangle]
pub unsafe extern "C" fn rs_modbus_parse_function(c_arg: *const c_char) -> *mut c_void {
    if c_arg.is_null() {
        return std::ptr::null_mut();
    }
    if let Ok(arg) = CStr::from_ptr(c_arg).to_str() {
        match parse_function(&arg) {
            Ok(detect) => return Box::into_raw(Box::new(detect)) as *mut c_void,
            Err(()) => return std::ptr::null_mut(),
        }
    }
    std::ptr::null_mut()
}

/// Intermediary function between the C code and the unit ID parsing function.
#[no_mangle]
pub unsafe extern "C" fn rs_modbus_parse_unit_id(c_arg: *const c_char) -> *mut c_void {
    if c_arg.is_null() {
        return std::ptr::null_mut();
    }
    if let Ok(arg) = CStr::from_ptr(c_arg).to_str() {
        match parse_unit_id(&arg) {
            Ok(detect) => return Box::into_raw(Box::new(detect)) as *mut c_void,
            Err(()) => return std::ptr::null_mut(),
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn rs_modbus_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr as *mut DetectModbusRust);
    }
}

/// Compares a transaction to a signature to determine whether the transaction
/// matches the signature. If it does, 1 is returned; otherwise 0 is returned.
#[no_mangle]
pub extern "C" fn rs_modbus_inspect(tx: &ModbusTransaction, modbus: &DetectModbusRust) -> u8 {
    let msg = match &tx.request {
        Some(r) => r,
        None => match &tx.response {
            Some(r) => r,
            None => return 0,
        },
    };

    if let Some(unit_id) = &modbus.unit_id {
        if !check_match(unit_id, msg.unit_id.into()) {
            return 0;
        }
    }

    if let Some(access_type) = &modbus.access_type {
        let rd_wr_access = *access_type & (AccessType::READ | AccessType::WRITE);
        let access_func = *access_type & AccessType::FUNC_MASK;

        if rd_wr_access == AccessType::NONE
            || !msg.access_type.intersects(rd_wr_access)
            || (access_func != AccessType::NONE && !msg.access_type.intersects(access_func))
        {
            return 0;
        }

        return inspect_data(msg, modbus) as u8;
    }

    if let Some(category) = modbus.category {
        return u8::from(msg.category.intersects(category));
    }

    match &modbus.function {
        Some(func) if func == &msg.function.code => match modbus.subfunction {
            Some(subfunc) => {
                if let Data::Diagnostic { func, data: _ } = &msg.data {
                    u8::from(subfunc == func.raw)
                } else {
                    0
                }
            }
            None => 1,
        },
        None => 1,
        _ => 0,
    }
}

/// Compares the transaction's data with the signature to determine whether or
/// not it is a match
fn inspect_data(msg: &Message, modbus: &DetectModbusRust) -> bool {
    let sig_address = if let Some(sig_addr) = &modbus.address {
        // Compare the transaction's address with the signature to determine whether or
        // not it is a match
        if let Some(req_addr) = msg.get_address_range() {
            if !check_match_range(sig_addr, req_addr) {
                return false;
            }
        } else {
            return false;
        }

        sig_addr.start
    } else {
        return true;
    };

    let sig_value = if let Some(value) = &modbus.value {
        value
    } else {
        return true;
    };

    if let Some(value) = msg.get_write_value_at_address(&sig_address) {
        check_match(sig_value, value)
    } else {
        false
    }
}

/// Parses the access type for the signature
fn parse_access(access_str: &str) -> Result<DetectModbusRust, ()> {
    let re = if let Some(re) = ACCESS_RE.captures(access_str) {
        re
    } else {
        return Err(());
    };

    // 1: Read | Write
    let mut access_type = match re.get(1) {
        Some(access) => match AccessType::from_str(access.as_str()) {
            Ok(access_type) => access_type,
            Err(_) => {
                SCLogError!("Unknown access keyword {}", access.as_str());
                return Err(());
            }
        },
        None => {
            SCLogError!("No access keyword found");
            return Err(());
        }
    };

    // 2: Discretes | Coils | Input | Holding
    access_type = match re.get(2) {
        Some(x) if x.as_str() == "coils" => access_type | AccessType::COILS,
        Some(x) if x.as_str() == "holding" => access_type | AccessType::HOLDING,
        Some(x) if x.as_str() == "discretes" => {
            if access_type == AccessType::WRITE {
                SCLogError!("Discrete access is only read access");
                return Err(());
            }
            access_type | AccessType::DISCRETES
        }
        Some(x) if x.as_str() == "input" => {
            if access_type == AccessType::WRITE {
                SCLogError!("Input access is only read access");
                return Err(());
            }
            access_type | AccessType::INPUT
        }
        Some(unknown) => {
            SCLogError!("Unknown access keyword {}", unknown.as_str());
            return Err(());
        }
        None => access_type,
    };

    // 3: Address min
    let address = if let Some(min) = re.get(3) {
        // 4: Address max
        let max_str = if let Some(max) = re.get(4) {
            max.as_str()
        } else {
            ""
        };
        parse_range(min.as_str(), max_str)?
    } else {
        return Ok(DetectModbusRust {
            access_type: Some(access_type),
            ..Default::default()
        });
    };

    // 5: Value min
    let value = if let Some(min) = re.get(5) {
        if address.start != address.end {
            SCLogError!("rule contains conflicting keywords (address range and value).");
            return Err(());
        }

        if access_type == AccessType::READ {
            SCLogError!("Value keyword only works in write access");
            return Err(());
        }

        // 6: Value max
        let max_str = if let Some(max) = re.get(6) {
            max.as_str()
        } else {
            ""
        };

        parse_range(min.as_str(), max_str)?
    } else {
        return Ok(DetectModbusRust {
            access_type: Some(access_type),
            address: Some(address),
            ..Default::default()
        });
    };

    Ok(DetectModbusRust {
        access_type: Some(access_type),
        address: Some(address),
        value: Some(value),
        ..Default::default()
    })
}

fn parse_function(func_str: &str) -> Result<DetectModbusRust, ()> {
    let re = if let Some(re) = FUNC_RE.captures(func_str) {
        re
    } else {
        return Err(());
    };

    let mut modbus: DetectModbusRust = Default::default();

    // 1: Function
    if let Some(x) = re.get(1) {
        let word = x.as_str();

        // Digit
        if let Ok(num) = word.parse::<u8>() {
            if num == 0 {
                SCLogError!("Invalid modbus function value");
                return Err(());
            }

            modbus.function = Some(FunctionCode::from_raw(num));

            // 2: Subfunction (optional)
            match re.get(2) {
                Some(x) => {
                    let subfunc = x.as_str();
                    match subfunc.parse::<u16>() {
                        Ok(num) => {
                            modbus.subfunction = Some(num);
                        }
                        Err(_) => {
                            SCLogError!("Invalid subfunction value: {}", subfunc);
                            return Err(());
                        }
                    }
                }
                None => return Ok(modbus),
            }
        }
        // Non-digit
        else {
            let neg = word.starts_with('!');

            let category = match &word[neg as usize..] {
                "assigned" => CodeCategory::PUBLIC_ASSIGNED,
                "unassigned" => CodeCategory::PUBLIC_UNASSIGNED,
                "public" => CodeCategory::PUBLIC_ASSIGNED | CodeCategory::PUBLIC_UNASSIGNED,
                "user" => CodeCategory::USER_DEFINED,
                "reserved" => CodeCategory::RESERVED,
                "all" => {
                    CodeCategory::PUBLIC_ASSIGNED
                        | CodeCategory::PUBLIC_UNASSIGNED
                        | CodeCategory::USER_DEFINED
                        | CodeCategory::RESERVED
                }
                _ => {
                    SCLogError!("Keyword unknown: {}", word);
                    return Err(());
                }
            };

            if neg {
                modbus.category = Some(!category);
            } else {
                modbus.category = Some(category);
            }
        }
    } else {
        return Err(());
    }

    Ok(modbus)
}

fn parse_unit_id(unit_str: &str) -> Result<DetectModbusRust, ()> {
    let re = if let Some(re) = UNIT_RE.captures(unit_str) {
        re
    } else {
        return Err(());
    };

    // 3: Either function or access string
    let mut modbus = if let Some(x) = re.get(3) {
        let extra = x.as_str();
        if let Ok(mbus) = parse_function(extra) {
            mbus
        } else if let Ok(mbus) = parse_access(extra) {
            mbus
        } else {
            SCLogError!("Invalid modbus option: {}", extra);
            return Err(());
        }
    } else {
        Default::default()
    };

    // 1: Unit ID min
    if let Some(min) = re.get(1) {
        // 2: Unit ID max
        let max_str = if let Some(max) = re.get(2) {
            max.as_str()
        } else {
            ""
        };

        modbus.unit_id = Some(parse_range(min.as_str(), max_str)?);
    } else {
        SCLogError!("Min modbus unit ID not found");
        return Err(());
    }

    Ok(modbus)
}
