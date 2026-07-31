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

use super::modbus::{ModbusTransaction, ALPROTO_MODBUS};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{
    DetectUintData, SCDetectU16Free, SCDetectU16Match, SCDetectU16Parse, SCDetectU8Free,
    SCDetectU8Match, SCDetectU8Parse,
};
use crate::detect::{SIGMATCH_INFO_UINT16, SIGMATCH_INFO_UINT8};
use crate::direction::Direction;
use lazy_static::lazy_static;
use regex::Regex;
use sawp_modbus::{AccessType, CodeCategory, Data, Flags, FunctionCode, Message, Read, Write};
use std::ffi::CStr;
use std::ops::{Range, RangeInclusive};
use std::os::raw::{c_char, c_int, c_void};
use std::str::FromStr;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectHelperBufferProgressRegister,
    SCDetectHelperKeywordRegister, SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList,
    SCSigTableAppLiteElmt, SigMatchCtx, Signature,
};

lazy_static! {
    static ref ACCESS_RE: Regex = Regex::new(
        "^[[:space:]]*\"?[[:space:]]*access[[:space:]]*(read|write)\
        [[:space:]]*(discretes|coils|input|holding)?\
        (?:,[[:space:]]*address[[:space:]]+([<>]?[[:digit:]]+)(?:<>([[:digit:]]+))?\
        (?:,[[:space:]]*value[[:space:]]+([<>]?[[:digit:]]+)(?:<>([[:digit:]]+))?)?)?\
        [[:space:]]*\"?[[:space:]]*$"
    )
    .unwrap();
    static ref FUNC_RE: Regex = Regex::new(
        "^[[:space:]]*\"?[[:space:]]*function[[:space:]]*(!?[A-z0-9]+)\
        (?:,[[:space:]]*subfunction[[:space:]]+([[:digit:]]+))?[[:space:]]*\"?[[:space:]]*$"
    )
    .unwrap();
    static ref UNIT_RE: Regex = Regex::new(
        "^[[:space:]]*\"?[[:space:]]*unit[[:space:]]+([<>]?[[:digit:]]+)\
        (?:<>([[:digit:]]+))?(?:,[[:space:]]*(.*))?[[:space:]]*\"?[[:space:]]*$"
    )
    .unwrap();
}

#[derive(Debug, PartialEq, Default)]
pub struct DetectModbusRust {
    category: Option<Flags<CodeCategory>>,
    function: Option<FunctionCode>,
    subfunction: Option<u16>,
    access_type: Option<Flags<AccessType>>,
    unit_id: Option<Range<u16>>,
    address: Option<Range<u16>>,
    value: Option<Range<u16>>,
}

/// Compares a range from the alert signature to the transaction's unit_id/address/value
/// range. If the signature's range intersects with the transaction, it is a match and true is
/// returned.
fn check_match_range(sig_range: &Range<u16>, trans_range: RangeInclusive<u16>) -> bool {
    if sig_range.start == sig_range.end {
        sig_range.start >= *trans_range.start() && sig_range.start <= *trans_range.end()
    } else if sig_range.start == u16::MIN {
        sig_range.end > *trans_range.start()
    } else if sig_range.end == u16::MAX {
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
    } else if sig_range.start == u16::MIN {
        sig_range.end > value
    } else if sig_range.end == u16::MAX {
        sig_range.start < value
    } else {
        sig_range.start < value && value < sig_range.end
    }
}

/// Gets the min/max range of an alert signature from the respective capture groups.
/// In the case where the max is not given, it is set based on the first char of the min str
/// which indicates what range we are looking for:
///     '<' = u16::MIN..min
///     '>' = min..u16::MAX
///     _ = min..min
/// If the max is given, the range returned is min..max
fn parse_range(min_str: &str, max_str: &str) -> Result<Range<u16>, ()> {
    if max_str.is_empty() {
        if let Some(sign) = min_str.chars().next() {
            debug_validate_bug_on!(!sign.is_ascii_digit() && sign != '<' && sign != '>');
            match min_str[!sign.is_ascii_digit() as usize..].parse::<u16>() {
                Ok(num) => match sign {
                    '>' => Ok(num..u16::MAX),
                    '<' => Ok(u16::MIN..num),
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

/// Intermediary function between the C code and the parsing functions.
#[no_mangle]
pub unsafe extern "C" fn SCModbusParse(c_arg: *const c_char) -> *mut c_void {
    if c_arg.is_null() {
        return std::ptr::null_mut();
    }
    if let Ok(arg) = CStr::from_ptr(c_arg).to_str() {
        match parse_unit_id(arg)
            .or_else(|_| parse_function(arg))
            .or_else(|_| parse_access(arg))
        {
            Ok(detect) => return Box::into_raw(Box::new(detect)) as *mut c_void,
            Err(()) => return std::ptr::null_mut(),
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn SCModbusFree(ptr: *mut c_void) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr as *mut DetectModbusRust);
    }
}

/// Compares a transaction to a signature to determine whether the transaction
/// matches the signature. If it does, 1 is returned; otherwise 0 is returned.
#[no_mangle]
pub extern "C" fn SCModbusInspect(tx: &ModbusTransaction, modbus: &DetectModbusRust) -> u8 {
    // All necessary information can be found in the request (value inspection currently
    // only supports write functions, which hold the value in the request).
    // Only inspect the response in the case where there is no request.
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

        if rd_wr_access.is_empty()
            || !msg.access_type.intersects(rd_wr_access)
            || (!access_func.is_empty() && !msg.access_type.intersects(access_func))
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

    if let Some(value) = msg.get_write_value_at_address(sig_address) {
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
    let mut access_type: Flags<AccessType> = match re.get(1) {
        Some(access) => match AccessType::from_str(access.as_str()) {
            Ok(access_type) => access_type.into(),
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
                "assigned" => CodeCategory::PUBLIC_ASSIGNED.into(),
                "unassigned" => CodeCategory::PUBLIC_UNASSIGNED.into(),
                "public" => CodeCategory::PUBLIC_ASSIGNED | CodeCategory::PUBLIC_UNASSIGNED,
                "user" => CodeCategory::USER_DEFINED.into(),
                "reserved" => CodeCategory::RESERVED.into(),
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

static mut G_MODBUS_UNIT_ID_KW_ID: u16 = 0;
static mut G_MODBUS_UNIT_ID_BUFFER_ID: c_int = 0;
static mut G_MODBUS_TRANSACTION_ID_KW_ID: u16 = 0;
static mut G_MODBUS_TRANSACTION_ID_BUFFER_ID: c_int = 0;
static mut G_MODBUS_PROTOCOL_ID_KW_ID: u16 = 0;
static mut G_MODBUS_PROTOCOL_ID_BUFFER_ID: c_int = 0;
static mut G_MODBUS_FUNCTION_KW_ID: u16 = 0;
static mut G_MODBUS_FUNCTION_BUFFER_ID: c_int = 0;
static mut G_MODBUS_SUBFUNCTION_KW_ID: u16 = 0;
static mut G_MODBUS_SUBFUNCTION_BUFFER_ID: c_int = 0;
static mut G_MODBUS_EXCEPTION_CODE_KW_ID: u16 = 0;
static mut G_MODBUS_EXCEPTION_CODE_BUFFER_ID: c_int = 0;
static mut G_MODBUS_READ_ADDRESS_KW_ID: u16 = 0;
static mut G_MODBUS_READ_ADDRESS_BUFFER_ID: c_int = 0;
static mut G_MODBUS_READ_QUANTITY_KW_ID: u16 = 0;
static mut G_MODBUS_READ_QUANTITY_BUFFER_ID: c_int = 0;
static mut G_MODBUS_WRITE_ADDRESS_KW_ID: u16 = 0;
static mut G_MODBUS_WRITE_ADDRESS_BUFFER_ID: c_int = 0;
static mut G_MODBUS_WRITE_QUANTITY_KW_ID: u16 = 0;
static mut G_MODBUS_WRITE_QUANTITY_BUFFER_ID: c_int = 0;
static mut G_MODBUS_WRITE_VALUE_KW_ID: u16 = 0;
static mut G_MODBUS_WRITE_VALUE_BUFFER_ID: c_int = 0;

/// Get the message matching the direction of the packet under inspection:
/// the request for to-server, the response for to-client.
fn tx_get_message(tx: &ModbusTransaction, direction: u8) -> Option<&Message> {
    let direction: Direction = direction.into();
    if direction == Direction::ToServer {
        return tx.request.as_ref();
    }
    return tx.response.as_ref();
}

unsafe extern "C" fn unit_id_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_UNIT_ID_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_UNIT_ID_BUFFER_ID,
    )
    .is_null()
    {
        unit_id_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn unit_id_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if let Some(msg) = tx_get_message(tx, flags) {
        return SCDetectU8Match(msg.unit_id, ctx);
    }
    return 0;
}

unsafe extern "C" fn unit_id_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn transaction_id_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_TRANSACTION_ID_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_TRANSACTION_ID_BUFFER_ID,
    )
    .is_null()
    {
        transaction_id_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn transaction_id_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    if let Some(msg) = tx_get_message(tx, flags) {
        return SCDetectU16Match(msg.transaction_id, ctx);
    }
    return 0;
}

unsafe extern "C" fn transaction_id_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

unsafe extern "C" fn protocol_id_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_PROTOCOL_ID_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_PROTOCOL_ID_BUFFER_ID,
    )
    .is_null()
    {
        protocol_id_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn protocol_id_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    if let Some(msg) = tx_get_message(tx, flags) {
        return SCDetectU16Match(msg.protocol_id, ctx);
    }
    return 0;
}

unsafe extern "C" fn protocol_id_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

fn tx_get_function(tx: &ModbusTransaction, direction: u8) -> Option<u8> {
    return tx_get_message(tx, direction).map(|msg| msg.function.raw);
}

fn tx_get_subfunction(tx: &ModbusTransaction, direction: u8) -> Option<u16> {
    if let Some(msg) = tx_get_message(tx, direction) {
        if let Data::Diagnostic { func, .. } = &msg.data {
            return Some(func.raw);
        }
    }
    return None;
}

fn tx_get_exception_code(tx: &ModbusTransaction, direction: u8) -> Option<u8> {
    if let Some(msg) = tx_get_message(tx, direction) {
        if let Data::Exception(exc) = &msg.data {
            return Some(exc.raw);
        }
    }
    return None;
}

unsafe extern "C" fn function_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_FUNCTION_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_FUNCTION_BUFFER_ID,
    )
    .is_null()
    {
        function_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn function_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if let Some(val) = tx_get_function(tx, flags) {
        return SCDetectU8Match(val, ctx);
    }
    return 0;
}

unsafe extern "C" fn function_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn subfunction_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_SUBFUNCTION_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_SUBFUNCTION_BUFFER_ID,
    )
    .is_null()
    {
        subfunction_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn subfunction_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    if let Some(val) = tx_get_subfunction(tx, flags) {
        return SCDetectU16Match(val, ctx);
    }
    return 0;
}

unsafe extern "C" fn subfunction_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

unsafe extern "C" fn exception_code_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_EXCEPTION_CODE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_EXCEPTION_CODE_BUFFER_ID,
    )
    .is_null()
    {
        exception_code_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn exception_code_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if let Some(val) = tx_get_exception_code(tx, flags) {
        return SCDetectU8Match(val, ctx);
    }
    return 0;
}

unsafe extern "C" fn exception_code_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

fn tx_get_read(tx: &ModbusTransaction, direction: u8) -> Option<&Read> {
    if let Some(msg) = tx_get_message(tx, direction) {
        match &msg.data {
            Data::Read(read) | Data::ReadWrite { read, .. } => return Some(read),
            _ => {}
        }
    }
    return None;
}

fn tx_get_write(tx: &ModbusTransaction, direction: u8) -> Option<&Write> {
    if let Some(msg) = tx_get_message(tx, direction) {
        match &msg.data {
            Data::Write(write) | Data::ReadWrite { write, .. } => return Some(write),
            _ => {}
        }
    }
    return None;
}

fn tx_get_read_address(tx: &ModbusTransaction, direction: u8) -> Option<u16> {
    if let Some(Read::Request { address, .. }) = tx_get_read(tx, direction) {
        return Some(*address);
    }
    return None;
}

fn tx_get_read_quantity(tx: &ModbusTransaction, direction: u8) -> Option<u16> {
    if let Some(Read::Request { quantity, .. }) = tx_get_read(tx, direction) {
        return Some(*quantity);
    }
    return None;
}

fn tx_get_write_address(tx: &ModbusTransaction, direction: u8) -> Option<u16> {
    if let Some(write) = tx_get_write(tx, direction) {
        match write {
            Write::MultReq { address, .. }
            | Write::Mask { address, .. }
            | Write::Other { address, .. } => {
                return Some(*address);
            }
        }
    }
    return None;
}

fn tx_get_write_quantity(tx: &ModbusTransaction, direction: u8) -> Option<u16> {
    if let Some(msg) = tx_get_message(tx, direction) {
        match &msg.data {
            Data::Write(Write::MultReq { quantity, .. })
            | Data::ReadWrite {
                write: Write::MultReq { quantity, .. },
                ..
            } => {
                return Some(*quantity);
            }
            // multiple-write responses echo the quantity in Write::Other
            Data::Write(Write::Other { data, .. })
                if msg.access_type.contains(AccessType::MULTIPLE) =>
            {
                return Some(*data);
            }
            _ => {}
        }
    }
    return None;
}

fn tx_get_write_value(tx: &ModbusTransaction, direction: u8) -> Option<u16> {
    if let Some(msg) = tx_get_message(tx, direction) {
        if let Data::Write(Write::Other { data, .. }) = &msg.data {
            // multiple-write responses echo the quantity in Write::Other,
            // only match the value of single writes
            if msg.access_type.contains(AccessType::SINGLE) {
                return Some(*data);
            }
        }
    }
    return None;
}

unsafe extern "C" fn read_address_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_READ_ADDRESS_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_READ_ADDRESS_BUFFER_ID,
    )
    .is_null()
    {
        read_address_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn read_address_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    if let Some(val) = tx_get_read_address(tx, flags) {
        return SCDetectU16Match(val, ctx);
    }
    return 0;
}

unsafe extern "C" fn read_address_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

unsafe extern "C" fn read_quantity_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_READ_QUANTITY_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_READ_QUANTITY_BUFFER_ID,
    )
    .is_null()
    {
        read_quantity_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn read_quantity_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    if let Some(val) = tx_get_read_quantity(tx, flags) {
        return SCDetectU16Match(val, ctx);
    }
    return 0;
}

unsafe extern "C" fn read_quantity_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

unsafe extern "C" fn write_address_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_WRITE_ADDRESS_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_WRITE_ADDRESS_BUFFER_ID,
    )
    .is_null()
    {
        write_address_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn write_address_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    if let Some(val) = tx_get_write_address(tx, flags) {
        return SCDetectU16Match(val, ctx);
    }
    return 0;
}

unsafe extern "C" fn write_address_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

unsafe extern "C" fn write_quantity_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_WRITE_QUANTITY_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_WRITE_QUANTITY_BUFFER_ID,
    )
    .is_null()
    {
        write_quantity_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn write_quantity_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    if let Some(val) = tx_get_write_quantity(tx, flags) {
        return SCDetectU16Match(val, ctx);
    }
    return 0;
}

unsafe extern "C" fn write_quantity_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

unsafe extern "C" fn write_value_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MODBUS_WRITE_VALUE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MODBUS_WRITE_VALUE_BUFFER_ID,
    )
    .is_null()
    {
        write_value_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn write_value_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    if let Some(val) = tx_get_write_value(tx, flags) {
        return SCDetectU16Match(val, ctx);
    }
    return 0;
}

unsafe extern "C" fn write_value_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectModbusRegister() {
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.unit_id\0".as_ptr() as *const c_char,
        desc: b"match on Modbus unit identifier\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-unit-id\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(unit_id_match),
        Setup: Some(unit_id_setup),
        Free: Some(unit_id_free),
        flags: SIGMATCH_INFO_UINT8,
    };
    G_MODBUS_UNIT_ID_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_UNIT_ID_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.unit_id\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.transaction_id\0".as_ptr() as *const c_char,
        desc: b"match on Modbus transaction identifier\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-transaction-id\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(transaction_id_match),
        Setup: Some(transaction_id_setup),
        Free: Some(transaction_id_free),
        flags: SIGMATCH_INFO_UINT16,
    };
    G_MODBUS_TRANSACTION_ID_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_TRANSACTION_ID_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.transaction_id\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.protocol_id\0".as_ptr() as *const c_char,
        desc: b"match on Modbus protocol identifier\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-protocol-id\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(protocol_id_match),
        Setup: Some(protocol_id_setup),
        Free: Some(protocol_id_free),
        flags: SIGMATCH_INFO_UINT16,
    };
    G_MODBUS_PROTOCOL_ID_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_PROTOCOL_ID_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.protocol_id\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.function\0".as_ptr() as *const c_char,
        desc: b"match on Modbus function code\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-function\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(function_match),
        Setup: Some(function_setup),
        Free: Some(function_free),
        flags: SIGMATCH_INFO_UINT8,
    };
    G_MODBUS_FUNCTION_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_FUNCTION_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.function\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.subfunction\0".as_ptr() as *const c_char,
        desc: b"match on Modbus diagnostic subfunction code\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-subfunction\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(subfunction_match),
        Setup: Some(subfunction_setup),
        Free: Some(subfunction_free),
        flags: SIGMATCH_INFO_UINT16,
    };
    G_MODBUS_SUBFUNCTION_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_SUBFUNCTION_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.subfunction\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.exception_code\0".as_ptr() as *const c_char,
        desc: b"match on Modbus exception code in error responses\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-exception-code\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(exception_code_match),
        Setup: Some(exception_code_setup),
        Free: Some(exception_code_free),
        flags: SIGMATCH_INFO_UINT8,
    };
    G_MODBUS_EXCEPTION_CODE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_EXCEPTION_CODE_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.exception_code\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.read.address\0".as_ptr() as *const c_char,
        desc: b"match on address of Modbus read requests\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-read-address\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(read_address_match),
        Setup: Some(read_address_setup),
        Free: Some(read_address_free),
        flags: SIGMATCH_INFO_UINT16,
    };
    G_MODBUS_READ_ADDRESS_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_READ_ADDRESS_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.read.address\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.read.quantity\0".as_ptr() as *const c_char,
        desc: b"match on quantity of Modbus read requests\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-read-quantity\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(read_quantity_match),
        Setup: Some(read_quantity_setup),
        Free: Some(read_quantity_free),
        flags: SIGMATCH_INFO_UINT16,
    };
    G_MODBUS_READ_QUANTITY_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_READ_QUANTITY_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.read.quantity\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.write.address\0".as_ptr() as *const c_char,
        desc: b"match on address of Modbus write accesses\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-write-address\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(write_address_match),
        Setup: Some(write_address_setup),
        Free: Some(write_address_free),
        flags: SIGMATCH_INFO_UINT16,
    };
    G_MODBUS_WRITE_ADDRESS_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_WRITE_ADDRESS_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.write.address\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.write.quantity\0".as_ptr() as *const c_char,
        desc: b"match on quantity of Modbus multiple-write requests\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-write-quantity\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(write_quantity_match),
        Setup: Some(write_quantity_setup),
        Free: Some(write_quantity_free),
        flags: SIGMATCH_INFO_UINT16,
    };
    G_MODBUS_WRITE_QUANTITY_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_WRITE_QUANTITY_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.write.quantity\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"modbus.write.value\0".as_ptr() as *const c_char,
        desc: b"match on value of Modbus single-write accesses\0".as_ptr() as *const c_char,
        url: b"/rules/modbus-keyword.html#modbus-write-value\0".as_ptr() as *const c_char,
        AppLayerTxMatch: Some(write_value_match),
        Setup: Some(write_value_setup),
        Free: Some(write_value_free),
        flags: SIGMATCH_INFO_UINT16,
    };
    G_MODBUS_WRITE_VALUE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MODBUS_WRITE_VALUE_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"modbus.write.value\0".as_ptr() as *const c_char,
        ALPROTO_MODBUS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        0,
    );
}

#[cfg(test)]
mod test {
    use super::super::modbus::ModbusState;
    use super::*;
    use crate::applayer::*;
    use sawp::parser::Direction;

    #[test]
    fn test_parse() {
        assert_eq!(
            parse_function("function 1"),
            Ok(DetectModbusRust {
                function: Some(FunctionCode::RdCoils),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_function("function 8, subfunction 4"),
            Ok(DetectModbusRust {
                function: Some(FunctionCode::Diagnostic),
                subfunction: Some(4),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_function("function reserved"),
            Ok(DetectModbusRust {
                category: Some(Flags::from(CodeCategory::RESERVED)),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_function("function !assigned"),
            Ok(DetectModbusRust {
                category: Some(!CodeCategory::PUBLIC_ASSIGNED),
                ..Default::default()
            })
        );

        assert_eq!(
            parse_access("access read"),
            Ok(DetectModbusRust {
                access_type: Some(Flags::from(AccessType::READ)),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_access("access read discretes"),
            Ok(DetectModbusRust {
                access_type: Some(AccessType::READ | AccessType::DISCRETES),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_access("access read, address 1000"),
            Ok(DetectModbusRust {
                access_type: Some(Flags::from(AccessType::READ)),
                address: Some(1000..1000),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_access("access write coils, address <500"),
            Ok(DetectModbusRust {
                access_type: Some(AccessType::WRITE | AccessType::COILS),
                address: Some(u16::MIN..500),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_access("access write coils, address >500"),
            Ok(DetectModbusRust {
                access_type: Some(AccessType::WRITE | AccessType::COILS),
                address: Some(500..u16::MAX),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_access("access write holding, address 100, value <1000"),
            Ok(DetectModbusRust {
                access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                address: Some(100..100),
                value: Some(u16::MIN..1000),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_access("access write holding, address 100, value 500<>1000"),
            Ok(DetectModbusRust {
                access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                address: Some(100..100),
                value: Some(500..1000),
                ..Default::default()
            })
        );

        assert_eq!(
            parse_unit_id("unit 10"),
            Ok(DetectModbusRust {
                unit_id: Some(10..10),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_unit_id("unit 10, function 8, subfunction 4"),
            Ok(DetectModbusRust {
                function: Some(FunctionCode::Diagnostic),
                subfunction: Some(4),
                unit_id: Some(10..10),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_unit_id("unit 10, access read, address 1000"),
            Ok(DetectModbusRust {
                access_type: Some(Flags::from(AccessType::READ)),
                unit_id: Some(10..10),
                address: Some(1000..1000),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_unit_id("unit <11"),
            Ok(DetectModbusRust {
                unit_id: Some(u16::MIN..11),
                ..Default::default()
            })
        );
        assert_eq!(
            parse_unit_id("unit 10<>500"),
            Ok(DetectModbusRust {
                unit_id: Some(10..500),
                ..Default::default()
            })
        );

        assert_eq!(parse_unit_id("unit ๖"), Err(()));

        assert_eq!(parse_access("access write holdin"), Err(()));
        assert_eq!(parse_access("unt 10"), Err(()));
        assert_eq!(
            parse_access("access write holding, address 100, value 500<>"),
            Err(())
        );
    }

    #[test]
    fn test_match() {
        let mut modbus = ModbusState::new();

        // Read/Write Multiple Registers Request
        assert_eq!(
            modbus.parse(
                std::ptr::null_mut(),
                &[
                    0x12, 0x34, // Transaction ID
                    0x00, 0x00, // Protocol ID
                    0x00, 0x11, // Length
                    0x0a, // Unit ID
                    0x17, // Function code
                    0x00, 0x03, // Read Starting Address
                    0x00, 0x06, // Quantity to Read
                    0x00, 0x0E, // Write Starting Address
                    0x00, 0x03, // Quantity to Write
                    0x06, // Write Byte count
                    0x12, 0x34, // Write Registers Value
                    0x56, 0x78, 0x9A, 0xBC
                ],
                Direction::ToServer
            ),
            AppLayerResult::ok()
        );
        assert_eq!(modbus.transactions.len(), 1);
        // function 23
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    function: Some(FunctionCode::RdWrMultRegs),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 15, value <4660
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(15..15),
                    value: Some(u16::MIN..4660),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 15, value 4661
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(15..15),
                    value: Some(4661..4661),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 16, value 20000<>22136
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(16..16),
                    value: Some(20000..22136),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 16, value 22136<>30000
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(16..16),
                    value: Some(22136..30000),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 15, value >4660
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(15..15),
                    value: Some(4660..u16::MAX),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 16, value <22137
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(16..16),
                    value: Some(u16::MIN..22137),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 16, value <22137
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(16..16),
                    value: Some(u16::MIN..22137),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 17, value 39612
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(17..17),
                    value: Some(39612..39612),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 17, value 30000<>39613
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(17..17),
                    value: Some(30000..39613),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 15, value 4659<>5000
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(15..15),
                    value: Some(4659..5000),
                    ..Default::default()
                }
            ),
            1
        );
        // access write holding, address 17, value >39611
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    access_type: Some(AccessType::WRITE | AccessType::HOLDING),
                    address: Some(17..17),
                    value: Some(39611..u16::MAX),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 12
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    unit_id: Some(12..12),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 5<>9
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    unit_id: Some(5..9),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 11<>15
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    unit_id: Some(11..15),
                    ..Default::default()
                }
            ),
            1
        );
        // unit >11
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    unit_id: Some(11..u16::MAX),
                    ..Default::default()
                }
            ),
            1
        );
        // unit <9
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    unit_id: Some(u16::MIN..9),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 10
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    unit_id: Some(10..10),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 5<>15
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    unit_id: Some(5..15),
                    ..Default::default()
                }
            ),
            1
        );
        // unit >9
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    unit_id: Some(9..u16::MAX),
                    ..Default::default()
                }
            ),
            1
        );
        // unit <11
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    unit_id: Some(u16::MIN..11),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 10, function 20
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    function: Some(FunctionCode::RdFileRec),
                    unit_id: Some(10..10),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 11, function 20
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    function: Some(FunctionCode::RdFileRec),
                    unit_id: Some(11..11),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 11, function 23
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    function: Some(FunctionCode::RdWrMultRegs),
                    unit_id: Some(11..11),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 11, function public
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    category: Some(CodeCategory::PUBLIC_ASSIGNED | CodeCategory::PUBLIC_UNASSIGNED),
                    unit_id: Some(11..11),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 10, function user
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    category: Some(Flags::from(CodeCategory::USER_DEFINED)),
                    unit_id: Some(10..10),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 10, function 23
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    function: Some(FunctionCode::RdWrMultRegs),
                    unit_id: Some(10..10),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 10, function public
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    category: Some(CodeCategory::PUBLIC_ASSIGNED | CodeCategory::PUBLIC_UNASSIGNED),
                    unit_id: Some(10..10),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 10, function !user
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[0],
                &DetectModbusRust {
                    category: Some(!CodeCategory::USER_DEFINED),
                    unit_id: Some(10..10),
                    ..Default::default()
                }
            ),
            1
        );

        // Force Listen Only Mode
        assert_eq!(
            modbus.parse(
                std::ptr::null_mut(),
                &[
                    0x0A, 0x00, // Transaction ID
                    0x00, 0x00, // Protocol ID
                    0x00, 0x06, // Length
                    0x00, // Unit ID
                    0x08, // Function code
                    0x00, 0x04, // Sub-function code
                    0x00, 0x00 // Data
                ],
                Direction::ToServer
            ),
            AppLayerResult::ok()
        );
        assert_eq!(modbus.transactions.len(), 2);
        // function 8, subfunction 4
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[1],
                &DetectModbusRust {
                    function: Some(FunctionCode::Diagnostic),
                    subfunction: Some(4),
                    ..Default::default()
                }
            ),
            1
        );

        // Encapsulated Interface Transport (MEI)
        assert_eq!(
            modbus.parse(
                std::ptr::null_mut(),
                &[
                    0x00, 0x10, // Transaction ID
                    0x00, 0x00, // Protocol ID
                    0x00, 0x05, // Length
                    0x00, // Unit ID
                    0x2B, // Function code
                    0x0F, // MEI Type
                    0x00, 0x00 // Data
                ],
                Direction::ToServer
            ),
            AppLayerResult::ok()
        );
        assert_eq!(modbus.transactions.len(), 3);
        // function reserved
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[2],
                &DetectModbusRust {
                    category: Some(Flags::from(CodeCategory::RESERVED)),
                    ..Default::default()
                }
            ),
            1
        );

        // Unassigned/Unknown function
        assert_eq!(
            modbus.parse(
                std::ptr::null_mut(),
                &[
                    0x00, 0x0A, // Transaction ID
                    0x00, 0x00, // Protocol ID
                    0x00, 0x02, // Length
                    0x00, // Unit ID
                    0x12  // Function code
                ],
                Direction::ToServer
            ),
            AppLayerResult::ok()
        );
        assert_eq!(modbus.transactions.len(), 4);
        // function !assigned
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[3],
                &DetectModbusRust {
                    category: Some(!CodeCategory::PUBLIC_ASSIGNED),
                    ..Default::default()
                }
            ),
            1
        );

        // Read Coils request
        assert_eq!(
            modbus.parse(
                std::ptr::null_mut(),
                &[
                    0x00, 0x00, // Transaction ID
                    0x00, 0x00, // Protocol ID
                    0x00, 0x06, // Length
                    0x0a, // Unit ID
                    0x01, // Function code
                    0x78, 0x90, // Starting Address
                    0x00, 0x13 // Quantity of coils
                ],
                Direction::ToServer
            ),
            AppLayerResult::ok()
        );
        assert_eq!(modbus.transactions.len(), 5);
        // access read
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[4],
                &DetectModbusRust {
                    access_type: Some(Flags::from(AccessType::READ)),
                    ..Default::default()
                }
            ),
            1
        );
        // access read, address 30870
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[4],
                &DetectModbusRust {
                    access_type: Some(Flags::from(AccessType::READ)),
                    address: Some(30870..30870),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 10, access read, address 30863
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[4],
                &DetectModbusRust {
                    access_type: Some(Flags::from(AccessType::READ)),
                    unit_id: Some(10..10),
                    address: Some(30863..30863),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 11, access read, address 30870
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[4],
                &DetectModbusRust {
                    access_type: Some(Flags::from(AccessType::READ)),
                    unit_id: Some(11..11),
                    address: Some(30870..30870),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 11, access read, address 30863
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[4],
                &DetectModbusRust {
                    access_type: Some(Flags::from(AccessType::READ)),
                    unit_id: Some(11..11),
                    address: Some(30863..30863),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 10, access write
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[4],
                &DetectModbusRust {
                    access_type: Some(Flags::from(AccessType::WRITE)),
                    unit_id: Some(10..10),
                    ..Default::default()
                }
            ),
            1
        );
        // unit 10, access read, address 30870
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[4],
                &DetectModbusRust {
                    access_type: Some(Flags::from(AccessType::READ)),
                    unit_id: Some(10..10),
                    address: Some(30870..30870),
                    ..Default::default()
                }
            ),
            1
        );

        // Read Inputs Register request
        assert_eq!(
            modbus.parse(
                std::ptr::null_mut(),
                &[
                    0x00, 0x0A, // Transaction ID
                    0x00, 0x00, // Protocol ID
                    0x00, 0x06, // Length
                    0x00, // Unit ID
                    0x04, // Function code
                    0x00, 0x08, // Starting Address
                    0x00, 0x60 // Quantity of Registers
                ],
                Direction::ToServer
            ),
            AppLayerResult::ok()
        );
        assert_eq!(modbus.transactions.len(), 6);
        // access read input
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    ..Default::default()
                }
            ),
            1
        );
        // access read input, address <9
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    address: Some(u16::MIN..9),
                    ..Default::default()
                }
            ),
            1
        );
        // access read input, address 5<>9
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    address: Some(5..9),
                    ..Default::default()
                }
            ),
            1
        );
        // access read input, address >104
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    address: Some(104..u16::MAX),
                    ..Default::default()
                }
            ),
            1
        );
        // access read input, address 104<>110
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    address: Some(104..110),
                    ..Default::default()
                }
            ),
            1
        );
        // access read input, address 9
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    address: Some(9..9),
                    ..Default::default()
                }
            ),
            1
        );
        // access read input, address <10
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    address: Some(u16::MIN..10),
                    ..Default::default()
                }
            ),
            1
        );
        // access read input, address 5<>10
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    address: Some(5..10),
                    ..Default::default()
                }
            ),
            1
        );
        // access read input, address >103
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    address: Some(103..u16::MAX),
                    ..Default::default()
                }
            ),
            1
        );
        // access read input, address 103<>110
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    address: Some(103..110),
                    ..Default::default()
                }
            ),
            1
        );
        // access read input, address 104
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[5],
                &DetectModbusRust {
                    access_type: Some(AccessType::READ | AccessType::INPUT),
                    address: Some(104..104),
                    ..Default::default()
                }
            ),
            1
        );

        // Origin: https://github.com/bro/bro/blob/master/testing/btest/Traces/modbus/modbus.trace
        // Read Coils Response
        assert_eq!(
            modbus.parse(
                std::ptr::null_mut(),
                &[
                    0x00, 0x01, // Transaction ID
                    0x00, 0x00, // Protocol ID
                    0x00, 0x04, // Length
                    0x0a, // Unit ID
                    0x01, // Function code
                    0x01, // Count
                    0x00, // Data
                ],
                Direction::ToClient
            ),
            AppLayerResult::ok()
        );
        assert_eq!(modbus.transactions.len(), 7);
        // function 1
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[6],
                &DetectModbusRust {
                    function: Some(FunctionCode::RdCoils),
                    ..Default::default()
                }
            ),
            1
        );
        // access read, address 104
        // Fails because there was no request, and the address is not retrievable
        // from the response.
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[6],
                &DetectModbusRust {
                    access_type: Some(Flags::from(AccessType::READ)),
                    address: Some(104..104),
                    ..Default::default()
                }
            ),
            1
        );

        // Origin: https://github.com/bro/bro/blob/master/testing/btest/Traces/modbus/modbus.trace
        // Write Single Register Response
        assert_eq!(
            modbus.parse(
                std::ptr::null_mut(),
                &[
                    0x00, 0x01, // Transaction ID
                    0x00, 0x00, // Protocol ID
                    0x00, 0x06, // Length
                    0x0a, // Unit ID
                    0x06, // Function code
                    0x00, 0x05, // Starting address
                    0x00, 0x0b // Data
                ],
                Direction::ToClient
            ),
            AppLayerResult::ok()
        );
        assert_eq!(modbus.transactions.len(), 8);
        // function 6
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[7],
                &DetectModbusRust {
                    function: Some(FunctionCode::WrSingleReg),
                    ..Default::default()
                }
            ),
            1
        );
        // access write, address 10
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[7],
                &DetectModbusRust {
                    access_type: Some(Flags::from(AccessType::WRITE)),
                    address: Some(10..10),
                    ..Default::default()
                }
            ),
            1
        );

        // Origin: https://github.com/bro/bro/blob/master/testing/btest/Traces/modbus/modbus.trace
        // Write Single Register Response
        assert_eq!(
            modbus.parse(
                std::ptr::null_mut(),
                &[
                    0x00, 0x00, // Transaction ID
                    0x00, 0x00, // Protocol ID
                    0x00, 0x06, // Length
                    0x0a, // Unit ID
                    0x08, // Function code
                    0x00, 0x0a, // Diagnostic code
                    0x00, 0x00 // Data
                ],
                Direction::ToClient
            ),
            AppLayerResult::ok()
        );
        assert_eq!(modbus.transactions.len(), 9);
        // function 8
        assert_eq!(
            SCModbusInspect(
                &modbus.transactions[8],
                &DetectModbusRust {
                    function: Some(FunctionCode::Diagnostic),
                    ..Default::default()
                }
            ),
            1
        );
        // access read
        assert_ne!(
            SCModbusInspect(
                &modbus.transactions[8],
                &DetectModbusRust {
                    access_type: Some(Flags::from(AccessType::READ)),
                    ..Default::default()
                }
            ),
            1
        );
    }
}
