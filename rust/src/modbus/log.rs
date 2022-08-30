/* Copyright (C) 2021-2022 Open Information Security Foundation
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
use crate::jsonbuilder::{JsonBuilder, JsonError};

use sawp_modbus::{Data, Message, Read, Write};

#[no_mangle]
pub extern "C" fn rs_modbus_to_json(tx: &mut ModbusTransaction, js: &mut JsonBuilder) -> bool {
    log(tx, js).is_ok()
}

/// populate a json object with transactional information, for logging
fn log(tx: &ModbusTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("modbus")?;
    js.set_uint("id", tx.id)?;

    if let Some(req) = &tx.request {
        js.open_object("request")?;
        log_message(req, js)?;
        js.close()?;
    }

    if let Some(resp) = &tx.response {
        js.open_object("response")?;
        log_message(resp, js)?;
        js.close()?;
    }

    js.close()?;
    Ok(())
}

fn log_message(msg: &Message, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_uint("transaction_id", msg.transaction_id.into())?;
    js.set_uint("protocol_id", msg.protocol_id.into())?;
    js.set_uint("unit_id", msg.unit_id.into())?;
    js.set_uint("function_raw", msg.function.raw.into())?;
    js.set_string("function_code", &msg.function.code.to_string())?;
    js.set_string("access_type", &msg.access_type.to_string())?;
    js.set_string("category", &msg.category.to_string())?;
    js.set_string("error_flags", &msg.error_flags.to_string())?;

    match &msg.data {
        Data::Exception(exc) => {
            js.open_object("exception")?;
            js.set_uint("raw", exc.raw.into())?;
            js.set_string("code", &exc.code.to_string())?;
            js.close()?;
        }
        Data::Diagnostic { func, data } => {
            js.open_object("diagnostic")?;
            js.set_uint("raw", func.raw.into())?;
            js.set_string("code", &func.code.to_string())?;
            js.set_string_from_bytes("data", data)?;
            js.close()?;
        }
        Data::MEI { mei_type, data } => {
            js.open_object("mei")?;
            js.set_uint("raw", mei_type.raw.into())?;
            js.set_string("code", &mei_type.code.to_string())?;
            js.set_string_from_bytes("data", data)?;
            js.close()?;
        }
        Data::Read(read) => {
            js.open_object("read")?;
            log_read(read, js)?;
            js.close()?;
        }
        Data::Write(write) => {
            js.open_object("write")?;
            log_write(write, js)?;
            js.close()?;
        }
        Data::ReadWrite { read, write } => {
            js.open_object("read")?;
            log_read(read, js)?;
            js.close()?;
            js.open_object("write")?;
            log_write(write, js)?;
            js.close()?;
        }
        Data::ByteVec(data) => {
            js.set_string_from_bytes("data", data)?;
        }
        Data::Empty => {}
    }

    Ok(())
}

fn log_read(read: &Read, js: &mut JsonBuilder) -> Result<(), JsonError> {
    match read {
        Read::Request { address, quantity } => {
            js.set_uint("address", (*address).into())?;
            js.set_uint("quantity", (*quantity).into())?;
        }
        Read::Response(data) => {
            js.set_string_from_bytes("data", data)?;
        }
    }

    Ok(())
}

fn log_write(write: &Write, js: &mut JsonBuilder) -> Result<(), JsonError> {
    match write {
        Write::MultReq {
            address,
            quantity,
            data,
        } => {
            js.set_uint("address", (*address).into())?;
            js.set_uint("quantity", (*quantity).into())?;
            js.set_string_from_bytes("data", data)?;
        }
        Write::Mask {
            address,
            and_mask,
            or_mask,
        } => {
            js.set_uint("address", (*address).into())?;
            js.set_uint("and_mask", (*and_mask).into())?;
            js.set_uint("or_mask", (*or_mask).into())?;
        }
        Write::Other { address, data } => {
            js.set_uint("address", (*address).into())?;
            js.set_uint("data", (*data).into())?;
        }
    }

    Ok(())
}
