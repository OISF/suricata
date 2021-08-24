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

use std;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::pgsql::pgsql::*;
use crate::pgsql::parser::*;

fn log_pgsql(tx: &PgsqlTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    // if let Some(ref request) = tx.request {
    //     js.set_string("request", &requests.to_string())?;
    // }
    // if let Some(ref response) = tx.response {
    //     js.set_string("response", &responses.to_string())?;
    // }
    // // TODO
    // // Check tx vectors and alternately print request and response? >_<
    // Ok(())
    SCLogNotice!("PGSQL Logger call.");
    if !tx.requests.is_empty() {
        for request in &tx.requests {
            // TODO change this logic, it can't be js.set_string, or maybe I will use
            // log_request differently
            // js.set_string("request", log_request(&request, js))?;
            js.set_string("request", &request.to_string());
        }
        for response in &tx.responses {
            js.set_string("response", &response.to_string())?;
        }
    }
    Ok(())
}

fn log_request(req: &PgsqlFEMessage, js: &mut JsonBuilder) -> Result<(), JsonError>
{
    match req {
        PgsqlFEMessage::StartupMessage(
            StartupPacket{
                length,
                proto_major,
                proto_minor,
                params}) => {
            let proto = format!("{}.{}", proto_major, proto_minor);
            js.open_object("startup message")?;
            // TODO handle the u32 to u64 issue
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            js.set_string("protocol version", &proto)?;
            let jb = log_pgsql_parameters(params)?;
            js.set_object("startup parameters", &jb)?;
        },
        PgsqlFEMessage::SslRequest(_) => todo!(),
        PgsqlFEMessage::PasswordMessage(_) => todo!(),
        PgsqlFEMessage::SASLInitialResponse(_) => todo!(),
        PgsqlFEMessage::SASLResponse(_) => todo!(),
        PgsqlFEMessage::SimpleQuery(_) => todo!(),

    }
    Ok(())
}

fn log_pgsql_parameters(params: &PgsqlStartupParameters) -> Result<JsonBuilder, JsonError>
{
    let mut jb = JsonBuilder::new_object();
    jb.set_string_from_bytes("user", &params.user.param_value)?;
    if let Some(PgsqlParameter{param_name: _, param_value}) = &params.database {
        jb.set_string_from_bytes("database", &param_value)?;
    }
    if let Some(vec) = &params.optional_params {
        for param in vec {
            // TODO extract this value?
            let param_name = String::from_utf8_lossy(&param.param_name);
            jb.set_string_from_bytes(&param_name, &param.param_value)?;
        }
    }
    jb.close()?;
    Ok(jb)
}

#[no_mangle]
pub extern "C" fn rs_pgsql_logger_log(tx: *mut std::os::raw::c_void, js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, PgsqlTransaction);
    log_pgsql(tx, js).is_ok()
}
