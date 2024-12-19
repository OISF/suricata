/* Copyright (C) 2024 Open Information Security Foundation
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

use super::socks::SocksTransaction;
use crate::dns::log::dns_print_addr;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

fn auth_method_string(m: u8) -> String {
    match m {
        0 => "No authentication",
        1 => "GSSAPI",
        2 => "Username/Password",
        _ => {
            return m.to_string();
        }
    }
    .to_string()
}

fn status_string(m: u8) -> String {
    match m {
        0 => "Success",
        _ => {
            return m.to_string();
        }
    }
    .to_string()
}

fn log_socks(tx: &SocksTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("socks")?;
    if let Some(ref connect) = tx.connect {
        js.open_object("connect")?;
        if let Some(ref domain) = &connect.domain {
            let domain = String::from_utf8_lossy(domain);
            js.set_string("domain", &domain)?;
        }
        if let Some(ref ipv4) = &connect.ipv4 {
            js.set_string("ipv4", &dns_print_addr(ipv4))?;
        }
        js.set_uint("port", connect.port as u64)?;
        if let Some(status) = connect.response {
            js.set_string("response", &status_string(status))?;
        }
        js.close()?;
    }
    if let Some(ref auth) = tx.auth_userpass {
        js.open_object("auth_userpass")?;
        js.set_uint("subnegotiation_version", auth.subver as u64)?;
        let user = String::from_utf8_lossy(&auth.user);
        js.set_string("user", &user)?;
        // TODO needs to be optional and disabled by default
        let pass = String::from_utf8_lossy(&auth.pass);
        js.set_string("pass", &pass)?;
        if let Some(status) = auth.response {
            js.set_string("response", &status_string(status))?;
        }
        js.close()?;
    }
    if let Some(ref auth_methods) = tx.auth_methods {
        js.open_object("auth_methods")?;
        js.open_array("request")?;
        for m in &auth_methods.request_methods {
            js.append_string(&auth_method_string(*m))?;
        }
        js.close()?;
        js.set_string(
            "response",
            &auth_method_string(auth_methods.response_method),
        )?;
        js.close()?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCSocksLogger(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, SocksTransaction);
    log_socks(tx, js).is_ok()
}
