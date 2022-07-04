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

use super::quic::QuicTransaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_template(tx: &QuicTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("quic")?;
    if tx.header.flags.is_long {
        js.set_string("version", String::from(tx.header.version).as_str())?;

        if let Some(sni) = &tx.sni {
            js.set_string("sni", &String::from_utf8_lossy(&sni))?;
        }
        if let Some(ua) = &tx.ua {
            js.set_string("ua", &String::from_utf8_lossy(&ua))?;
        }
    }
    if tx.cyu.len() > 0 {
        js.open_array("cyu")?;
        for cyu in &tx.cyu {
            js.start_object()?;
            js.set_string("hash", &cyu.hash)?;
            js.set_string("string", &cyu.string)?;
            js.close()?;
        }
        js.close()?;
    }

    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_quic_to_json(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    log_template(tx, js).is_ok()
}
