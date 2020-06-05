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

use super::bittorrent_dht::BitTorrentDHTTransaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_bittorrent_dht(
    tx: &BitTorrentDHTTransaction, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    js.set_string("transaction_id", &tx.transaction_id)?;
    if let Some(client_version) = &tx.client_version {
        js.set_string("client_version", client_version)?;
    }
    if let Some(request_type) = &tx.request_type {
        js.set_string("request_type", request_type)?;
    }
    if let Some(error) = &tx.error {
        js.open_object("error")?;
        js.set_uint("num", u64::from(error.num))?;
        js.set_string("msg", &error.msg)?;
        js.close()?;
    };
    if let Some(request) = &tx.request {
        js.open_object("request")?;
        js.set_string("id", &request.id)?;
        if let Some(target) = &request.target {
            js.set_string("target", target)?;
        }
        if let Some(info_hash) = &request.info_hash {
            js.set_string("info_hash", info_hash)?;
        }
        if let Some(token) = &request.token {
            js.set_string("token", token)?;
        }
        if let Some(implied_port) = request.implied_port {
            js.set_uint("implied_port", u64::from(implied_port))?;
        }
        if let Some(port) = request.port {
            js.set_uint("port", u64::from(port))?;
        }
        js.close()?;
    };
    if let Some(response) = &tx.response {
        js.open_object("response")?;
        js.set_string("id", &response.id)?;
        if let Some(nodes) = &response.nodes {
            js.set_string("nodes", nodes)?;
        }
        if let Some(values) = &response.values {
            js.open_array("values")?;
            for value in values {
                js.append_string(value)?;
            }
            js.close()?;
        }
        if let Some(token) = &response.token {
            js.set_string("token", token)?;
        }
        js.close()?;
    };
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_logger_log(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, BitTorrentDHTTransaction);
    log_bittorrent_dht(tx, js).is_ok()
}
