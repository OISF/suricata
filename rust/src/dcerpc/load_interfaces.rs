/* Copyright (C) 2026 Open Information Security Foundation
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

use lazy_static::lazy_static;
use serde::Deserialize;
use std::collections::HashMap;
use uuid::Uuid;

const DCERPC_INTERFACES_JSON: &str = include_str!("data/dcerpc_interfaces.json");

#[derive(Deserialize)]
pub struct DcerpcInterface {
    uuid: Uuid,
    pub service: String,
    /// opnum -> procedure name; absent in the source for interfaces with no
    /// documented opcodes.
    #[serde(default)]
    pub opcodes: HashMap<u16, String>,
}

fn load_interface_map(contents: &str) -> HashMap<Uuid, DcerpcInterface> {
    let mut map = HashMap::new();
    for line in contents.lines() {
        if !line.trim().is_empty() {
            if let Ok(iface) = serde_json::from_str::<DcerpcInterface>(line) {
                let uuid = iface.uuid;
                if map.insert(uuid, iface).is_some() {
                    // can only happen if the loaded JSON file was hand edited
                    SCLogWarning!(
                        "duplicate DCERPC interface UUID {} in dcerpc_interfaces.json; \
                         keeping last entry",
                        uuid.to_hyphenated()
                    );
                }
            }
        }
    }
    map
}

lazy_static! {
    pub static ref DCERPC_INTERFACE_MAP: HashMap<Uuid, DcerpcInterface> =
        load_interface_map(DCERPC_INTERFACES_JSON);
}
