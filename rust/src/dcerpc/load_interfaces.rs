/* Copyright (c) 1995-now, The Regents of the University of California
 * through the Lawrence Berkeley National Laboratory and the
 * International Computer Science Institute. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * (3) Neither the name of the University of California, Lawrence Berkeley
 *     National Laboratory, U.S. Dept. of Energy, International Computer
 *     Science Institute, nor the names of contributors may be used to endorse
 *     or promote products derived from this software without specific prior
 *     written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that some files in the distribution may carry their own copyright
 * notices.
 */

// Above License comes from Zeek and covers the data extracted and converted to
// NDJSON in dcerpc_interfaces.json using the script extract_dce_rpc_interfaces.py
// from the file doc/scripts/base/protocols/dce-rpc/consts.zeek.rst of the
// Zeek project.
// Most of Zeek's data comes from the bzar project. ref:
// https://github.com/mitre-attack/bzar
// However, given that Zeek's data is a superset among the two, the file has
// Zeek's license.
//
// The License lives here given that JSON cannot have comments and this file
// acts as the entry point loader for the extracted data into Suricata codebase.

use lazy_static::lazy_static;
use serde::Deserialize;
use std::collections::HashMap;
use uuid::Uuid;

const DCERPC_INTERFACES_JSON: &str = include_str!("dcerpc_interfaces.json");

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
                    SCLogError!(
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
