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

// Author: Shivani Bhardwaj <shivani@oisf.net>

//! This module exposes items from the datasets C code to Rust.

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::ffi::{c_char, CStr};
use base64::{Engine, engine::general_purpose::STANDARD};

/// Opaque Dataset type defined in C
#[derive(Copy, Clone)]
pub enum Dataset {}

// Simple C type converted to Rust
#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct DataRepType {
    pub value: u16,
}

// Extern fns operating on the opaque Dataset type above
/// cbindgen:ignore
extern {
    pub fn DatasetAdd(set: &Dataset, data: *const u8, len: u32) -> i32;
    pub fn DatasetAddwRep(set: &Dataset, data: *const u8, len: u32, rep: *const DataRepType) -> i32;
}

#[no_mangle]
pub unsafe extern "C" fn ProcessDatasets(set: &Dataset, fname: *const c_char) {
    let file_string = CStr::from_ptr(fname).to_str().unwrap();
    let filename = Path::new(file_string);
    SCLogNotice!("Path: {:?}", filename);
    if let Ok(lines) = read_lines(filename) {
        for line in lines.flatten() {
            SCLogNotice!("{}", line);
            let v: Vec<&str> = line.split(',').collect();
            // Ignore empty and invalid lines in dataset/rep file
            if v.is_empty() || v.len() > 2 {
                continue;
            }
            if v.len() == 1 {
                // Dataset
                let mut decoded: Vec<u8> = vec![];
                if STANDARD.decode_vec(v[0], &mut decoded).is_err() {
                    // FatalErrorOnInit STODO
                }
                DatasetAdd(&set, decoded.as_ptr(), decoded.len() as u32);
            } else {
                // Datarep
                let mut decoded: Vec<u8> = vec![];
                if STANDARD.decode_vec(v[0], &mut decoded).is_err() {
                    // FatalErrorOnInit STODO
                }
                if let Ok(val) = v[1].to_string().parse::<u16>() {
                    let rep: DataRepType = DataRepType { value: val };
                    DatasetAddwRep(&set, decoded.as_ptr(), decoded.len() as u32, &rep);
                } else {
                    // FatalErrorOnInit STODO
                }
            }
        }
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
