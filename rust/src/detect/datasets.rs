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

use std::fs::{File, OpenOptions};
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
pub unsafe extern "C" fn ProcessDatasets(set: &Dataset, name: *const c_char, fname: *const c_char, fmode: *const c_char) -> i32 {
    let file_string = CStr::from_ptr(fname).to_str().unwrap();
    let mode = CStr::from_ptr(fmode).to_str().unwrap();
    let set_name = CStr::from_ptr(name).to_str().unwrap();
    let filename = Path::new(file_string);
    if let Ok(lines) = read_lines(filename, mode) {
        for line in lines.map_while(Result::ok) {
            let v: Vec<&str> = line.split(',').collect();
            // Ignore empty and invalid lines in dataset/rep file
            if v.is_empty() || v.len() > 2 {
                continue;
            }
            if v.len() == 1 {
                // Dataset
                let mut decoded: Vec<u8> = vec![];
                if STANDARD.decode_vec(v[0], &mut decoded).is_err() {
                    SCLogError!("bad base64 encoding {}", set_name);
                    return -2;
                }
                DatasetAdd(set, decoded.as_ptr(), decoded.len() as u32);
            } else {
                // Datarep
                let mut decoded: Vec<u8> = vec![];
                if STANDARD.decode_vec(v[0], &mut decoded).is_err() {
                    SCLogError!("bad base64 encoding {}", set_name);
                    return -2;
                }
                if let Ok(val) = v[1].to_string().parse::<u16>() {
                    let rep: DataRepType = DataRepType { value: val };
                    DatasetAddwRep(set, decoded.as_ptr(), decoded.len() as u32, &rep);
                } else {
                    SCLogError!("Invalid datarep value {}", set_name);
                    return -2;
                }
            }
        }
    } else {
        return -1;
    }
    0
}

fn read_lines<P>(filename: P, fmode: &str) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file: File = if fmode == "r" {
        File::open(filename)?
    } else {
        OpenOptions::new().append(true).create(true).read(true).open(filename)?
    };
    Ok(io::BufReader::new(file).lines())
}
