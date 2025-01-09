/* Copyright (C) 2025 Open Information Security Foundation
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

use crate::common::CallbackFatalErrorOnInit;
use base64::{self, Engine};
use std::ffi::{c_char, CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

/// Opaque Dataset type defined in C
#[derive(Copy, Clone)]
pub enum Dataset {}

// Simple C type converted to Rust
#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct DataRepType {
    pub value: u16,
}

#[derive(Debug)]
#[repr(C)]
pub enum DatasetType {
    DSString = 0,
    DSMd5,
    DSSha256,
    DSIpv4,
    DSIpv6,
}

// Extern fns operating on the opaque Dataset type above
/// cbindgen:ignore
extern "C" {
    pub fn DatasetAdd(set: &Dataset, data: *const u8, len: u32) -> i32;
    pub fn DatasetAddwRep(set: &Dataset, data: *const u8, len: u32, rep: *const DataRepType)
        -> i32;
}

#[no_mangle]
pub unsafe extern "C" fn ParseDatasets(
    set: &Dataset, name: *const c_char, fname: *const c_char, fmode: *const c_char,
    dstype: DatasetType,
) -> i32 {
    let file_string = unwrap_or_return!(CStr::from_ptr(fname).to_str(), -2);
    let mode = unwrap_or_return!(CStr::from_ptr(fmode).to_str(), -2);
    let set_name = unwrap_or_return!(CStr::from_ptr(name).to_str(), -2);
    let filename = Path::new(file_string);
    let mut is_dataset = false;
    let mut is_datarep = false;
    if let Ok(lines) = read_lines(filename, mode) {
        for line in lines.map_while(Result::ok) {
            let v: Vec<&str> = line.split(',').collect();
            // Ignore empty and invalid lines in dataset/rep file
            if v.is_empty() || v.len() > 2 {
                continue;
            }

            if v.len() == 1 {
                if is_datarep {
                    SCLogError!(
                        "Cannot mix dataset and datarep values for set {} in {}",
                        set_name,
                        filename.display()
                    );
                    return -2;
                }
                // Dataset
                is_dataset = true;
            } else {
                if is_dataset {
                    SCLogError!(
                        "Cannot mix dataset and datarep values for set {} in {}",
                        set_name,
                        filename.display()
                    );
                    return -2;
                }
                // Datarep
                is_datarep = true;
            }
            match dstype {
                DatasetType::DSString => {
                    if process_string_set(set, v, set_name, filename, is_dataset) == -1 {
                        continue;
                    }
                }
                DatasetType::DSMd5 => {
                    if process_md5_set(set, v, set_name, filename, is_dataset) == -1 {
                        continue;
                    }
                }
                DatasetType::DSSha256 => {
                    if process_sha256_set(set, v, set_name, filename, is_dataset) == -1 {
                        continue;
                    }
                }
                DatasetType::DSIpv4 => {
                    if process_ipv4_set(set, v, set_name, filename, is_dataset) == -1 {
                        continue;
                    }
                }
                DatasetType::DSIpv6 => {
                    if process_ipv6_set(set, v, set_name, filename, is_dataset) == -1 {
                        continue;
                    }
                }
            }
        }
    } else {
        return -1;
    }

    0
}

unsafe fn process_string_set(
    set: &Dataset, v: Vec<&str>, set_name: &str, filename: &Path, is_dataset: bool,
) -> i32 {
    let mut decoded: Vec<u8> = vec![];
    if base64::engine::general_purpose::STANDARD
        .decode_vec(v[0], &mut decoded)
        .is_err()
    {
        let msg = CString::new(format!(
            "bad base64 encoding {} in {}",
            set_name,
            filename.display()
        ))
        .unwrap();
        CallbackFatalErrorOnInit(msg.as_ptr());
        return -1;
    }
    if is_dataset {
        DatasetAdd(set, decoded.as_ptr(), decoded.len() as u32);
    } else {
        if let Ok(val) = v[1].to_string().parse::<u16>() {
            let rep: DataRepType = DataRepType { value: val };
            DatasetAddwRep(set, decoded.as_ptr(), decoded.len() as u32, &rep);
        } else {
            let msg = CString::new(format!(
                "invalid datarep value {} in {}",
                set_name,
                filename.display()
            ))
            .unwrap();
            CallbackFatalErrorOnInit(msg.as_ptr());
            return -1;
        }
    }
    0
}

unsafe fn process_md5_set(
    set: &Dataset, v: Vec<&str>, set_name: &str, filename: &Path, is_dataset: bool,
) -> i32 {
    let md5_string = match hex::decode(v[0]) {
        Ok(rs) => rs,
        Err(_) => {
            return -1;
        }
    };

    if is_dataset {
        DatasetAdd(set, md5_string.as_ptr(), 16);
    } else {
        if let Ok(val) = v[1].to_string().parse::<u16>() {
            let rep: DataRepType = DataRepType { value: val };
            DatasetAddwRep(set, md5_string.as_ptr(), 16, &rep);
        } else {
            let msg = CString::new(format!(
                "invalid datarep value {} in {}",
                set_name,
                filename.display()
            ))
            .unwrap();
            CallbackFatalErrorOnInit(msg.as_ptr());
            return -1;
        }
    }
    0
}

unsafe fn process_sha256_set(
    set: &Dataset, v: Vec<&str>, set_name: &str, filename: &Path, is_dataset: bool,
) -> i32 {
    let sha256_string = match hex::decode(v[0]) {
        Ok(rs) => rs,
        Err(_) => {
            return -1;
        }
    };

    if is_dataset {
        DatasetAdd(set, sha256_string.as_ptr(), 32);
    } else {
        if let Ok(val) = v[1].to_string().parse::<u16>() {
            let rep: DataRepType = DataRepType { value: val };
            DatasetAddwRep(set, sha256_string.as_ptr(), 32, &rep);
        } else {
            let msg = CString::new(format!(
                "invalid datarep value {} in {}",
                set_name,
                filename.display()
            ))
            .unwrap();
            CallbackFatalErrorOnInit(msg.as_ptr());
            return -1;
        }
    }
    0
}

unsafe fn process_ipv4_set(
    set: &Dataset, v: Vec<&str>, set_name: &str, filename: &Path, is_dataset: bool,
) -> i32 {
    let ipv4 = match Ipv4Addr::from_str(v[0]) {
        Ok(a) => a,
        Err(_) => {
            let msg = CString::new(format!(
                "invalid Ipv4 value {} in {}",
                set_name,
                filename.display()
            ))
            .unwrap();
            CallbackFatalErrorOnInit(msg.as_ptr());
            return -1;
        }
    };
    if is_dataset {
        DatasetAdd(set, ipv4.octets().as_ptr(), 4);
    } else {
        if let Ok(val) = v[1].to_string().parse::<u16>() {
            let rep: DataRepType = DataRepType { value: val };
            DatasetAddwRep(set, ipv4.octets().as_ptr(), 4, &rep);
        } else {
            let msg = CString::new(format!(
                "invalid datarep value {} in {}",
                set_name,
                filename.display()
            ))
            .unwrap();
            CallbackFatalErrorOnInit(msg.as_ptr());
            return -1;
        }
    }
    0
}

unsafe fn process_ipv6_set(
    set: &Dataset, v: Vec<&str>, set_name: &str, filename: &Path, is_dataset: bool,
) -> i32 {
    let ipv6 = match Ipv6Addr::from_str(v[0]) {
        Ok(a) => a,
        Err(_) => {
            let msg = CString::new(format!(
                "invalid Ipv6 value {} in {}",
                set_name,
                filename.display()
            ))
            .unwrap();
            CallbackFatalErrorOnInit(msg.as_ptr());
            return -1;
        }
    };
    let mut fin_ipv6 = ipv6;

    if ipv6.to_ipv4_mapped().is_some() {
        let ipv6_octets = ipv6.octets();
        let mut internal_ipv6: [u8; 16] = [0; 16];
        internal_ipv6[0] = ipv6_octets[12];
        internal_ipv6[1] = ipv6_octets[13];
        internal_ipv6[2] = ipv6_octets[14];
        internal_ipv6[3] = ipv6_octets[15];
        let ipv6_bits = u128::from_be_bytes(internal_ipv6);
        fin_ipv6 = Ipv6Addr::from_bits(ipv6_bits);
    }
    if is_dataset {
        DatasetAdd(set, fin_ipv6.octets().as_ptr(), 16);
    } else {
        if let Ok(val) = v[1].to_string().parse::<u16>() {
            let rep: DataRepType = DataRepType { value: val };
            DatasetAddwRep(set, fin_ipv6.octets().as_ptr(), 16, &rep);
        } else {
            let msg = CString::new(format!(
                "invalid datarep value {} in {}",
                set_name,
                filename.display()
            ))
            .unwrap();
            CallbackFatalErrorOnInit(msg.as_ptr());
            return -1;
        }
    }
    0
}

fn read_lines<P>(filename: P, fmode: &str) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file: File = if fmode == "r" {
        File::open(filename)?
    } else {
        OpenOptions::new()
            .append(true)
            .create(true)
            .read(true)
            .open(filename)?
    };
    Ok(io::BufReader::new(file).lines())
}
