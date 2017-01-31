extern crate libc;
//use std;
use std::ptr;
//use std::ffi::CString;
use libc::{c_void};
use common::*;

macro_rules! println_debug(
    ($($arg:tt)*) => { {
        //println!($($arg)*);
    } }
);

pub struct SuricataFile;
#[repr(C)]
pub struct SuricataFileContainer {
    head: * mut c_void,
    tail: * mut c_void,
}

impl Drop for SuricataFileContainer {
    fn drop(&mut self) {
        println_debug!("Dropping!");
        match unsafe {suricata_config} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                (c.fn_filecontainerrecycle)(&self);
            },
        }
    }
}

impl SuricataFileContainer {
    pub fn default() -> SuricataFileContainer {
        SuricataFileContainer { head:ptr::null_mut(), tail:ptr::null_mut() }
    }

    pub fn file_open(&mut self, name: &[u8], flags: u16) -> i32 {
        match unsafe {suricata_config} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                println_debug!("FILE {:p} OPEN flags {:04X}", &self, flags);
                //let ref res =
                (c.fn_fileopenfile)(&self, c.sbcfg,
                        name.as_ptr(), name.len() as u16,
                        ptr::null(), 0u32, flags);
                //if !res {
                //    panic!("c.fn_fileopenfile failed");
                //}
                0
            }
        }
    }

    pub fn file_append(&mut self, data: &[u8]) -> i32 {
        println_debug!("FILECONTAINER: append {}", data.len());
        if data.len() == 0 {
            return 0
        }
        match unsafe {suricata_config} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                let res = (c.fn_fileappenddata)(&self, data.as_ptr(), data.len() as u32);
                if res != 0 {
                    panic!("c.fn_fileappenddata failed");
                }
                res
            }
        }
    }

    pub fn file_close(&mut self, flags: u16) -> i32 {
        println_debug!("FILECONTAINER: CLOSEing");

        match unsafe {suricata_config} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                let res = (c.fn_fileclosefile)(&self, ptr::null(), 0u32, flags);
                if res != 0 {
                    panic!("c.fn_fileclosefile failed");
                }
                res
            }
        }

    }

    pub fn files_prune(&mut self) {
        println_debug!("FILECONTAINER: pruning");
        match unsafe {suricata_config} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                (c.fn_fileprune)(&self);
            }
        }
    }
}

