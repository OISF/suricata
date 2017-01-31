extern crate libc;
use std;
//use std::ptr;
//use std::ffi::CString;
//use libc::{c_void};
use filecontainer::*;

const SURICATA_RUST_MAGIC : u32 = 0x1234;

//pub type LogCallback = extern "C" fn (lvl: u32, file: *const i8, line: u32, func: *const i8, err: u32, msg: *const i8);

pub struct SuricataStreamingBufferConfig;

//File *(*FileOpenFile)(FileContainer *, const StreamingBufferConfig *,
//       const uint8_t *name, uint16_t name_len,
//       const uint8_t *data, uint32_t data_len, uint16_t flags);
pub type SCFileOpenFile = extern "C" fn (
        file_container: &SuricataFileContainer,
        sbcfg: &SuricataStreamingBufferConfig,
        name: *const u8, name_len: u16,
        data: *const u8, data_len: u32,
        flags: u16) -> SuricataFile;
//int (*FileCloseFile)(FileContainer *, const uint8_t *data, uint32_t data_len, uint16_t flags);
pub type SCFileCloseFile = extern "C" fn (
        file_container: &SuricataFileContainer,
        data: *const u8, data_len: u32,
        flags: u16) -> i32;
//int (*FileAppendData)(FileContainer *, const uint8_t *data, uint32_t data_len);
pub type SCFileAppendData = extern "C" fn (
        file_container: &SuricataFileContainer,
        data: *const u8, data_len: u32) -> i32;
// void FilePrune(FileContainer *ffc)
pub type SCFilePrune = extern "C" fn (
        file_container: &SuricataFileContainer);
// void FileContainerRecycle(FileContainer *ffc)
pub type SCFileContainerRecycle = extern "C" fn (
        file_container: &SuricataFileContainer);

#[repr(C)]
pub struct SuricataConfig {
    pub magic: u32,
    pub sbcfg: &'static SuricataStreamingBufferConfig,
    pub magic2: u32,
    pub fn_fileopenfile: SCFileOpenFile,
    pub magic3: u32,
    pub fn_fileclosefile: SCFileCloseFile,
    pub fn_fileappenddata: SCFileAppendData,
    pub magic4: u32,
    pub fn_filecontainerrecycle: SCFileContainerRecycle,
    pub fn_fileprune: SCFilePrune,
    pub magic5: u32,
    // other members
}

pub static mut suricata_config : Option<&'static SuricataConfig> = None;

#[no_mangle]
pub extern "C" fn r_nfstcp_init(config: &'static mut SuricataConfig) -> i32 {
    assert!(std::ptr::null_mut() != config);
    unsafe { suricata_config = Some(config) };
    
    assert_eq!(config.magic,SURICATA_RUST_MAGIC);
    
    println!("SURICATA NFS Rust parser ready, magic {:X}/{:X}/{:X}/{:X}/{:X}!",config.magic, config.magic2, config.magic3, config.magic4, config.magic5);
/*    
    let fd = vec![0x01, 0x02, 0x03, 0x04];

    match unsafe {suricata_config} {
        None => panic!("BUG no suricata_config"),
        Some(c) => {
            let fc = SuricataFileContainer { head:ptr::null_mut(), tail:ptr::null_mut() };
            let v = fd;
            let res = (c.fn_fileappenddata)(&fc, v.as_ptr(), v.len() as u32);
        }
    }
*/
    0
}

