use crate::suricata::JsonBuilder;
use crate::suricata::{jb_close, jb_open_object, jb_set_string, jb_set_uint};
use crate::util::ctor_pointer;
use crate::zabbix::ZabbixTransaction;

use std::ffi::CString;

#[derive(Debug, PartialEq, Eq)]
pub enum JsonError {
    SuricataError,
}

impl std::error::Error for JsonError {}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            JsonError::SuricataError => write!(f, "suricata returned error"),
        }
    }
}

fn jb_set_string_sc(jb: &mut JsonBuilder, key: &str, val: &str) -> Result<(), JsonError> {
    let keyc = CString::new(key).unwrap();
    let valc = CString::new(val.escape_default().to_string()).unwrap();
    if unsafe { !jb_set_string(jb, keyc.as_ptr(), valc.as_ptr()) } {
        return Err(JsonError::SuricataError);
    }
    Ok(())
}

fn jb_close_sc(jb: &mut JsonBuilder) -> Result<(), JsonError> {
    if unsafe { !jb_close(jb) } {
        return Err(JsonError::SuricataError);
    }
    Ok(())
}

fn jb_open_object_sc(jb: &mut JsonBuilder, key: &str) -> Result<(), JsonError> {
    let keyc = CString::new(key).unwrap();
    if unsafe { !jb_open_object(jb, keyc.as_ptr()) } {
        return Err(JsonError::SuricataError);
    }
    Ok(())
}

fn jb_set_uint_sc(jb: &mut JsonBuilder, key: &str, val: u64) -> Result<(), JsonError> {
    let keyc = CString::new(key).unwrap();
    if unsafe { !jb_set_uint(jb, keyc.as_ptr(), val) } {
        return Err(JsonError::SuricataError);
    }
    Ok(())
}

fn log_zabbix(tx: &ZabbixTransaction, jb: &mut JsonBuilder) -> Result<(), JsonError> {
    jb_open_object_sc(jb, "zabbix")?;
    jb_set_uint_sc(jb, "flags", tx.zabbix.flags.into())?;
    //TODO make configurable
    if tx.zabbix.data.len() < 256 {
        jb_set_string_sc(jb, "data", &String::from_utf8_lossy(&tx.zabbix.data))?;
    } else {
        jb_set_string_sc(jb, "data", &String::from_utf8_lossy(&tx.zabbix.data[..256]))?;
    }
    jb_close_sc(jb)?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_log(
    tx: *mut std::os::raw::c_void,
    jb: *mut std::os::raw::c_void,
) -> bool {
    let tx = ctor_pointer!(tx, ZabbixTransaction);
    let jb = ctor_pointer!(jb, JsonBuilder);
    log_zabbix(tx, jb).is_ok()
}
