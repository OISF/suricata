extern crate libc;

use json::*;
use tftp::tftp::*;

#[no_mangle]
pub extern "C" fn rs_tftp_log_json_request(tx: &mut TFTPTransaction) -> *mut JsonT
{
    let js = Json::object();
    match tx.opcode {
        1 => js.set_string("packet", "read"),
        2 => js.set_string("packet", "write"),
        _ => js.set_string("packet", "error")
    };
    js.set_string("file", tx.filename.as_str());
    js.set_string("mode", tx.mode.as_str());
    js.unwrap()
}
