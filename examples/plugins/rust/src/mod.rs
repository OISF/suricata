use std::ptr::null_mut;

use suricata_ffi::eve::{self, Flow, Packet, SCJsonBuilder, ThreadVars};
use suricata_ffi::jsonbuilder::JsonBuilder;
use suricata_ffi::{SCLogError, SCLogNotice};
use suricata_sys::sys::{SCEveRegisterCallback, SCPlugin};

unsafe extern "C" fn init() {
    suricata_ffi::plugin::init();
    SCLogNotice!("Initializing rust example plugin");

    if let Err(err) = register() {
        SCLogError!("Failed to register rust example EVE callback: {}", err);
    }
}

pub fn register() -> Result<(), &'static str> {
    if !unsafe { SCEveRegisterCallback(Some(log_eve_raw), null_mut()) } {
        return Err("Failed to register raw EVE callback");
    }
    eve::register_callback(log_eve_wrapped)
}

unsafe extern "C" fn log_eve_raw(
    _tv: *mut ThreadVars,
    _p: *const Packet,
    _f: *mut Flow,
    jb: *mut SCJsonBuilder,
    _user: *mut std::os::raw::c_void,
) {
    let mut jb = JsonBuilder::from_raw(jb);
    let _ = jb.open_object("foobar");
    let _ = jb.set_string("example", "eve-callback");
    let _ = jb.close();
}

fn log_eve_wrapped(
    _tv: *mut ThreadVars,
    _p: *const Packet,
    f: *mut Flow,
    jb: &mut JsonBuilder,
) -> Result<(), suricata_ffi::jsonbuilder::Error> {
    jb.open_object("rust_wrapped")?;
    jb.set_string("example", "eve-callback")?;
    jb.set_string("has_flow", if f.is_null() { "false" } else { "true" })?;
    jb.close()?;
    Ok(())
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *mut SCPlugin {
    suricata_ffi::plugin::Plugin {
        name: "rust",
        version: env!("CARGO_PKG_VERSION"),
        license: "MIT",
        author: "Open Information Security Foundation",
        init,
    }
    .into_raw()
}
