use std::ptr::null_mut;

use suricata_ffi::eve::{self, SCJsonBuilder};
use suricata_ffi::flow;
use suricata_ffi::jsonbuilder::JsonBuilder;
use suricata_ffi::{SCLogError, SCLogNotice};
use suricata_sys::sys::{Flow, Packet, SCEveRegisterCallback, SCPlugin, ThreadVars};

unsafe extern "C" fn init() {
    suricata_ffi::plugin::init();
    SCLogNotice!("Initializing rust example plugin");

    if let Err(err) = register_eve_callbacks() {
        SCLogError!("Failed to register rust example EVE callbacks: {}", err);
    }
    if let Err(err) = register_flow_callbacks() {
        SCLogError!("Failed to register rust example flow callbacks: {}", err);
    }
}

pub fn register() -> Result<(), &'static str> {
    register_eve_callbacks()?;
    register_flow_callbacks()?;
    Ok(())
}

pub fn register_eve_callbacks() -> Result<(), &'static str> {
    if !unsafe { SCEveRegisterCallback(Some(log_eve_raw), null_mut()) } {
        return Err("Failed to register raw EVE callback");
    }
    eve::register_callback(log_eve_wrapped)
}

pub fn register_flow_callbacks() -> Result<(), &'static str> {
    flow::register_init_callback(log_flow_init)?;
    flow::register_update_callback(log_flow_update)?;
    flow::register_finish_callback(log_flow_finish)?;
    Ok(())
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

fn log_flow_init(_tv: *mut ThreadVars, _f: *mut Flow, _p: *const Packet) {
    SCLogNotice!("rust example flow init callback: flow={:p}", _f);
}

fn log_flow_update(_tv: *mut ThreadVars, _f: *mut Flow, _p: *mut Packet) {
    SCLogNotice!(
        "rust example flow update callback: flow={:p}, packet={:p}",
        _f,
        _p
    );
}

fn log_flow_finish(_tv: *mut ThreadVars, _f: *mut Flow) {
    SCLogNotice!("rust example flow finish callback: flow={:p}", _f);
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
