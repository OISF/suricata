use std::os::raw::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicI32, Ordering};

use suricata_ffi::eve::{self, SCJsonBuilder};
use suricata_ffi::flow;
use suricata_ffi::jsonbuilder::JsonBuilder;
use suricata_ffi::{SCLogError, SCLogNotice};
use suricata_sys::sys::{
    Flow, Packet, SCEveRegisterCallback, SCFlowGetStorageById, SCFlowSetStorageById,
    SCFlowStorageId, SCFlowStorageRegister, SCPlugin, ThreadVars,
};

struct FlowStorage {
    updates: u64,
}

// A static mut will be a hard error in 2024 edition, so use an atomic instead. A OnceLock is an
// option as well.
static FLOW_STORAGE_ID: AtomicI32 = AtomicI32::new(-1);

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
    let id =
        unsafe { SCFlowStorageRegister(c"rust-flow-storage".as_ptr(), Some(flow_storage_free)) };
    if id.id < 0 {
        return Err("Failed to register flow storage");
    }
    FLOW_STORAGE_ID.store(id.id, Ordering::Relaxed);
    flow::register_init_callback(log_flow_init)?;
    flow::register_update_callback(log_flow_update)?;
    flow::register_finish_callback(log_flow_finish)?;
    Ok(())
}

unsafe extern "C" fn flow_storage_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr as *mut FlowStorage));
    }
}

unsafe fn flow_storage_get(f: *mut Flow) -> *mut FlowStorage {
    let id = FLOW_STORAGE_ID.load(Ordering::Relaxed);
    if f.is_null() || id < 0 {
        return null_mut();
    }
    SCFlowGetStorageById(f, SCFlowStorageId { id }) as *mut FlowStorage
}

unsafe extern "C" fn log_eve_raw(
    _tv: *mut ThreadVars,
    _p: *const Packet,
    f: *mut Flow,
    jb: *mut SCJsonBuilder,
    _user: *mut c_void,
) {
    let mut jb = JsonBuilder::from_raw(jb);
    let _ = jb.open_object("foobar");
    let _ = jb.set_string("example", "eve-callback");
    let storage = flow_storage_get(f);
    if !storage.is_null() {
        let _ = jb.set_uint("flow_updates", (*storage).updates);
    }
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

fn log_flow_init(_tv: *mut ThreadVars, f: *mut Flow, _p: *const Packet) {
    if f.is_null() {
        return;
    }
    let id = FLOW_STORAGE_ID.load(Ordering::Relaxed);
    if id < 0 {
        return;
    }
    let storage = Box::into_raw(Box::new(FlowStorage { updates: 0 }));
    unsafe {
        if SCFlowSetStorageById(f, SCFlowStorageId { id }, storage as *mut c_void) != 0 {
            drop(Box::from_raw(storage));
            SCLogError!("failed to set rust example flow storage");
            return;
        }
    }
    SCLogNotice!("rust example flow init callback: flow={:p}", f);
}

fn log_flow_update(_tv: *mut ThreadVars, f: *mut Flow, p: *mut Packet) {
    unsafe {
        let storage = flow_storage_get(f);
        if !storage.is_null() {
            (*storage).updates += 1;
        }
    }
    SCLogNotice!(
        "rust example flow update callback: flow={:p}, packet={:p}",
        f,
        p
    );
}

fn log_flow_finish(_tv: *mut ThreadVars, f: *mut Flow) {
    let updates = unsafe {
        let storage = flow_storage_get(f);
        if storage.is_null() {
            0
        } else {
            (*storage).updates
        }
    };
    SCLogNotice!(
        "rust example flow finish callback: flow={:p}, updates={}",
        f,
        updates
    );
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
