use std::ptr::null_mut;

use suricata_ffi::eve::{self, SCJsonBuilder};
use suricata_ffi::flow;
use suricata_ffi::jsonbuilder::JsonBuilder;
use suricata_ffi::thread::{self, ThreadStorage, ThreadVars};
use suricata_ffi::{SCLogError, SCLogNotice, SCLogWarning};
use suricata_sys::sys::{self, Flow, Packet, SCEveRegisterCallback, SCPlugin};

/// Per-thread state stored in Suricata thread storage.
#[derive(Default)]
struct ThreadState {
    flows: u64,
}

unsafe extern "C" fn init() {
    suricata_ffi::plugin::init();
    SCLogNotice!("Initializing rust example plugin");

    // Register per-thread storage once, then hand the (copyable) handle to the
    // callbacks that use it.
    let thread_storage = match ThreadStorage::<ThreadState>::register("rust-example-thread") {
        Ok(storage) => storage,
        Err(err) => {
            SCLogError!("Failed to register rust example thread storage: {}", err);
            return;
        }
    };

    if let Err(err) = register_eve_callbacks() {
        SCLogError!("Failed to register rust example EVE callbacks: {}", err);
    }
    if let Err(err) = register_flow_callbacks(thread_storage) {
        SCLogError!("Failed to register rust example flow callbacks: {}", err);
    }
    if let Err(err) = register_thread_callbacks(thread_storage) {
        SCLogError!("Failed to register rust example thread callbacks: {}", err);
    }
}

fn register_eve_callbacks() -> Result<(), &'static str> {
    if !unsafe { SCEveRegisterCallback(Some(log_eve_raw), null_mut()) } {
        return Err("Failed to register raw EVE callback");
    }
    eve::register_callback(log_eve_wrapped)
}

fn register_flow_callbacks(storage: ThreadStorage<ThreadState>) -> Result<(), &'static str> {
    flow::register_init_callback(move |tv, f, p| log_flow_init(storage, tv, f, p))?;
    flow::register_update_callback(log_flow_update)?;
    flow::register_finish_callback(log_flow_finish)?;
    Ok(())
}

fn register_thread_callbacks(storage: ThreadStorage<ThreadState>) -> Result<(), &'static str> {
    thread::register_init_callback(move |tv| on_thread_init(storage, tv))
}

unsafe extern "C" fn log_eve_raw(
    _tv: *mut sys::ThreadVars,
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
    _tv: &mut ThreadVars,
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

fn on_thread_init(storage: ThreadStorage<ThreadState>, tv: &mut ThreadVars) {
    // Initialize the per-thread storage for this thread.
    if let Err(err) = storage.get_or_insert_with(tv, ThreadState::default) {
        SCLogError!("failed to initialize rust example thread storage: {}", err);
    }
    SCLogNotice!(
        "rust example thread init callback: thread={:p}",
        tv.as_ptr()
    );
}

fn log_flow_init(
    storage: ThreadStorage<ThreadState>,
    tv: &mut ThreadVars,
    f: *mut Flow,
    _p: *const Packet,
) {
    // Count flows seen by this thread using the per-thread storage.
    let flows = match storage.get_mut(tv) {
        Some(state) => {
            state.flows += 1;
            state.flows
        }
        None => {
            SCLogWarning!("rust example thread storage was not initialized");
            0
        }
    };
    SCLogNotice!(
        "rust example flow init callback: flow={:p}, thread_flows={}",
        f,
        flows
    );
}

fn log_flow_update(_tv: &mut ThreadVars, _f: *mut Flow, _p: *mut Packet) {
    SCLogNotice!(
        "rust example flow update callback: flow={:p}, packet={:p}",
        _f,
        _p
    );
}

fn log_flow_finish(_tv: &mut ThreadVars, _f: *mut Flow) {
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
