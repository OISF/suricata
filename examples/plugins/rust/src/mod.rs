use std::ptr::null_mut;

use suricata_ffi::eve::{self, SCJsonBuilder};
use suricata_ffi::flow::{self, Flow, FlowStorage};
use suricata_ffi::jsonbuilder::JsonBuilder;
use suricata_ffi::packet::Packet;
use suricata_ffi::threadvars::ThreadVars;
use suricata_ffi::{SCLogError, SCLogNotice};
use suricata_sys::sys::{
    Flow as RawFlow, Packet as RawPacket, SCEveRegisterCallback, SCPlugin,
    ThreadVars as RawThreadVars,
};

unsafe extern "C" fn init() {
    suricata_ffi::plugin::init();
    SCLogNotice!("Initializing rust example plugin");

    if let Err(err) = register() {
        SCLogError!("Failed to register rust example callbacks: {}", err);
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

#[derive(Default)]
struct ExampleFlowState {
    packets: u64,
}

pub fn register_flow_callbacks() -> Result<(), &'static str> {
    let state = FlowStorage::<ExampleFlowState>::register("rust-example-flow")?;

    flow::register_init_callback(move |tv, f, p| log_flow_init(tv, f, p, state))?;
    flow::register_update_callback(move |tv, f, p| log_flow_update(tv, f, p, state))?;
    flow::register_finish_callback(move |tv, f| log_flow_finish(tv, f, state))?;
    Ok(())
}

unsafe extern "C" fn log_eve_raw(
    _tv: *mut RawThreadVars,
    _p: *const RawPacket,
    _f: *mut RawFlow,
    jb: *mut SCJsonBuilder,
    _user: *mut std::os::raw::c_void,
) {
    let mut jb = JsonBuilder::from_raw(jb);
    let _ = jb.open_object("foobar");
    let _ = jb.set_string("example", "eve-callback");
    let _ = jb.close();
}

fn log_eve_wrapped(
    _tv: ThreadVars<'_>,
    p: Option<Packet<'_>>,
    f: Option<Flow<'_>>,
    jb: &mut JsonBuilder,
) -> Result<(), suricata_ffi::jsonbuilder::Error> {
    jb.open_object("rust_wrapped")?;
    jb.set_string("example", "eve-callback")?;
    jb.set_string("has_packet", if p.is_some() { "true" } else { "false" })?;
    jb.set_string("has_flow", if f.is_some() { "true" } else { "false" })?;
    jb.close()?;
    Ok(())
}

fn log_flow_init(
    _tv: ThreadVars<'_>,
    mut f: Flow<'_>,
    p: Option<Packet<'_>>,
    state: FlowStorage<ExampleFlowState>,
) {
    let packets = match state.get_or_insert_with(&mut f, ExampleFlowState::default) {
        Ok(data) => {
            if p.is_some() {
                data.packets += 1;
            }
            data.packets
        }
        Err(err) => {
            SCLogError!("failed to initialize rust example flow storage: {}", err);
            0
        }
    };

    SCLogNotice!(
        "rust example flow init callback: flow={:p}, has_packet={}, packets={}",
        f.as_ptr(),
        p.is_some(),
        packets
    );
}

fn log_flow_update(
    _tv: ThreadVars<'_>,
    mut f: Flow<'_>,
    p: Option<Packet<'_>>,
    state: FlowStorage<ExampleFlowState>,
) {
    let packets = match state.get_or_insert_with(&mut f, ExampleFlowState::default) {
        Ok(data) => {
            if p.is_some() {
                data.packets += 1;
            }
            data.packets
        }
        Err(err) => {
            SCLogError!("failed to update rust example flow storage: {}", err);
            0
        }
    };

    SCLogNotice!(
        "rust example flow update callback: flow={:p}, has_packet={}, packets={}",
        f.as_ptr(),
        p.is_some(),
        packets
    );
}

fn log_flow_finish(_tv: ThreadVars<'_>, f: Flow<'_>, state: FlowStorage<ExampleFlowState>) {
    let packets = state.get(&f).map(|data| data.packets).unwrap_or_default();
    SCLogNotice!(
        "rust example flow finish callback: flow={:p}, packets={}",
        f.as_ptr(),
        packets
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
