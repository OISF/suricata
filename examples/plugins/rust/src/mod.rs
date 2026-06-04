use std::ptr::null_mut;

use suricata_ffi::eve::{self, SCJsonBuilder};
use suricata_ffi::flow::{self, Flow, FlowStorage};
use suricata_ffi::jsonbuilder::JsonBuilder;
use suricata_ffi::thread::{self, ThreadStorage, ThreadVars};
use suricata_ffi::{SCLogError, SCLogNotice, SCLogWarning};
use suricata_sys::sys::{self, Packet, SCEveRegisterCallback, SCPlugin};

/// Per-thread state stored in Suricata thread storage.
#[derive(Default)]
struct ThreadState {
    flows: u64,
}

/// Per-flow state stored in Suricata flow storage.
#[derive(Default)]
struct FlowState {
    packets: u64,
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
    let flow_storage = match FlowStorage::<FlowState>::register("rust-example-flow") {
        Ok(storage) => storage,
        Err(err) => {
            SCLogError!("Failed to register rust example flow storage: {}", err);
            return;
        }
    };

    if let Err(err) = register_eve_callbacks(flow_storage) {
        SCLogError!("Failed to register rust example EVE callbacks: {}", err);
    }
    if let Err(err) = register_flow_callbacks(thread_storage, flow_storage) {
        SCLogError!("Failed to register rust example flow callbacks: {}", err);
    }
    if let Err(err) = register_thread_callbacks(thread_storage) {
        SCLogError!("Failed to register rust example thread callbacks: {}", err);
    }
}

fn register_eve_callbacks(flow_storage: FlowStorage<FlowState>) -> Result<(), &'static str> {
    if !unsafe { SCEveRegisterCallback(Some(log_eve_raw), null_mut()) } {
        return Err("Failed to register raw EVE callback");
    }
    eve::register_callback(move |tv, p, f, jb| log_eve_wrapped(flow_storage, tv, p, f, jb))
}

fn register_flow_callbacks(
    thread_storage: ThreadStorage<ThreadState>,
    flow_storage: FlowStorage<FlowState>,
) -> Result<(), &'static str> {
    flow::register_init_callback(move |tv, f, p| {
        log_flow_init(thread_storage, flow_storage, tv, f, p)
    })?;
    flow::register_update_callback(move |tv, f, p| log_flow_update(flow_storage, tv, f, p))?;
    flow::register_finish_callback(move |tv, f| log_flow_finish(flow_storage, tv, f))?;
    Ok(())
}

fn register_thread_callbacks(storage: ThreadStorage<ThreadState>) -> Result<(), &'static str> {
    thread::register_init_callback(move |tv| on_thread_init(storage, tv))
}

unsafe extern "C" fn log_eve_raw(
    _tv: *mut sys::ThreadVars,
    _p: *const Packet,
    _f: *mut sys::Flow,
    jb: *mut SCJsonBuilder,
    _user: *mut std::os::raw::c_void,
) {
    let mut jb = JsonBuilder::from_raw(jb);
    let _ = jb.open_object("foobar");
    let _ = jb.set_string("example", "eve-callback");
    let _ = jb.close();
}

fn log_eve_wrapped(
    flow_storage: FlowStorage<FlowState>,
    _tv: &mut ThreadVars,
    _p: *const Packet,
    f: Option<&mut Flow>,
    jb: &mut JsonBuilder,
) -> Result<(), suricata_ffi::jsonbuilder::Error> {
    jb.open_object("rust_wrapped")?;
    jb.set_string("example", "eve-callback")?;
    jb.set_string("has_flow", if f.is_some() { "true" } else { "false" })?;

    // If we have a flow, show the `Flow` wrapper accessors and log something
    // from flow storage.
    if let Some(f) = f {
        let src_ip = f
            .source_address()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        let dst_ip = f
            .destination_address()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        let toserver = f.to_server_packet_count();
        let toclient = f.to_client_packet_count();

        jb.open_object("flow_accessors")?;
        jb.set_string("src_ip", &src_ip)?;
        jb.set_uint("src_port", f.source_port() as u64)?;
        jb.set_string("dest_ip", &dst_ip)?;
        jb.set_uint("dest_port", f.destination_port() as u64)?;
        jb.set_uint("ip_proto", f.ip_protocol() as u64)?;
        jb.set_uint("app_proto", f.app_protocol() as u64)?;
        jb.set_uint("toserver_pkts", toserver as u64)?;
        jb.set_uint("toclient_pkts", toclient as u64)?;
        jb.set_uint("last_seen", f.last_time().as_secs())?;
        jb.close()?;

        if let Some(state) = flow_storage.get(f) {
            jb.set_uint("flow_packets", state.packets)?;
        }
    }
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
    thread_storage: ThreadStorage<ThreadState>,
    flow_storage: FlowStorage<FlowState>,
    tv: &mut ThreadVars,
    f: &mut Flow,
    _p: *const Packet,
) {
    // Count flows seen by this thread using the per-thread storage.
    let flows = match thread_storage.get_mut(tv) {
        Some(state) => {
            state.flows += 1;
            state.flows
        }
        None => {
            SCLogWarning!("rust example thread storage was not initialized");
            0
        }
    };
    // Initialize the per-flow storage for this flow.
    if let Err(err) = flow_storage.get_or_insert_with(f, FlowState::default) {
        SCLogError!("failed to initialize rust example flow storage: {}", err);
    }
    SCLogNotice!(
        "rust example flow init callback: flow={:p}, thread_flows={}",
        f.as_ptr(),
        flows
    );
}

fn log_flow_update(
    flow_storage: FlowStorage<FlowState>,
    _tv: &mut ThreadVars,
    f: &mut Flow,
    _p: *mut Packet,
) {
    // Count packets seen on this flow using the per-flow storage.
    let packets = match flow_storage.get_mut(f) {
        Some(state) => {
            state.packets += 1;
            state.packets
        }
        None => {
            SCLogWarning!("rust example flow storage was not initialized");
            0
        }
    };
    SCLogNotice!(
        "rust example flow update callback: flow={:p}, flow_packets={}",
        f.as_ptr(),
        packets
    );
}

fn log_flow_finish(flow_storage: FlowStorage<FlowState>, _tv: &mut ThreadVars, f: &mut Flow) {
    let packets = flow_storage.get(f).map(|state| state.packets).unwrap_or(0);
    SCLogNotice!(
        "rust example flow finish callback: flow={:p}, flow_packets={}",
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
