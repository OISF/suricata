extern crate libc;
use libc::{c_void,c_char};
use std::ffi::CString;

#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;

extern crate nom;

#[macro_use]
extern crate log;

use log::LogLevelFilter;

extern crate num_traits;

extern crate ntp_parser;
extern crate tls_parser;

const SURICATA_RUST_MAGIC : u32 = 0x72757374;

pub use common::*;
#[macro_use]
pub mod common;

pub use logger::*;
pub mod logger;

#[macro_use]
extern crate suricata_interface;
use suricata_interface::rparser::RParser;

pub use ntp::*;
pub mod ntp;

pub use tls::*;
pub mod tls;

use tls_parser::tls_ciphers::CIPHERS;

type ProbeFn      = extern "C" fn (*const i8, u32, *const i8) -> u16;
type ParseFn      = extern "C" fn (u8, *const i8, u32, *mut c_void) -> u32;
type NewStateFn   = extern "C" fn () -> *mut c_void;
type FreeStateFn  = extern "C" fn (*mut c_void) -> ();

struct RustParser {
    /// Protocol name.
    name:         CString,
    /// Default port
    default_port: CString,

    /// The structure exposed to the C code
    c_parser:     Option<RustCParser>,
}

#[repr(C)]
struct RustCParser {
    /// Protocol name. Must be \0-terminated
    name:         *const c_char,
    ip_proto:     u16,
    default_port: *const c_char,
    min_frame_length: i32,
    /// Application layer protocol ID
    al_proto:     u16,
    /// Events table
    events:       *const c_void,
    probe:        ProbeFn,
    parse:        ParseFn,
    new_state:    NewStateFn,
    free_state:   FreeStateFn,
}

/// Declare RustCParser as shareable between threads.
/// This is only true because we only use read-only instances, but is necessary to initialize
/// the global registry and send structures to the C code.
unsafe impl Sync for RustCParser { }

extern {
    fn crust_register_alproto(alproto: *const c_char) -> u16;
}

impl RustParser {
    pub fn new(name: &str, proto: u16, default_port: &str, min_frame_length: i32,
               global_al_proto: &mut u16,
               events: *const c_void,
               probe: ProbeFn, parse: ParseFn, new: NewStateFn, free: FreeStateFn)
            -> RustParser {
        let r = RustParser{
            name:         CString::new(name).unwrap(),
            default_port: CString::new(default_port).unwrap(),
            c_parser:     None,
        };
        let al_proto = unsafe{ crust_register_alproto(r.name.as_ptr()) };
        if (al_proto == 0) || (al_proto == 0xffff) {
            panic!("Application layer protocol registration failed for protocol {}", name);
        };
        // println!("Registered alproto {} returned {}", name, al_proto);
        *global_al_proto = al_proto;
        RustParser{
            c_parser: Some(
                          RustCParser{
                              name:         r.name.as_ptr(),
                              ip_proto:     proto,
                              default_port: r.default_port.as_ptr(),
                              min_frame_length: min_frame_length,
                              al_proto:     al_proto,
                              events:       events,
                              probe:        probe,
                              parse:        parse,
                              new_state:    new,
                              free_state:   free,
                          }
                          ),
            .. r
        }
    }
}

lazy_static! {
    /// Global parsers registry.
    /// The registry is built at compile time and is immutable.
    static ref HASHMAP: HashMap<String, RustParser> = {
        let mut m = HashMap::new();
        m.insert("ntp".to_string(),RustParser::new("rust-ntp", 17, "123", 0,
                                                   unsafe{ &mut ntp::ALPROTO_NTP },
                                                   std::ptr::null(),
                                                   r_ntp_probe, r_generic_parse,
                                                   r_ntp_state_new, r_ntp_state_free));
        m.insert("tls".to_string(),RustParser::new("rust-tls", 6, "443", 0,
                                                   unsafe{ &mut tls::ALPROTO_TLS },
                                                   TLS_EVENTS.as_ptr() as *const c_void,
                                                   r_tls_probe, r_generic_parse,
                                                   r_tls_state_new, r_tls_state_free));
        m
    };
}


/// Returns the nth parser, or NULL
#[no_mangle]
pub extern "C" fn rusticata_get_parser(index: u32) -> *const c_void {
    match HASHMAP.values().nth(index as usize) {
        Some(parser) => {
            match parser.c_parser {
                Some(ref cp) => cp as *const _ as *const c_void,
                None         => std::ptr::null(),
            }
        },
        None         => std::ptr::null(),
    }
}



/// Rusticata crate init function
///
/// This function **must** be called by the client application (Suricata) to initialize the
/// rusticata library functions.
///
/// The argument is a pointer to a configuration structure, containing a magic number,
/// a pointer to the C log function, and the log level of the client application.
/// Rusticata will use the same log level, and configure a Rust Logger object to send logs
/// to Suricata.
///
/// The lifetime of the configuration **must** be greater or equal to the one of the
/// rusticata crate.
#[no_mangle]
pub extern "C" fn rusticata_init(config: &'static mut SuricataConfig) -> i32 {
    assert!(std::ptr::null_mut() != config);
    unsafe { SURICATA_CONFIG = Some(config) };

    assert_eq!(config.magic,SURICATA_RUST_MAGIC);

    let log_level = match config.log_level {
        0...4  => LogLevelFilter::Error,
        5      => LogLevelFilter::Warn,
        6...7  => LogLevelFilter::Info,
        8...11 => LogLevelFilter::Debug,
        12...15 => LogLevelFilter::Trace,
        _      => LogLevelFilter::Off,
    };

    logger::init(log_level).unwrap();

    info!("Rusticata TLS parser ready, {} ciphers loaded",CIPHERS.len());

    info!("Rusticata parsers loaded");

    0
}



#[no_mangle]
pub extern "C" fn r_generic_parse(direction: u8, input: *const c_char, input_len: u32, raw_ptr: *mut c_void) -> u32 {
    let ptr = raw_ptr as *mut Box<RParser>;
    let data_len = input_len as usize;
    let data : &[u8] = unsafe { std::slice::from_raw_parts(input as *mut u8, data_len) };
    if ptr.is_null() { return 0xffff; };
    let ptr_typed = ptr as *mut Box<RParser>;
    let parser = unsafe { &mut *ptr_typed };
    parser.parse(data, direction)
}

#[no_mangle]
pub extern "C" fn r_get_next_event(raw_ptr: *mut c_void) -> u32 {
    let ptr = raw_ptr as *mut Box<RParser>;
    if ptr.is_null() { return 0xffff; };
    let ptr_typed = ptr as *mut Box<RParser>;
    let parser = unsafe { &mut *ptr_typed };
    parser.get_next_event()
}

