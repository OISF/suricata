extern crate libc;

#[macro_use]
extern crate nom;

#[macro_use]
extern crate log;

use log::LogLevelFilter;

extern crate num_traits;

extern crate ntp_parser;
extern crate tls_parser;

const SURICATA_RUST_MAGIC : u32 = 0x1234;

pub use common::*;
#[macro_use]
pub mod common;

pub use logger::*;
pub mod logger;

#[macro_use]
extern crate suricata_interface;

pub use ntp::*;
pub mod ntp;

pub use tls::*;
pub mod tls;

use tls_parser::tls_ciphers::CIPHERS;

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
    unsafe { suricata_config = Some(config) };

    assert_eq!(config.magic,SURICATA_RUST_MAGIC);

    let log_level = match config.log_level {
        0...4  => LogLevelFilter::Error,
        5      => LogLevelFilter::Warn,
        6...7  => LogLevelFilter::Info,
        8...11 => LogLevelFilter::Debug,
        _      => LogLevelFilter::Off,
    };

    logger::init(log_level).unwrap();

    info!("Rusticata TLS parser ready, {} ciphers loaded",CIPHERS.len());

    info!("Rusticata parsers loaded");

    0
}
