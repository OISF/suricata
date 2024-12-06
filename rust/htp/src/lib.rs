//! Root crate for libhtp.

#![deny(missing_docs)]
#![deny(unused_lifetimes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#[repr(C)]
#[derive(PartialEq, Eq, Debug)]

/// Status codes used by LibHTP internally.
pub enum HtpStatus {
    /// The lowest value LibHTP will use internally.
    ERROR_RESERVED = -1000,
    /// General-purpose error code.
    ERROR = -1,
    /// No processing or work was done. This is typically used by callbacks
    /// to indicate that they were not interested in doing any work in the
    /// given context.
    DECLINED = 0,
    /// Returned by a function when its work was successfully completed.
    OK = 1,
    ///  Returned when processing a connection stream, after consuming all
    ///  provided data. The caller should call again with more data.
    DATA = 2,
    /// Returned when processing a connection stream, after encountering
    /// a situation where processing needs to continue on the alternate
    /// stream (e.g., the inbound parser needs to observe some outbound
    /// data). The data provided was not completely consumed. On the next
    /// invocation the caller should supply only the data that has not
    /// been processed already. Use request_data_consumed() and response_data_consumed()
    /// to determine how much of the most recent data chunk was consumed.
    DATA_OTHER = 3,
    /// Used by callbacks to indicate that the processing should stop. For example,
    /// returning HtpStatus::STOP from a connection callback indicates that LibHTP should
    /// stop following that particular connection.
    STOP = 4,
    /// Same as DATA, but indicates that any non-consumed part of the data chunk
    /// should be preserved (buffered) for later.
    DATA_BUFFER = 5,
    /// The highest value LibHTP will use internally.
    STATUS_RESERVED = 1000,
}

/// Module for providing logging functions.
#[macro_use]
pub mod log;
/// Module for bstr functions.
pub mod bstr;
/// Module for all functions facing c_api.
pub mod c_api;
/// Module for all decompressors functions.
pub mod decompressors;
/// Module for all errors.
pub mod error;
/// Module for header parsing.
mod headers;
/// Module for hooks.
pub mod hook;
/// Module for providing unicode bestfit mappings.
#[macro_use]
mod unicode_bestfit_map;
/// Module for libhtp configurations.
pub mod config;
/// Module for all connection.
pub mod connection;
/// Module for connection parser.
pub mod connection_parser;
/// Module for extra utility parsers. (only public for doc tests)
pub mod parsers;
/// Module for request parsing.
pub mod request;
/// Module for response parsing.
pub mod response;
/// Module for custom table.
pub mod table;
/// Module for transaction parsing.
pub mod transaction;
/// Module to track multiple transactions
pub mod transactions;
/// Module for uri parsing.
pub mod uri;
/// Module for url decoding.
pub mod urlencoded;
/// Module for utf8 decoding.
mod utf8_decoder;
/// Module for utility functions.
pub mod util;

/// Test harness
// TODO: add #[cfg(test)] here when this is fixed: https://github.com/rust-lang/cargo/issues/8379
pub mod test;
