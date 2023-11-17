/* Copyright (C) 2017-2021 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//! Suricata is a network intrusion prevention and monitoring engine.
//!
//! Suricata is a hybrid C and Rust application. What is found here are
//! the components written in Rust.

#![cfg_attr(feature = "strict", deny(warnings))]

// Allow these patterns as its a style we like.
#![allow(clippy::needless_return)]
#![allow(clippy::let_and_return)]
#![allow(clippy::uninlined_format_args)]

// We find this is beyond what the linter should flag.
#![allow(clippy::items_after_test_module)]

// We find this makes sense at time.
#![allow(clippy::module_inception)]

// The match macro is not always more clear. But its use is
// recommended where it makes sense.
#![allow(clippy::match_like_matches_macro)]

// Something we should be conscious of, but due to interfacing with C
// is unavoidable at this time.
#![allow(clippy::too_many_arguments)]

// This would be nice, but having this lint enables causes
// clippy --fix to make changes that don't meet our MSRV.
#![allow(clippy::derivable_impls)]

// TODO: All unsafe functions should have a safety doc, even if its
// just due to FFI.
#![allow(clippy::missing_safety_doc)]

#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate crc;
extern crate memchr;
#[macro_use]
extern crate num_derive;
extern crate widestring;

extern crate der_parser;
extern crate kerberos_parser;
extern crate tls_parser;
extern crate x509_parser;

#[macro_use]
extern crate suricata_derive;

#[macro_use]
pub mod log;

#[macro_use]
pub mod core;

#[macro_use]
pub mod common;
pub mod conf;
pub mod jsonbuilder;
#[macro_use]
pub mod applayer;
pub mod frames;
pub mod filecontainer;
pub mod filetracker;
pub mod kerberos;
pub mod detect;

pub mod ja4;

pub mod lua;

pub mod dns;
pub mod nfs;
pub mod ftp;
pub mod smb;
pub mod krb;
pub mod dcerpc;
pub mod modbus;

pub mod ike;
pub mod snmp;

pub mod ntp;
pub mod tftp;
pub mod dhcp;
pub mod sip;
pub mod rfb;
pub mod mqtt;
pub mod pgsql;
pub mod telnet;
pub mod websocket;
pub mod enip;
pub mod applayertemplate;
pub mod rdp;
pub mod x509;
pub mod asn1;
pub mod mime;
pub mod ssh;
pub mod http2;
pub mod quic;
pub mod bittorrent_dht;
pub mod plugin;
pub mod lzma;
pub mod util;
pub mod ffi;
pub mod feature;
pub mod sdp;

#[allow(unused_imports)]
pub use suricata_lua_sys;
