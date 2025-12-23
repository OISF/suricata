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
// Allow unknown lints, our MSRV doesn't know them all, for
// example static_mut_refs.
#![allow(unknown_lints)]

#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate crc;
extern crate lru;
extern crate memchr;
#[macro_use]
extern crate num_derive;
extern crate widestring;

extern crate der_parser;
extern crate kerberos_parser;
extern crate ldap_parser;
extern crate tls_parser;
extern crate x509_parser;

#[macro_use]
extern crate suricata_derive;

#[macro_use]
pub mod core;

#[macro_use]
pub mod debug;

pub mod common;
pub mod conf;
pub mod jsonbuilder;
#[macro_use]
pub mod applayer;
pub mod detect;
pub mod filecontainer;
pub mod filetracker;
pub mod frames;
pub mod kerberos;
pub mod utils;

pub mod handshake;
pub mod ja4;
pub mod tls_version;

pub mod lua;

pub mod dcerpc;
pub mod dnp3;
pub mod dns;
pub mod ftp;
pub mod krb;
pub mod mdns;
pub mod modbus;
pub mod nfs;
pub mod smb;

pub mod ike;
pub mod snmp;

pub mod applayertemplate;
pub mod asn1;
pub mod bittorrent_dht;
pub mod dhcp;
pub mod direction;
pub mod enip;
pub mod feature;
pub mod ffi;
pub mod flow;
pub mod http2;
pub mod ldap;
pub mod lzma;
pub mod mime;
pub mod mqtt;
pub mod ntp;
pub mod pgsql;
pub mod plugin;
pub mod pop3;
pub mod quic;
pub mod rdp;
pub mod rfb;
pub mod sdp;
pub mod sip;
pub mod ssh;
pub mod telnet;
pub mod tftp;
pub mod util;
pub mod websocket;
pub mod x509;

#[allow(unused_imports)]
pub use suricata_lua_sys;
//Re-export htp symbols
pub use htp::c_api::*;
