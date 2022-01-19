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

#![cfg_attr(feature = "strict", deny(warnings))]

// Clippy lints we want to suppress due to style, or simply too noisy
// and not a priority right now.
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::needless_return)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::len_zero)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::let_and_return)]
#![allow(clippy::needless_bool)]
#![allow(clippy::char_lit_as_u8)]

// To be fixed, but remove the noise for now.
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::redundant_static_lifetimes)]
#![allow(clippy::bool_comparison)]
#![allow(clippy::for_loops_over_fallibles)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::single_match)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::new_without_default)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::match_ref_pats)]
#![allow(clippy::module_inception)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::enum_variant_names)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::extra_unused_lifetimes)]
#![allow(clippy::mixed_case_hex_literals)]
#![allow(clippy::type_complexity)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::never_loop)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::for_loops_over_fallibles)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::branches_sharing_code)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::field_reassign_with_default)]

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
/// cbindgen:ignore
pub mod frames;
pub mod filecontainer;
pub mod filetracker;
pub mod kerberos;
pub mod detect;

#[cfg(feature = "lua")]
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
pub mod applayertemplate;
pub mod rdp;
pub mod x509;
pub mod asn1;
pub mod mime;
pub mod ssh;
pub mod http2;
pub mod quic;
pub mod plugin;
pub mod util;
pub mod ffi;
