/* Copyright (C) 2020-2023 Open Information Security Foundation
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

#![deny(warnings)]
#![allow(clippy::uninlined_format_args)]

extern crate proc_macro;

use proc_macro::TokenStream;

mod applayerevent;
mod applayerframetype;
mod applayerstate;
mod stringenum;

/// The `AppLayerEvent` derive macro generates a `AppLayerEvent` trait
/// implementation for enums that define AppLayerEvents.
///
/// Example usage (DNS app-layer events):
///
/// #[derive(AppLayerEvent)]
/// enum {
///     MalformedData,
///     NotRequest,
///     NotResponse,
///     #[name("reserved_z_flag_set")]
///     ZFlagSet,
/// }
///
/// The enum variants must follow the naming convention of OneTwoThree
/// for proper conversion to the name used in rules (one_tow_three) or
/// optionally add a name attribute.
#[proc_macro_derive(AppLayerEvent, attributes(name))]
pub fn derive_app_layer_event(input: TokenStream) -> TokenStream {
    applayerevent::derive_app_layer_event(input)
}

#[proc_macro_derive(AppLayerFrameType)]
pub fn derive_app_layer_frame_type(input: TokenStream) -> TokenStream {
    applayerframetype::derive_app_layer_frame_type(input)
}

#[proc_macro_derive(AppLayerState, attributes(suricata))]
pub fn derive_app_layer_state(input: TokenStream) -> TokenStream {
    applayerstate::derive_app_layer_state(input)
}

#[proc_macro_derive(EnumStringU8, attributes(name, suricata))]
pub fn derive_enum_string_u8(input: TokenStream) -> TokenStream {
    stringenum::derive_enum_string::<u8>(input, "u8")
}

#[proc_macro_derive(EnumStringU16, attributes(name))]
pub fn derive_enum_string_u16(input: TokenStream) -> TokenStream {
    stringenum::derive_enum_string::<u16>(input, "u16")
}

#[proc_macro_derive(EnumStringU32, attributes(name, suricata))]
pub fn derive_enum_string_u32(input: TokenStream) -> TokenStream {
    stringenum::derive_enum_string::<u32>(input, "u32")
}
