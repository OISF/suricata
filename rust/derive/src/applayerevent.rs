/* Copyright (C) 2021-2023 Open Information Security Foundation
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

extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{self, parse_macro_input, DeriveInput};

pub fn derive_app_layer_event(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let mut fields = Vec::new();
    let mut event_ids = Vec::new();
    let mut event_cstrings = Vec::new();
    let mut event_names = Vec::new();

    match input.data {
        syn::Data::Enum(ref data) => {
            for (i, v) in (&data.variants).into_iter().enumerate() {
                fields.push(v.ident.clone());
                let event_name = if let Some(xname) = parse_name(&v.attrs) {
                    xname.value()
                } else {
                    transform_name(&v.ident.to_string())
                };
                let cname = format!("{}\0", event_name);
                event_names.push(event_name);
                event_cstrings.push(cname);
                event_ids.push(i as u8);
            }
        }
        _ => panic!("AppLayerEvent can only be derived for enums"),
    }

    // If we're being used from within Suricata we have to reference the internal name space with
    // "crate", but if we're being used by a library or plugin user we need to reference the
    // Suricata name space as "suricata". Check the CARGO_PKG_NAME environment variable to
    // determine what identifier to setup.
    let is_suricata = std::env::var("CARGO_PKG_NAME").map(|var| var == "suricata").unwrap_or(false);
    let crate_id = if is_suricata {
        syn::Ident::new("crate", proc_macro2::Span::call_site())
    } else {
        syn::Ident::new("suricata", proc_macro2::Span::call_site())
    };

    let expanded = quote! {
        impl #crate_id::applayer::AppLayerEvent for #name {
            fn from_id(id: u8) -> Option<#name> {
                match id {
                    #( #event_ids => Some(#name::#fields) ,)*
                    _ => None,
                }
            }

            fn as_u8(&self) -> u8 {
                match *self {
                    #( #name::#fields => #event_ids ,)*
                }
            }

            fn to_cstring(&self) -> &str {
                match *self {
                    #( #name::#fields => #event_cstrings ,)*
                }
            }

            fn from_string(s: &str) -> Option<#name> {
                match s {
                    #( #event_names => Some(#name::#fields) ,)*
                    _ => None
                }
            }

            unsafe extern "C" fn get_event_info(
                event_name: *const std::os::raw::c_char,
                event_id: *mut u8,
                event_type: *mut #crate_id::sys::AppLayerEventType,
            ) -> std::os::raw::c_int {
                #crate_id::applayer::get_event_info::<#name>(event_name, event_id, event_type)
            }

            unsafe extern "C" fn get_event_info_by_id(
                event_id: u8,
                event_name: *mut *const std::os::raw::c_char,
                event_type: *mut #crate_id::sys::AppLayerEventType,
            ) -> std::os::raw::c_int {
                #crate_id::applayer::get_event_info_by_id::<#name>(event_id, event_name, event_type)
            }

        }
    };

    proc_macro::TokenStream::from(expanded)
}

/// Transform names such as "OneTwoThree" to "one_two_three".
pub fn transform_name(in_name: &str) -> String {
    if in_name.to_uppercase() == in_name {
        return in_name.to_lowercase();
    }
    let mut out = String::new();
    for (i, c) in in_name.chars().enumerate() {
        if i == 0 {
            out.push_str(&c.to_lowercase().to_string());
        } else if c.is_uppercase() {
            out.push('_');
            out.push_str(&c.to_lowercase().to_string());
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse the event name from the "name" attribute.
///
/// For example:
/// ```ignore
/// #[derive(AppLayerEvent)]
/// pub enum FtpEvent {
///    #[name("request_command_too_long")]
///    FtpEventRequestCommandTooLong,
///    #[name("response_command_too_long")]
///    FtpEventResponseCommandTooLong,
/// }
/// ```
fn parse_name(attrs: &[syn::Attribute]) -> Option<syn::LitStr> {
    for attr in attrs {
        if attr.path.is_ident("name") {
            if let Ok(val) = attr.parse_args::<syn::LitStr>() {
                return Some(val);
            }
        }
    }
    None
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_transform_name() {
        assert_eq!(transform_name("One"), "one".to_string());
        assert_eq!(transform_name("SomeEvent"), "some_event".to_string());
        assert_eq!(
            transform_name("UnassignedMsgType"),
            "unassigned_msg_type".to_string()
        );
        assert_eq!(transform_name("SAMECASE"), "samecase".to_string());
        assert_eq!(transform_name("ZFlagSet"), "z_flag_set".to_string());
    }
}
