/* Copyright (C) 2021 Open Information Security Foundation
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

use crate::utils;

pub fn derive_app_layer_event(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let mut fields = Vec::new();
    let mut vals = Vec::new();
    let mut cstrings = Vec::new();
    let mut names = Vec::new();

    match input.data {
        syn::Data::Enum(ref data) => {
            for (i, v) in (&data.variants).into_iter().enumerate() {
                fields.push(v.ident.clone());
                let name = utils::transform_name(&v.ident.to_string(), '_');
                let cname = format!("{}\0", name);
                names.push(name);
                cstrings.push(cname);
                vals.push(i as i32);
            }
        }
        _ => panic!("AppLayerEvent can only be derived for enums"),
    }

    let crate_id = utils::crate_id();
    let expanded = quote! {
        impl #crate_id::applayer::AppLayerEvent for #name {
            fn from_id(id: i32) -> Option<#name> {
                match id {
                    #( #vals => Some(#name::#fields) ,)*
                    _ => None,
                }
            }

            fn as_i32(&self) -> i32 {
                match *self {
                    #( #name::#fields => #vals ,)*
                }
            }

            fn to_cstring(&self) -> &str {
                match *self {
                    #( #name::#fields => #cstrings ,)*
                }
            }

            fn from_string(s: &str) -> Option<#name> {
                match s {
                    #( #names => Some(#name::#fields) ,)*
                    _ => None
                }
            }

            unsafe extern "C" fn get_event_info(
                event_name: *const std::os::raw::c_char,
                event_id: *mut std::os::raw::c_int,
                event_type: *mut #crate_id::core::AppLayerEventType,
            ) -> std::os::raw::c_int {
                #crate_id::applayer::get_event_info::<#name>(event_name, event_id, event_type)
            }

            unsafe extern "C" fn get_event_info_by_id(
                event_id: std::os::raw::c_int,
                event_name: *mut *const std::os::raw::c_char,
                event_type: *mut #crate_id::core::AppLayerEventType,
            ) -> i8 {
                #crate_id::applayer::get_event_info_by_id::<#name>(event_id, event_name, event_type)
            }

        }
    };

    proc_macro::TokenStream::from(expanded)
}
