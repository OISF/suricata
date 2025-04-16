/* Copyright (C) 2025 Open Information Security Foundation
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

pub fn derive_app_layer_state(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let mut fields = Vec::new();
    let mut vals = Vec::new();
    let mut cstrings = Vec::new();
    let mut names = Vec::new();
    let mut strip_prefix = String::from("");

    match input.data {
        syn::Data::Enum(ref data) => {
            for attr in input.attrs.iter() {
                if attr.path.is_ident("sc_alstate_strip_prefix") {
                    let meta = attr.parse_meta().unwrap();
                    if let syn::Meta::NameValue(nv) = meta {
                        if let syn::Lit::Str(s) = nv.lit {
                            strip_prefix = s.value();
                            break;
                        }
                    }
                    panic!("sc_alstate_strip_prefix is not a meta namevalue with string lit")
                }
            }
            for (i, v) in (&data.variants).into_iter().enumerate() {
                fields.push(v.ident.clone());
                let name = transform_name(&v.ident.to_string(), &strip_prefix);
                let cname = format!("{}\0", name);
                names.push(name);
                cstrings.push(cname);
                vals.push(i as u8);
            }
        }
        _ => panic!("AppLayerState can only be derived for enums"),
    }

    let expanded = quote! {
        impl crate::applayer::AppLayerState for #name {
            fn from_u8(val: u8) -> Option<Self> {
                match val {
                    #( #vals => Some(#name::#fields) ,)*
                    _ => None,
                }
            }

            fn as_u8(&self) -> u8 {
                match *self {
                    #( #name::#fields => #vals ,)*
                }
            }

            fn to_cstring(&self) -> *const std::os::raw::c_char {
                let s = match *self {
                    #( #name::#fields => #cstrings ,)*
                };
                s.as_ptr() as *const std::os::raw::c_char
            }

            fn from_str(s: &str) -> Option<#name> {
                match s {
                    #( #names => Some(#name::#fields) ,)*
                    _ => None
                }
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

fn transform_name(name: &str, strip_prefix: &str) -> String {
    if !name.starts_with(strip_prefix) {
        panic!("strip prefix is not good")
    }
    let mut xname = String::new();
    let chars: Vec<char> = name[strip_prefix.len()..].chars().collect();
    for i in 0..chars.len() {
        if i > 0 && i < chars.len() - 1 && chars[i].is_uppercase() && chars[i + 1].is_lowercase() {
            xname.push('_');
        }
        xname.push_str(&chars[i].to_lowercase().to_string());
    }
    xname
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_transform_name() {
        assert_eq!(transform_name("One", ""), "one");
        assert_eq!(transform_name("OneTwo", ""), "one_two");
        assert_eq!(transform_name("OneTwoThree", ""), "one_two_three");
        assert_eq!(transform_name("SshStateInProgress", "SshState"), "in_progress");
    }

    #[test]
    #[should_panic(expected = "strip prefix is not good")]
    fn test_transform_name_panic() {
        assert_eq!(transform_name("SshStateInProgress", "toto"), "in_progress");
    }
}
