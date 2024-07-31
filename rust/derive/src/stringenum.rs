/* Copyright (C) 2023 Open Information Security Foundation
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
use super::applayerevent::transform_name;
use proc_macro::TokenStream;
use quote::quote;
use syn::{self, parse_macro_input, DeriveInput};
use std::str::FromStr;

pub fn derive_enum_string<T: std::str::FromStr + quote::ToTokens>(input: TokenStream, ustr: &str) -> TokenStream where <T as FromStr>::Err: std::fmt::Display {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let mut values = Vec::new();
    let mut names = Vec::new();
    let mut names_upper = Vec::new();
    let mut fields = Vec::new();

    if let syn::Data::Enum(ref data) = input.data {
        for v in (&data.variants).into_iter() {
            if let Some((_, val)) = &v.discriminant {
                let fname = transform_name(&v.ident.to_string());
                let fnameu = fname.to_ascii_uppercase();
                names.push(fname);
                names_upper.push(fnameu);
                fields.push(v.ident.clone());
                if let syn::Expr::Lit(l) = val {
                    if let syn::Lit::Int(li) = &l.lit {
                        if let Ok(value) = li.base10_parse::<T>() {
                            values.push(value);
                        } else {
                            panic!("EnumString requires explicit {}", ustr);
                        }
                    } else {
                        panic!("EnumString requires explicit literal integer");
                    }
                } else {
                    panic!("EnumString requires explicit literal");
                }
            } else {
                panic!("EnumString requires explicit values");
            }
        }
    } else {
        panic!("EnumString can only be derived for enums");
    }

    let is_suricata = std::env::var("CARGO_PKG_NAME").map(|var| var == "suricata").unwrap_or(false);
    let crate_id = if is_suricata {
        syn::Ident::new("crate", proc_macro2::Span::call_site())
    } else {
        syn::Ident::new("suricata", proc_macro2::Span::call_site())
    };

    let utype_str = syn::Ident::new(ustr, proc_macro2::Span::call_site());

    let expanded = quote! {
        impl #crate_id::detect::EnumString<#utype_str> for #name {
            fn from_u(v: #utype_str) -> Option<Self> {
                match v {
                    #( #values => Some(#name::#fields) ,)*
                    _ => None,
                }
            }
            fn into_u(self) -> #utype_str {
                match self {
                    #( #name::#fields => #values ,)*
                }
            }
            fn to_str(&self) -> &'static str {
                match *self {
                    #( #name::#fields => #names ,)*
                }
            }
            fn from_str(s: &str) -> Option<Self> {
                match s.to_ascii_uppercase().as_str() {
                    #( #names_upper => Some(#name::#fields) ,)*
                    _ => None
                }
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}
