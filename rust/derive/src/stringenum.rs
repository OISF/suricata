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
    let mut fields = Vec::new();

    if let syn::Data::Enum(ref data) = input.data {
        let mut default_seen = false;
        for (_, v) in (&data.variants).into_iter().enumerate() {
            if let Some((_, val)) = &v.discriminant {
                let fname = transform_name(&v.ident.to_string());
                names.push(fname);
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
                if let syn::Fields::Unnamed(f) = &v.fields {
                    if default_seen || f.unnamed.len() != 1 {
                        panic!("EnumString requires explicit values or one Unknown({})", ustr);
                    }
                    if v.ident.to_string() != "Unknown" {
                        panic!("EnumString default case must be Unknown({})", ustr);
                    }
                    if let syn::Type::Path(p) = &f.unnamed[0].ty {
                        if p.path.segments.len() != 1 {
                            panic!("EnumString requires explicit values or one Unknown({})", ustr);
                        }
                        if p.path.segments[0].ident.to_string() != ustr {
                            panic!("EnumString default case must be Unknown({})", ustr);
                        }
                    } else {
                        panic!("EnumString requires explicit values or one Unknown({})", ustr);
                    }
                    default_seen = true;
                } else {
                    panic!("EnumString requires explicit values or one Unknown({})", ustr);
                }
            }
        }
    } else {
        panic!("EnumString can only be derived for enums");
    }

    let utype_str = syn::Ident::new(&ustr, proc_macro2::Span::call_site());

    let expanded = quote! {
        impl #name {
            pub(crate) fn from_u(v: #utype_str) -> Self {
                match v {
                    #( #values => #name::#fields ,)*
                    _ => #name::Unknown(v),
                }
            }
            pub(crate) fn into_u(&self) -> #utype_str {
                match *self {
                    #( #name::#fields => #values ,)*
                    #name::Unknown(v) => v,
                }
            }
            pub(crate) fn to_string(&self) -> String {
                match *self {
                    #( #name::#fields => #names.to_string() ,)*
                    #name::Unknown(v) => format!("unknown-{}", v),
                }
            }
            pub(crate) fn from_str(s: &str) -> Option<#name> {
                match s {
                    #( #names => Some(#name::#fields) ,)*
                    _ => None
                }
            }
            pub(crate) fn to_detect_ctx(s: &str) -> Option<DetectUintData<#utype_str>> {
                if let Ok((_, ctx)) = detect_parse_uint::<#utype_str>(s) {
                    return Some(ctx);
                }
                if let Some(arg1) = #name::from_str(s) {
                    let arg1 = #name::into_u(&arg1);
                    let ctx = DetectUintData::<#utype_str> {
                        arg1,
                        arg2: 0,
                        mode: DetectUintMode::DetectUintModeEqual,
                    };
                    return Some(ctx);
                }
                return None;
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}
