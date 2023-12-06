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

pub fn derive_enum_string_u8(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = transform_name(&input.ident.to_string());
    let mut values = Vec::new();
    let mut names = Vec::new();

    if let syn::Data::Enum(ref data) = input.data {
        for (_, v) in (&data.variants).into_iter().enumerate() {
            let fname = transform_name(&v.ident.to_string());
            names.push(fname);
            if let Some((_, val)) = &v.discriminant {
                if let syn::Expr::Lit(l) = val {
                    if let syn::Lit::Int(li) = &l.lit {
                        if let Ok(value) = li.base10_parse::<u8>() {
                            values.push(value);
                        } else {
                            panic!("EnumString requires explicit u8");
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

    let stringer = syn::Ident::new(&(name.clone() + "_string"), proc_macro2::Span::call_site());
    let parser = syn::Ident::new(&(name + "_parse"), proc_macro2::Span::call_site());

    let expanded = quote! {
            fn #stringer(v: u8) -> Option<&'static str> {
                match v {
                    #( #values => Some(#names) ,)*
                    _ => None,
                }
            }

            pub(crate) fn #parser(v: &str) -> Option<u8> {
                match v {
                    #( #names => Some(#values) ,)*
                    _ => None,
                }
            }
    };

    proc_macro::TokenStream::from(expanded)
}
