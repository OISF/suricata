extern crate proc_macro;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{self, parse_macro_input, DeriveInput};

use crate::utils;

pub fn derive_app_layer_state(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let state_type = input.ident;
    let state_name = utils::transform_name(&state_type.to_string(), '_');

    let mut transaction_type: Option<syn::Ident> = None;
    match input.data {
        syn::Data::Struct(data) => {
            if let syn::Fields::Named(fields) = &data.fields {
                for field in &fields.named {
                    if &field.ident.as_ref().unwrap().to_string() == "transactions" {
                        let (_, inner) = split_generic(&field.ty)
                            .unwrap_or_else(|| panic!("transactions must be a collection"));
                        transaction_type = Some(inner);
                    }
                }
            }
        }
        _ => panic!("AppLayerState can only be derived for structs"),
    }

    if transaction_type.is_none() {
        panic!("AppLayerState unable to detect Transaction type");
    }

    if let Some(transaction_type) = transaction_type {
        let crate_id = utils::crate_id();
        let c_new = format_ident!("rs_{}_new", state_name);
        let c_free = format_ident!("rs_{}_free", state_name);
        let c_tx_free = format_ident!("rs_{}_tx_free", state_name);
        let c_get_tx = format_ident!("rs_{}_get_tx", state_name);
        let c_get_tx_count = format_ident!("rs_{}_get_tx_count", state_name);
        let c_get_data = format_ident!("rs_{}_get_data", state_name);

        let stream = quote! {
            impl State<#transaction_type> for #state_type {
                fn get_transaction_count(&self) -> usize {
                    self.transactions.len()
                }

                fn get_transaction_by_index(&self, index: usize) -> Option<&#transaction_type> {
                    self.transactions.get(index)
                }
            }

            impl #state_type {
                /// Construct a new `#transaction_type`
                pub fn new_tx(&mut self) -> #transaction_type {
                    self.tx_id += 1;
                    #transaction_type::new(self.tx_id)
                }

                /// Free transaction by id
                pub fn free_tx(&mut self, tx_id: u64) {
                    if let Some(index) = self.transactions.iter().position(|tx| tx.id() == tx_id + 1) {
                        self.transactions.remove(index);
                    }
                }

                /// Get transaction with id, if it exists
                pub fn get_tx(&self, tx_id: u64) -> Option<&#transaction_type> {
                    self.transactions.iter().find(|tx| tx.id() == tx_id + 1)
                }

                /// Get mutable transaction with id, if it exists
                pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut #transaction_type> {
                    self.transactions.iter_mut().find(|tx| tx.id() == tx_id + 1)
                }

                /// Get current transaction, if it exists
                fn get_current_tx(&self) -> Option<&#transaction_type> {
                    self.transactions.iter().find(|tx| tx.id() == self.tx_id)
                }

                /// Get mutable current transaction, if it exists
                fn get_current_tx_mut(&mut self) -> Option<&mut #transaction_type> {
                    let tx_id = self.tx_id;
                    self.transactions.iter_mut().find(|tx| tx.id() == tx_id)
                }
            }

            // C exports
            #[no_mangle]
            pub extern "C" fn #c_new(
                _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
            ) -> *mut std::os::raw::c_void {
                let state = #state_type::new();
                let boxed = Box::new(state);
                return Box::into_raw(boxed) as *mut std::os::raw::c_void;
            }

            #[no_mangle]
            pub unsafe extern "C" fn #c_free(state: *mut std::os::raw::c_void) {
                std::mem::drop(Box::from_raw(state as *mut #state_type));
            }

            #[no_mangle]
            pub unsafe extern "C" fn #c_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
                let state = cast_pointer!(state, #state_type);
                state.free_tx(tx_id);
            }

            #[no_mangle]
            pub unsafe extern "C" fn #c_get_tx(
                state: *mut std::os::raw::c_void, tx_id: u64,
            ) -> *mut std::os::raw::c_void {
                let state = cast_pointer!(state, #state_type);
                match state.get_tx_mut(tx_id) {
                    Some(tx) => {
                        return tx as *const _ as *mut _;
                    }
                    None => {
                        return std::ptr::null_mut();
                    }
                }
            }

            #[no_mangle]
            pub unsafe extern "C" fn #c_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
                let state = cast_pointer!(state, #state_type);
                return state.tx_id;
            }

            #[no_mangle]
            pub unsafe extern "C" fn #c_get_data(state: *mut std::os::raw::c_void)
                -> *mut #crate_id::applayer::AppLayerStateData
            {
                let state = &mut *(state as *mut #state_type);
                &mut state.state_data
            }
        };

        proc_macro::TokenStream::from(stream)
    } else {
        panic!("AppLayerState unable to detect Transaction type");
    }
}

/// Get outer and inner types of a generic data type
/// Returns `None` if there isn't exactly 1 generic
///
/// # Example
/// ```ignore
/// Vec<u8> -> Some(Vec, u8)
/// Option<String> -> Some(Option, String)
/// ```
fn split_generic(ty: &syn::Type) -> Option<(syn::Ident, syn::Ident)> {
    if let syn::Type::Path(ty) = ty {
        if let Some((ident, arg)) = split_generic_helper(ty) {
            if let Some(inner_ident) = arg.path.get_ident() {
                return Some((ident, (*inner_ident).clone()));
            }
        }
    }
    None
}

fn split_generic_helper(ty: &syn::TypePath) -> Option<(syn::Ident, syn::TypePath)> {
    let segment = &ty.path.segments.first().expect("Path with no segments");
    if let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments {
        if arguments.args.len() == 1 {
            if let syn::GenericArgument::Type(syn::Type::Path(arg)) = &arguments.args[0] {
                return Some((segment.ident.clone(), arg.clone()));
            }
        }
    }
    None
}
