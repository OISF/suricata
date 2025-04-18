use crate::{
    connection_parser::{ConnectionParser, ParserData},
    error::Result,
    transaction::{Data, Transaction},
    HtpStatus,
};

/// External (C) callback function prototype
pub(crate) type TxExternalCallbackFn =
    unsafe extern "C" fn(connp: *const ConnectionParser, tx: *mut Transaction) -> HtpStatus;

/// Native (rust) callback function prototype
pub(crate) type TxNativeCallbackFn = fn(tx: &mut Transaction) -> Result<()>;

/// Hook for Transaction
pub(crate) type TxHook = Hook<TxExternalCallbackFn, TxNativeCallbackFn>;

/// External (C) callback function prototype
pub(crate) type TxCreateCallbackFn = unsafe extern "C" fn(req: bool) -> *mut libc::c_void;

/// External (C) callback function prototype
pub(crate) type TxDestroyCallbackFn = unsafe extern "C" fn(tx_ud: *mut libc::c_void);

/// External (C) callback function prototype
pub(crate) type DataExternalCallbackFn =
    unsafe extern "C" fn(connp: *const ConnectionParser, data: *mut Data) -> HtpStatus;

/// Native (rust) callback function prototype
pub(crate) type DataNativeCallbackFn = fn(&mut Transaction, data: &ParserData) -> Result<()>;

/// Hook for Data
pub(crate) type DataHook = Hook<DataExternalCallbackFn, DataNativeCallbackFn>;

/// Callback list
#[derive(Clone)]
pub struct Hook<E, N> {
    /// List of all callbacks.
    pub(crate) callbacks: Vec<Callback<E, N>>,
}

impl<E, N> Default for Hook<E, N> {
    /// Create a new callback list
    fn default() -> Self {
        Hook {
            callbacks: Vec::new(),
        }
    }
}
impl<E, N> Hook<E, N> {
    /// Register a native (rust) callback function
    #[cfg(test)]
    pub(crate) fn register(&mut self, cbk_fn: N) {
        self.callbacks.push(Callback::Native(cbk_fn))
    }

    /// Register an external (C) callback function
    pub(crate) fn register_extern(&mut self, cbk_fn: E) {
        self.callbacks.push(Callback::External(cbk_fn))
    }
}

impl TxHook {
    /// Run all callbacks on the list
    ///
    /// This function will exit early if a callback fails to return HtpStatus::OK
    /// or HtpStatus::DECLINED.
    pub(crate) fn run_all(&self, connp: &mut ConnectionParser, tx_index: usize) -> Result<()> {
        let connp_ptr: *mut ConnectionParser = connp as *mut ConnectionParser;
        if let Some(tx) = connp.tx_mut(tx_index) {
            for cbk_fn in &self.callbacks {
                match cbk_fn {
                    Callback::External(cbk_fn) => {
                        let result = unsafe { cbk_fn(connp_ptr, tx) };
                        if result != HtpStatus::OK && result != HtpStatus::DECLINED {
                            return Err(result);
                        }
                    }
                    Callback::Native(cbk_fn) => {
                        if let Err(e) = cbk_fn(tx) {
                            if e != HtpStatus::DECLINED {
                                return Err(e);
                            }
                        }
                    }
                };
            }
        }
        Ok(())
    }
}

impl DataHook {
    /// Run all callbacks on the list
    ///
    /// This function will exit early if a callback fails to return HtpStatus::OK
    /// or HtpStatus::DECLINED.
    pub(crate) fn run_all(&self, connp: &ConnectionParser, data: &mut Data) -> Result<()> {
        for cbk_fn in &self.callbacks {
            match cbk_fn {
                Callback::External(cbk_fn) => {
                    let result = unsafe { cbk_fn(connp, data) };
                    if result != HtpStatus::OK && result != HtpStatus::DECLINED {
                        return Err(result);
                    }
                }
                Callback::Native(cbk_fn) => {
                    if let Err(e) = cbk_fn(unsafe { &mut *data.tx() }, data.parser_data()) {
                        if e != HtpStatus::DECLINED {
                            return Err(e);
                        }
                    }
                }
            };
        }
        Ok(())
    }
}

/// Type of callbacks
#[derive(Copy, Clone)]
pub enum Callback<E, N> {
    /// External (C) callback function
    External(E),
    /// Native (rust) callback function
    Native(N),
}
