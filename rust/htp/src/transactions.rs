use crate::{config::Config, log::Logger, transaction::Transaction};
use std::collections::VecDeque;

/// Transaction is a structure which tracks request and response
/// transactions, and guarantees that the current request or
/// response transaction will always exist.
pub(crate) struct Transactions {
    config: &'static Config,
    logger: Logger,
    request: usize,
    response: usize,
    transactions: VecDeque<Transaction>,
}

impl Transactions {
    /// Make a new Transactions struct with the given config
    pub(crate) fn new(cfg: &'static Config, logger: &Logger) -> Self {
        Self {
            config: cfg,
            logger: logger.clone(),
            request: 0,
            response: 0,
            transactions: VecDeque::new(),
        }
    }

    /// Return the number of transactions processed.
    /// The value returned may wrap around if the number of transactions
    /// exceeds the storage size available to `usize`.
    pub(crate) fn size(&self) -> usize {
        // The total number of transactions is just the maximum
        // of the request or response transaction index + 1 (if
        // that transaction is started), or zero if neither
        // request or response transaction exist yet
        let tx_to_check = std::cmp::max(self.request, self.response);
        match self.get(tx_to_check) {
            // Transaction is created, check if it is started
            Some(tx) => tx.index.wrapping_add(tx.is_started() as usize),
            // Transaction doesn't exist yet, so the index is the size
            None => tx_to_check,
        }
    }

    /// Get the current request transaction index
    pub(crate) fn request_index(&self) -> usize {
        self.request
    }

    /// Get the current request transaction
    pub(crate) fn request(&mut self) -> Option<&Transaction> {
        match self.request_mut() {
            Some(req) => Some(req),
            None => None,
        }
    }

    /// Get the current request transaction
    pub(crate) fn request_mut(&mut self) -> Option<&mut Transaction> {
        let nbtx = self.transactions.len();
        // use rposition as the current request is rather the tx at the back of VecDeque
        if let Some(pos) = self
            .transactions
            .iter()
            .rposition(|tx| tx.index == self.request)
        {
            return Some(&mut self.transactions[pos]);
        }
        if nbtx >= self.config.max_tx as usize {
            return None;
        }
        let tx = Transaction::new(self.config, &self.logger, self.request, true);
        if let Some(tx) = tx {
            self.transactions.push_back(tx);
            return self.transactions.back_mut();
        }
        None
    }

    /// Get the current response transaction index
    pub(crate) fn response_index(&self) -> usize {
        self.response
    }

    /// Get the current response transaction
    pub(crate) fn response(&mut self) -> Option<&Transaction> {
        match self.response_mut() {
            Some(resp) => Some(resp),
            None => None,
        }
    }

    /// Get the current response transaction
    pub(crate) fn response_mut(&mut self) -> Option<&mut Transaction> {
        if let Some(pos) = self
            .transactions
            .iter()
            .position(|tx| tx.index == self.response)
        {
            return Some(&mut self.transactions[pos]);
        }
        if self.transactions.len() >= self.config.max_tx as usize {
            return None;
        }
        let tx = Transaction::new(self.config, &self.logger, self.response, false);
        if let Some(tx) = tx {
            self.transactions.push_back(tx);
            return self.transactions.back_mut();
        }
        None
    }

    /// Increment the request transaction number.
    /// May cause the previous transaction to be freed if configured to auto-destroy.
    /// Returns the new request transaction index
    pub(crate) fn request_next(&mut self) -> usize {
        self.request = self.request.wrapping_add(1);
        self.request
    }

    /// Increment the response transaction number.
    /// May cause the previous transaction to be freed if configured to auto-destroy.
    /// Returns the new response transaction index
    pub(crate) fn response_next(&mut self) -> usize {
        self.response = self.response.wrapping_add(1);
        self.response
    }

    /// Remove the transaction at the given index. If the transaction
    /// existed, it is returned.
    pub(crate) fn remove(&mut self, index: usize) {
        if let Some(pos) = self.transactions.iter().position(|tx| tx.index == index) {
            self.transactions.remove(pos);
        }
    }

    /// Get the given transaction by index number
    pub(crate) fn get(&self, index: usize) -> Option<&Transaction> {
        if let Some(pos) = self.transactions.iter().position(|tx| tx.index == index) {
            return Some(&self.transactions[pos]);
        }
        None
    }

    /// Get the given transaction by index number
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut Transaction> {
        if let Some(pos) = self.transactions.iter().position(|tx| tx.index == index) {
            return Some(&mut self.transactions[pos]);
        }
        None
    }

    /// Get the given transaction by index number
    pub(crate) fn get_index(&mut self, index: usize) -> Option<&mut Transaction> {
        if index < self.transactions.len() {
            return Some(&mut self.transactions[index]);
        }
        None
    }
}
