use crate::log::Log;
use std::{cell::RefCell, collections::VecDeque, net::IpAddr, rc::Rc, time::SystemTime};
use time::OffsetDateTime;

/// Export Connection ConnectionFlags
#[repr(C)]
pub(crate) struct ConnectionFlags;

/// `Connection` Flags
impl ConnectionFlags {
    /// Seen pipelined requests.
    pub(crate) const PIPELINED: u8 = 0x01;
    /// Seen extra data after a HTTP 0.9 communication.
    pub(crate) const HTTP_0_9_EXTRA: u8 = 0x02;
}

/// Stores information about the session.
pub struct Connection {
    /// Client IP address.
    pub(crate) client_addr: Option<IpAddr>,
    /// Client port.
    pub(crate) client_port: Option<u16>,
    /// Server IP address.
    pub(crate) server_addr: Option<IpAddr>,
    /// Server port.
    pub(crate) server_port: Option<u16>,

    /// Messages channel associated with this connection.
    log_channel: Rc<RefCell<VecDeque<Log>>>,

    /// Parsing flags.
    pub(crate) flags: u8,
    /// When was this connection opened?
    pub(crate) open_timestamp: OffsetDateTime,
    /// When was this connection closed?
    pub(crate) close_timestamp: OffsetDateTime,
    /// Inbound data counter.
    pub(crate) request_data_counter: u64,
    /// Outbound data counter.
    pub(crate) response_data_counter: u64,
}

impl Default for Connection {
    /// Returns a new Connection instance with default values.
    fn default() -> Self {
        Self {
            client_addr: None,
            client_port: None,
            server_addr: None,
            server_port: None,
            log_channel: Rc::new(RefCell::new(VecDeque::new())),
            flags: 0,
            open_timestamp: OffsetDateTime::from(SystemTime::now()),
            close_timestamp: OffsetDateTime::from(SystemTime::now()),
            request_data_counter: 0,
            response_data_counter: 0,
        }
    }
}

impl Connection {
    /// Opens a connection. This function will essentially only store the provided data
    /// for future reference.
    pub(crate) fn open(
        &mut self, client_addr: Option<IpAddr>, client_port: Option<u16>,
        server_addr: Option<IpAddr>, server_port: Option<u16>, timestamp: Option<OffsetDateTime>,
    ) {
        self.client_addr = client_addr;
        self.client_port = client_port;
        self.server_addr = server_addr;
        self.server_port = server_port;

        // Remember when the connection was opened.
        if let Some(timestamp) = timestamp {
            self.open_timestamp = timestamp;
        }
    }

    /// Closes the connection.
    pub(crate) fn close(&mut self, timestamp: Option<OffsetDateTime>) {
        // Update timestamp.
        if let Some(timestamp) = timestamp {
            self.close_timestamp = timestamp;
        }
    }

    /// Keeps track of inbound packets and data.
    pub(crate) fn track_inbound_data(&mut self, len: usize) {
        self.request_data_counter = (self.request_data_counter).wrapping_add(len as u64);
    }

    /// Keeps track of outbound packets and data.
    pub(crate) fn track_outbound_data(&mut self, len: usize) {
        self.response_data_counter = (self.response_data_counter).wrapping_add(len as u64);
    }

    /// Return the log channel sender
    pub(crate) fn get_sender(&self) -> &Rc<RefCell<VecDeque<Log>>> {
        &self.log_channel
    }

    /// Drains and returns a vector of all current logs received by the log channel
    #[cfg(test)]
    pub(crate) fn get_logs(&self) -> Vec<Log> {
        let mut lc = self.log_channel.borrow_mut();
        let mut r = Vec::with_capacity(lc.len());
        while let Some(e) = lc.pop_front() {
            r.push(e)
        }
        r
    }

    /// Returns the next logged message received by the log channel
    pub(crate) fn get_next_log(&self) -> Option<Log> {
        let mut lc = self.log_channel.borrow_mut();
        lc.pop_front()
    }
}

impl PartialEq for Connection {
    /// Returns true if connections are the same, false otherwise.
    fn eq(&self, rhs: &Self) -> bool {
        self.client_addr == rhs.client_addr
            && self.client_port == rhs.client_port
            && self.server_addr == rhs.server_addr
            && self.server_port == rhs.server_port
    }
}
