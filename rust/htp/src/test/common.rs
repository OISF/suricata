#![allow(non_snake_case)]
use crate::{
    bstr::Bstr,
    config::{Config, HtpServerPersonality},
    connection_parser::{ConnectionParser, HtpStreamState, ParserData},
    error::Result,
    transaction::Transaction,
};
use std::{
    env,
    iter::IntoIterator,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::SystemTime,
};
use time::OffsetDateTime;

#[derive(Debug)]
enum Chunk {
    Client(ParserData<'static>),
    Server(ParserData<'static>),
}

/// A structure to hold callback data
pub(super) struct MainUserData {
    /// Call order of callbacks
    pub order: Vec<String>,
    /// Request data from callbacks
    pub request_data: Vec<Bstr>,
    /// Response data from callbacks
    pub response_data: Vec<Bstr>,
}

impl Default for MainUserData {
    /// Make a new user data struct
    fn default() -> Self {
        Self {
            order: Vec::new(),
            request_data: Vec::with_capacity(5),
            response_data: Vec::with_capacity(5),
        }
    }
}

#[derive(Debug)]
struct TestInput {
    chunks: Vec<Chunk>,
}

impl IntoIterator for TestInput {
    type Item = Chunk;
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.chunks.into_iter()
    }
}

impl From<PathBuf> for TestInput {
    fn from(file: PathBuf) -> Self {
        let input = std::fs::read(file)
            .expect("Could not read file {:?}. Do you need to set a base dir in env('srcdir')?");
        TestInput::from(input.as_slice())
    }
}

impl From<&[u8]> for TestInput {
    fn from(input: &[u8]) -> Self {
        let mut test_input = TestInput { chunks: Vec::new() };
        let mut current = Vec::<u8>::new();
        let mut client = true;
        let mut is_gap = false;
        let mut start = true;
        for line in input.split_inclusive(|c| *c == b'\n') {
            if line.len() >= 4
                && line.len() <= 5
                && (&line[0..3] == b"<<<"
                    || &line[0..3] == b"<><"
                    || &line[0..3] == b">>>"
                    || &line[0..3] == b"><>")
                && (line.len() == 4 || line[3] == b'\r')
                && line[line.len() - 1] == b'\n'
            {
                if !current.is_empty() {
                    // Pop off the CRLF from the last line, which
                    // just separates the previous data from the
                    // boundary <<< >>> chars and isn't actual data
                    if let Some(b'\n') = current.last() {
                        current.pop();
                    }
                    if let Some(b'\r') = current.last() {
                        current.pop();
                    }
                    test_input.append(client, current, is_gap);
                    current = Vec::<u8>::new();
                }
                // Client represented by first char is >
                client = line[0] == b'>';
                // Gaps represented by <>< or ><>
                is_gap = line[0] != line[1];
                start = false;
            } else {
                if start {
                    // we need to start with an indicated direction
                    return test_input;
                }
                current.append(&mut line.to_vec());
            }
        }
        test_input.append(client, current, is_gap);
        test_input
    }
}

impl TestInput {
    fn append(&mut self, client: bool, data: Vec<u8>, is_gap: bool) {
        let chunk = match (client, is_gap) {
            // client gap
            (true, true) => Chunk::Client(data.len().into()),
            // client data
            (true, false) => Chunk::Client(data.into()),
            // server gap
            (false, true) => Chunk::Server(data.len().into()),
            // server data
            (false, false) => Chunk::Server(data.into()),
        };
        self.chunks.push(chunk);
    }
}

/// Error types
#[derive(Debug)]
pub(super) enum TestError {
    /// The parser entered the Error state
    StreamError,
}

/// Test harness
#[derive(Debug)]
pub(super) struct Test {
    /// The connection parse
    pub connp: ConnectionParser,
    /// The base directory for the crate - used to find files.
    pub basedir: Option<PathBuf>,
}

/// Return a default Config to use with tests
pub(super) fn TestConfig() -> Config {
    let mut cfg = Config::default();
    cfg.set_server_personality(HtpServerPersonality::APACHE_2)
        .unwrap();
    // The default bomb limit may be slow in some development environments causing tests to fail.
    cfg.compression_options
        .set_time_limit(10 * cfg.compression_options.get_time_limit());

    cfg
}

impl Test {
    /// Make a new test with the given config
    pub(super) fn new(cfg: Config) -> Self {
        let basedir = if let Ok(dir) = std::env::var("srcdir") {
            Some(PathBuf::from(dir))
        } else if let Ok(dir) = env::var("CARGO_MANIFEST_DIR") {
            let mut base = PathBuf::from(dir);
            base.push("src");
            base.push("test");
            base.push("files");
            Some(base)
        } else {
            None
        };

        let cfg = Box::leak(Box::new(cfg));
        let connp = ConnectionParser::new(cfg);
        Test { connp, basedir }
    }

    /// Make a new test with the default TestConfig and register body callbacks.
    pub(super) fn new_with_callbacks() -> Self {
        let mut cfg = TestConfig();
        cfg.register_request_start(request_start);
        cfg.register_request_complete(request_complete);
        cfg.register_response_start(response_start);
        cfg.register_response_complete(response_complete);
        cfg.register_response_body_data(response_body_data);
        cfg.register_request_body_data(request_body_data);
        cfg.register_transaction_complete(transaction_complete);
        let mut t = Test::new(cfg);
        // Configure user data and callbacks
        t.connp
            .response_mut()
            .unwrap()
            .set_user_data(Box::<MainUserData>::default());
        t
    }

    /// Open a connection on the underlying ConnectionParser. Useful if you
    /// want to send data directly to the ConnectionParser after.
    pub(super) fn open_connection(&mut self, tv_start: Option<OffsetDateTime>) {
        self.connp.open(
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            Some(10000),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            Some(80),
            tv_start,
        );
    }

    fn run(&mut self, test: TestInput) -> std::result::Result<(), TestError> {
        let tv_start = Some(OffsetDateTime::from(SystemTime::now()));
        self.open_connection(tv_start);

        let mut request_buf: Option<ParserData> = None;
        let mut response_buf: Option<ParserData> = None;
        for chunk in test {
            match chunk {
                Chunk::Client(data) => {
                    let rc = self.connp.request_data(data.clone(), tv_start);

                    if rc == HtpStreamState::ERROR {
                        return Err(TestError::StreamError);
                    }

                    if rc == HtpStreamState::DATA_OTHER {
                        let consumed = self.connp.request_data_consumed();
                        let remaining = data.clone().into_owned();
                        remaining.consume(consumed);
                        request_buf = Some(remaining);
                    }
                }
                Chunk::Server(data) => {
                    // If we have leftover data from before then use it first
                    if let Some(response_remaining) = response_buf {
                        let rc = self
                            .connp
                            .response_data(response_remaining.as_slice().into(), tv_start);
                        response_buf = None;
                        if rc == HtpStreamState::ERROR {
                            return Err(TestError::StreamError);
                        }
                    }

                    // Now use up this data chunk
                    let rc = self.connp.response_data(data.clone(), tv_start);
                    if rc == HtpStreamState::ERROR {
                        return Err(TestError::StreamError);
                    }

                    if rc == HtpStreamState::DATA_OTHER {
                        let consumed = self.connp.response_data_consumed();
                        let remaining = data.clone().into_owned();
                        remaining.consume(consumed);
                        response_buf = Some(remaining);
                    }

                    // And check if we also had some input data buffered
                    if let Some(request_remaining) = request_buf {
                        let rc = self
                            .connp
                            .request_data(request_remaining.as_slice().into(), tv_start);
                        request_buf = None;
                        if rc == HtpStreamState::ERROR {
                            return Err(TestError::StreamError);
                        }
                    }
                }
            }
        }

        // Clean up any remaining server data
        if let Some(response_remaining) = response_buf {
            let rc = self
                .connp
                .response_data(response_remaining.as_slice().into(), tv_start);
            if rc == HtpStreamState::ERROR {
                return Err(TestError::StreamError);
            }
        }
        self.connp
            .close(Some(OffsetDateTime::from(SystemTime::now())));
        Ok(())
    }

    /// Run on a slice of input data. Used with fuzzing.
    pub(super) fn run_slice(&mut self, slice: &[u8]) -> std::result::Result<(), TestError> {
        self.run(TestInput::from(slice))
    }

    /// Run on a file path. Used in integration tests.
    pub(super) fn run_file(&mut self, file: &str) -> std::result::Result<(), TestError> {
        let testfile = if let Some(base) = &self.basedir {
            let mut path = base.clone();
            path.push(file);
            path
        } else {
            PathBuf::from(file)
        };

        self.run(TestInput::from(testfile))
    }
}

fn request_start(tx: &mut Transaction) -> Result<()> {
    let id = tx.index;
    let user_data = tx.user_data_mut::<MainUserData>().unwrap();
    user_data.order.push(format!("request_start {}", id));
    Ok(())
}

fn request_complete(tx: &mut Transaction) -> Result<()> {
    let id = tx.index;
    let user_data = &mut tx.user_data_mut::<MainUserData>().unwrap();
    user_data.order.push(format!("request_complete {}", id));
    Ok(())
}

fn response_start(tx: &mut Transaction) -> Result<()> {
    let id = tx.index;
    let user_data = tx.user_data_mut::<MainUserData>().unwrap();
    user_data.order.push(format!("response_start {}", id));
    Ok(())
}

fn response_complete(tx: &mut Transaction) -> Result<()> {
    let id = tx.index;
    let user_data = tx.user_data_mut::<MainUserData>().unwrap();
    user_data.order.push(format!("response_complete {}", id));
    Ok(())
}

fn transaction_complete(tx: &mut Transaction) -> Result<()> {
    let id = tx.index;
    let user_data = tx.user_data_mut::<MainUserData>().unwrap();
    user_data.order.push(format!("transaction_complete {}", id));
    Ok(())
}

fn response_body_data(tx: &mut Transaction, d: &ParserData) -> Result<()> {
    let user_data = tx.user_data_mut::<MainUserData>().unwrap();
    let bstr = if d.is_gap() {
        Bstr::with_capacity(d.len())
    } else {
        Bstr::from(d.as_slice())
    };
    user_data.response_data.push(bstr);
    Ok(())
}

fn request_body_data(tx: &mut Transaction, d: &ParserData) -> Result<()> {
    let user_data = tx.user_data_mut::<MainUserData>().unwrap();
    let bstr = if d.is_gap() {
        Bstr::with_capacity(d.len())
    } else {
        Bstr::from(d.as_slice())
    };
    user_data.request_data.push(bstr);
    Ok(())
}

#[no_mangle]
/// Creates a Fuzz test runner, and runs a byte slice on it
/// # Safety
/// Input pointer must be non-null.
pub unsafe extern "C" fn libhtprsFuzzRun(
    input: *const u8, input_len: u32,
) -> *mut std::os::raw::c_void {
    let mut cfg = TestConfig();
    cfg.set_server_personality(HtpServerPersonality::IDS)
        .unwrap();
    let mut t = Test::new(cfg);
    let data = std::slice::from_raw_parts(input, input_len as usize);
    t.run_slice(data).ok();
    let boxed = Box::new(t);
    Box::into_raw(boxed) as *mut _
}

#[no_mangle]
/// Frees a Fuzz test runner
/// # Safety
/// Input pointer must be non-null.
pub unsafe extern "C" fn libhtprsFreeFuzzRun(state: *mut std::os::raw::c_void) {
    //just unbox
    std::mem::drop(Box::from_raw(state as *mut Test));
}

#[no_mangle]
/// Gets connection parser out of a test runner
/// # Safety
/// Input pointer must be non-null.
pub unsafe extern "C" fn libhtprsFuzzConnp(t: *mut std::os::raw::c_void) -> *mut ConnectionParser {
    let state = t as *mut Test;
    &mut (*state).connp
}

#[macro_export]
/// Cstring converter
macro_rules! cstr {
    ( $x:expr ) => {{
        CString::new($x).unwrap().as_ptr()
    }};
}

/// Compares a transaction's header value to an expected value.
///
/// The `attr` argument is meant to be either `request_headers` or `response_headers`.
///
/// Example usage:
/// assert_header_eq!(tx, request_headers, "host", ""www.example.com");
macro_rules! assert_header_eq {
    ($tx:expr, $attr:ident, $key:expr, $val:expr) => {{
        let header = &(*$tx).$attr
            .get_nocase_nozero($key)
            .expect(format!(
                "expected header '{}' to exist at {}:{}:{}",
                $key,
                file!(),
                line!(),
                column!()
            ).as_ref());
        assert_eq!(*header.value, $val);
    }};
    ($tx:expr, $attr:ident, $key:expr, $val:expr,) => {{
        assert_header_eq!($tx, $attr, $key, $val);
    }};
    ($tx:expr, $attr:ident, $key:expr, $val:expr, $($arg:tt)+) => {{
        let header = (*(*$tx).$attr)
            .get_nocase_nozero($key)
            .expect(format!(
                "expected header '{}' to exist at {}:{}:{}",
                $key,
                file!(),
                line!(),
                column!()
            ).as_ref())
            .1
            .as_ref()
            .expect(format!(
                "expected header '{}' to exist at {}:{}:{}",
                $key,
                file!(),
                line!(),
                column!()
            ).as_ref());
        assert_eq!(*header.value, $val, $($arg)*);
    }};
}
pub(crate) use assert_header_eq;

/// Compares a transaction's request header value to an expected value.
///
/// Example usage:
/// assert_request_header_eq!(tx, "host", ""www.example.com");
macro_rules! assert_request_header_eq {
    ($tx:expr, $key:expr, $val:expr) => {{
        assert_header_eq!($tx, request_headers, $key, $val);
    }};
    ($tx:expr, $key:expr, $val:expr,) => {{
        assert_header_eq!($tx, request_headers, $key, $val);
    }};
    ($tx:expr, $key:expr, $val:expr, $($arg:tt)+) => {{
        assert_header_eq!($tx, request_headers, $val, $($arg)*);
    }};
}
pub(crate) use assert_request_header_eq;

/// Compares a transaction's response header value to an expected value.
///
/// Example usage:
/// assert_response_header_eq!(tx, "content-encoding", ""gzip");
macro_rules! assert_response_header_eq {
    ($tx:expr, $key:expr, $val:expr) => {{
        assert_header_eq!($tx, response_headers, $key, $val);
    }};
    ($tx:expr, $key:expr, $val:expr,) => {{
        assert_header_eq!($tx, response_headers, $key, $val);
    }};
    ($tx:expr, $key:expr, $val:expr, $($arg:tt)+) => {{
        assert_header_eq!($tx, response_headers, $val, $($arg)*);
    }};
}
pub(crate) use assert_response_header_eq;

/// Asserts that a transaction's response contains a flag.
///
/// Example usage:
/// assert_response_header_flag_contains!(tx, "Content-Length", Flags::FIELD_REPEATED);
macro_rules! assert_response_header_flag_contains {
    ($tx:expr, $key:expr, $val:expr) => {{
        let header = &(*$tx).response_headers
            .get_nocase_nozero($key)
            .expect(format!(
                "expected header '{}' to exist at {}:{}:{}",
                $key,
                file!(),
                line!(),
                column!()
            ).as_ref());
        assert!(header.flags.is_set($val));
        }};
    ($tx:expr, $key:expr, $val:expr,) => {{
        assert_response_header_flag_contains!($tx, response_headers, $key, $val);
    }};
    ($tx:expr, $key:expr, $val:expr, $($arg:tt)+) => {{
        let header = (*(*$tx).response_headers)
            .get_nocase_nozero($key)
            .expect(format!(
                "expected header '{}' to exist at {}:{}:{}",
                $key,
                file!(),
                line!(),
                column!()
            ).as_ref())
            .1
            .as_ref()
            .expect(format!(
                "expected header '{}' to exist at {}:{}:{}",
                $key,
                file!(),
                line!(),
                column!()
            ).as_ref());
        assert_eq!(*header.value, $val, $($arg)*);
        assert!((*header).flags.is_set($val), $($arg)*);
    }};
}
pub(crate) use assert_response_header_flag_contains;

/// Assert the common evader request values are as expected
///
/// Example usage:
/// assert_evader_request!(tx, "url");
macro_rules! assert_evader_request {
    ($tx:expr, $url:expr) => {{
        assert!(($tx).request_method.as_ref().unwrap().eq_slice("GET"));
        assert!(($tx).request_uri.as_ref().unwrap().eq_slice($url));
        assert_eq!(HtpProtocol::V1_1, ($tx).request_protocol_number);
        assert_header_eq!($tx, request_headers, "host", "evader.example.com");
    }};
}
pub(crate) use assert_evader_request;

/// Assert the common evader response values are as expected
///
/// Example usage:
/// assert_evader_response!(tx);
macro_rules! assert_evader_response {
    ($tx:expr) => {{
        assert_eq!(HtpProtocol::V1_1, ($tx).response_protocol_number);
        assert!(($tx).response_status_number.eq_num(200));
        assert_response_header_eq!($tx, "Content-type", "application/octet-stream");
        assert_response_header_eq!(
            $tx,
            "Content-disposition",
            "attachment; filename=\"eicar.txt\""
        );
        assert!(($tx)
            .response_headers
            .get_nocase_nozero("Connection")
            .is_some());
    }};
}
pub(crate) use assert_evader_response;

/// Assert the response transfer encoding is detected as chunked
///
/// Example usage:
/// assert_evader_chunked_response!(tx);
macro_rules! assert_evader_chunked {
    ($tx:expr) => {{
        assert_eq!($tx.response_transfer_coding, HtpTransferCoding::Chunked);
        assert_response_header_eq!($tx, "Yet-Another-Header", "foo");
        assert_eq!(68, ($tx).response_entity_len);
        assert_eq!(156, ($tx).response_message_len);
        let user_data = ($tx).user_data::<MainUserData>().unwrap();
        assert!(user_data.request_data.is_empty());
        assert_eq!(17, user_data.response_data.len());
        assert_eq!(b"X5O!".as_ref(), (&user_data.response_data[0]).as_slice());
        assert_eq!(b"P%@A".as_ref(), (&user_data.response_data[1]).as_slice());
        assert_eq!(b"P[4\\".as_ref(), (&user_data.response_data[2]).as_slice());
        assert_eq!(b"PZX5".as_ref(), (&user_data.response_data[3]).as_slice());
        assert_eq!(b"4(P^".as_ref(), (&user_data.response_data[4]).as_slice());
        assert_eq!(b")7CC".as_ref(), (&user_data.response_data[5]).as_slice());
        assert_eq!(b")7}$".as_ref(), (&user_data.response_data[6]).as_slice());
        assert_eq!(b"EICA".as_ref(), (&user_data.response_data[7]).as_slice());
        assert_eq!(b"R-ST".as_ref(), (&user_data.response_data[8]).as_slice());
        assert_eq!(b"ANDA".as_ref(), (&user_data.response_data[9]).as_slice());
        assert_eq!(b"RD-A".as_ref(), (&user_data.response_data[10]).as_slice());
        assert_eq!(b"NTIV".as_ref(), (&user_data.response_data[11]).as_slice());
        assert_eq!(b"IRUS".as_ref(), (&user_data.response_data[12]).as_slice());
        assert_eq!(b"-TES".as_ref(), (&user_data.response_data[13]).as_slice());
        assert_eq!(b"T-FI".as_ref(), (&user_data.response_data[14]).as_slice());
        assert_eq!(b"LE!$".as_ref(), (&user_data.response_data[15]).as_slice());
        assert_eq!(b"H+H*".as_ref(), (&user_data.response_data[16]).as_slice());
        assert_eq!(HtpRequestProgress::COMPLETE, ($tx).request_progress);
        assert_eq!(HtpResponseProgress::COMPLETE, ($tx).response_progress);
    }};
}
pub(crate) use assert_evader_chunked;
