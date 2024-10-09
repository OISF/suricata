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
pub struct MainUserData {
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
pub enum TestError {
    /// The parser entered the Error state
    StreamError,
}

/// Test harness
#[derive(Debug)]
pub struct Test {
    /// The connection parse
    pub connp: ConnectionParser,
    /// The base directory for the crate - used to find files.
    pub basedir: Option<PathBuf>,
}

/// Return a default Config to use with tests
pub fn TestConfig() -> Config {
    let mut cfg = Config::default();
    cfg.set_server_personality(HtpServerPersonality::APACHE_2)
        .unwrap();
    // The default bomb limit may be slow in some development environments causing tests to fail.
    cfg.compression_options
        .set_time_limit(10 * cfg.compression_options.get_time_limit());
    cfg.set_parse_urlencoded(true);

    cfg
}

impl Test {
    /// Make a new test with the given config
    pub fn new(cfg: Config) -> Self {
        let basedir = if let Ok(dir) = std::env::var("srcdir") {
            Some(PathBuf::from(dir))
        } else if let Ok(dir) = env::var("CARGO_MANIFEST_DIR") {
            let mut base = PathBuf::from(dir);
            base.push("tests");
            base.push("files");
            Some(base)
        } else {
            None
        };

        let connp = ConnectionParser::new(cfg);
        Test { connp, basedir }
    }

    /// Make a new test with the default TestConfig and register body callbacks.
    pub fn new_with_callbacks() -> Self {
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
    pub fn open_connection(&mut self, tv_start: Option<OffsetDateTime>) {
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
    pub fn run_slice(&mut self, slice: &[u8]) -> std::result::Result<(), TestError> {
        self.run(TestInput::from(slice))
    }

    /// Run on a file path. Used in integration tests.
    pub fn run_file(&mut self, file: &str) -> std::result::Result<(), TestError> {
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
    input: *const u8,
    input_len: u32,
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
