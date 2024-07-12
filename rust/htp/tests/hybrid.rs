#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use htp::{
    bstr::Bstr,
    config::{Config, HtpServerPersonality},
    connection_parser::{ConnectionParser, ParserData},
    error::Result,
    transaction::{Header, HtpProtocol, HtpResponseNumber, Transaction},
    uri::Uri,
    HtpStatus,
};
use std::net::{IpAddr, Ipv4Addr};

// import common testing utilities
mod common;

struct HybridParsing_Get_User_Data {
    // Request callback indicators.
    callback_REQUEST_START_invoked: i32,
    callback_REQUEST_LINE_invoked: i32,
    callback_REQUEST_HEADERS_invoked: i32,
    callback_REQUEST_COMPLETE_invoked: i32,

    // Response callback indicators.
    callback_RESPONSE_START_invoked: i32,
    callback_RESPONSE_LINE_invoked: i32,
    callback_RESPONSE_HEADERS_invoked: i32,
    callback_RESPONSE_COMPLETE_invoked: i32,

    // Transaction callback indicators.
    callback_TRANSACTION_COMPLETE_invoked: i32,

    // Response body handling fields.
    response_body_chunks_seen: i32,
    response_body_correctly_received: i32,
}

impl HybridParsing_Get_User_Data {
    pub fn new() -> Self {
        HybridParsing_Get_User_Data {
            callback_REQUEST_START_invoked: 0,
            callback_REQUEST_LINE_invoked: 0,
            callback_REQUEST_HEADERS_invoked: 0,
            callback_REQUEST_COMPLETE_invoked: 0,
            callback_RESPONSE_START_invoked: 0,
            callback_RESPONSE_LINE_invoked: 0,
            callback_RESPONSE_HEADERS_invoked: 0,
            callback_RESPONSE_COMPLETE_invoked: 0,
            callback_TRANSACTION_COMPLETE_invoked: 0,
            response_body_chunks_seen: 0,
            response_body_correctly_received: 0,
        }
    }
}

fn HybridParsing_Get_Callback_REQUEST_START(tx: &mut Transaction) -> Result<()> {
    let user_data = tx.user_data_mut::<HybridParsing_Get_User_Data>().unwrap();
    user_data.callback_REQUEST_START_invoked += 1;
    Ok(())
}

fn HybridParsing_Get_Callback_REQUEST_LINE(tx: &mut Transaction) -> Result<()> {
    let user_data = tx.user_data_mut::<HybridParsing_Get_User_Data>().unwrap();
    user_data.callback_REQUEST_LINE_invoked += 1;
    Ok(())
}

fn HybridParsing_Get_Callback_REQUEST_HEADERS(tx: &mut Transaction) -> Result<()> {
    let user_data = tx.user_data_mut::<HybridParsing_Get_User_Data>().unwrap();
    user_data.callback_REQUEST_HEADERS_invoked += 1;
    Ok(())
}

fn HybridParsing_Get_Callback_REQUEST_COMPLETE(tx: &mut Transaction) -> Result<()> {
    let user_data = tx.user_data_mut::<HybridParsing_Get_User_Data>().unwrap();
    user_data.callback_REQUEST_COMPLETE_invoked += 1;
    Ok(())
}

fn HybridParsing_Get_Callback_RESPONSE_START(tx: &mut Transaction) -> Result<()> {
    let user_data = tx.user_data_mut::<HybridParsing_Get_User_Data>().unwrap();
    user_data.callback_RESPONSE_START_invoked += 1;
    Ok(())
}

fn HybridParsing_Get_Callback_RESPONSE_LINE(tx: &mut Transaction) -> Result<()> {
    let user_data = tx.user_data_mut::<HybridParsing_Get_User_Data>().unwrap();
    user_data.callback_RESPONSE_LINE_invoked += 1;
    Ok(())
}

fn HybridParsing_Get_Callback_RESPONSE_HEADERS(tx: &mut Transaction) -> Result<()> {
    let user_data = tx.user_data_mut::<HybridParsing_Get_User_Data>().unwrap();
    user_data.callback_RESPONSE_HEADERS_invoked += 1;
    Ok(())
}

fn HybridParsing_Get_Callback_RESPONSE_COMPLETE(tx: &mut Transaction) -> Result<()> {
    let user_data = tx.user_data_mut::<HybridParsing_Get_User_Data>().unwrap();
    user_data.callback_RESPONSE_COMPLETE_invoked += 1;
    Ok(())
}

fn HybridParsing_Get_Callback_TRANSACTION_COMPLETE(tx: &mut Transaction) -> Result<()> {
    let user_data = tx.user_data_mut::<HybridParsing_Get_User_Data>().unwrap();
    user_data.callback_TRANSACTION_COMPLETE_invoked += 1;
    Ok(())
}

fn HybridParsing_Get_Callback_RESPONSE_BODY_DATA(
    tx: &mut Transaction,
    d: &ParserData,
) -> Result<()> {
    let user_data = tx.user_data_mut::<HybridParsing_Get_User_Data>().unwrap();

    // Don't do anything if in errored state.
    if user_data.response_body_correctly_received == -1 {
        return Err(HtpStatus::ERROR);
    }

    let data = d.as_slice();
    match user_data.response_body_chunks_seen {
        0 => {
            if data == b"<h1>Hello" {
                user_data.response_body_chunks_seen += 1;
            } else {
                eprintln!("Mismatch in 1st chunk");
                user_data.response_body_correctly_received = -1;
            }
        }
        1 => {
            if data == b" " {
                user_data.response_body_chunks_seen += 1;
            } else {
                eprintln!("Mismatch in 2nd chunk");
                user_data.response_body_correctly_received = -1;
            }
        }
        2 => {
            if data == b"World!</h1>" {
                user_data.response_body_chunks_seen += 1;
                user_data.response_body_correctly_received = 1;
            } else {
                eprintln!("Mismatch in 3rd chunk");
                user_data.response_body_correctly_received = -1;
            }
        }
        _ => {
            eprintln!("Seen more than 3 chunks");
            user_data.response_body_correctly_received = -1;
        }
    }
    Ok(())
}

// Set one request header.
macro_rules! tx_set_header {
    ($headers:expr, $name:expr, $value:expr) => {
        $headers
            .elements
            .push(Header::new($name.into(), $value.into()))
    };
}

fn TestConfig() -> Config {
    let mut cfg = Config::default();
    cfg.set_server_personality(HtpServerPersonality::APACHE_2)
        .unwrap();
    cfg.set_parse_urlencoded(true);
    cfg
}

fn register_user_callbacks(cfg: &mut Config) {
    // Request callbacks
    cfg.register_request_start(HybridParsing_Get_Callback_REQUEST_START);
    cfg.register_request_line(HybridParsing_Get_Callback_REQUEST_LINE);
    cfg.register_request_headers(HybridParsing_Get_Callback_REQUEST_HEADERS);
    cfg.register_request_complete(HybridParsing_Get_Callback_REQUEST_COMPLETE);

    // Response callbacks
    cfg.register_response_start(HybridParsing_Get_Callback_RESPONSE_START);
    cfg.register_response_line(HybridParsing_Get_Callback_RESPONSE_LINE);
    cfg.register_response_headers(HybridParsing_Get_Callback_RESPONSE_HEADERS);
    cfg.register_response_body_data(HybridParsing_Get_Callback_RESPONSE_BODY_DATA);
    cfg.register_response_complete(HybridParsing_Get_Callback_RESPONSE_COMPLETE);

    // Transaction callbacks
    cfg.register_transaction_complete(HybridParsing_Get_Callback_TRANSACTION_COMPLETE);
}

struct HybridParsingTest {
    connp: ConnectionParser,
}

impl HybridParsingTest {
    fn new(cfg: Config) -> Self {
        let mut connp = ConnectionParser::new(cfg);
        connp.open(
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            Some(32768),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            Some(80),
            None,
        );

        HybridParsingTest { connp }
    }
}

/// Test hybrid mode with one complete GET transaction; request then response
/// with a body. Most features are tested, including query string parameters and callbacks.
#[test]
fn GetTest() {
    let mut cfg = TestConfig();
    // Register callbacks
    register_user_callbacks(&mut cfg);
    let mut t = HybridParsingTest::new(cfg);
    let tx = t.connp.request_mut().unwrap();

    // Configure user data and callbacks
    tx.set_user_data(Box::new(HybridParsing_Get_User_Data::new()));
    // We should be operating on the same transaction throughout
    let tx_id = tx.index;

    // Make dummy parser data to satisfy callbacks
    let mut p = ParserData::from(b"" as &[u8]);

    // Request begins
    t.connp.state_request_start().unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_REQUEST_START_invoked);

    // Request line data
    t.connp
        .parse_request_line(b"GET /?p=1&q=2 HTTP/1.1")
        .unwrap();

    // Request line complete
    t.connp.state_request_line().unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_REQUEST_LINE_invoked);

    // Check request line data
    let tx = t.connp.tx_mut(tx_id).unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/?p=1&q=2"));
    assert!(tx.request_protocol.as_ref().unwrap().eq_slice("HTTP/1.1"));
    let parsed_uri = tx.parsed_uri.as_ref().unwrap();
    assert!(parsed_uri.path.as_ref().unwrap().eq_slice("/"));
    assert!(parsed_uri.query.as_ref().unwrap().eq_slice("p=1&q=2"));

    // Request headers
    tx_set_header!(tx.request_headers, "Host", "www.example.com");
    tx_set_header!(tx.request_headers, "Connection", "keep-alive");
    tx_set_header!(tx.request_headers, "User-Agent", "Mozilla/5.0");

    // Request headers complete
    t.connp.state_request_headers(&mut p).unwrap();

    // Check headers
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_REQUEST_HEADERS_invoked);

    let tx = t.connp.tx(tx_id).unwrap();
    assert_request_header_eq!(tx, "host", "www.example.com");
    assert_request_header_eq!(tx, "connection", "keep-alive");
    assert_request_header_eq!(tx, "user-agent", "Mozilla/5.0");

    // Request complete
    t.connp.state_request_complete(&mut p).unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_REQUEST_COMPLETE_invoked);

    // Response begins
    t.connp.state_response_start().unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_RESPONSE_START_invoked);

    // Response line data
    t.connp.parse_response_line(b"HTTP/1.1 200 OK").unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    assert!(tx.response_protocol.as_ref().unwrap().eq_slice("HTTP/1.1"));
    assert_eq!(HtpProtocol::V1_1, tx.response_protocol_number);
    assert!(tx.response_status.as_ref().unwrap().eq_slice("200"));
    assert!(tx.response_status_number.eq_num(200));
    assert!(tx.response_message.as_ref().unwrap().eq_slice("OK"));

    // Response line complete
    t.connp.state_response_line().unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();

    assert_eq!(1, user_data.callback_RESPONSE_LINE_invoked);

    // Response header data
    let tx = t.connp.tx_mut(tx_id).unwrap();
    tx_set_header!(tx.response_headers, "Content-Type", "text/html");
    tx_set_header!(tx.response_headers, "Server", "Apache");

    // Response headers complete
    t.connp.state_response_headers(&mut p).unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_RESPONSE_HEADERS_invoked);

    // Check response headers
    let tx = t.connp.tx(tx_id).unwrap();
    assert_response_header_eq!(tx, "content-type", "text/html");
    assert_response_header_eq!(tx, "server", "Apache");

    // Response body data
    t.connp.response_body_data(Some(b"<h1>Hello")).unwrap();
    t.connp.response_body_data(Some(b" ")).unwrap();
    t.connp.response_body_data(Some(b"World!</h1>")).unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.response_body_correctly_received);

    let tx = t.connp.tx_mut(tx_id).unwrap();
    tx_set_header!(tx.response_headers, "Content-Type", "text/html");
    tx_set_header!(tx.response_headers, "Server", "Apache");

    // Check trailing response headers
    assert_response_header_eq!(tx, "content-type", "text/html");
    assert_response_header_eq!(tx, "server", "Apache");

    t.connp.state_response_complete(&mut p).unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_RESPONSE_COMPLETE_invoked);
}

/// Use a POST request in order to test request body processing and parameter parsing.
#[test]
fn PostUrlecodedTest() {
    let mut t = HybridParsingTest::new(TestConfig());
    let tx_id = t.connp.request().unwrap().index;

    // Make dummy parser data to satisfy callbacks
    let mut p = ParserData::from(b"" as &[u8]);

    // Request begins
    t.connp.state_request_start().unwrap();

    // Request line data
    t.connp.parse_request_line(b"POST / HTTP/1.1").unwrap();

    // Request line complete
    t.connp.state_request_line().unwrap();

    // Configure headers to trigger the URLENCODED parser
    let tx = t.connp.tx_mut(tx_id).unwrap();
    tx_set_header!(
        tx.request_headers,
        "Content-Type",
        "application/x-www-form-urlencoded"
    );
    tx_set_header!(tx.request_headers, "Content-Length", "7");

    // Request headers complete
    t.connp.state_request_headers(&mut p).unwrap();

    // Send request body
    t.connp.request_body_data(Some(b"p=1")).unwrap();
    t.connp.request_body_data(Some(b"")).unwrap();
    t.connp.request_body_data(Some(b"&")).unwrap();
    t.connp.request_body_data(Some(b"q=2")).unwrap();

    let tx = t.connp.tx_mut(tx_id).unwrap();
    tx_set_header!(tx.request_headers, "Host", "www.example.com");
    tx_set_header!(tx.request_headers, "Connection", "keep-alive");
    tx_set_header!(tx.request_headers, "User-Agent", "Mozilla/5.0");

    assert_request_header_eq!(tx, "host", "www.example.com");
    assert_request_header_eq!(tx, "connection", "keep-alive");
    assert_request_header_eq!(tx, "user-agent", "Mozilla/5.0");

    // Request complete
    t.connp.state_request_complete(&mut p).unwrap();
}

/// Test with a compressed response body and decompression enabled.
#[test]
fn CompressedResponse() {
    let mut t = HybridParsingTest::new(TestConfig());
    let tx_id = t.connp.request().unwrap().index;

    // Make dummy parser data to satisfy callbacks
    let mut p = ParserData::from(b"" as &[u8]);

    t.connp.state_request_start().unwrap();

    t.connp.parse_request_line(b"GET / HTTP/1.1").unwrap();

    t.connp.state_request_line().unwrap();
    t.connp.state_request_headers(&mut p).unwrap();
    t.connp.state_request_complete(&mut p).unwrap();

    t.connp.state_response_start().unwrap();

    t.connp.parse_response_line(b"HTTP/1.1 200 OK").unwrap();
    let tx = t.connp.tx_mut(tx_id).unwrap();
    tx_set_header!(tx.response_headers, "Content-Encoding", "gzip");
    tx_set_header!(tx.response_headers, "Content-Length", "187");

    t.connp.state_response_headers(&mut p).unwrap();

    let RESPONSE: &[u8] =
        b"H4sIAAAAAAAAAG2PwQ6CMBBE73xFU++tXk2pASliAiEhPegRYUOJYEktEP5eqB6dy2ZnJ5O3LJFZ\
      yj2WiCBah7zKVPBMT1AjCf2gTWnabmH0e/AY/QXDPLqj8HLO07zw8S52wkiKm1zXvRPeeg//2lbX\
      kwpQrauxh5dFqnyj3uVYgJJCxD5W1g5HSud5Jo3WTQek0mR8UgNlDYZOLcz0ZMuH3y+YKzDAaMDJ\
      SrihOVL32QceVXUy4QAAAA==";

    let body = Bstr::from(base64::decode(RESPONSE).unwrap());

    t.connp.response_body_data(Some(body.as_slice())).unwrap();

    t.connp.state_response_complete(&mut p).unwrap();

    let tx = t.connp.tx(tx_id).unwrap();
    assert_eq!(187, tx.response_message_len);
    assert_eq!(225, tx.response_entity_len);
}

#[test]
fn ParamCaseSensitivity() {
    let mut t = HybridParsingTest::new(TestConfig());

    // Request begins
    t.connp.state_request_start().unwrap();

    // Request line data
    t.connp
        .parse_request_line(b"GET /?p=1&Q=2 HTTP/1.1")
        .unwrap();

    // Request line complete
    t.connp.state_request_line().unwrap();
}

/// Use a POST request in order to test request body processing and parameter
/// parsing. In hybrid mode, we expect that the body arrives to us dechunked.
#[test]
fn PostUrlecodedChunked() {
    let mut t = HybridParsingTest::new(TestConfig());
    let tx_id = t.connp.request().unwrap().index;

    // Make dummy parser data to satisfy callbacks
    let mut p = ParserData::from(b"" as &[u8]);

    // Request begins.
    t.connp.state_request_start().unwrap();

    // Request line data.
    t.connp.parse_request_line(b"POST / HTTP/1.1").unwrap();
    t.connp.state_request_line().unwrap();

    // Configure headers to trigger the URLENCODED parser.
    let tx = t.connp.tx_mut(tx_id).unwrap();
    tx_set_header!(
        tx.request_headers,
        "Content-Type",
        "application/x-www-form-urlencoded"
    );
    tx_set_header!(tx.request_headers, "Transfer-Encoding", "chunked");

    // Request headers complete.
    t.connp.state_request_headers(&mut p).unwrap();

    // Send request body.
    t.connp.request_body_data(Some(b"p=1")).unwrap();
    t.connp.request_body_data(Some(b"&")).unwrap();
    t.connp.request_body_data(Some(b"q=2")).unwrap();

    // Request complete.
    t.connp.state_request_complete(&mut p).unwrap();
}

#[test]
fn RequestLineParsing1() {
    let mut t = HybridParsingTest::new(TestConfig());
    let tx_id = t.connp.request().unwrap().index;

    // Request begins
    t.connp.state_request_start().unwrap();

    // Request line data
    t.connp
        .parse_request_line(b"GET /?p=1&q=2 HTTP/1.0")
        .unwrap();

    // Request line complete
    t.connp.state_request_line().unwrap();

    let tx = t.connp.tx(tx_id).unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/?p=1&q=2"));
    assert!(tx.request_protocol.as_ref().unwrap().eq_slice("HTTP/1.0"));
    let parsed_uri = tx.parsed_uri.as_ref().unwrap();
    assert!(parsed_uri.query.as_ref().unwrap().eq_slice("p=1&q=2"));
}

#[test]
fn RequestLineParsing2() {
    let mut t = HybridParsingTest::new(TestConfig());
    let tx_id = t.connp.request().unwrap().index;

    // Feed data to the parser.
    t.connp.state_request_start().unwrap();
    t.connp.parse_request_line(b"GET /").unwrap();
    t.connp.state_request_line().unwrap();

    // Check the results now.
    let tx = t.connp.tx(tx_id).unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert!(tx.is_protocol_0_9);
    assert_eq!(HtpProtocol::V0_9, tx.request_protocol_number);
    assert!(tx.request_protocol.is_none());
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/"));
}

#[test]
fn RequestLineParsing3() {
    let mut t = HybridParsingTest::new(TestConfig());
    let tx_id = t.connp.request().unwrap().index;

    // Feed data to the parser.
    t.connp.state_request_start().unwrap();
    t.connp.parse_request_line(b"GET / HTTP  / 01.1").unwrap();
    t.connp.state_request_line().unwrap();

    // Check the results now.
    let tx = t.connp.tx(tx_id).unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpProtocol::V1_1, tx.request_protocol_number);
    assert!(tx
        .request_protocol
        .as_ref()
        .unwrap()
        .eq_slice("HTTP  / 01.1"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/"));
}

#[test]
fn RequestLineParsing4() {
    let mut t = HybridParsingTest::new(TestConfig());
    let tx_id = t.connp.request().unwrap().index;

    // Feed data to the parser.
    t.connp.state_request_start().unwrap();
    t.connp.parse_request_line(b"GET / HTTP  / 01.10").unwrap();
    t.connp.state_request_line().unwrap();

    // Check the results now.
    let tx = t.connp.tx(tx_id).unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpProtocol::INVALID, tx.request_protocol_number);
    assert!(tx
        .request_protocol
        .as_ref()
        .unwrap()
        .eq_slice("HTTP  / 01.10"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/"));
}

#[test]
fn RequestLineParsing5() {
    let mut cfg = TestConfig();
    cfg.set_allow_space_uri(true);
    let mut t = HybridParsingTest::new(cfg);
    let tx_id = t.connp.request().unwrap().index;

    // Feed data to the parser.
    t.connp.state_request_start().unwrap();
    t.connp.parse_request_line(b"GET / HTTP  / 01.10").unwrap();
    t.connp.state_request_line().unwrap();

    // Check the results now.
    let tx = t.connp.tx(tx_id).unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpProtocol::INVALID, tx.request_protocol_number);
    assert!(tx.request_protocol.as_ref().unwrap().eq_slice("01.10"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/ HTTP  /"));
}

#[test]
fn RequestLineParsing6() {
    let mut cfg = TestConfig();
    cfg.set_allow_space_uri(true);
    let mut t = HybridParsingTest::new(cfg);
    let tx_id = t.connp.request().unwrap().index;

    // Feed data to the parser.
    t.connp.state_request_start().unwrap();
    // Test the parser's "found bad chars" path
    t.connp
        .parse_request_line(b"GET\t/\tHTTP\t\t/\t01.10")
        .unwrap();
    t.connp.state_request_line().unwrap();

    // Check the results now.
    let tx = t.connp.tx(tx_id).unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpProtocol::INVALID, tx.request_protocol_number);
    assert!(tx.request_protocol.as_ref().unwrap().eq_slice("01.10"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/\tHTTP\t\t/"));
}

#[test]
fn ParsedUriSupplied() {
    let mut t = HybridParsingTest::new(TestConfig());
    let tx_id = t.connp.request().unwrap().index;

    // Feed data to the parser.
    t.connp.state_request_start().unwrap();
    t.connp
        .parse_request_line(b"GET /?p=1&q=2 HTTP/1.0")
        .unwrap();

    let tx = t.connp.tx_mut(tx_id).unwrap();
    let u = Uri {
        path: Some(Bstr::from("/123")),
        ..Default::default()
    };
    tx.parsed_uri = Some(u);
    t.connp.state_request_line().unwrap();

    // Check the results now.
    let tx = t.connp.tx(tx_id).unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpProtocol::V1_0, tx.request_protocol_number);
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/?p=1&q=2"));
    let parsed_uri = tx.parsed_uri.as_ref().unwrap();
    assert!(parsed_uri.path.as_ref().unwrap().eq_slice("/123"));
}

#[test]
fn DoubleEncodedUriPath() {
    let mut cfg = TestConfig();
    cfg.set_double_decode_normalized_path(true);
    let mut t = HybridParsingTest::new(cfg);
    // Feed data to the parser.

    t.connp.state_request_start().unwrap();
    t.connp.parse_request_line(b"GET /%2500 HTTP/1.0").unwrap();
    t.connp.state_request_line().unwrap();

    // Check the results now.

    let tx = t.connp.request().unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpProtocol::V1_0, tx.request_protocol_number);
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/%2500"));
    let parsed_uri = tx.parsed_uri.as_ref().unwrap();
    assert!(parsed_uri.path.as_ref().unwrap().eq_slice("/%00"));
    assert!(tx.complete_normalized_uri.as_ref().unwrap().eq_slice("/\0"));
}

#[test]
fn DoubleEncodedUriQuery() {
    let mut cfg = TestConfig();
    cfg.set_double_decode_normalized_query(true);
    let mut t = HybridParsingTest::new(cfg);
    // Feed data to the parser.

    t.connp.state_request_start().unwrap();
    t.connp
        .parse_request_line(b"GET /?a=%2500 HTTP/1.0")
        .unwrap();
    t.connp.state_request_line().unwrap();

    // Check the results now.

    let tx = t.connp.request().unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpProtocol::V1_0, tx.request_protocol_number);
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/?a=%2500"));
    let parsed_uri = tx.parsed_uri.as_ref().unwrap();
    assert!(parsed_uri.path.as_ref().unwrap().eq_slice("/"));
    assert!(parsed_uri.query.as_ref().unwrap().eq_slice("a=%2500"));
    assert!(tx
        .complete_normalized_uri
        .as_ref()
        .unwrap()
        .eq_slice("/?a=\0"));
}

/// Test hybrid mode with one complete GET transaction; request then response
/// with no body. Used to crash in htp_connp_close().
#[test]
fn TestRepeatCallbacks() {
    let mut cfg = TestConfig();
    // Request callbacks
    register_user_callbacks(&mut cfg);
    let mut t = HybridParsingTest::new(cfg);

    let tx_id = t.connp.request().unwrap().index;

    // Configure user data and callbacks
    let tx = t.connp.tx_mut(tx_id).unwrap();
    tx.set_user_data(Box::new(HybridParsing_Get_User_Data::new()));

    // Make dummy parser data to satisfy callbacks
    let mut p = ParserData::from(b"" as &[u8]);

    // Request begins
    t.connp.state_request_start().unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_REQUEST_START_invoked);

    // Request line data
    t.connp.parse_request_line(b"GET / HTTP/1.0").unwrap();

    // Request line complete
    t.connp.state_request_line().unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_REQUEST_LINE_invoked);

    let tx = t.connp.tx(tx_id).unwrap();
    // Check request line data
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/"));
    assert!(tx.request_protocol.as_ref().unwrap().eq_slice("HTTP/1.0"));
    let parsed_uri = tx.parsed_uri.as_ref().unwrap();
    assert!(parsed_uri.path.as_ref().unwrap().eq_slice("/"));

    // Request headers complete
    t.connp.state_request_headers(&mut p).unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_REQUEST_HEADERS_invoked);

    // Request complete
    t.connp.state_request_complete(&mut p).unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_REQUEST_COMPLETE_invoked);

    // Response begins
    t.connp.state_response_start().unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_RESPONSE_START_invoked);

    // Response line data
    t.connp.parse_response_line(b"HTTP/1.1 200 OK\r\n").unwrap();

    // Response line complete
    t.connp.state_response_line().unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_RESPONSE_LINE_invoked);

    // Response headers complete
    t.connp.state_response_headers(&mut p).unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_RESPONSE_HEADERS_invoked);

    // Response complete
    t.connp.state_response_complete(&mut p).unwrap();
    let tx = t.connp.tx(tx_id).unwrap();
    let user_data = tx.user_data::<HybridParsing_Get_User_Data>().unwrap();
    assert_eq!(1, user_data.callback_REQUEST_START_invoked);
    assert_eq!(1, user_data.callback_REQUEST_LINE_invoked);
    assert_eq!(1, user_data.callback_REQUEST_HEADERS_invoked);
    assert_eq!(1, user_data.callback_REQUEST_COMPLETE_invoked);
    assert_eq!(1, user_data.callback_RESPONSE_START_invoked);
    assert_eq!(1, user_data.callback_RESPONSE_LINE_invoked);
    assert_eq!(1, user_data.callback_RESPONSE_HEADERS_invoked);
    assert_eq!(1, user_data.callback_RESPONSE_COMPLETE_invoked);
    assert_eq!(1, user_data.callback_TRANSACTION_COMPLETE_invoked);
}

/// Try response line with missing response code and message
#[test]
fn ResponseLineIncomplete() {
    let mut t = HybridParsingTest::new(TestConfig());

    // Make dummy parser data to satisfy callbacks
    let mut p = ParserData::from(b"" as &[u8]);

    t.connp.state_response_start().unwrap();
    t.connp.parse_response_line(b"HTTP/1.1").unwrap();
    let tx = t.connp.response().unwrap();
    assert!(tx.response_protocol.as_ref().unwrap().eq_slice("HTTP/1.1"));
    assert_eq!(HtpProtocol::V1_1, tx.response_protocol_number);
    assert!(tx.response_status.is_none());
    assert_eq!(HtpResponseNumber::INVALID, tx.response_status_number);
    assert!(tx.response_message.is_none());
    t.connp.state_response_complete(&mut p).unwrap();
}

/// Try response line with missing response message
#[test]
fn ResponseLineIncomplete1() {
    let mut t = HybridParsingTest::new(TestConfig());

    // Make dummy parser data to satisfy callbacks
    let mut p = ParserData::from(b"" as &[u8]);

    t.connp.state_response_start().unwrap();
    t.connp.parse_response_line(b"HTTP/1.1 200").unwrap();
    let tx = t.connp.response().unwrap();
    assert!(tx.response_protocol.as_ref().unwrap().eq_slice("HTTP/1.1"));
    assert_eq!(HtpProtocol::V1_1, tx.response_protocol_number);
    assert!(tx.response_status.as_ref().unwrap().eq_slice("200"));
    assert!(tx.response_status_number.eq_num(200));
    assert!(tx.response_message.is_none());
    t.connp.state_response_complete(&mut p).unwrap();
}
