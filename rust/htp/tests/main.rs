#![allow(non_snake_case)]
use htp::{
    bstr::Bstr,
    config::HtpServerPersonality,
    connection::ConnectionFlags,
    connection_parser::ParserData,
    error::Result,
    log::{HtpLogCode, HtpLogLevel},
    transaction::{
        HtpAuthType, HtpProtocol, HtpRequestProgress, HtpResponseNumber, HtpResponseProgress,
        HtpTransferCoding, Transaction,
    },
    util::{FlagOperations, HtpFlags},
};

use htp::test::{MainUserData, Test, TestConfig};

use std::iter::IntoIterator;

// import common testing utilities
mod common;

#[test]
fn AdHoc() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("00-adhoc.t").is_ok());
}

#[test]
fn Get() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("01-get.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/?p=%20"));

    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .query
        .as_ref()
        .unwrap()
        .eq_slice("p=%20"));
}

#[test]
fn GetSlice() {
    let mut t = Test::new(TestConfig());
    assert!(t
        .run_slice(
            b">>>
GET /?p=%20 HTTP/1.0
User-Agent: Mozilla


<<<
HTTP/1.0 200 OK
Date: Mon, 31 Aug 2009 20:25:50 GMT
Server: Apache
Connection: close
Content-Type: text/html
Content-Length: 12

Hello World!"
        )
        .is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/?p=%20"));

    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .query
        .as_ref()
        .unwrap()
        .eq_slice("p=%20"));
}

#[test]
fn GetEncodedRelPath() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("99-get.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert!(tx
        .request_hostname
        .as_ref()
        .unwrap()
        .eq_slice("www.example.com"));
    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .path
        .as_ref()
        .unwrap()
        .eq_slice("/images.gif"));
}

#[test]
fn ApacheHeaderParsing() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("02-header-test-apache2.t").is_ok());

    let tx = t.connp.tx(0).expect("expected tx to exist");

    let actual: Vec<(&[u8], &[u8])> = (&tx.request_headers)
        .into_iter()
        .map(|val| (val.name.as_slice(), val.value.as_slice()))
        .collect();

    let expected: Vec<(&[u8], &[u8])> = [
        ("Invalid-Folding", "1"),
        ("Valid-Folding", "2 2"),
        ("Normal-Header", "3"),
        ("Invalid Header Name", "4"),
        ("Same-Name-Headers", "5, 6"),
        ("Empty-Value-Header", ""),
        ("", "8, "),
        ("Header-With-LWS-After", "9"),
        ("Header-With-NUL", "BEFORE\0AFTER"),
    ]
    .iter()
    .map(|(key, val)| (key.as_bytes(), val.as_bytes()))
    .collect();
    assert_eq!(
        actual,
        expected,
        "{:?} != {:?}",
        actual
            .clone()
            .into_iter()
            .map(|(key, val)| (
                String::from_utf8_lossy(key).to_string(),
                String::from_utf8_lossy(val).to_string()
            ))
            .collect::<Vec<(String, String)>>(),
        expected
            .clone()
            .into_iter()
            .map(|(key, val)| (
                String::from_utf8_lossy(key).to_string(),
                String::from_utf8_lossy(val).to_string()
            ))
            .collect::<Vec<(String, String)>>(),
    );
}

#[test]
fn PostUrlencoded() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("03-post-urlencoded.t").is_ok());

    assert_eq!(2, t.connp.tx_size());

    // Transaction 1
    let tx = t.connp.tx(0).unwrap();

    assert_eq!(tx.request_progress, HtpRequestProgress::COMPLETE);
    assert_eq!(tx.response_progress, HtpResponseProgress::COMPLETE);

    assert_response_header_eq!(tx, "Server", "Apache");

    // Transaction 2
    let tx2 = t.connp.tx(1).unwrap();

    assert_eq!(tx2.request_progress, HtpRequestProgress::COMPLETE);
    assert_eq!(tx2.response_progress, HtpResponseProgress::COMPLETE);

    assert_response_header_eq!(tx2, "Server", "Apache");
}

#[test]
fn PostUrlencodedChunked() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("04-post-urlencoded-chunked.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(25, tx.request_message_len);
    assert_eq!(12, tx.request_entity_len);
}

#[test]
fn Expect() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("05-expect.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    // The interim header from the 100 response should not be among the final headers.
    assert!(tx.request_headers.get_nocase_nozero("Header1").is_none());
}

#[test]
fn UriNormal() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("06-uri-normal.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let _tx = t.connp.tx(0).unwrap();
}

#[test]
fn PipelinedConn() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("07-pipelined-connection.t").is_ok());

    assert_eq!(2, t.connp.tx_size());

    assert!(t.connp.conn.flags.is_set(ConnectionFlags::PIPELINED));

    let _tx = t.connp.tx(0).unwrap();
}

#[test]
fn NotPipelinedConn() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("08-not-pipelined-connection.t").is_ok());

    assert_eq!(2, t.connp.tx_size());

    assert!(!t.connp.conn.flags.is_set(ConnectionFlags::PIPELINED));

    let tx = t.connp.tx(0).unwrap();

    assert!(!tx.flags.is_set(HtpFlags::MULTI_PACKET_HEAD));
}

#[test]
fn MultiPacketRequest() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("09-multi-packet-request-head.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::MULTI_PACKET_HEAD));
}

#[test]
fn HeaderHostParsing() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("10-host-in-headers.t").is_ok());
    assert_eq!(4, t.connp.tx_size());

    let tx1 = t.connp.tx(0).unwrap();

    assert!(tx1
        .request_hostname
        .as_ref()
        .unwrap()
        .eq_slice("www.example.com"));

    let tx2 = t.connp.tx(1).unwrap();

    assert!(tx2
        .request_hostname
        .as_ref()
        .unwrap()
        .eq_slice("www.example.com."));

    let tx3 = t.connp.tx(2).unwrap();

    assert!(tx3
        .request_hostname
        .as_ref()
        .unwrap()
        .eq_slice("www.example.com"));

    let tx4 = t.connp.tx(3).unwrap();

    assert!(tx4
        .request_hostname
        .as_ref()
        .unwrap()
        .eq_slice("www.example.com"));
}

#[test]
fn ResponseWithoutContentLength() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("11-response-stream-closure.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());
}

#[test]
fn FailedConnectRequest() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("12-connect-request.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());
    assert!(tx.request_method.as_ref().unwrap().eq_slice("CONNECT"));
    assert!(tx
        .response_content_type
        .as_ref()
        .unwrap()
        .eq_slice("text/html"));
    assert!(tx
        .response_message
        .as_ref()
        .unwrap()
        .eq_slice("Method Not Allowed"));
    assert!(tx.response_status_number.eq_num(405));
}

#[test]
fn CompressedResponseContentType() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("13-compressed-response-gzip-ct.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    assert_eq!(187, tx.response_message_len);
    assert_eq!(225, tx.response_entity_len);
    assert!(tx
        .response_message
        .as_ref()
        .unwrap()
        .eq_slice("Moved Temporarily"));
}

#[test]
fn CompressedResponseChunked() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("14-compressed-response-gzip-chunked.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());

    assert_eq!(28261, tx.response_message_len);

    assert_eq!(159_590, tx.response_entity_len);
}

#[test]
fn SuccessfulConnectRequest() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("15-connect-complete.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    // TODO: Update the test_run_file() function to provide better
    //       simulation of real traffic. At the moment, it does not
    //       invoke inbound parsing after outbound parsing returns
    //       HTP_DATA_OTHER, which is why the check below fails.
    //assert!(tx.is_complete());

    assert!(tx.request_method.as_ref().unwrap().eq_slice("CONNECT"));

    assert!(tx.response_status_number.eq_num(200));
}

#[test]
fn ConnectRequestWithExtraData() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("16-connect-extra.t").is_ok());

    assert_eq!(2, t.connp.tx_size());

    let tx1 = t.connp.tx(0).unwrap();

    assert!(tx1.is_complete());
    assert!(tx1
        .response_content_type
        .as_ref()
        .unwrap()
        .eq_slice("text/html"));

    let tx2 = t.connp.tx(1).unwrap();

    assert!(tx2.is_complete());
}

#[test]
fn Multipart() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("17-multipart-1.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());
}

#[test]
fn CompressedResponseDeflate() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("18-compressed-response-deflate.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());

    assert_eq!(755, tx.response_message_len);

    assert_eq!(1433, tx.response_entity_len);
}

#[test]
fn UrlEncoded() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("19-urlencoded-test.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());

    assert!(tx.request_method.as_ref().unwrap().eq_slice("POST"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/?p=1&q=2"));
}

#[test]
fn AmbiguousHost() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("20-ambiguous-host.t").is_ok());

    assert_eq!(5, t.connp.tx_size());

    let tx1 = t.connp.tx(0).unwrap();

    assert!(tx1.is_complete());
    assert!(!tx1.flags.is_set(HtpFlags::HOST_AMBIGUOUS));

    let tx2 = t.connp.tx(1).unwrap();

    assert!(tx2.is_complete());
    assert!(tx2.flags.is_set(HtpFlags::HOST_AMBIGUOUS));
    assert!(tx2
        .request_hostname
        .as_ref()
        .unwrap()
        .eq_slice("example.com"));

    let tx3 = t.connp.tx(2).unwrap();

    assert!(tx3.is_complete());
    assert!(!tx3.flags.is_set(HtpFlags::HOST_AMBIGUOUS));
    assert!(tx3
        .request_hostname
        .as_ref()
        .unwrap()
        .eq_slice("www.example.com"));
    assert_eq!(Some(8001), tx3.request_port_number);

    let tx4 = t.connp.tx(3).unwrap();

    assert!(tx4.is_complete());
    assert!(tx4.flags.is_set(HtpFlags::HOST_AMBIGUOUS));
    assert!(tx4
        .request_hostname
        .as_ref()
        .unwrap()
        .eq_slice("www.example.com"));
    assert_eq!(Some(8002), tx4.request_port_number);

    let tx5 = t.connp.tx(4).unwrap();

    assert!(tx5.is_complete());
    assert!(!tx5.flags.is_set(HtpFlags::HOST_AMBIGUOUS));
    assert!(tx5
        .request_hostname
        .as_ref()
        .unwrap()
        .eq_slice("www.example.com"));
    assert_eq!(Some(80), tx5.request_port_number);
}

#[test]
fn Http_0_9() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("21-http09.t").is_ok());

    assert_eq!(1, t.connp.tx_size());
    assert!(!t.connp.conn.flags.is_set(ConnectionFlags::HTTP_0_9_EXTRA));

    let _tx = t.connp.tx(0).unwrap();
}

#[test]
fn Http11HostMissing() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("22-http_1_1-host_missing").is_ok());
    assert_eq!(1, t.connp.tx_size());
    let tx = t.connp.tx(0).unwrap();
    assert!(tx.flags.is_set(HtpFlags::HOST_MISSING));
}

#[test]
fn Http_0_9_Multiple() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("23-http09-multiple.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let _tx = t.connp.tx(0).unwrap();
}

#[test]
fn Http_0_9_Explicit() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("24-http09-explicit.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    assert!(!tx.is_protocol_0_9);
}

#[test]
fn SmallChunks() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("25-small-chunks.t").is_ok());
}

fn ConnectionParsing_RequestHeaderData_REQUEST_HEADER_DATA(
    tx: &mut Transaction,
    d: &ParserData,
) -> Result<()> {
    let mut counter = *tx.user_data::<i32>().unwrap_or(&0);
    let data = d.as_slice();
    match counter {
        0 => {
            if data != b"User-Agent:" {
                eprintln!("Mismatch in chunk 0");
                counter = -1;
            }
        }
        1 => {
            if data != b" Test" {
                eprintln!("Mismatch in chunk 1");
                counter = -1;
            }
        }
        2 => {
            if data != b" User" {
                eprintln!("Mismatch in chunk 2");
                counter = -1;
            }
        }
        3 => {
            if data != b" Agent\nHost: www.example.com\n\n" {
                eprintln!("Mismatch in chunk 3");
                counter = -1;
            }
        }
        _ => {
            if counter >= 0 {
                eprintln!("Seen more than 4 chunks");
                counter = -1;
            }
        }
    }

    if counter >= 0 {
        counter += 1;
    }
    tx.set_user_data(Box::new(counter));
    Ok(())
}

#[test]
fn RequestHeaderData() {
    let mut cfg = TestConfig();
    cfg.register_request_header_data(ConnectionParsing_RequestHeaderData_REQUEST_HEADER_DATA);
    let mut t = Test::new(cfg);
    assert!(t.run_file("26-request-headers-raw.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_eq!(4, *tx.user_data::<i32>().unwrap());
}

fn ConnectionParsing_RequestTrailerData_REQUEST_TRAILER_DATA(
    tx: &mut Transaction,
    d: &ParserData,
) -> Result<()> {
    let mut counter = *tx.user_data::<i32>().unwrap_or(&0);
    let data = d.as_slice();
    match counter {
        0 => {
            if data != b"Cookie:" {
                eprintln!("Mismatch in chunk 0");
                counter = -1;
            }
        }
        1 => {
            if data != b" 2\r\n\r\n" {
                eprintln!("Mismatch in chunk 1");
                counter = -2;
            }
        }
        _ => {
            if counter >= 0 {
                eprintln!("Seen more than 4 chunks");
                counter = -3;
            }
        }
    }

    if counter >= 0 {
        counter += 1;
    }
    tx.set_user_data(Box::new(counter));
    Ok(())
}

#[test]
fn RequestTrailerData() {
    let mut cfg = TestConfig();
    cfg.register_request_trailer_data(ConnectionParsing_RequestTrailerData_REQUEST_TRAILER_DATA);
    let mut t = Test::new(cfg);
    assert!(t.run_file("27-request-trailer-raw.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_eq!(2, *tx.user_data::<i32>().unwrap());
}

fn ConnectionParsing_ResponseHeaderData_RESPONSE_HEADER_DATA(
    tx: &mut Transaction,
    d: &ParserData,
) -> Result<()> {
    let mut counter = *tx.user_data::<i32>().unwrap_or(&0);
    let data = d.as_slice();
    match counter {
            0 => {
                if data != b"Date:" {
                    eprintln!("Mismatch in chunk 0");
                    counter = -1;
                }
            }
            1 => {
                if data != b" Mon," {
                    eprintln!("Mismatch in chunk 1");
                    counter = -2;
                }
            }
            2 => {
                if data != b" 31 Aug 2009 20:25:50 GMT\r\nServer:" {
                    eprintln!("Mismatch in chunk 2");
                    counter = -3;
                }
            }
            3 => {
                if data != b" Apache\r\nConnection: close\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n" {
                    eprintln!("Mismatch in chunk 3");
                    counter = -4;
                }
            }
            _ => {
                if counter >= 0 {
                    eprintln!("Seen more than 4 chunks");
                    counter = -5;
                }
            }
        }

    if counter >= 0 {
        counter += 1;
    }
    tx.set_user_data(Box::new(counter));
    Ok(())
}

#[test]
fn ResponseHeaderData() {
    let mut cfg = TestConfig();
    cfg.register_response_header_data(ConnectionParsing_ResponseHeaderData_RESPONSE_HEADER_DATA);
    let mut t = Test::new(cfg);
    assert!(t.run_file("28-response-headers-raw.t").is_ok());

    let tx = t.connp.tx(0).unwrap();
    assert_eq!(4, *tx.user_data::<i32>().unwrap());
}

fn ConnectionParsing_ResponseTrailerData_RESPONSE_TRAILER_DATA(
    tx: &mut Transaction,
    d: &ParserData,
) -> Result<()> {
    let mut counter = *tx.user_data::<i32>().unwrap_or(&0);
    let data = d.as_slice();
    match counter {
        0 => {
            if data != b"Set-Cookie:" {
                eprintln!("Mismatch in chunk 0");
                counter = -1;
            }
        }

        1 => {
            if data != b" name=" {
                eprintln!("Mismatch in chunk 1");
                counter = -2;
            }
        }

        2 => {
            if data != b"value\r\nAnother-Header:" {
                eprintln!("Mismatch in chunk 1");
                counter = -3;
            }
        }

        3 => {
            if data != b" Header-Value\r\n\r\n" {
                eprintln!("Mismatch in chunk 1");
                counter = -4;
            }
        }

        _ => {
            if counter >= 0 {
                eprintln!("Seen more than 4 chunks");
                counter = -5;
            }
        }
    }

    if counter >= 0 {
        counter += 1;
    }
    tx.set_user_data(Box::new(counter));
    Ok(())
}

#[test]
fn ResponseTrailerData() {
    let mut cfg = TestConfig();
    cfg.register_response_trailer_data(ConnectionParsing_ResponseTrailerData_RESPONSE_TRAILER_DATA);
    let mut t = Test::new(cfg);
    assert!(t.run_file("29-response-trailer-raw.t").is_ok());

    let tx = t.connp.tx(0).unwrap();
    assert_eq!(4, *tx.user_data::<i32>().unwrap());
}

#[test]
fn GetIPv6() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("30-get-ipv6.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));

    assert!(tx
        .request_uri
        .as_ref()
        .unwrap()
        .eq_slice("http://[::1]:8080/?p=%20"));

    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .hostname
        .as_ref()
        .unwrap()
        .eq_slice("[::1]"));
    assert_eq!(8080, tx.parsed_uri.as_ref().unwrap().port_number.unwrap());
    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .query
        .as_ref()
        .unwrap()
        .eq_slice("p=%20"));
}

#[test]
fn GetRequestLineNul() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("31-get-request-line-nul.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/?p=%20"));
}

#[test]
fn InvalidHostname1() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("32-invalid-hostname.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    assert!(tx.flags.is_set(HtpFlags::HOSTH_INVALID));
    assert!(tx.flags.is_set(HtpFlags::HOSTU_INVALID));
    assert!(tx.flags.is_set(HtpFlags::HOST_INVALID));
}

#[test]
fn InvalidHostname2() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("33-invalid-hostname.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(!tx.flags.is_set(HtpFlags::HOSTH_INVALID));
    assert!(tx.flags.is_set(HtpFlags::HOSTU_INVALID));
    assert!(tx.flags.is_set(HtpFlags::HOST_INVALID));
}

#[test]
fn InvalidHostname3() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("34-invalid-hostname.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::HOSTH_INVALID));
    assert!(!tx.flags.is_set(HtpFlags::HOSTU_INVALID));
    assert!(tx.flags.is_set(HtpFlags::HOST_INVALID));
}

#[test]
fn EarlyResponse() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("35-early-response.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert!(tx.is_complete());
}

#[test]
fn InvalidRequest1() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("36-invalid-request-1-invalid-c-l.t").is_err());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::HEADERS, tx.request_progress);

    assert!(tx.flags.is_set(HtpFlags::REQUEST_INVALID));
    assert!(tx.flags.is_set(HtpFlags::REQUEST_INVALID_C_L));

    assert!(tx.request_hostname.is_some());
}

#[test]
fn InvalidRequest2() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("37-invalid-request-2-t-e-and-c-l.t").is_ok());
    // No error, flags only.

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert!(tx.flags.is_set(HtpFlags::REQUEST_SMUGGLING));

    assert!(tx.request_hostname.is_some());
}

#[test]
fn InvalidRequest3() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("38-invalid-request-3-invalid-t-e.t").is_err());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::HEADERS, tx.request_progress);

    assert!(tx.flags.is_set(HtpFlags::REQUEST_INVALID));
    assert!(tx.flags.is_set(HtpFlags::REQUEST_INVALID_T_E));

    assert!(tx.request_hostname.is_some());
}

#[test]
fn AutoDestroyCrash() {
    let mut cfg = TestConfig();
    cfg.set_tx_auto_destroy(true);
    let mut t = Test::new(cfg);
    assert!(t.run_file("39-auto-destroy-crash.t").is_ok());

    assert_eq!(4, t.connp.tx_size());
}

#[test]
fn AuthBasic() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("40-auth-basic.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpAuthType::BASIC, tx.request_auth_type);

    assert!(tx.request_auth_username.as_ref().unwrap().eq_slice("ivanr"));
    assert!(tx
        .request_auth_password
        .as_ref()
        .unwrap()
        .eq_slice("secret"));
}

#[test]
fn AuthDigest() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("41-auth-digest.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert_eq!(HtpAuthType::DIGEST, tx.request_auth_type);

    assert!(tx.request_auth_username.as_ref().unwrap().eq_slice("ivanr"));

    assert!(tx.request_auth_password.is_none());
}

#[test]
fn Unknown_MethodOnly() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("42-unknown-method_only.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert!(tx.request_method.as_ref().unwrap().eq_slice("HELLO"));

    assert!(tx.request_uri.is_none());

    assert!(tx.is_protocol_0_9);
}

#[test]
fn InvalidHtpProtocol() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("43-invalid-protocol.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert_eq!(HtpProtocol::INVALID, tx.request_protocol_number);
}

#[test]
fn AuthBasicInvalid() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("44-auth-basic-invalid.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert_eq!(HtpAuthType::BASIC, tx.request_auth_type);

    assert!(tx.request_auth_username.is_none());

    assert!(tx.request_auth_password.is_none());

    assert!(tx.flags.is_set(HtpFlags::AUTH_INVALID));
}

#[test]
fn AuthDigestUnquotedUsername() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("45-auth-digest-unquoted-username.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert_eq!(HtpAuthType::DIGEST, tx.request_auth_type);

    assert!(tx.request_auth_username.is_none());

    assert!(tx.request_auth_password.is_none());

    assert!(tx.flags.is_set(HtpFlags::AUTH_INVALID));
}

#[test]
fn AuthDigestInvalidUsername1() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("46-auth-digest-invalid-username.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert_eq!(HtpAuthType::DIGEST, tx.request_auth_type);

    assert!(tx.request_auth_username.is_none());

    assert!(tx.request_auth_password.is_none());

    assert!(tx.flags.is_set(HtpFlags::AUTH_INVALID));
}

#[test]
fn AuthUnrecognized() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("47-auth-unrecognized.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert_eq!(HtpAuthType::UNRECOGNIZED, tx.request_auth_type);

    assert!(tx.request_auth_username.is_none());

    assert!(tx.request_auth_password.is_none());
}

#[test]
fn InvalidResponseHeaders1() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("48-invalid-response-headers-1.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    assert_eq!(8, tx.response_headers.size());

    assert_response_header_eq!(tx, "", "No Colon");
    assert_response_header_flag_contains!(tx, "", HtpFlags::FIELD_INVALID);
    assert_response_header_flag_contains!(tx, "", HtpFlags::FIELD_UNPARSEABLE);

    assert_response_header_eq!(tx, "Lws", "After Header Name");
    assert_response_header_flag_contains!(tx, "Lws", HtpFlags::FIELD_INVALID);

    assert_response_header_eq!(tx, "Header@Name", "Not Token");
    assert_response_header_flag_contains!(tx, "Header@Name", HtpFlags::FIELD_INVALID);
}

#[test]
fn InvalidResponseHeaders2() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("49-invalid-response-headers-2.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    assert_eq!(6, tx.response_headers.size());

    assert_response_header_eq!(tx, "", "Empty Name");
    assert_response_header_flag_contains!(tx, "", HtpFlags::FIELD_INVALID);
}

#[test]
fn Util() {
    use htp::{htp_error, htp_log};
    let mut cfg = TestConfig();
    cfg.log_level = HtpLogLevel::NONE;
    let mut t = Test::new(cfg);
    assert!(t.run_file("50-util.t").is_ok());
    // Explicitly add a log message to verify it is not logged
    htp_error!(&mut t.connp.logger, HtpLogCode::UNKNOWN, "Log message");
    assert_eq!(0, t.connp.conn.get_logs().len());
}

#[test]
fn GetIPv6Invalid() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("51-get-ipv6-invalid.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));

    assert!(tx
        .request_uri
        .as_ref()
        .unwrap()
        .eq_slice("http://[::1:8080/?p=%20"));
    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .hostname
        .as_ref()
        .unwrap()
        .eq_slice("[::1:8080"));
}

#[test]
fn InvalidPath() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("52-invalid-path.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));

    assert!(tx
        .request_uri
        .as_ref()
        .unwrap()
        .eq_slice("invalid/path?p=%20"));
    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .path
        .as_ref()
        .unwrap()
        .eq_slice("invalid/path"));
}

#[test]
fn PathUtf8_None() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("53-path-utf8-none.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(!tx.flags.is_set(HtpFlags::PATH_UTF8_VALID));
    assert!(!tx.flags.is_set(HtpFlags::PATH_UTF8_OVERLONG));
    assert!(!tx.flags.is_set(HtpFlags::PATH_HALF_FULL_RANGE));
}

#[test]
fn PathUtf8_Valid() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("54-path-utf8-valid.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_UTF8_VALID));
}

#[test]
fn PathUtf8_Overlong2() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("55-path-utf8-overlong-2.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_UTF8_OVERLONG));
}

#[test]
fn PathUtf8_Overlong3() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("56-path-utf8-overlong-3.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_UTF8_OVERLONG));
}

#[test]
fn PathUtf8_Overlong4() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("57-path-utf8-overlong-4.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_UTF8_OVERLONG));
}

#[test]
fn PathUtf8_Invalid() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("58-path-utf8-invalid.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_UTF8_INVALID));
    assert!(!tx.flags.is_set(HtpFlags::PATH_UTF8_VALID));
}

#[test]
fn PathUtf8_FullWidth() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("59-path-utf8-fullwidth.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_HALF_FULL_RANGE));
}

#[test]
fn PathUtf8_Decode_Valid() {
    let mut cfg = TestConfig();
    cfg.set_utf8_convert_bestfit(true);
    let mut t = Test::new(cfg);

    assert!(t.run_file("54-path-utf8-valid.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .path
        .as_ref()
        .unwrap()
        .eq_slice("/Ristic.txt"));
}

#[test]
fn PathUtf8_Decode_Overlong2() {
    let mut cfg = TestConfig();
    cfg.set_utf8_convert_bestfit(true);
    let mut t = Test::new(cfg);
    assert!(t.run_file("55-path-utf8-overlong-2.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_UTF8_OVERLONG));

    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .path
        .as_ref()
        .unwrap()
        .eq_slice("/&.txt"));
}

#[test]
fn PathUtf8_Decode_Overlong3() {
    let mut cfg = TestConfig();
    cfg.set_utf8_convert_bestfit(true);
    let mut t = Test::new(cfg);

    assert!(t.run_file("56-path-utf8-overlong-3.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_UTF8_OVERLONG));

    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .path
        .as_ref()
        .unwrap()
        .eq_slice("/&.txt"));
}

#[test]
fn PathUtf8_Decode_Overlong4() {
    let mut cfg = TestConfig();
    cfg.set_utf8_convert_bestfit(true);
    let mut t = Test::new(cfg);

    assert!(t.run_file("57-path-utf8-overlong-4.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_UTF8_OVERLONG));
    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .path
        .as_ref()
        .unwrap()
        .eq_slice("/&.txt"));
}

#[test]
fn PathUtf8_Decode_Invalid() {
    let mut cfg = TestConfig();
    cfg.set_utf8_convert_bestfit(true);
    let mut t = Test::new(cfg);
    assert!(t.run_file("58-path-utf8-invalid.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_UTF8_INVALID));
    assert!(!tx.flags.is_set(HtpFlags::PATH_UTF8_VALID));
    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .path
        .as_ref()
        .unwrap()
        .eq_slice("/Ristic?.txt"));
}

#[test]
fn PathUtf8_Decode_FullWidth() {
    let mut cfg = TestConfig();
    cfg.set_utf8_convert_bestfit(true);
    let mut t = Test::new(cfg);

    assert!(t.run_file("59-path-utf8-fullwidth.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.flags.is_set(HtpFlags::PATH_HALF_FULL_RANGE));

    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .path
        .as_ref()
        .unwrap()
        .eq_slice("/&.txt"));
}

#[test]
fn EmptyLineBetweenRequests() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("61-empty-line-between-requests.t").is_ok());

    assert_eq!(2, t.connp.tx_size());

    let _tx = t.connp.tx(1).unwrap();

    /*part of previous request body assert_eq!(1, tx.request_ignored_lines);*/
}

#[test]
fn PostNoBody() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("62-post-no-body.t").is_ok());

    assert_eq!(2, t.connp.tx_size());

    let tx1 = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx1.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx1.response_progress);
    assert!(tx1
        .response_content_type
        .as_ref()
        .unwrap()
        .eq_slice("text/html"));

    let tx2 = t.connp.tx(1).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx2.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx2.response_progress);
    assert!(tx2
        .response_content_type
        .as_ref()
        .unwrap()
        .eq_slice("text/html"));
}

#[test]
fn PostChunkedValid1() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("63-post-chunked-invalid-1.t").is_err());
}

#[test]
fn PostChunkedInvalid2() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("64-post-chunked-invalid-2.t").is_err());
}

#[test]
fn PostChunkedInvalid3() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("65-post-chunked-invalid-3.t").is_err());
}

#[test]
fn PostChunkedSplitChunk() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("66-post-chunked-split-chunk.t").is_ok());

    assert_eq!(1, t.connp.tx_size());
}

#[test]
fn LongRequestLine1() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("67-long-request-line.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx
        .request_uri
        .as_ref()
        .unwrap()
        .eq_slice("/0123456789/0123456789/"));
}

#[test]
fn LongRequestLine2() {
    let mut cfg = TestConfig();
    cfg.set_field_limit(16);
    let mut t = Test::new(cfg);

    assert!(t.run_file("67-long-request-line.t").is_err());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::LINE, tx.request_progress);
}

#[test]
fn InvalidRequestHeader() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("68-invalid-request-header.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).expect("expected at least one transaction");

    assert_request_header_eq!(tx, "Header-With-NUL", "BEFORE  \0AFTER");
}

#[test]
fn TestGenericPersonality() {
    let mut cfg = TestConfig();
    cfg.set_server_personality(HtpServerPersonality::IDS)
        .unwrap();
    let mut t = Test::new(cfg);

    assert!(t.run_file("02-header-test-apache2.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let _tx = t.connp.tx(0).unwrap();
}

#[test]
fn LongResponseHeader() {
    let mut cfg = TestConfig();
    cfg.set_field_limit(18);
    let mut t = Test::new(cfg);

    assert!(t.run_file("69-long-response-header.t").is_err());

    let tx = t.connp.tx(0).unwrap();

    //error first assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::HEADERS, tx.response_progress);
}

#[test]
fn ResponseInvalidChunkLength() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("70-response-invalid-chunk-length.t").is_ok());
}

#[test]
fn ResponseSplitChunk() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("71-response-split-chunk.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn ResponseBody() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("72-response-split-body.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn ResponseContainsTeAndCl() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("73-response-te-and-cl.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    assert!(tx.flags.is_set(HtpFlags::REQUEST_SMUGGLING));
}

#[test]
fn ResponseMultipleCl() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("74-response-multiple-cl.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    assert!(tx.flags.is_set(HtpFlags::REQUEST_SMUGGLING));

    assert_response_header_eq!(tx, "Content-Length", "12");
    assert_response_header_flag_contains!(tx, "Content-Length", HtpFlags::FIELD_REPEATED);
}

#[test]
fn ResponseMultipleClMismatch() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("88-response-multiple-cl-mismatch.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    assert!(tx.flags.is_set(HtpFlags::REQUEST_SMUGGLING));

    assert_response_header_eq!(tx, "Content-Length", "12");
    assert_response_header_flag_contains!(tx, "Content-Length", HtpFlags::FIELD_REPEATED);

    let logs = t.connp.conn.get_logs();
    assert_eq!(2, logs.len());
    assert_eq!(
        logs.first().unwrap().msg.msg,
        "Ambiguous response C-L value"
    );
    assert_eq!(HtpLogLevel::WARNING, logs.first().unwrap().msg.level);
    assert_eq!(logs.get(1).unwrap().msg.msg, "Repetition for header");
    assert_eq!(HtpLogLevel::WARNING, logs.get(1).unwrap().msg.level);
}

#[test]
fn ResponseInvalidCl() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("75-response-invalid-cl.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    assert!(!tx.flags.is_set(HtpFlags::REQUEST_SMUGGLING));
}

#[test]
fn ResponseNoBody() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("76-response-no-body.t").is_ok());

    assert_eq!(2, t.connp.tx_size());

    let tx1 = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx1.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx1.response_progress);

    assert_response_header_eq!(tx1, "Server", "Apache");

    let tx2 = t.connp.tx(1).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx2.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx2.response_progress);

    assert!(tx1 != tx2);
}

#[test]
fn ResponseFoldedHeaders() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("77-response-folded-headers.t").is_ok());

    assert_eq!(2, t.connp.tx_size());

    let tx1 = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx1.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx1.response_progress);

    assert_response_header_eq!(tx1, "Server", "Apache Server");

    let tx2 = t.connp.tx(1).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx2.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx2.response_progress);
}

#[test]
fn ResponseNoStatusHeaders() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("78-response-no-status-headers.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn ConnectInvalidHostport() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("79-connect-invalid-hostport.t").is_ok());

    assert_eq!(2, t.connp.tx_size());
}

#[test]
fn HostnameInvalid1() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("80-hostname-invalid-1.t").is_ok());

    assert_eq!(1, t.connp.tx_size());
}

#[test]
fn HostnameInvalid2() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("81-hostname-invalid-2.t").is_ok());

    assert_eq!(1, t.connp.tx_size());
}

#[test]
fn AuthDigestInvalidUsername2() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("83-auth-digest-invalid-username-2.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert_eq!(HtpAuthType::DIGEST, tx.request_auth_type);

    assert!(tx.request_auth_username.is_none());

    assert!(tx.request_auth_password.is_none());

    assert!(tx.flags.is_set(HtpFlags::AUTH_INVALID));
}

#[test]
fn ResponseNoStatusHeaders2() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("84-response-no-status-headers-2.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

// Test was commented out of libhtp
//#[test]
//fn ZeroByteRequestTimeout() {
//    let mut t = Test::new(TestConfig());
//unsafe {
//    assert!(t.run_file("85-zero-byte-request-timeout.t").is_ok());
//
//    assert_eq!(1, t.connp.tx_size());
//
//    let tx = t.connp.conn.get_tx(0);
//    assert!(!tx.is_null());
//
//    assert_eq!(HtpRequestProgress::NOT_STARTED, tx.request_progress);
//    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
//}}

#[test]
fn PartialRequestTimeout() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("86-partial-request-timeout.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn IncorrectHostAmbiguousWarning() {
    let mut t = Test::new(TestConfig());
    assert!(t
        .run_file("87-issue-55-incorrect-host-ambiguous-warning.t")
        .is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx
        .parsed_uri_raw
        .as_ref()
        .unwrap()
        .port
        .as_ref()
        .unwrap()
        .eq_slice("443"));
    assert!(tx
        .parsed_uri_raw
        .as_ref()
        .unwrap()
        .hostname
        .as_ref()
        .unwrap()
        .eq_slice("www.example.com"));
    assert_eq!(
        443,
        tx.parsed_uri_raw.as_ref().unwrap().port_number.unwrap()
    );

    assert!(tx
        .request_hostname
        .as_ref()
        .unwrap()
        .eq_slice("www.example.com"));

    assert!(!tx.flags.is_set(HtpFlags::HOST_AMBIGUOUS));
}

#[test]
fn GetWhitespace() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("89-get-whitespace.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice(" GET"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/?p=%20"));
    assert!(tx
        .parsed_uri
        .as_ref()
        .unwrap()
        .query
        .as_ref()
        .unwrap()
        .eq_slice("p=%20"));
}

#[test]
fn RequestUriTooLarge() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("90-request-uri-too-large.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn RequestInvalid() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("91-request-unexpected-body.t").is_ok());

    assert_eq!(2, t.connp.tx_size());

    let mut tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("POST"));
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    tx = t.connp.tx(1).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::NOT_STARTED, tx.response_progress);
}

#[test]
fn Http_0_9_MethodOnly() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("92-http_0_9-method_only.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/"));
    assert!(tx.is_protocol_0_9);
}

#[test]
fn CompressedResponseDeflateAsGzip() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("93-compressed-response-deflateasgzip.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());

    assert_eq!(755, tx.response_message_len);
    assert_eq!(1433, tx.response_entity_len);
}

#[test]
fn CompressedResponseZlibAsDeflate() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-118.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    assert!(tx.is_complete());

    assert_response_header_eq!(
        tx,
        "content-disposition",
        "attachment; filename=\"eicar.txt\""
    );
    assert_response_header_eq!(tx, "content-encoding", "deflate");
    assert_eq!(68, tx.response_entity_len);
    let user_data = tx.user_data::<MainUserData>().unwrap();
    assert!(user_data.request_data.is_empty());
    assert_eq!(1, user_data.response_data.len());
    let chunk = &user_data.response_data[0];
    assert_eq!(
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".as_ref(),
        chunk.as_slice()
    );
}

#[test]
fn CompressedResponseMultiple() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("94-compressed-response-multiple.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());

    assert_eq!(51, tx.response_message_len);
    assert_eq!(25, tx.response_entity_len);
}

#[test]
fn CompressedResponseBombLimitOkay() {
    let mut cfg = TestConfig();
    cfg.compression_options.set_bomb_limit(0);
    let mut t = Test::new(cfg);

    assert!(t.run_file("14-compressed-response-gzip-chunked.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());

    assert_eq!(28261, tx.response_message_len);
    assert_eq!(159_590, tx.response_entity_len);
}

#[test]
fn CompressedResponseBombLimitExceeded() {
    let mut cfg = TestConfig();
    cfg.compression_options.set_bomb_limit(0);
    cfg.compression_options.set_bomb_ratio(2);
    let mut t = Test::new(cfg);

    assert!(t.run_file("14-compressed-response-gzip-chunked.t").is_err());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    assert!(!tx.is_complete());

    assert_eq!(1208, tx.response_message_len);
    assert_eq!(2608, tx.response_entity_len);
}

#[test]
fn CompressedResponseTimeLimitExceeded() {
    let mut cfg = TestConfig();
    cfg.compression_options.set_time_limit(0);
    let mut t = Test::new(cfg);

    assert!(t.run_file("14-compressed-response-gzip-chunked.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    assert!(tx.is_complete());

    assert_eq!(28261, tx.response_message_len);
    assert_eq!(29656, tx.response_entity_len);
}

#[test]
fn CompressedResponseGzipAsDeflate() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("95-compressed-response-gzipasdeflate.t").is_ok());
    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());

    assert_eq!(187, tx.response_message_len);
    assert_eq!(225, tx.response_entity_len);
}

#[test]
fn CompressedResponseLzma() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("96-compressed-response-lzma.t").is_ok());
    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());

    assert_eq!(90, tx.response_message_len);
    assert_eq!(68, tx.response_entity_len);
}

#[test]
fn CompressedResponseLzmaDisabled() {
    let mut cfg = TestConfig();
    cfg.compression_options.set_lzma_memlimit(0);
    let mut t = Test::new(cfg);

    assert!(t.run_file("96-compressed-response-lzma.t").is_ok());
    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    assert!(tx.is_complete());

    assert_eq!(90, tx.response_message_len);
    assert_eq!(90, tx.response_entity_len);
}

#[test]
fn CompressedResponseLzmaMemlimit() {
    let mut cfg = TestConfig();
    cfg.compression_options.set_lzma_memlimit(1);
    let mut t = Test::new(cfg);

    assert!(t.run_file("96-compressed-response-lzma.t").is_ok());
    assert_eq!(1, t.connp.tx_size());
    let tx = t.connp.tx(0).unwrap();
    assert!(tx.is_complete());
    assert_eq!(90, tx.response_message_len);
    assert_eq!(72, tx.response_entity_len);
    assert!(tx.response_message.as_ref().unwrap().eq_slice("ok"));
}

#[test]
fn RequestsCut() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("97-requests-cut.t").is_ok());

    assert_eq!(2, t.connp.tx_size());
    let mut tx = t.connp.tx(0).unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    tx = t.connp.tx(1).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
}

#[test]
fn ResponsesCut() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("98-responses-cut.t").is_ok());

    assert_eq!(2, t.connp.tx_size());
    let mut tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert!(tx.response_status_number.eq_num(200));
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    tx = t.connp.tx(1).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert!(tx.response_status_number.eq_num(200));
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn AuthDigest_EscapedQuote() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("100-auth-digest-escaped-quote.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);

    assert_eq!(HtpAuthType::DIGEST, tx.request_auth_type);

    assert!(tx
        .request_auth_username
        .as_ref()
        .unwrap()
        .eq_slice("ivan\"r\""));

    assert!(tx.request_auth_password.is_none());
}

#[test]
fn Tunnelled1() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("106-tunnelled-1.t").is_ok());
    assert_eq!(2, t.connp.tx_size());
    let tx1 = t.connp.tx(0).unwrap();

    assert!(tx1.request_method.as_ref().unwrap().eq_slice("CONNECT"));
    let tx2 = t.connp.tx(1).unwrap();

    assert!(tx2.request_method.as_ref().unwrap().eq_slice("GET"));
}

#[test]
fn Expect100() {
    let mut t = Test::new(TestConfig());

    assert!(t.run_file("105-expect-100.t").is_ok());
    assert_eq!(2, t.connp.tx_size());
    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("PUT"));
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert!(tx.response_status_number.eq_num(401));
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    let tx = t.connp.tx(1).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("POST"));
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert!(tx.response_status_number.eq_num(200));
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn UnknownStatusNumber() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("107-response_unknown_status.t").is_ok());
    assert_eq!(1, t.connp.tx_size());
    let tx = t.connp.tx(0).unwrap();

    assert_eq!(tx.response_status_number, HtpResponseNumber::UNKNOWN);
}

#[test]
fn ResponseHeaderCrOnly() {
    // Content-Length terminated with \r only.
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("108-response-headers-cr-only.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_eq!(2, tx.response_headers.size());
    // Check response headers
    assert_response_header_eq!(tx, "content-type", "text/html");
    assert_response_header_eq!(tx, "Content-Length", "7");
}

#[test]
fn ResponseHeaderDeformedEOL() {
    // Content-Length terminated with \n\r\r\n\r\n only.
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("109-response-headers-deformed-eol.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_eq!(2, tx.response_headers.size());
    // Check response headers
    assert_response_header_eq!(tx, "content-type", "text/html");
    assert_response_header_eq!(tx, "content-length", "6");
    let logs = t.connp.conn.get_logs();
    let log_message_count = logs.len();
    assert_eq!(log_message_count, 2);
    assert_eq!(logs.first().unwrap().msg.code, HtpLogCode::DEFORMED_EOL);

    let user_data = tx.user_data::<MainUserData>().unwrap();
    assert!(user_data.request_data.is_empty());
    assert_eq!(2, user_data.response_data.len());
    assert_eq!(b"abcdef".as_ref(), user_data.response_data[0].as_slice());
}

#[test]
fn ResponseFoldedHeaders2() {
    // Space folding char
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("110-response-folded-headers-2.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    assert_response_header_eq!(tx, "Server", "Apache Server");
    assert_eq!(3, tx.response_headers.size());
}

#[test]
fn ResponseHeadersChunked() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("111-response-headers-chunked.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    assert_eq!(2, tx.response_headers.size());

    assert_response_header_eq!(tx, "content-type", "text/html");
    assert_response_header_eq!(tx, "content-length", "12");
}

#[test]
fn ResponseHeadersChunked2() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("112-response-headers-chunked-2.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    assert_eq!(2, tx.response_headers.size());

    assert_response_header_eq!(tx, "content-type", "text/html");
    assert_response_header_eq!(tx, "content-length", "12");
}

#[test]
fn ResponseMultipartRanges() {
    // This should be is_ok() once multipart/byteranges is handled in response parsing
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("113-response-multipart-byte-ranges.t").is_err());
}

#[test]
fn Http2Upgrade() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("114-http-2-upgrade.t").is_ok());

    assert_eq!(2, t.connp.tx_size());
    assert!(!t.connp.tx(0).unwrap().is_http_2_upgrade);
    assert!(t.connp.tx(1).unwrap().is_http_2_upgrade);
}

#[test]
fn AuthBearer() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("115-auth-bearer.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpAuthType::BEARER, tx.request_auth_type);

    assert!(tx
        .request_auth_token
        .as_ref()
        .unwrap()
        .eq_slice("mF_9.B5f-4.1JqM"));
}

#[test]
fn HttpCloseHeaders() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("http-close-headers.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert!(tx.request_method.as_ref().unwrap().eq_slice("GET"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/"));

    assert_eq!(HtpProtocol::V1_1, tx.request_protocol_number);
    assert_eq!(HtpProtocol::V1_0, tx.response_protocol_number);

    assert_request_header_eq!(tx, "Host", "100.64.0.200");
    assert_request_header_eq!(tx, "Connection", "keep-alive");
    assert_request_header_eq!(tx, "Accept-Encoding", "gzip, deflate");
    assert_request_header_eq!(tx, "Accept", "*/*");
    assert_request_header_eq!(tx, "User-Agent", "python-requests/2.21.0");
    assert_response_header_eq!(tx, "Server", "ng1nx");

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn HttpStartFromResponse() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("http-start-from-response.t").is_ok());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.is_none());
    assert_eq!(
        tx.request_uri,
        Some(Bstr::from("/libhtp::request_uri_not_seen"))
    );
    assert!(tx.response_status_number.eq_num(200));

    assert_eq!(HtpProtocol::UNKNOWN, tx.request_protocol_number);
    assert_eq!(HtpProtocol::V1_1, tx.response_protocol_number);

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    let tx = t.connp.tx(1).unwrap();
    assert_eq!(tx.request_method, Some(Bstr::from("GET")));
    assert_eq!(tx.request_uri, Some(Bstr::from("/favicon.ico")));
    assert!(tx.response_status_number.eq_num(404));

    assert_eq!(HtpProtocol::V1_1, tx.request_protocol_number);
    assert_eq!(HtpProtocol::V1_1, tx.response_protocol_number);

    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);

    let logs = t.connp.conn.get_logs();
    assert_eq!(1, logs.len());
    assert_eq!(
        logs.first().unwrap().msg.msg,
        "Unable to match response to request"
    );
    assert_eq!(HtpLogLevel::ERROR, logs.first().unwrap().msg.level);
}

#[test]
fn RequestCompression() {
    let mut cfg = TestConfig();
    cfg.set_request_decompression(true);
    let mut t = Test::new(cfg);

    assert!(t.run_file("116-request-compression.t").is_ok());
    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());

    assert_eq!(1355, tx.request_message_len);
    assert_eq!(2614, tx.request_entity_len);
}

#[test]
fn RequestResponseCompression() {
    let mut cfg = TestConfig();
    cfg.set_request_decompression(true);
    let mut t = Test::new(cfg);

    assert!(t.run_file("117-request-response-compression.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.is_complete());

    assert_eq!(1355, tx.request_message_len);
    assert_eq!(2614, tx.request_entity_len);

    assert_eq!(51, tx.response_message_len);
    assert_eq!(25, tx.response_entity_len);
}

#[test]
fn AmbiguousEOL() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("119-ambiguous-eol.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();

    assert!(tx.request_method.as_ref().unwrap().eq_slice("POST"));
    assert!(tx.request_uri.as_ref().unwrap().eq_slice("/"));
    assert_eq!(HtpProtocol::V1_0, tx.request_protocol_number);

    assert_eq!(HtpProtocol::V1_0, tx.response_protocol_number);
    assert!(tx.response_status_number.eq_num(200));
}

// Evader Tests
#[test]
fn HttpEvader017() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-017.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/chunked/eicar.txt/cr-size");
    assert_evader_response!(tx);
    assert_response_header_eq!(tx, "transfer-encoding", "chunked");
    assert_eq!(68, tx.response_entity_len);
    assert_eq!(101, tx.response_message_len);
    let user_data = tx.user_data::<MainUserData>().unwrap();
    assert!(user_data.request_data.is_empty());
    assert_eq!(5, user_data.response_data.len());
    assert_eq!(
        b"X5O!P%@AP[4\\PZX".as_ref(),
        user_data.response_data[0].as_slice()
    );
    assert_eq!(
        b"54(P^)7CC)7}$EI".as_ref(),
        user_data.response_data[1].as_slice()
    );
    assert_eq!(
        b"CAR-STANDARD-AN".as_ref(),
        user_data.response_data[2].as_slice()
    );
    assert_eq!(
        b"TIVIRUS-TEST-FI".as_ref(),
        user_data.response_data[3].as_slice()
    );
    assert_eq!(b"LE!$H+H*".as_ref(), user_data.response_data[4].as_slice());
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn HttpEvader018() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-018.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/chunked/eicar.txt/lf-size");
    assert_evader_response!(tx);
    assert_response_header_eq!(tx, "transfer-encoding", "chunked");
    assert_eq!(68, tx.response_entity_len);
    assert_eq!(101, tx.response_message_len);
    let user_data = tx.user_data::<MainUserData>().unwrap();
    assert!(user_data.request_data.is_empty());
    assert_eq!(5, user_data.response_data.len());
    assert_eq!(
        b"X5O!P%@AP[4\\PZX".as_ref(),
        user_data.response_data[0].as_slice()
    );
    assert_eq!(
        b"54(P^)7CC)7}$EI".as_ref(),
        user_data.response_data[1].as_slice()
    );
    assert_eq!(
        b"CAR-STANDARD-AN".as_ref(),
        user_data.response_data[2].as_slice()
    );
    assert_eq!(
        b"TIVIRUS-TEST-FI".as_ref(),
        user_data.response_data[3].as_slice()
    );
    assert_eq!(b"LE!$H+H*".as_ref(), user_data.response_data[4].as_slice());
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn HttpEvader044() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-044.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/chunked/eicar.txt/chunked,http10,do_clen");
    assert_eq!(HtpProtocol::V1_0, tx.response_protocol_number);
    assert!(tx.response_status_number.eq_num(200));
    assert_response_header_eq!(tx, "content-type", "application/octet-stream");
    assert_response_header_eq!(
        tx,
        "content-disposition",
        "attachment; filename=\"eicar.txt\""
    );
    assert_response_header_eq!(tx, "transfer-encoding", "chunked");
    assert_response_header_eq!(tx, "connection", "close");
    assert_eq!(68, tx.response_entity_len);
    assert_eq!(68, tx.response_message_len);
    let user_data = tx.user_data::<MainUserData>().unwrap();
    assert!(user_data.request_data.is_empty());
    assert_eq!(1, user_data.response_data.len());
    let chunk = &user_data.response_data[0];
    assert_eq!(
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".as_ref(),
        chunk.as_slice()
    );
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn HttpEvader059() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-059.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/chunked/eicar.txt/chunkednl-");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader060() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-060.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/chunked/eicar.txt/nl-nl-chunked");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader061() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-061.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/chunked/eicar.txt/nl-nl-chunked-nl-");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}
#[test]
fn HttpEvader078() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-078.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/chunked/eicar.txt/chunkedcr-,do_clen");
    assert_evader_response!(tx);
    assert_response_header_eq!(tx, "transfer-encoding", "chunked");
    assert_eq!(68, tx.response_entity_len);
    assert_eq!(68, tx.response_message_len);
    let user_data = tx.user_data::<MainUserData>().unwrap();
    assert!(user_data.request_data.is_empty());
    assert_eq!(1, user_data.response_data.len());
    let chunk = &user_data.response_data[0];
    assert_eq!(
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".as_ref(),
        chunk.as_slice()
    );
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn HttpEvader130() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("http-evader-130.t").is_err());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(
        tx,
        "/compressed/eicar.txt/ce%3Adeflate-nl-,-nl-deflate-nl-;deflate;deflate"
    );
    assert_evader_response!(tx);
    assert_response_header_eq!(tx, "Content-Encoding", "deflate , deflate");
    assert_response_header_eq!(tx, "Content-Length", "75");
    assert_eq!(68, tx.response_entity_len);
    assert_eq!(76, tx.response_message_len);
}

#[test]
fn HttpEvader195() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-195.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(
        tx,
        "/compressed/eicar.txt/ce%3Agzip;gzip;replace%3A3,1%7C02;replace%3A10,0=0000"
    );
    assert_response_header_eq!(tx, "Content-Encoding", "gzip");
    assert_eq!(68, tx.response_entity_len);
    assert_eq!(90, tx.response_message_len);
    let user_data = tx.user_data::<MainUserData>().unwrap();
    assert!(user_data.request_data.is_empty());
    assert_eq!(1, user_data.response_data.len());
    assert_eq!(
        user_data.response_data[0].as_slice(),
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".as_ref()
    );
}

#[test]
fn HttpEvader274() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-274.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/somehdr;space;chunked");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader284() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-284.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/cr;chunked");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader286() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-286.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/crcronly;chunked");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader287() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-287.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/cr-cronly;chunked");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader297() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-297.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/te%5C015%5C040%3Achunked;do_chunked");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader300() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-300.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/te%5C015%5C012%5C040%5C015%5C012%5C040%3A%5C015%5C012%5C040chunked;do_chunked");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader303() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-303.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/te%3A%5C000chunked;do_chunked");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader307() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-307.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/te%3A%5C012%5C000chunked;do_chunked");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader318() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("http-evader-318.t").is_err());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/ce%5C015%5C012%5C040%3Agzip;do_gzip");
    assert_evader_response!(tx);
    assert_response_header_eq!(tx, "Content-Encoding", "gzip");
    assert_eq!(68, tx.response_entity_len);
    assert_eq!(89, tx.response_message_len);
}

#[test]
fn HttpEvader320() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("http-evader-320.t").is_err());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/ce%5C013%3Agzip;do_gzip");
    assert_evader_response!(tx);
    assert_response_header_eq!(tx, "Content-Encoding", "gzip");
    assert_response_header_eq!(tx, "Content-Length", "88");
    assert_eq!(88, tx.response_entity_len);
    assert_eq!(99, tx.response_message_len);
}

#[test]
fn HttpEvader321() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("http-evader-321.t").is_err());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/ce%5C014%3Agzip;do_gzip");
    assert_evader_response!(tx);
    assert_response_header_eq!(tx, "Content-Encoding", "gzip");
    assert_response_header_eq!(tx, "Content-Length", "88");
    assert_eq!(88, tx.response_entity_len);
    assert_eq!(99, tx.response_message_len);
}

#[test]
fn HttpEvader390() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-390.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(
        tx,
        "/broken/eicar.txt/status%3A%5C000HTTP/1.1%28space%29200%28space%29ok;chunked"
    );
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader402() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-402.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/chunked;cr-no-crlf;end-crlflf");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader405() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-405.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/chunked;lfcr-no-crlf;end-crlfcrlf");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader411() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-411.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/end-lfcrcrlf;chunked");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader416() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-416.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/end-lf%5C040lf");
    assert_evader_response!(tx);
    assert_response_header_eq!(tx, "Content-length", "68");
    assert_eq!(69, tx.response_message_len);
    assert_eq!(69, tx.response_entity_len);
    let user_data = tx.user_data::<MainUserData>().unwrap();
    assert!(user_data.request_data.is_empty());
    assert_eq!(2, user_data.response_data.len());
    assert_eq!(
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".as_ref(),
        user_data.response_data[0].as_slice()
    );
    assert_eq!(b"\n".as_ref(), user_data.response_data[1].as_slice());
    assert_eq!(HtpRequestProgress::COMPLETE, tx.request_progress);
    assert_eq!(HtpResponseProgress::COMPLETE, tx.response_progress);
}

#[test]
fn HttpEvader419() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("http-evader-419.t").is_ok());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/chunked;end-lf%5C040lf");
    assert_evader_response!(tx);
    assert_evader_chunked!(tx);
}

#[test]
fn HttpEvader423() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("http-evader-423.t").is_err());
    let tx = t.connp.tx(0).unwrap();
    assert_evader_request!(tx, "/broken/eicar.txt/gzip;end-lf%5C040lflf");
    assert_evader_response!(tx);
    assert_response_header_eq!(tx, "Content-Encoding", "gzip");
    assert_response_header_eq!(tx, "Content-length", "88");
    assert_eq!(89, tx.response_message_len);
    assert_eq!(68, tx.response_entity_len);
}

#[test]
fn RequestGap() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("120-request-gap.t").is_ok());
    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    let user_data = tx.user_data::<MainUserData>().unwrap();

    assert!(tx.flags.is_set(HtpFlags::REQUEST_MISSING_BYTES));

    // The interim header from the 100 response should not be among the final headers.
    assert!(tx.request_headers.get_nocase_nozero("Header1").is_none());
    assert_eq!(user_data.request_data[1].as_slice(), b"<? echo ".as_ref());
    // Next chunk is a gap of size 5
    assert_eq!(user_data.request_data[2].as_slice(), b"".as_ref());
    assert_eq!(user_data.request_data[2].capacity(), 5);
    assert_eq!(user_data.request_data[3].as_slice(), b"; ?>".as_ref());
}

#[test]
fn ResponseGap() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("121-response-gap.t").is_ok());
    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    let user_data = tx.user_data::<MainUserData>().unwrap();

    assert!(tx.flags.is_set(HtpFlags::RESPONSE_MISSING_BYTES));

    assert_eq!(user_data.response_data[0].as_slice(), b"Hell".as_ref());
    // Next chunk is a gap of size 4
    assert_eq!(user_data.response_data[1].as_slice(), b"".as_ref());
    assert_eq!(user_data.response_data[1].capacity(), 4);
    assert_eq!(user_data.response_data[2].as_slice(), b"rld!".as_ref());
}

#[test]
fn ResponseBodyData() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("122-response-body-data.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    assert!(tx.is_complete());

    let user_data = tx.user_data::<MainUserData>().unwrap();
    let response_data = &user_data.response_data;
    assert_eq!(3, response_data.len());
    assert_eq!(b"1\n", response_data[0].as_slice());
    assert_eq!(b"23\n", response_data[1].as_slice());
    assert_eq!(b"4", response_data[2].as_slice());
}

#[test]
fn ResponseHeaderParsing() {
    let mut t = Test::new(TestConfig());
    assert!(t.run_file("123-response-header-bug.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).expect("expected tx to exist");

    let actual: Vec<(&[u8], &[u8])> = (&tx.response_headers)
        .into_iter()
        .map(|val| (val.name.as_slice(), val.value.as_slice()))
        .collect();

    let expected: Vec<(&[u8], &[u8])> = [
        ("Date", "Mon, 31 Aug 2009 20:25:50 GMT"),
        ("Server", "Apache"),
        ("Connection", "close"),
        ("Content-Type", "text/html"),
        ("Content-Length", "12"),
    ]
    .iter()
    .map(|(key, val)| (key.as_bytes(), val.as_bytes()))
    .collect();
    assert_eq!(
        actual,
        expected,
        "{:?} != {:?}",
        actual
            .clone()
            .into_iter()
            .map(|(key, val)| (
                String::from_utf8_lossy(key).to_string(),
                String::from_utf8_lossy(val).to_string()
            ))
            .collect::<Vec<(String, String)>>(),
        expected
            .clone()
            .into_iter()
            .map(|(key, val)| (
                String::from_utf8_lossy(key).to_string(),
                String::from_utf8_lossy(val).to_string()
            ))
            .collect::<Vec<(String, String)>>(),
    );
}

#[test]
fn RequestSingleBytes() {
    // Test input fed in one byte at a time
    let input = b" GET / HTTP/1.0\r\nUser-Agent: Test/1.0\r\n\r\n";
    let mut t = Test::new_with_callbacks();
    t.open_connection(None);
    for x in 0..input.len() {
        t.connp
            .request_data(ParserData::from(&input[x..(x + 1)]), None);
    }
    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    let h = tx.request_headers.get_nocase_nozero("User-Agent").unwrap();
    assert!(h.value.eq_slice(b"Test/1.0"));
}

#[test]
fn ResponseIncomplete() {
    let mut t = Test::new_with_callbacks();
    assert!(t.run_file("124-response-incomplete.t").is_ok());

    assert_eq!(1, t.connp.tx_size());

    let tx = t.connp.tx(0).unwrap();
    assert!(tx.is_complete());

    let user_data = tx.user_data::<MainUserData>().unwrap();

    assert_eq!(
        vec![
            "request_start 0",
            "response_start 0",
            "request_complete 0",
            "response_complete 0",
            "transaction_complete 0"
        ],
        user_data.order
    );
}

#[test]
fn RandomInput() {
    let mut t = Test::new(TestConfig());
    if let Ok(file) = std::env::var("LIBHTP_TEST") {
        t.run_file(&file).ok();
        println!("{:#?}", t.connp);
        for x in 0..t.connp.tx_size() {
            println!("{:#?}", t.connp.tx(x));
        }
    }
}
