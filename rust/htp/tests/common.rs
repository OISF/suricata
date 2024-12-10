#[macro_export]
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
#[allow(unused_macros)]
#[macro_export]
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

/// Compares a transaction's request header value to an expected value.
///
/// Example usage:
/// assert_request_header_eq!(tx, "host", ""www.example.com");
#[macro_export]
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

/// Compares a transaction's response header value to an expected value.
///
/// Example usage:
/// assert_response_header_eq!(tx, "content-encoding", ""gzip");
#[macro_export]
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

/// Asserts that a transaction's response contains a flag.
///
/// Example usage:
/// assert_response_header_flag_contains!(tx, "Content-Length", Flags::FIELD_REPEATED);
#[macro_export]
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

/// Assert the common evader request values are as expected
///
/// Example usage:
/// assert_evader_request!(tx, "url");
#[macro_export]
macro_rules! assert_evader_request {
    ($tx:expr, $url:expr) => {{
        assert!(($tx).request_method.as_ref().unwrap().eq_slice("GET"));
        assert!(($tx).request_uri.as_ref().unwrap().eq_slice($url));
        assert_eq!(HtpProtocol::V1_1, ($tx).request_protocol_number);
        assert_header_eq!($tx, request_headers, "host", "evader.example.com");
    }};
}

/// Assert the common evader response values are as expected
///
/// Example usage:
/// assert_evader_response!(tx);
#[macro_export]
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

/// Assert the response transfer encoding is detected as chunked
///
/// Example usage:
/// assert_evader_chunked_response!(tx);
#[macro_export]
macro_rules! assert_evader_chunked {
    ($tx:expr) => {{
        assert_eq!($tx.response_transfer_coding, HtpTransferCoding::CHUNKED);
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
