use crate::{
    bstr::Bstr,
    error::Result,
    log::Logger,
    transaction::{Header, HtpAuthType, HtpProtocol, HtpResponseNumber, Transaction},
    util::{
        ascii_digits, convert_port, hex_digits, take_ascii_whitespace, take_chunked_ctl_chars,
        validate_hostname,
    },
    HtpStatus,
};
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, tag_no_case, take_until, take_while},
    combinator::{map, not, opt, peek},
    error::ErrorKind,
    multi::many0,
    sequence::tuple,
    IResult,
};

/// Parses the content type header, trimming any leading whitespace.
/// Finds the end of the MIME type, using the same approach PHP 5.4.3 uses.
///
/// Returns a tuple of the remaining unparsed header data and the content type
fn content_type() -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| {
        map(
            tuple((take_ascii_whitespace(), is_not(";, "))),
            |(_, content_type)| content_type,
        )(input)
    }
}

/// Parses the content type header from the given header value, lowercases it, and stores it in the provided ct bstr.
/// Finds the end of the MIME type, using the same approach PHP 5.4.3 uses.
pub fn parse_content_type(header: &[u8]) -> Result<Bstr> {
    let (_, content_type) = content_type()(header)?;
    let mut ct = Bstr::from(content_type);
    ct.make_ascii_lowercase();
    Ok(ct)
}

/// Parses Content-Length string (positive decimal number). White space is
/// allowed before and after the number.
///
/// Returns content length, or None if input is not valid.
pub fn parse_content_length(input: &[u8], logger: Option<&mut Logger>) -> Option<u64> {
    let (trailing_data, (leading_data, content_length)) = ascii_digits()(input).ok()?;
    if let Some(logger) = logger {
        if !leading_data.is_empty() {
            // Contains invalid characters! But still attempt to process
            htp_warn!(
                logger,
                HtpLogCode::CONTENT_LENGTH_EXTRA_DATA_START,
                "C-L value with extra data in the beginning"
            );
        }

        if !trailing_data.is_empty() {
            // Ok to have junk afterwards
            htp_warn!(
                logger,
                HtpLogCode::CONTENT_LENGTH_EXTRA_DATA_END,
                "C-L value with extra data in the end"
            );
        }
    }
    std::str::from_utf8(content_length)
        .ok()?
        .parse::<u64>()
        .ok()
}

/// Parses chunked length (positive hexadecimal number). White space is allowed before
/// and after the number.
pub fn parse_chunked_length(input: &[u8]) -> Result<(Option<u64>, bool)> {
    let (rest, _) = take_chunked_ctl_chars(input)?;
    let (trailing_data, chunked_length) = hex_digits()(rest)?;
    if trailing_data.is_empty() && chunked_length.is_empty() {
        return Ok((None, false));
    }
    let chunked_len = u64::from_str_radix(
        std::str::from_utf8(chunked_length).map_err(|_| HtpStatus::ERROR)?,
        16,
    )
    .map_err(|_| HtpStatus::ERROR)?;
    //TODO: remove this limit and update appropriate tests after differential fuzzing
    if chunked_len > std::i32::MAX as u64 {
        return Ok((None, false));
    }
    let has_ext = trailing_data.contains(&b';');
    Ok((Some(chunked_len), has_ext))
}

/// Attempts to extract the scheme from a given input URI.
/// # Example
/// ```
/// use htp::parsers::scheme;
///
/// let data: &[u8] = b"http://www.example.com";
/// let (left, scheme) = scheme()(data).unwrap();
/// assert_eq!(left, b"//www.example.com");
/// assert_eq!(scheme, b"http");
/// ```
///
/// Returns a tuple of the unconsumed data and the matched scheme.
pub fn scheme() -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| {
        // Scheme test: if it doesn't start with a forward slash character (which it must
        // for the contents to be a path or an authority), then it must be the scheme part
        map(
            tuple((peek(not(tag("/"))), take_until(":"), tag(":"))),
            |(_, scheme, _)| scheme,
        )(input)
    }
}

/// Helper for parsed credentials (username, Option<password>)
pub type ParsedCredentials<'a> = (&'a [u8], Option<&'a [u8]>);

/// Attempts to extract the credentials from a given input URI, assuming the scheme has already been extracted.
/// # Example
/// ```
/// use htp::parsers::credentials;
///
/// let data: &[u8] = b"//user:pass@www.example.com:1234/path1/path2?a=b&c=d#frag";
/// let (left, (user, pass)) = credentials()(data).unwrap();
/// assert_eq!(user, b"user");
/// assert_eq!(pass.unwrap(), b"pass");
/// assert_eq!(left, b"www.example.com:1234/path1/path2?a=b&c=d#frag");
/// ```
///
/// Returns a tuple of the remaining unconsumed data and a tuple of the matched username and password.
pub fn credentials() -> impl Fn(&[u8]) -> IResult<&[u8], ParsedCredentials> {
    move |input| {
        // Authority test: two forward slash characters and it's an authority.
        // One, three or more slash characters, and it's a path.
        // Note: we only attempt to parse authority if we've seen a scheme.
        let (input, (_, _, credentials, _)) =
            tuple((tag("//"), peek(not(tag("/"))), take_until("@"), tag("@")))(input)?;
        let (password, username) = opt(tuple((take_until(":"), tag(":"))))(credentials)?;
        if let Some((username, _)) = username {
            Ok((input, (username, Some(password))))
        } else {
            Ok((input, (credentials, None)))
        }
    }
}

/// Attempts to extract an IPv6 hostname from a given input URI,
/// assuming any scheme, credentials, hostname, port, and path have been already parsed out.
/// # Example
/// ```
/// use htp::parsers::ipv6;
///
/// let data: &[u8] = b"[::]/path1?a=b&c=d#frag";
/// let (left, ipv6) = ipv6()(data).unwrap();
/// assert_eq!(ipv6, b"[::]");
/// assert_eq!(left, b"/path1?a=b&c=d#frag");
/// ```
///
/// Returns a tuple of the remaining unconsumed data and the matched ipv6 hostname.
pub fn ipv6() -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| -> IResult<&[u8], &[u8]> {
        let (rest, _) = tuple((tag("["), is_not("/?#]"), opt(tag("]"))))(input)?;
        Ok((rest, &input[..input.len() - rest.len()]))
    }
}

/// Attempts to extract the hostname from a given input URI
/// # Example
/// ```
/// use htp::parsers::hostname;
///
/// let data: &[u8] = b"www.example.com:8080/path";
/// let (left, host) = hostname()(data).unwrap();
/// assert_eq!(host, b"www.example.com");
/// assert_eq!(left, b":8080/path");
/// ```
///
/// Returns a tuple of the remaining unconsumed data and the matched hostname.
pub fn hostname() -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| {
        let (input, mut hostname) = map(
            tuple((
                opt(tag("//")), //If it starts with "//", skip (might have parsed a scheme and no creds)
                peek(not(tag("/"))), //If it starts with '/', this is a path, not a hostname
                many0(tag(" ")),
                alt((ipv6(), is_not("/?#:"))),
            )),
            |(_, _, _, hostname)| hostname,
        )(input)?;
        //There may be spaces in the middle of a hostname, so much trim only at the end
        while hostname.ends_with(&[b' ']) {
            hostname = &hostname[..hostname.len() - 1];
        }
        Ok((input, hostname))
    }
}

/// Attempts to extract the port from a given input URI,
/// assuming any scheme, credentials, or hostname have been already parsed out.
/// # Example
/// ```
/// use htp::parsers::port;
///
/// let data: &[u8] = b":8080/path";
/// let (left, port) = port()(data).unwrap();
/// assert_eq!(port, b"8080");
/// assert_eq!(left, b"/path");
/// ```
///
/// Returns a tuple of the remaining unconsumed data and the matched port.
pub fn port() -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| {
        // Must start with ":" for there to be a port to parse
        let (input, (_, _, port, _)) =
            tuple((tag(":"), many0(tag(" ")), is_not("/?#"), many0(tag(" "))))(input)?;
        let (_, port) = is_not(" ")(port)?; //we assume there never will be a space in the middle of a port
        Ok((input, port))
    }
}

/// Attempts to extract the path from a given input URI,
/// assuming any scheme, credentials, hostname, and port have been already parsed out.
/// # Example
/// ```
/// use htp::parsers::path;
///
/// let data: &[u8] = b"/path1/path2?query";
/// let (left, path) = path()(data).unwrap();
/// assert_eq!(path, b"/path1/path2");
/// assert_eq!(left, b"?query");
/// ```
///
/// Returns a tuple of the remaining unconsumed data and the matched path.
pub fn path() -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| is_not("#?")(input)
}

/// Attempts to extract the query from a given input URI,
/// assuming any scheme, credentials, hostname, port, and path have been already parsed out.
/// # Example
/// ```
/// use htp::parsers::query;
///
/// let data: &[u8] = b"?a=b&c=d#frag";
/// let (left, query) = query()(data).unwrap();
/// assert_eq!(query, b"a=b&c=d");
/// assert_eq!(left, b"#frag");
/// ```
///
/// Returns a tuple of the remaining unconsumed data and the matched query.
pub fn query() -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| {
        // Skip the starting '?'
        map(tuple((tag("?"), is_not("#"))), |(_, query)| query)(input)
    }
}

/// Attempts to extract the fragment from a given input URI,
/// assuming any other components have been parsed out.
/// ```
/// use htp::parsers::fragment;
///
/// let data: &[u8] = b"#fragment";
/// let (left, fragment) = fragment()(data).unwrap();
/// assert_eq!(fragment, b"fragment");
/// assert_eq!(left, b"");
/// ```
///
/// Returns a tuple of the remaining unconsumed data and the matched fragment.
pub fn fragment() -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| {
        // Skip the starting '#'
        let (input, _) = tag("#")(input)?;
        Ok((b"", input))
    }
}

type parsed_port<'a> = Option<(&'a [u8], Option<u16>)>;
type parsed_hostport<'a> = (&'a [u8], parsed_port<'a>, bool);

/// Parses an authority string, which consists of a hostname with an optional port number
///
/// Returns a remaining unparsed data, parsed hostname, parsed port, converted port number,
/// and a flag indicating whether the parsed data is valid.
pub fn parse_hostport(input: &[u8]) -> IResult<&[u8], parsed_hostport> {
    let (input, host) = hostname()(input)?;
    let mut valid = validate_hostname(host);
    if let Ok((_, p)) = port()(input) {
        if let Some(port) = convert_port(p) {
            return Ok((input, (host, Some((p, Some(port))), valid)));
        } else {
            return Ok((input, (host, Some((p, None)), false)));
        }
    } else if !input.is_empty() {
        //Trailing data after the hostname that is invalid e.g. [::1]xxxxx
        valid = false;
    }
    Ok((input, (host, None, valid)))
}

/// Extracts the version protocol from the input slice.
///
/// Returns (any unparsed trailing data, (version_number, flag indicating whether input contains trailing and/or leading whitespace and/or leading zeros))
fn protocol_version(input: &[u8]) -> IResult<&[u8], (&[u8], bool)> {
    map(
        tuple((
            take_ascii_whitespace(),
            tag_no_case("HTTP"),
            take_ascii_whitespace(),
            tag("/"),
            take_while(|c: u8| c.is_ascii_whitespace() || c == b'0'),
            alt((tag(".9"), tag("1.0"), tag("1.1"))),
            take_ascii_whitespace(),
        )),
        |(_, _, leading, _, trailing, version, _)| {
            (version, !leading.is_empty() || !trailing.is_empty())
        },
    )(input)
}

/// Determines protocol number from a textual representation (i.e., "HTTP/1.1"). This
/// function tries to be flexible, allowing whitespace before and after the forward slash,
/// as well as allowing leading zeros in the version number. If such leading/trailing
/// characters are discovered, however, a warning will be logged.
///
/// Returns HtpProtocol version or invalid.
pub fn parse_protocol(input: &[u8], logger: &mut Logger) -> HtpProtocol {
    if let Ok((remaining, (version, contains_trailing))) = protocol_version(input) {
        if !remaining.is_empty() {
            return HtpProtocol::INVALID;
        }
        if contains_trailing {
            htp_warn!(
                    logger,
                    HtpLogCode::PROTOCOL_CONTAINS_EXTRA_DATA,
                    "HtpProtocol version contains leading and/or trailing whitespace and/or leading zeros"
                );
        }
        match version {
            b".9" => HtpProtocol::V0_9,
            b"1.0" => HtpProtocol::V1_0,
            b"1.1" => HtpProtocol::V1_1,
            _ => HtpProtocol::INVALID,
        }
    } else {
        HtpProtocol::INVALID
    }
}

/// Determines the numerical value of a response status given as a string.
pub fn parse_status(status: &[u8]) -> HtpResponseNumber {
    if let Ok((trailing_data, (leading_data, status_code))) = ascii_digits()(status) {
        if !trailing_data.is_empty() || !leading_data.is_empty() {
            //There are invalid characters in the status code
            return HtpResponseNumber::INVALID;
        }
        if let Ok(status_code) = std::str::from_utf8(status_code) {
            if let Ok(status_code) = status_code.parse::<u16>() {
                if (100..=999).contains(&status_code) {
                    return HtpResponseNumber::VALID(status_code);
                }
            }
        }
    }
    HtpResponseNumber::INVALID
}

/// Parses Digest Authorization request header.
fn parse_authorization_digest(auth_header_value: &[u8]) -> IResult<&[u8], Vec<u8>> {
    // Extract the username
    let (mut remaining_input, _) = tuple((
        take_until("username="),
        tag("username="),
        take_ascii_whitespace(), // allow lws
        tag("\""),               // First character after LWS must be a double quote
    ))(auth_header_value)?;
    let mut result = Vec::new();
    // Unescape any escaped double quotes and find the closing quote
    loop {
        let (remaining, (auth_header, _)) = tuple((take_until("\""), tag("\"")))(remaining_input)?;
        remaining_input = remaining;
        result.extend_from_slice(auth_header);
        if result.last() == Some(&(b'\\')) {
            // Remove the escape and push back the double quote
            result.pop();
            result.push(b'\"');
        } else {
            // We found the closing double quote!
            break;
        }
    }
    Ok((remaining_input, result))
}

/// Parses Basic Authorization request header.
fn parse_authorization_basic(request_tx: &mut Transaction, auth_header: &Header) -> Result<()> {
    // Skip 'Basic<lws>'
    let (remaining_input, _) =
        tuple((tag_no_case("basic"), take_ascii_whitespace()))(auth_header.value.as_slice())
            .map_err(|_| HtpStatus::DECLINED)?;
    // Decode base64-encoded data
    let decoded = base64::decode(remaining_input).map_err(|_| HtpStatus::DECLINED)?;
    let (password, (username, _)) =
        tuple::<_, _, (&[u8], ErrorKind), _>((take_until(":"), tag(":")))(decoded.as_slice())
            .map_err(|_| HtpStatus::DECLINED)?;
    request_tx.request_auth_username = Some(Bstr::from(username));
    request_tx.request_auth_password = Some(Bstr::from(password));
    Ok(())
}

/// Parses Authorization request header.
pub fn parse_authorization(request_tx: &mut Transaction) -> Result<()> {
    let auth_header = if let Some(auth_header) = request_tx
        .request_headers
        .get_nocase_nozero("authorization")
    {
        auth_header.clone()
    } else {
        request_tx.request_auth_type = HtpAuthType::NONE;
        return Ok(());
    };
    // TODO Need a flag to raise when failing to parse authentication headers.
    if auth_header.value.starts_with_nocase("basic") {
        // Basic authentication
        request_tx.request_auth_type = HtpAuthType::BASIC;
        return parse_authorization_basic(request_tx, &auth_header);
    } else if auth_header.value.starts_with_nocase("digest") {
        // Digest authentication
        request_tx.request_auth_type = HtpAuthType::DIGEST;
        let (_, auth_username) = parse_authorization_digest(auth_header.value.as_slice())
            .map_err(|_| HtpStatus::DECLINED)?;
        if let Some(username) = &mut request_tx.request_auth_username {
            username.clear();
            username.add(auth_username);
        } else {
            request_tx.request_auth_username = Some(Bstr::from(auth_username));
        }
    } else if auth_header.value.starts_with_nocase("bearer") {
        request_tx.request_auth_type = HtpAuthType::BEARER;
        let (token, _) = tuple((
            tag_no_case("bearer"),
            take_ascii_whitespace(), // allow lws
        ))(auth_header.value.as_slice())
        .map_err(|_| HtpStatus::DECLINED)?;
        request_tx.request_auth_token = Some(Bstr::from(token));
    } else {
        // Unrecognized authentication method
        request_tx.request_auth_type = HtpAuthType::UNRECOGNIZED
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("   username=   \"ivan\\\"r\\\"\"", "ivan\"r\"", "")]
    #[case("username=\"ivan\\\"r\\\"\"", "ivan\"r\"", "")]
    #[case("username=\"ivan\\\"r\\\"\"   ", "ivan\"r\"", "   ")]
    #[case("username=\"ivanr\"   ", "ivanr", "   ")]
    #[case("username=   \"ivanr\"   ", "ivanr", "   ")]
    #[should_panic]
    #[case("username=ivanr\"   ", "", "")]
    #[should_panic]
    #[case("username=\"ivanr   ", "", "")]
    fn test_parse_authorization_digest(
        #[case] input: &str,
        #[case] username: &str,
        #[case] remaining: &str,
    ) {
        assert_eq!(
            parse_authorization_digest(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), username.as_bytes().to_vec())
        );
    }

    #[rstest]
    #[case("   200    ", HtpResponseNumber::VALID(200))]
    #[case("  \t 404    ", HtpResponseNumber::VALID(404))]
    #[case("123", HtpResponseNumber::VALID(123))]
    #[case("99", HtpResponseNumber::INVALID)]
    #[case("1000", HtpResponseNumber::INVALID)]
    #[case("200 OK", HtpResponseNumber::INVALID)]
    #[case("NOT 200", HtpResponseNumber::INVALID)]
    fn test_parse_status(#[case] input: &str, #[case] expected: HtpResponseNumber) {
        assert_eq!(parse_status(&Bstr::from(input)), expected);
    }

    #[rstest]
    #[case(
        "http://user:pass@www.example.com:1234/path1/path2?a=b&c=d#frag",
        "http",
        "//user:pass@www.example.com:1234/path1/path2?a=b&c=d#frag"
    )]
    #[should_panic]
    #[case(
        "/http://user:pass@www.example.com:1234/path1/path2?a=b&c=d#frag",
        "",
        ""
    )]
    fn test_scheme(#[case] input: &str, #[case] s: &str, #[case] remaining: &str) {
        assert_eq!(
            scheme()(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), s.as_bytes())
        );
    }

    #[rstest]
    #[case(
        "//user:pass@www.example.com:1234/path1/path2?a=b&c=d#frag",
        "user",
        Some("pass"),
        "www.example.com:1234/path1/path2?a=b&c=d#frag"
    )]
    #[case(
        "//user@www.example.com:1234/path1/path2?a=b&c=d#frag",
        "user",
        None,
        "www.example.com:1234/path1/path2?a=b&c=d#frag"
    )]
    #[should_panic]
    #[case(
        "http://user:pass@www.example.com:1234/path1/path2?a=b&c=d#frag",
        "",
        None,
        ""
    )]
    fn test_credentials(
        #[case] input: &str,
        #[case] username: &str,
        #[case] password: Option<&str>,
        #[case] remaining: &str,
    ) {
        assert_eq!(
            credentials()(input.as_bytes()).unwrap(),
            (
                remaining.as_bytes(),
                (username.as_bytes(), password.map(|i| i.as_bytes()))
            )
        );
    }

    #[rstest]
    #[case(
        "www.example.com:1234/path1/path2?a=b&c=d#frag",
        "www.example.com",
        ":1234/path1/path2?a=b&c=d#frag"
    )]
    #[case(
        "www.example.com/path1/path2?a=b&c=d#frag",
        "www.example.com",
        "/path1/path2?a=b&c=d#frag"
    )]
    #[case("www.example.com?a=b&c=d#frag", "www.example.com", "?a=b&c=d#frag")]
    #[case("www.example.com#frag", "www.example.com", "#frag")]
    #[case("[::1]:8080", "[::1]", ":8080")]
    #[case("[::1", "[::1", "")]
    #[case("[::1/path1[0]", "[::1", "/path1[0]")]
    #[case("[::1]xxxx", "[::1]", "xxxx")]
    #[should_panic]
    #[case("/www.example.com/path1/path2?a=b&c=d#frag", "", "")]
    fn test_hostname(#[case] input: &str, #[case] host: &str, #[case] remaining: &str) {
        assert_eq!(
            hostname()(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), host.as_bytes())
        );
    }

    #[rstest]
    #[case(":1234/path1/path2?a=b&c=d#frag", "1234", "/path1/path2?a=b&c=d#frag")]
    #[case(":1234?a=b&c=d#frag", "1234", "?a=b&c=d#frag")]
    #[case(":1234#frag", "1234", "#frag")]
    #[should_panic]
    #[case("1234/path1/path2?a=b&c=d#frag", "", "")]
    fn test_port(#[case] input: &str, #[case] p: &str, #[case] remaining: &str) {
        assert_eq!(
            port()(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), p.as_bytes())
        );
    }

    #[rstest]
    #[case("/path1/path2?a=b&c=d#frag", "/path1/path2", "?a=b&c=d#frag")]
    #[case("/path1/path2#frag", "/path1/path2", "#frag")]
    #[case("path1/path2?a=b&c=d#frag", "path1/path2", "?a=b&c=d#frag")]
    #[case("//", "//", "")]
    #[case(
        "/uid=0(root) gid=0(root) groups=0(root)asdf",
        "/uid=0(root) gid=0(root) groups=0(root)asdf",
        ""
    )]
    fn test_path(#[case] input: &str, #[case] p: &str, #[case] remaining: &str) {
        assert_eq!(
            path()(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), p.as_bytes())
        );
    }

    #[rstest]
    #[case("?a=b&c=d#frag", "a=b&c=d", "#frag")]
    #[case("?a=b&c=d", "a=b&c=d", "")]
    fn test_query(#[case] input: &str, #[case] q: &str, #[case] remaining: &str) {
        assert_eq!(
            query()(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), q.as_bytes())
        );
    }

    #[rstest]
    #[case("#frag", "frag")]
    #[case("##frag", "#frag")]
    #[should_panic]
    #[case("frag", "")]
    #[should_panic]
    #[case("/path#frag", "")]
    fn test_fragment(#[case] input: &str, #[case] frag: &str) {
        assert_eq!(
            fragment()(input.as_bytes()).unwrap(),
            ("".as_bytes(), frag.as_bytes())
        );
    }

    #[rstest]
    #[case("www.example.com", "www.example.com", None, true, "")]
    #[case(" www.example.com ", "www.example.com", None, true, "")]
    #[case(" www.example.com:8001 ", "www.example.com", Some(("8001", Some(8001))), true, ":8001 ")]
    #[case(" www.example.com :  8001 ", "www.example.com", Some(("8001", Some(8001))), true, ":  8001 ")]
    #[case("www.example.com.", "www.example.com.", None, true, "")]
    #[case("www.example.com.", "www.example.com.", None, true, "")]
    #[case("www.example.com:", "www.example.com", None, false, ":")]
    #[case("www.example.com:ff", "www.example.com", Some(("ff", None)), false, ":ff")]
    #[case("www.example.com:0", "www.example.com", Some(("0", None)), false, ":0")]
    #[case("www.example.com:65536", "www.example.com", Some(("65536", None)), false, ":65536")]
    #[case("[::1]:8080", "[::1]", Some(("8080", Some(8080))), true, ":8080")]
    #[case("[::1]:", "[::1]", None, false, ":")]
    #[case("[::1]x", "[::1]", None, false, "x")]
    #[case("[::1", "[::1", None, false, "")]
    fn test_parse_hostport(
        #[case] input: &str,
        #[case] hostname: &str,
        #[case] parsed_port: Option<(&str, Option<u16>)>,
        #[case] valid: bool,
        #[case] remaining: &str,
    ) {
        assert_eq!(
            parse_hostport(input.as_bytes()).unwrap(),
            (
                remaining.as_bytes(),
                (
                    hostname.as_bytes(),
                    parsed_port.map(|(port, port_nmb)| (port.as_bytes(), port_nmb)),
                    valid
                )
            )
        );
    }

    #[rstest]
    #[case("134", Some(134))]
    #[case("    \t134    ", Some(134))]
    #[case("abcd134    ", Some(134))]
    #[case("abcd    ", None)]
    fn test_parse_content_length(#[case] input: &str, #[case] expected: Option<u64>) {
        assert_eq!(parse_content_length(input.as_bytes(), None), expected);
    }

    #[rstest]
    #[case("0 ; qw3=asd3; zc3=\"rt\"y3\"", (Some(0), true))]
    #[case("12a5", (Some(0x12a5), false))]
    #[case("12a5;ext=value", (Some(0x12a5), true))]
    #[case("    \t12a5    ", (Some(0x12a5), false))]
    #[case("    \t    ", (None, false))]
    fn test_parse_chunked_length(#[case] input: &str, #[case] expected: (Option<u64>, bool)) {
        assert_eq!(parse_chunked_length(input.as_bytes()).unwrap(), expected);
    }

    #[rstest]
    #[case("multipart/form-data", "multipart/form-data")]
    #[case("multipart/form-data;boundary=X", "multipart/form-data")]
    #[case("multipart/form-data boundary=X", "multipart/form-data")]
    #[case("multipart/form-data,boundary=X", "multipart/form-data")]
    #[case("multipart/FoRm-data", "multipart/form-data")]
    #[case("multipart/form-data\t boundary=X", "multipart/form-data\t")]
    #[case("   \tmultipart/form-data boundary=X", "multipart/form-data")]
    fn test_parse_content_type(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(
            parse_content_type(input.as_bytes()).unwrap(),
            Bstr::from(expected)
        );
    }
}
