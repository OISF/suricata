//! Utility functions for http parsing.

use crate::{config::HtpServerPersonality, error::NomError};
use nom::AsChar;
use nom::{
    branch::alt,
    bytes::complete::{
        is_not, tag, tag_no_case, take_till, take_until, take_while, take_while1, take_while_m_n,
    },
    bytes::streaming::{tag as streaming_tag, take_till as streaming_take_till},
    character::complete::{char, digit1},
    combinator::{map, opt},
    Err::Incomplete,
    IResult, Needed, Parser,
};
use std::str::FromStr;

/// String for the libhtp version.
pub const HTP_VERSION_STRING_FULL: &'_ str = concat!("LibHTP v", env!("CARGO_PKG_VERSION"), "\x00");

/// Trait to allow interacting with flags.
pub(crate) trait FlagOperations<T> {
    /// Inserts the specified flags in-place.
    fn set(&mut self, other: T);
    /// Removes the specified flags in-place.
    fn unset(&mut self, other: T);
    /// Determine if the specified flags are set
    fn is_set(&self, other: T) -> bool;
}

impl FlagOperations<u8> for u8 {
    /// Inserts the specified flags in-place.
    fn set(&mut self, other: u8) {
        *self |= other;
    }
    /// Removes the specified flags in-place.
    fn unset(&mut self, other: u8) {
        *self &= !other;
    }
    /// Determine if the specified flags are set
    fn is_set(&self, other: u8) -> bool {
        self & other != 0
    }
}

impl FlagOperations<u64> for u64 {
    /// Inserts the specified flags in-place.
    fn set(&mut self, other: u64) {
        *self |= other;
    }
    /// Removes the specified flags in-place.
    fn unset(&mut self, other: u64) {
        *self &= !other;
    }
    /// Determine if the specified flags are set
    fn is_set(&self, other: u64) -> bool {
        self & other != 0
    }
}

/// Various flag bits. Even though we have a flag field in several places
/// (header, transaction, connection), these fields are all in the same namespace
/// because we may want to set the same flag in several locations. For example, we
/// may set HTP_FIELD_FOLDED on the actual folded header, but also on the transaction
/// that contains the header. Both uses are useful.
#[repr(C)]
pub struct HtpFlags;

impl HtpFlags {
    /// Field cannot be parsed.
    pub const FIELD_UNPARSEABLE: u64 = 0x0000_0000_0004;
    /// Field is invalid.
    pub const FIELD_INVALID: u64 = 0x0000_0000_0008;
    /// Field is folded.
    pub const FIELD_FOLDED: u64 = 0x0000_0000_0010;
    /// Field has been seen more than once.
    pub const FIELD_REPEATED: u64 = 0x0000_0000_0020;
    // Field is too long.
    //pub const FIELD_LONG: u64 = 0x0000_0000_0040;
    // Field contains raw null byte.
    //pub const FIELD_RAW_NUL: u64 = 0x0000_0000_0080;
    /// Detect HTTP request smuggling.
    pub const REQUEST_SMUGGLING: u64 = 0x0000_0000_0100;
    /// Invalid header folding.
    pub const INVALID_FOLDING: u64 = 0x0000_0000_0200;
    /// Invalid request transfer-encoding.
    pub const REQUEST_INVALID_T_E: u64 = 0x0000_0000_0400;
    /// Multiple chunks.
    pub const MULTI_PACKET_HEAD: u64 = 0x0000_0000_0800;
    /// No host information in header.
    pub const HOST_MISSING: u64 = 0x0000_0000_1000;
    /// Inconsistent host or port information.
    pub const HOST_AMBIGUOUS: u64 = 0x0000_0000_2000;
    /// Encoded path contains null.
    pub const PATH_ENCODED_NUL: u64 = 0x0000_0000_4000;
    /// Url encoded contains raw null.
    pub const PATH_RAW_NUL: u64 = 0x0000_0000_8000;
    /// Url encoding is invalid.
    pub const PATH_INVALID_ENCODING: u64 = 0x0000_0001_0000;
    // Path is invalid.
    //pub const PATH_INVALID: u64 = 0x0000_0002_0000;
    /// Overlong usage in path.
    pub const PATH_OVERLONG_U: u64 = 0x0000_0004_0000;
    /// Encoded path separators present.
    pub const PATH_ENCODED_SEPARATOR: u64 = 0x0000_0008_0000;
    /// At least one valid UTF-8 character and no invalid ones.
    pub const PATH_UTF8_VALID: u64 = 0x0000_0010_0000;
    /// Invalid utf8 in path.
    pub const PATH_UTF8_INVALID: u64 = 0x0000_0020_0000;
    /// Invalid utf8 overlong character.
    pub const PATH_UTF8_OVERLONG: u64 = 0x0000_0040_0000;
    /// Range U+FF00 - U+FFEF detected.
    pub const PATH_HALF_FULL_RANGE: u64 = 0x0000_0080_0000;
    /// Status line is invalid.
    pub const STATUS_LINE_INVALID: u64 = 0x0000_0100_0000;
    /// Host in the URI.
    pub const HOSTU_INVALID: u64 = 0x0000_0200_0000;
    /// Host in the Host header.
    pub const HOSTH_INVALID: u64 = 0x0000_0400_0000;
    /// Contains null.
    pub const URLEN_ENCODED_NUL: u64 = 0x0000_0800_0000;
    /// Invalid encoding.
    pub const URLEN_INVALID_ENCODING: u64 = 0x0000_1000_0000;
    /// Overlong usage.
    pub const URLEN_OVERLONG_U: u64 = 0x0000_2000_0000;
    /// Range U+FF00 - U+FFEF detected.
    pub const URLEN_HALF_FULL_RANGE: u64 = 0x0000_4000_0000;
    /// Raw null byte.
    pub const URLEN_RAW_NUL: u64 = 0x0000_8000_0000;
    /// Request invalid.
    pub const REQUEST_INVALID: u64 = 0x0001_0000_0000;
    /// Request content-length invalid.
    pub const REQUEST_INVALID_C_L: u64 = 0x0002_0000_0000;
    /// Authorization is invalid.
    pub const AUTH_INVALID: u64 = 0x0004_0000_0000;
    /// Missing bytes in request and/or response data.
    pub const MISSING_BYTES: u64 = 0x0008_0000_0000;
    /// Missing bytes in request data.
    pub const REQUEST_MISSING_BYTES: u64 = (0x0010_0000_0000 | Self::MISSING_BYTES);
    /// Missing bytes in the response data.
    pub const RESPONSE_MISSING_BYTES: u64 = (0x0020_0000_0000 | Self::MISSING_BYTES);
    /// Too many headers, log only once.
    pub const HEADERS_TOO_MANY: u64 = 0x0040_0000_0000;
}

#[allow(clippy::upper_case_acronyms)]
/// Enumerates possible EOLs
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub(crate) enum Eol {
    /// '\n'
    LF,
    /// '\r'
    CR,
    /// "\r\n"
    CRLF,
}

/// Determines if character in a seperator.
/// separators = "(" | ")" | "<" | ">" | "@"
/// | "," | ";" | ":" | "\" | <">
/// | "/" | "[" | "]" | "?" | "="
/// | "{" | "}" | SP | HT
fn is_separator(c: u8) -> bool {
    matches!(
        c as char,
        '(' | ')'
            | '<'
            | '>'
            | '@'
            | ','
            | ';'
            | ':'
            | '\\'
            | '"'
            | '/'
            | '['
            | ']'
            | '?'
            | '='
            | '{'
            | '}'
            | ' '
            | '\t'
    )
}

/// Determines if character is a token.
/// token = 1*<any CHAR except CTLs or separators>
/// CHAR  = <any US-ASCII character (octets 0 - 127)>
pub(crate) fn is_token(c: u8) -> bool {
    (32..=126).contains(&c) && !is_separator(c)
}

/// This parser takes leading whitespace as defined by is_ascii_whitespace.
pub(crate) fn take_ascii_whitespace() -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| take_while(|c: u8| c.is_ascii_whitespace()).parse(input)
}

/// Remove all line terminators (LF, CR or CRLF) from
/// the end of the line provided as input.
pub(crate) fn chomp(mut data: &[u8]) -> &[u8] {
    loop {
        let last_char = data.last();
        if last_char == Some(&(b'\n')) || last_char == Some(&(b'\r')) {
            data = &data[..data.len() - 1];
        } else {
            break;
        }
    }
    data
}

/// Trim the leading whitespace
fn trim_start(input: &[u8]) -> &[u8] {
    let mut result = input;
    while let Some(x) = result.first() {
        if is_space(*x) {
            result = &result[1..]
        } else {
            break;
        }
    }
    result
}

/// Trim the trailing whitespace
fn trim_end(input: &[u8]) -> &[u8] {
    let mut result = input;
    while let Some(x) = result.last() {
        if is_space(*x) {
            result = &result[..(result.len() - 1)]
        } else {
            break;
        }
    }
    result
}

/// Trim the leading and trailing whitespace from this byteslice.
pub(crate) fn trimmed(input: &[u8]) -> &[u8] {
    trim_end(trim_start(input))
}

/// Splits the given input into two halves using the given predicate.
/// The `reverse` parameter determines whether or not to split on the
/// first match or the second match.
/// The `do_trim` parameter will return results with leading and trailing
/// whitespace trimmed.
/// If the predicate does not match, then the entire input is returned
/// in the first predicate element and an empty binary string is returned
/// in the second element.
pub(crate) fn split_on_predicate<F>(
    input: &[u8], reverse: bool, do_trim: bool, predicate: F,
) -> (&[u8], &[u8])
where
    F: FnMut(&u8) -> bool,
{
    let (first, second) = if reverse {
        let mut iter = input.rsplitn(2, predicate);
        let mut second = iter.next();
        let mut first = iter.next();
        // If we do not get two results, then put the only result first
        if first.is_none() {
            first = second;
            second = None;
        }
        (first.unwrap_or(b""), second.unwrap_or(b""))
    } else {
        let mut iter = input.splitn(2, predicate);
        let first = iter.next();
        let second = iter.next();
        (first.unwrap_or(b""), second.unwrap_or(b""))
    };

    if do_trim {
        (trimmed(first), trimmed(second))
    } else {
        (first, second)
    }
}

/// Determines if character is a whitespace character.
/// whitespace = ' ' | '\t' | '\r' | '\n' | '\x0b' | '\x0c'
pub(crate) fn is_space(c: u8) -> bool {
    matches!(c as char, ' ' | '\t' | '\r' | '\n' | '\x0b' | '\x0c')
}

/// Is the given line empty?
///
/// Returns true or false
fn is_line_empty(data: &[u8]) -> bool {
    matches!(data, b"\x0d" | b"\x0a" | b"\x0d\x0a")
}

/// Determine if entire line is whitespace as defined by
/// util::is_space.
fn is_line_whitespace(data: &[u8]) -> bool {
    !data.iter().any(|c| !is_space(*c))
}

/// Searches for and extracts the next set of ascii digits from the input slice if present
/// Parses over leading and trailing LWS characters.
///
/// Returns (any trailing non-LWS characters, (non-LWS leading characters, ascii digits))
pub(crate) fn ascii_digits(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    map(
        (
            nom_take_is_space,
            take_till(|c: u8| c.is_ascii_digit()),
            digit1,
            nom_take_is_space,
        ),
        |(_, leading_data, digits, _)| (leading_data, digits),
    )
    .parse(input)
}

/// Searches for and extracts the next set of hex digits from the input slice if present
/// Parses over leading and trailing LWS characters.
///
/// Returns a tuple of any trailing non-LWS characters and the found hex digits
pub(crate) fn hex_digits() -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| {
        map(
            (
                nom_take_is_space,
                take_while(|c: u8| c.is_ascii_hexdigit()),
                nom_take_is_space,
            ),
            |(_, digits, _)| digits,
        )
        .parse(input)
    }
}

/// Determines if the given line is a request terminator.
fn is_line_terminator(
    server_personality: HtpServerPersonality, data: &[u8], next_no_lf: bool,
) -> bool {
    // Is this the end of request headers?
    if server_personality == HtpServerPersonality::IIS_5_0 {
        // IIS 5 will accept a whitespace line as a terminator
        if is_line_whitespace(data) {
            return true;
        }
    }

    // Treat an empty line as terminator
    if is_line_empty(data) {
        return true;
    }
    if data.len() == 2 && data[0].is_space() && data[1] == b'\n' {
        return next_no_lf;
    }
    false
}

/// Determines if the given line can be ignored when it appears before a request.
pub(crate) fn is_line_ignorable(server_personality: HtpServerPersonality, data: &[u8]) -> bool {
    is_line_terminator(server_personality, data, false)
}

/// Attempts to convert the provided port slice to a u16
///
/// Returns port number if a valid one is found. None if fails to convert or the result is 0
pub(crate) fn convert_port(port: &[u8]) -> Option<u16> {
    if port.is_empty() {
        return None;
    }
    let port_number = std::str::from_utf8(port).ok()?.parse::<u16>().ok()?;
    if port_number == 0 {
        None
    } else {
        Some(port_number)
    }
}

/// Determine if the information provided on the response line
/// is good enough. Browsers are lax when it comes to response
/// line parsing. In most cases they will only look for the
/// words "http" at the beginning.
///
/// Returns true for good enough (treat as response body) or false for not good enough
pub(crate) fn treat_response_line_as_body(data: &[u8]) -> bool {
    // Browser behavior:
    //      Firefox 3.5.x: (?i)^\s*http
    //      IE: (?i)^\s*http\s*/
    //      Safari: ^HTTP/\d+\.\d+\s+\d{3}

    (opt(take_is_space_or_null), tag_no_case("http"))
        .parse(data)
        .is_err()
}

/// Implements relaxed (not strictly RFC) hostname validation.
///
/// Returns true if the supplied hostname is valid; false if it is not.
pub(crate) fn validate_hostname(input: &[u8]) -> bool {
    if input.is_empty() || input.len() > 255 {
        return false;
    }

    // Check IPv6
    if let Ok((_rest, (_left_br, addr, _right_br))) = (
        char::<_, NomError<&[u8]>>('['),
        is_not::<_, _, NomError<&[u8]>>("#?/]"),
        char::<_, NomError<&[u8]>>(']'),
    )
        .parse(input)
    {
        if let Ok(str) = std::str::from_utf8(addr) {
            return std::net::Ipv6Addr::from_str(str).is_ok();
        }
    }

    if tag::<_, _, NomError<&[u8]>>(".").parse(input).is_ok()
        || take_until::<_, _, NomError<&[u8]>>("..")
            .parse(input)
            .is_ok()
    {
        return false;
    }
    for section in input.split(|&c| c == b'.') {
        if section.len() > 63 {
            return false;
        }
        // According to the RFC, an underscore it not allowed in the label, but
        // we allow it here because we think it's often seen in practice.
        if take_while_m_n::<_, _, NomError<&[u8]>>(section.len(), section.len(), |c| {
            c == b'_' || c == b'-' || (c as char).is_alphanumeric()
        })(section)
        .is_err()
        {
            return false;
        }
    }
    true
}

/// Returns the LibHTP version string.
pub(crate) fn get_version() -> &'static str {
    HTP_VERSION_STRING_FULL
}

/// Take leading whitespace as defined by AsChar::is_space.
pub(crate) fn nom_take_is_space(data: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|c: u8| c.is_space()).parse(data)
}

/// Take data before the first null character if it exists.
pub(crate) fn take_until_null(data: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|c| c != b'\0').parse(data)
}

/// Take leading space as defined by util::is_space.
pub(crate) fn take_is_space(data: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(is_space).parse(data)
}

/// Take leading null characters or spaces as defined by util::is_space
pub(crate) fn take_is_space_or_null(data: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|c| is_space(c) || c == b'\0').parse(data)
}

/// Take any non-space character as defined by is_space.
pub(crate) fn take_not_is_space(data: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|c: u8| !is_space(c)).parse(data)
}

/// Returns all data up to and including the first new line or null
/// Returns Err if not found
pub(crate) fn take_till_lf_null(data: &[u8]) -> IResult<&[u8], &[u8]> {
    let (_, line) = streaming_take_till(|c| c == b'\n' || c == 0).parse(data)?;
    Ok((&data[line.len() + 1..], &data[0..line.len() + 1]))
}

/// Returns all data up to and including the first new line
/// Returns Err if not found
pub(crate) fn take_till_lf(data: &[u8]) -> IResult<&[u8], &[u8]> {
    let (_, line) = streaming_take_till(|c| c == b'\n').parse(data)?;
    Ok((&data[line.len() + 1..], &data[0..line.len() + 1]))
}

/// Returns all data up to and including the first EOL and which EOL was seen
///
/// Returns Err if not found
pub(crate) fn take_till_eol(data: &[u8]) -> IResult<&[u8], (&[u8], Eol)> {
    let (_, (line, eol)) = (
        streaming_take_till(|c| c == b'\n' || c == b'\r'),
        alt((
            streaming_tag("\r\n"),
            streaming_tag("\r"),
            streaming_tag("\n"),
        )),
    )
        .parse(data)?;
    match eol {
        b"\n" => Ok((&data[line.len() + 1..], (&data[0..line.len() + 1], Eol::LF))),
        b"\r" => Ok((&data[line.len() + 1..], (&data[0..line.len() + 1], Eol::CR))),
        b"\r\n" => Ok((
            &data[line.len() + 2..],
            (&data[0..line.len() + 2], Eol::CRLF),
        )),
        _ => Err(Incomplete(Needed::new(1))),
    }
}

/// Skip control characters
pub(crate) fn take_chunked_ctl_chars(data: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(is_chunked_ctl_char).parse(data)
}

/// Check if the data contains valid chunked length chars, i.e. leading chunked ctl chars and ascii hexdigits
///
/// Returns true if valid, false otherwise
pub(crate) fn is_valid_chunked_length_data(data: &[u8]) -> bool {
    (
        take_chunked_ctl_chars,
        take_while1(|c: u8| !c.is_ascii_hexdigit()),
    )
        .parse(data)
        .is_err()
}

fn is_chunked_ctl_char(c: u8) -> bool {
    matches!(c, 0x0d | 0x0a | 0x20 | 0x09 | 0x0b | 0x0c)
}

/// Check if the entire input line is chunked control characters
pub(crate) fn is_chunked_ctl_line(l: &[u8]) -> bool {
    for c in l {
        if !is_chunked_ctl_char(*c) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::util::*;
    use rstest::rstest;

    #[rstest]
    #[case("", "", "")]
    #[case("hello world", "", "hello world")]
    #[case("\0", "\0", "")]
    #[case("hello_world  \0   ", "\0   ", "hello_world  ")]
    #[case("hello\0\0\0\0", "\0\0\0\0", "hello")]
    fn test_take_until_null(#[case] input: &str, #[case] remaining: &str, #[case] parsed: &str) {
        assert_eq!(
            take_until_null(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), parsed.as_bytes())
        );
    }

    #[rstest]
    #[case("", "", "")]
    #[case("   hell o", "hell o", "   ")]
    #[case("   \thell o", "hell o", "   \t")]
    #[case("hell o", "hell o", "")]
    #[case("\r\x0b  \thell \to", "hell \to", "\r\x0b  \t")]
    fn test_take_is_space(#[case] input: &str, #[case] remaining: &str, #[case] parsed: &str) {
        assert_eq!(
            take_is_space(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), parsed.as_bytes())
        );
    }

    #[rstest]
    #[case("   http 1.1", false)]
    #[case("\0 http 1.1", false)]
    #[case("http", false)]
    #[case("HTTP", false)]
    #[case("    HTTP", false)]
    #[case("test", true)]
    #[case("     test", true)]
    #[case("", true)]
    #[case("kfgjl  hTtp ", true)]
    fn test_treat_response_line_as_body(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(treat_response_line_as_body(input.as_bytes()), expected);
    }

    #[rstest]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Incomplete(Size(1))")]
    #[case("", "", "")]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Incomplete(Size(1))")]
    #[case("header:value\r\r", "", "")]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Incomplete(Size(1))")]
    #[case("header:value", "", "")]
    #[case("\nheader:value\r\n", "header:value\r\n", "\n")]
    #[case("header:value\r\n", "", "header:value\r\n")]
    #[case("header:value\n\r", "\r", "header:value\n")]
    #[case("header:value\n\n", "\n", "header:value\n")]
    #[case("abcdefg\nhijk", "hijk", "abcdefg\n")]
    fn test_take_till_lf(#[case] input: &str, #[case] remaining: &str, #[case] parsed: &str) {
        assert_eq!(
            take_till_lf(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), parsed.as_bytes())
        );
    }

    #[rstest]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Incomplete(Size(1))")]
    #[case("", "", "", Eol::CR)]
    #[case("abcdefg\n", "", "abcdefg\n", Eol::LF)]
    #[case("abcdefg\n\r", "\r", "abcdefg\n", Eol::LF)]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Incomplete(Size(1))")]
    #[case("abcdefg\r", "", "", Eol::CR)]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Incomplete(Size(1))")]
    #[case("abcdefg", "", "", Eol::CR)]
    #[case("abcdefg\nhijk", "hijk", "abcdefg\n", Eol::LF)]
    #[case("abcdefg\n\r\nhijk", "\r\nhijk", "abcdefg\n", Eol::LF)]
    #[case("abcdefg\rhijk", "hijk", "abcdefg\r", Eol::CR)]
    #[case("abcdefg\r\nhijk", "hijk", "abcdefg\r\n", Eol::CRLF)]
    #[case("abcdefg\r\n", "", "abcdefg\r\n", Eol::CRLF)]
    fn test_take_till_eol(
        #[case] input: &str, #[case] remaining: &str, #[case] parsed: &str, #[case] eol: Eol,
    ) {
        assert_eq!(
            take_till_eol(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), (parsed.as_bytes(), eol))
        );
    }

    #[rstest]
    #[case(b'a', false)]
    #[case(b'^', false)]
    #[case(b'-', false)]
    #[case(b'_', false)]
    #[case(b'&', false)]
    #[case(b'(', true)]
    #[case(b'\\', true)]
    #[case(b'/', true)]
    #[case(b'=', true)]
    #[case(b'\t', true)]
    fn test_is_separator(#[case] input: u8, #[case] expected: bool) {
        assert_eq!(is_separator(input), expected);
    }

    #[rstest]
    #[case(b'a', true)]
    #[case(b'&', true)]
    #[case(b'+', true)]
    #[case(b'\t', false)]
    #[case(b'\n', false)]
    fn test_is_token(#[case] input: u8, #[case] expected: bool) {
        assert_eq!(is_token(input), expected);
    }

    #[rstest]
    #[case("", "")]
    #[case("test\n", "test")]
    #[case("test\r\n", "test")]
    #[case("test\r\n\n", "test")]
    #[case("test\n\r\r\n\r", "test")]
    #[case("test", "test")]
    #[case("te\nst", "te\nst")]
    fn test_chomp(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(chomp(input.as_bytes()), expected.as_bytes());
    }

    #[rstest]
    #[case::trimmed(b"notrim", b"notrim")]
    #[case::trim_start(b"\t trim", b"trim")]
    #[case::trim_both(b" trim ", b"trim")]
    #[case::trim_both_ignore_middle(b" trim trim ", b"trim trim")]
    #[case::trim_end(b"trim \t", b"trim")]
    #[case::trim_empty(b"", b"")]
    fn test_trim(#[case] input: &[u8], #[case] expected: &[u8]) {
        assert_eq!(trimmed(input), expected);
    }

    #[rstest]
    #[case::non_space(0x61, false)]
    #[case::space(0x20, true)]
    #[case::form_feed(0x0c, true)]
    #[case::newline(0x0a, true)]
    #[case::carriage_return(0x0d, true)]
    #[case::tab(0x09, true)]
    #[case::vertical_tab(0x0b, true)]
    fn test_is_space(#[case] input: u8, #[case] expected: bool) {
        assert_eq!(is_space(input), expected);
    }

    #[rstest]
    #[case("", false)]
    #[case("arfarf", false)]
    #[case("\n\r", false)]
    #[case("\rabc", false)]
    #[case("\r\n", true)]
    #[case("\r", true)]
    #[case("\n", true)]
    fn test_is_line_empty(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(is_line_empty(input.as_bytes()), expected);
    }

    #[rstest]
    #[case("", false)]
    #[case("www.ExAmplE-1984.com", true)]
    #[case("[::]", true)]
    #[case("[2001:3db8:0000:0000:0000:ff00:d042:8530]", true)]
    #[case("www.example.com", true)]
    #[case("www.exa-mple.com", true)]
    #[case("www.exa_mple.com", true)]
    #[case(".www.example.com", false)]
    #[case("www..example.com", false)]
    #[case("www.example.com..", false)]
    #[case("www example com", false)]
    #[case("[::", false)]
    #[case("[::/path[0]", false)]
    #[case("[::#garbage]", false)]
    #[case("[::?]", false)]
    #[case::over64_char(
        "www.exampleexampleexampleexampleexampleexampleexampleexampleexampleexample.com",
        false
    )]
    fn test_validate_hostname(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(validate_hostname(input.as_bytes()), expected);
    }

    #[rstest]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: Error(Error { input: [], code: Digit })"
    )]
    #[case("   garbage no ascii ", "", "", "")]
    #[case("    a200 \t  bcd ", "bcd ", "a", "200")]
    #[case("   555555555    ", "", "", "555555555")]
    #[case("   555555555    500", "500", "", "555555555")]
    fn test_ascii_digits(
        #[case] input: &str, #[case] remaining: &str, #[case] leading: &str, #[case] digits: &str,
    ) {
        // Returns (any trailing non-LWS characters, (non-LWS leading characters, ascii digits))
        assert_eq!(
            ascii_digits(input.as_bytes()).unwrap(),
            (
                remaining.as_bytes(),
                (leading.as_bytes(), digits.as_bytes())
            )
        );
    }

    #[rstest]
    #[case("", "", "")]
    #[case("12a5", "", "12a5")]
    #[case("12a5   .....", ".....", "12a5")]
    #[case("    \t12a5.....    ", ".....    ", "12a5")]
    #[case(" 68656c6c6f   12a5", "12a5", "68656c6c6f")]
    #[case("  .....", ".....", "")]
    fn test_hex_digits(#[case] input: &str, #[case] remaining: &str, #[case] digits: &str) {
        //(trailing non-LWS characters, found hex digits)
        assert_eq!(
            hex_digits()(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), digits.as_bytes())
        );
    }

    #[rstest]
    #[case("", "", "")]
    #[case("no chunked ctl chars here", "no chunked ctl chars here", "")]
    #[case(
        "\x0d\x0a\x20\x09\x0b\x0cno chunked ctl chars here",
        "no chunked ctl chars here",
        "\x0d\x0a\x20\x09\x0b\x0c"
    )]
    #[case(
        "no chunked ctl chars here\x20\x09\x0b\x0c",
        "no chunked ctl chars here\x20\x09\x0b\x0c",
        ""
    )]
    #[case(
        "\x20\x09\x0b\x0cno chunked ctl chars here\x20\x09\x0b\x0c",
        "no chunked ctl chars here\x20\x09\x0b\x0c",
        "\x20\x09\x0b\x0c"
    )]
    fn test_take_chunked_ctl_chars(
        #[case] input: &str, #[case] remaining: &str, #[case] hex_digits: &str,
    ) {
        //(trailing non-LWS characters, found hex digits)
        assert_eq!(
            take_chunked_ctl_chars(input.as_bytes()).unwrap(),
            (remaining.as_bytes(), hex_digits.as_bytes())
        );
    }

    #[rstest]
    #[case("", true)]
    #[case("68656c6c6f", true)]
    #[case("\x0d\x0a\x20\x09\x0b\x0c68656c6c6f", true)]
    #[case("X5O!P%@AP", false)]
    #[case("\x0d\x0a\x20\x09\x0b\x0cX5O!P%@AP", false)]
    fn test_is_valid_chunked_length_data(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(is_valid_chunked_length_data(input.as_bytes()), expected);
    }

    #[rstest]
    #[case("", false, true, ("", ""))]
    #[case("ONE TWO THREE", false, true, ("ONE", "TWO THREE"))]
    #[case("ONE TWO THREE", true, true, ("ONE TWO", "THREE"))]
    #[case("ONE   TWO   THREE", false, true, ("ONE", "TWO   THREE"))]
    #[case("ONE   TWO   THREE", true, true, ("ONE   TWO", "THREE"))]
    #[case("ONE", false, true, ("ONE", ""))]
    #[case("ONE", true, true, ("ONE", ""))]
    fn test_split_on_predicate(
        #[case] input: &str, #[case] reverse: bool, #[case] trim: bool,
        #[case] expected: (&str, &str),
    ) {
        assert_eq!(
            split_on_predicate(input.as_bytes(), reverse, trim, |c| *c == 0x20),
            (expected.0.as_bytes(), expected.1.as_bytes())
        );
    }
}
