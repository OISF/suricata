use crate::{
    bstr::Bstr,
    config::{DecoderConfig, HtpUnwanted, HtpUrlEncodingHandling},
    error::Result,
    util::{FlagOperations, HtpFlags},
};

use nom::{
    branch::alt,
    bytes::complete::{tag_no_case, take, take_while_m_n},
    character::complete::char,
    combinator::{map, not},
    multi::fold_many0,
    number::complete::be_u8,
    sequence::tuple,
    IResult,
};

/// Convert two input bytes, pointed to by the pointer parameter,
/// into a single byte by assuming the input consists of hexadecimal
/// characters. This function will happily convert invalid input.
///
/// Returns hex-decoded byte
fn x2c(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, (c1, c2)) = tuple((be_u8, be_u8))(input)?;
    let mut decoded_byte = if c1 >= b'A' {
        ((c1 & 0xdf) - b'A') + 10
    } else {
        c1 - b'0'
    };
    decoded_byte = (decoded_byte as i32 * 16) as u8;
    decoded_byte += if c2 >= b'A' {
        ((c2 & 0xdf) - b'A') + 10
    } else {
        c2 - b'0'
    };
    Ok((input, decoded_byte))
}

/// Decode a path %u-encoded character, using best-fit mapping as necessary.
///
/// Sets i to decoded byte
fn path_decode_u_encoding<'a>(
    i: &'a [u8], cfg: &DecoderConfig,
) -> IResult<&'a [u8], (u8, u64, HtpUnwanted)> {
    let mut flags = 0;
    let mut expected_status_code = HtpUnwanted::Ignore;
    let (i, c1) = x2c(i)?;
    let (i, c2) = x2c(i)?;
    let mut r = c2;
    if c1 == 0 {
        flags.set(HtpFlags::PATH_OVERLONG_U)
    } else {
        // Check for fullwidth form evasion
        if c1 == 0xff {
            flags.set(HtpFlags::PATH_HALF_FULL_RANGE)
        }
        expected_status_code = cfg.u_encoding_unwanted;
        // Use best-fit mapping
        r = cfg.bestfit_map.get(bestfit_key!(c1, c2));
    }
    // Check for encoded path separators
    if r == b'/' || cfg.backslash_convert_slashes && r == b'\\' {
        flags.set(HtpFlags::PATH_ENCODED_SEPARATOR)
    }
    Ok((i, (r, flags, expected_status_code)))
}

/// Decode a %u-encoded character, using best-fit mapping as necessary. Params version.
///
/// Returns decoded byte
fn decode_u_encoding_params<'a>(i: &'a [u8], cfg: &DecoderConfig) -> IResult<&'a [u8], (u8, u64)> {
    let (i, c1) = x2c(i)?;
    let (i, c2) = x2c(i)?;
    let mut flags = 0;
    // Check for overlong usage first.
    if c1 == 0 {
        flags.set(HtpFlags::URLEN_OVERLONG_U);
        return Ok((i, (c2, flags)));
    }
    // Both bytes were used.
    // Detect half-width and full-width range.
    if c1 == 0xff && c2 <= 0xef {
        flags.set(HtpFlags::URLEN_HALF_FULL_RANGE)
    }
    // Use best-fit mapping.
    Ok((i, (cfg.bestfit_map.get(bestfit_key!(c1, c2)), flags)))
}

struct UrlParseResult {
    byte: u8,
    expected_status_code: HtpUnwanted,
    flags: u64,
    decode: bool,
}

/// Decodes path valid uencoded params according to the given cfg settings.
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn path_decode_valid_u_encoding(
    cfg: &DecoderConfig,
) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |remaining_input| {
        let (left, _) = tag_no_case("u")(remaining_input)?;
        let mut output = remaining_input;
        let mut byte = b'%';
        let mut flags = 0;
        let mut expected_status_code = HtpUnwanted::Ignore;
        if cfg.u_encoding_decode {
            let (left, hex) = take_while_m_n(4, 4, |c: u8| c.is_ascii_hexdigit())(left)?;
            output = left;
            expected_status_code = cfg.u_encoding_unwanted;
            // Decode a valid %u encoding.
            let (_, (b, f, c)) = path_decode_u_encoding(hex, cfg)?;
            byte = b;
            flags.set(f);
            if c != HtpUnwanted::Ignore {
                expected_status_code = c;
            }
            if byte == 0 {
                flags.set(HtpFlags::PATH_ENCODED_NUL);
                if cfg.nul_encoded_unwanted != HtpUnwanted::Ignore {
                    expected_status_code = cfg.nul_encoded_unwanted
                }
                if cfg.nul_encoded_terminates {
                    // Terminate the path at the raw NUL byte.
                    return Ok((
                        b"",
                        UrlParseResult {
                            byte,
                            expected_status_code,
                            flags,
                            decode: false,
                        },
                    ));
                }
            }
        }
        let (byte, code) = path_decode_control(byte, cfg);
        if code != HtpUnwanted::Ignore {
            expected_status_code = code;
        }
        Ok((
            output,
            UrlParseResult {
                byte,
                expected_status_code,
                flags,
                decode: true,
            },
        ))
    }
}

/// Decodes path invalid uencoded params according to the given cfg settings.
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn path_decode_invalid_u_encoding(
    cfg: &DecoderConfig,
) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |remaining_input| {
        let mut output = remaining_input;
        let mut byte = b'%';
        let mut flags = 0;
        let mut expected_status_code = HtpUnwanted::Ignore;
        let (left, _) = tag_no_case("u")(remaining_input)?;
        if cfg.u_encoding_decode {
            let (left, hex) = take(4usize)(left)?;
            // Invalid %u encoding
            flags = HtpFlags::PATH_INVALID_ENCODING;
            expected_status_code = cfg.url_encoding_invalid_unwanted;
            if cfg.url_encoding_invalid_handling == HtpUrlEncodingHandling::REMOVE_PERCENT {
                // Do not place anything in output; consume the %.
                return Ok((
                    remaining_input,
                    UrlParseResult {
                        byte,
                        expected_status_code,
                        flags,
                        decode: false,
                    },
                ));
            } else if cfg.url_encoding_invalid_handling == HtpUrlEncodingHandling::PROCESS_INVALID {
                let (_, (b, f, c)) = path_decode_u_encoding(hex, cfg)?;
                if c != HtpUnwanted::Ignore {
                    expected_status_code = c;
                }
                flags.set(f);
                byte = b;
                output = left;
            }
        }
        let (byte, code) = path_decode_control(byte, cfg);
        if code != HtpUnwanted::Ignore {
            expected_status_code = code;
        }
        Ok((
            output,
            UrlParseResult {
                byte,
                expected_status_code,
                flags,
                decode: true,
            },
        ))
    }
}

/// Decodes path valid hex according to the given cfg settings.
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn path_decode_valid_hex(
    cfg: &DecoderConfig,
) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |remaining_input| {
        let original_remaining = remaining_input;
        // Valid encoding (2 xbytes)
        not(tag_no_case("u"))(remaining_input)?;
        let (mut left, hex) = take_while_m_n(2, 2, |c: u8| c.is_ascii_hexdigit())(remaining_input)?;
        let mut flags = 0;
        // Convert from hex.
        let (_, mut byte) = x2c(hex)?;
        if byte == 0 {
            flags.set(HtpFlags::PATH_ENCODED_NUL);
            if cfg.nul_encoded_terminates {
                // Terminate the path at the raw NUL byte.
                return Ok((
                    b"",
                    UrlParseResult {
                        byte,
                        expected_status_code: cfg.nul_encoded_unwanted,
                        flags,
                        decode: false,
                    },
                ));
            }
        }
        if byte == b'/' || (cfg.backslash_convert_slashes && byte == b'\\') {
            flags.set(HtpFlags::PATH_ENCODED_SEPARATOR);
            if !cfg.path_separators_decode {
                // Leave encoded
                byte = b'%';
                left = original_remaining;
            }
        }
        let (byte, expected_status_code) = path_decode_control(byte, cfg);
        Ok((
            left,
            UrlParseResult {
                byte,
                expected_status_code,
                flags,
                decode: true,
            },
        ))
    }
}

/// Decodes invalid path hex according to the given cfg settings.
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn path_decode_invalid_hex(
    cfg: &DecoderConfig,
) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |remaining_input| {
        let mut remaining = remaining_input;
        // Valid encoding (2 xbytes)
        not(tag_no_case("u"))(remaining_input)?;
        let (left, hex) = take(2usize)(remaining_input)?;
        let mut byte = b'%';
        // Invalid encoding
        let flags = HtpFlags::PATH_INVALID_ENCODING;
        let expected_status_code = cfg.url_encoding_invalid_unwanted;
        if cfg.url_encoding_invalid_handling == HtpUrlEncodingHandling::REMOVE_PERCENT {
            // Do not place anything in output; consume the %.
            return Ok((
                remaining_input,
                UrlParseResult {
                    byte,
                    expected_status_code,
                    flags,
                    decode: false,
                },
            ));
        } else if cfg.url_encoding_invalid_handling == HtpUrlEncodingHandling::PROCESS_INVALID {
            // Decode
            let (_, b) = x2c(hex)?;
            remaining = left;
            byte = b;
        }
        let (byte, expected_status_code) = path_decode_control(byte, cfg);
        Ok((
            remaining,
            UrlParseResult {
                byte,
                expected_status_code,
                flags,
                decode: true,
            },
        ))
    }
}

/// If the first byte of the input path string is a '%', it attempts to decode according to the
/// configuration specified by cfg. Various flags (HTP_PATH_*) might be set. If something in the
/// input would cause a particular server to respond with an error, the appropriate status
/// code will be set.
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn path_decode_percent(
    cfg: &DecoderConfig,
) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |i| {
        map(
            tuple((
                char('%'),
                alt((
                    path_decode_valid_u_encoding(cfg),
                    path_decode_invalid_u_encoding(cfg),
                    move |remaining_input| {
                        let (_, _) = tag_no_case("u")(remaining_input)?;
                        // Incomplete invalid %u encoding
                        Ok((
                            remaining_input,
                            UrlParseResult {
                                byte: b'%',
                                expected_status_code: cfg.url_encoding_invalid_unwanted,
                                flags: HtpFlags::PATH_INVALID_ENCODING,
                                decode: cfg.url_encoding_invalid_handling
                                    != HtpUrlEncodingHandling::REMOVE_PERCENT,
                            },
                        ))
                    },
                    path_decode_valid_hex(cfg),
                    path_decode_invalid_hex(cfg),
                    move |remaining_input| {
                        // Invalid URL encoding (not even 2 bytes of data)
                        Ok((
                            remaining_input,
                            UrlParseResult {
                                byte: b'%',
                                expected_status_code: cfg.url_encoding_invalid_unwanted,
                                flags: HtpFlags::PATH_INVALID_ENCODING,
                                decode: cfg.url_encoding_invalid_handling
                                    != HtpUrlEncodingHandling::REMOVE_PERCENT,
                            },
                        ))
                    },
                )),
            )),
            |(_, result)| result,
        )(i)
    }
}

/// Assumes the input is already decoded and checks if it is null byte or control character, handling each
/// according to the decoder configurations settings.
///
/// Returns parsed byte, corresponding status code, appropriate flags and whether the byte should be output.
fn path_parse_other(cfg: &DecoderConfig) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |i| {
        let (remaining_input, byte) = be_u8(i)?;
        // One non-encoded byte.
        // Did we get a raw NUL byte?
        if byte == 0 && cfg.nul_raw_terminates {
            // Terminate the path at the encoded NUL byte.
            return Ok((
                b"",
                UrlParseResult {
                    byte,
                    expected_status_code: cfg.nul_raw_unwanted,
                    flags: 0,
                    decode: false,
                },
            ));
        }
        let (byte, expected_status_code) = path_decode_control(byte, cfg);
        Ok((
            remaining_input,
            UrlParseResult {
                byte,
                expected_status_code,
                flags: 0,
                decode: true,
            },
        ))
    }
}
/// Checks for control characters and converts them according to the cfg settings
///
/// Returns decoded byte and expected_status_code
fn path_decode_control(mut byte: u8, cfg: &DecoderConfig) -> (u8, HtpUnwanted) {
    // Note: What if an invalid encoding decodes into a path
    //       separator? This is theoretical at the moment, because
    //       the only platform we know doesn't convert separators is
    //       Apache, who will also respond with 400 if invalid encoding
    //       is encountered. Thus no check for a separator here.
    // Place the character into output
    // Check for control characters
    let expected_status_code = if byte < 0x20 {
        cfg.control_chars_unwanted
    } else {
        HtpUnwanted::Ignore
    };
    // Convert backslashes to forward slashes, if necessary
    if byte == b'\\' && cfg.backslash_convert_slashes {
        byte = b'/'
    }
    // Lowercase characters, if necessary
    if cfg.convert_lowercase {
        byte = byte.to_ascii_lowercase()
    }
    (byte, expected_status_code)
}

/// Performs decoding of the input path uri string, according to the configuration specified
/// by cfg. Various flags (HTP_PATH_*) might be set. If something in the input would
/// cause a particular server to respond with an error, the appropriate status
/// code will be set.
///
/// Returns decoded bytes, flags set during decoding, and corresponding status code
fn path_decode_uri<'a>(
    input: &'a [u8], cfg: &DecoderConfig,
) -> IResult<&'a [u8], (Vec<u8>, u64, HtpUnwanted)> {
    fold_many0(
        alt((path_decode_percent(cfg), path_parse_other(cfg))),
        || (Vec::new(), 0, HtpUnwanted::Ignore),
        |mut acc: (Vec<_>, u64, HtpUnwanted), upr| {
            // If we're compressing separators then we need
            // to check if the previous character was a separator
            if upr.decode {
                // insert
                if upr.byte == b'/' && cfg.path_separators_compress {
                    if !acc.0.is_empty() {
                        if acc.0[acc.0.len() - 1] != b'/' {
                            acc.0.push(upr.byte);
                        }
                    } else {
                        acc.0.push(upr.byte);
                    }
                } else {
                    acc.0.push(upr.byte);
                }
            }
            acc.1.set(upr.flags);
            acc.2 = upr.expected_status_code;
            acc
        },
    )(input)
}

/// Decode the parsed uri path inplace according to the settings in the
/// transaction configuration structure.
pub(crate) fn path_decode_uri_inplace(
    decoder_cfg: &DecoderConfig, flag: &mut u64, status: &mut HtpUnwanted, path: &mut Bstr,
) {
    if let Ok((_, (consumed, flags, expected_status_code))) =
        path_decode_uri(path.as_slice(), decoder_cfg)
    {
        path.clear();
        path.add(consumed.as_slice());
        *status = expected_status_code;
        flag.set(flags);
    }
}

/// Performs decoding of the input uri string, according to the configuration specified
/// by cfg. Various flags (HTP_URLEN_*) might be set. If something in the input would
/// cause a particular server to respond with an error, the appropriate status
/// code will be set.
///
/// Returns decoded bytes, flags set during decoding, and corresponding status code
fn decode_uri<'a>(
    input: &'a [u8], cfg: &DecoderConfig,
) -> IResult<&'a [u8], (Vec<u8>, u64, HtpUnwanted)> {
    fold_many0(
        alt((decode_percent(cfg), decode_plus(cfg), unencoded_byte(cfg))),
        || (Vec::new(), 0, HtpUnwanted::Ignore),
        |mut acc: (Vec<_>, u64, HtpUnwanted), upr| {
            if upr.decode {
                acc.0.push(upr.byte);
            }
            acc.1.set(upr.flags);
            if upr.expected_status_code != HtpUnwanted::Ignore {
                acc.2 = upr.expected_status_code;
            }
            acc
        },
    )(input)
}

/// Performs decoding of the uri string, according to the configuration specified
/// by cfg. Various flags might be set.
pub(crate) fn decode_uri_with_flags(
    decoder_cfg: &DecoderConfig, flags: &mut u64, input: &[u8],
) -> Result<Bstr> {
    let (_, (consumed, f, _)) = decode_uri(input, decoder_cfg)?;
    if f.is_set(HtpFlags::URLEN_INVALID_ENCODING) {
        flags.set(HtpFlags::PATH_INVALID_ENCODING)
    }
    if f.is_set(HtpFlags::URLEN_ENCODED_NUL) {
        flags.set(HtpFlags::PATH_ENCODED_NUL)
    }
    if f.is_set(HtpFlags::URLEN_RAW_NUL) {
        flags.set(HtpFlags::PATH_RAW_NUL);
    }
    Ok(Bstr::from(consumed))
}

/// Performs in-place decoding of the input uri string, according to the configuration specified by cfg and ctx.
///
/// Returns OK on success, ERROR on failure.
pub(crate) fn decode_uri_inplace(cfg: &DecoderConfig, input: &mut Bstr) -> Result<()> {
    let (_, (consumed, _, _)) = decode_uri(input.as_slice(), cfg)?;
    (*input).clear();
    input.add(consumed.as_slice());
    Ok(())
}

/// Decodes valid uencoded hex bytes according to the given cfg settings.
/// e.g. "u0064" -> "d"
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn decode_valid_u_encoding(
    cfg: &DecoderConfig,
) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |input| {
        let (left, _) = alt((char('u'), char('U')))(input)?;
        if cfg.u_encoding_decode {
            let (input, hex) = take_while_m_n(4, 4, |c: u8| c.is_ascii_hexdigit())(left)?;
            let (_, (byte, flags)) = decode_u_encoding_params(hex, cfg)?;
            return Ok((
                input,
                UrlParseResult {
                    byte,
                    expected_status_code: cfg.u_encoding_unwanted,
                    flags,
                    decode: true,
                },
            ));
        }
        Ok((
            input,
            UrlParseResult {
                byte: b'%',
                expected_status_code: HtpUnwanted::Ignore,
                flags: 0,
                decode: true,
            },
        ))
    }
}

/// Decodes invalid uencoded params according to the given cfg settings.
/// e.g. "u00}9" -> "i"
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn decode_invalid_u_encoding(
    cfg: &DecoderConfig,
) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |mut input| {
        let (left, _) = alt((char('u'), char('U')))(input)?;
        let mut byte = b'%';
        let mut code = HtpUnwanted::Ignore;
        let mut flags = 0;
        let mut insert = true;
        if cfg.u_encoding_decode {
            // Invalid %u encoding (could not find 4 xdigits).
            let (left, invalid_hex) = take(4usize)(left)?;
            flags.set(HtpFlags::URLEN_INVALID_ENCODING);
            code = if cfg.url_encoding_invalid_unwanted != HtpUnwanted::Ignore {
                cfg.url_encoding_invalid_unwanted
            } else {
                cfg.u_encoding_unwanted
            };
            if cfg.url_encoding_invalid_handling == HtpUrlEncodingHandling::REMOVE_PERCENT {
                // Do not place anything in output; consume the %.
                insert = false;
            } else if cfg.url_encoding_invalid_handling == HtpUrlEncodingHandling::PROCESS_INVALID {
                let (_, (b, f)) = decode_u_encoding_params(invalid_hex, cfg)?;
                flags.set(f);
                byte = b;
                input = left;
            }
        }
        Ok((
            input,
            UrlParseResult {
                byte,
                expected_status_code: code,
                flags,
                decode: insert,
            },
        ))
    }
}

/// Decodes valid hex byte.
///  e.g. "2f" -> "/"
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn decode_valid_hex() -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> {
    move |input| {
        // Valid encoding (2 xbytes)
        not(alt((char('u'), char('U'))))(input)?;
        let (input, hex) = take_while_m_n(2, 2, |c: u8| c.is_ascii_hexdigit())(input)?;
        let (_, byte) = x2c(hex)?;
        Ok((
            input,
            UrlParseResult {
                byte,
                expected_status_code: HtpUnwanted::Ignore,
                flags: 0,
                decode: true,
            },
        ))
    }
}

/// Decodes invalid hex byte according to the given cfg settings.
/// e.g. "}9" -> "i"
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn decode_invalid_hex(
    cfg: &DecoderConfig,
) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |mut input| {
        not(alt((char('u'), char('U'))))(input)?;
        // Invalid encoding (2 bytes, but not hexadecimal digits).
        let mut byte = b'%';
        let mut insert = true;
        if cfg.url_encoding_invalid_handling == HtpUrlEncodingHandling::REMOVE_PERCENT {
            // Do not place anything in output; consume the %.
            insert = false;
        } else if cfg.url_encoding_invalid_handling == HtpUrlEncodingHandling::PROCESS_INVALID {
            let (left, b) = x2c(input)?;
            input = left;
            byte = b;
        }
        Ok((
            input,
            UrlParseResult {
                byte,
                expected_status_code: cfg.url_encoding_invalid_unwanted,
                flags: HtpFlags::URLEN_INVALID_ENCODING,
                decode: insert,
            },
        ))
    }
}

/// If the first byte of the input string is a '%', it attempts to decode according to the
/// configuration specified by cfg. Various flags (HTP_URLEN_*) might be set. If something in the
/// input would cause a particular server to respond with an error, the appropriate status
/// code will be set.
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn decode_percent(cfg: &DecoderConfig) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |i| {
        let (input, _) = char('%')(i)?;
        let (input, upr) = alt((
            decode_valid_u_encoding(cfg),
            decode_invalid_u_encoding(cfg),
            decode_valid_hex(),
            decode_invalid_hex(cfg),
            move |input| {
                // Invalid %u encoding; not enough data. (not even 2 bytes)
                // Do not place anything in output if REMOVE_PERCENT; consume the %.
                Ok((
                    input,
                    UrlParseResult {
                        byte: b'%',
                        expected_status_code: cfg.url_encoding_invalid_unwanted,
                        flags: HtpFlags::URLEN_INVALID_ENCODING,
                        decode: !(cfg.url_encoding_invalid_handling
                            == HtpUrlEncodingHandling::REMOVE_PERCENT),
                    },
                ))
            },
        ))(input)?;
        //Did we get an encoded NUL byte?
        if upr.byte == 0 {
            let flags = upr.flags | HtpFlags::URLEN_ENCODED_NUL;
            let mut expected_status_code = upr.expected_status_code;
            if cfg.nul_encoded_unwanted != HtpUnwanted::Ignore {
                expected_status_code = cfg.nul_encoded_unwanted
            }
            if cfg.nul_encoded_terminates {
                // Terminate the path at the encoded NUL byte.
                return Ok((
                    b"",
                    UrlParseResult {
                        byte: upr.byte,
                        expected_status_code,
                        flags,
                        decode: false,
                    },
                ));
            }
        }
        Ok((
            input,
            UrlParseResult {
                byte: upr.byte,
                expected_status_code: upr.expected_status_code,
                flags: upr.flags,
                decode: upr.decode,
            },
        ))
    }
}

/// Consumes the next nullbyte if it is a '+', decoding it according to the cfg
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn decode_plus(cfg: &DecoderConfig) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |input| {
        let (input, byte) = map(char('+'), |byte| {
            // Decoding of the plus character is conditional on the configuration.
            if cfg.plusspace_decode {
                0x20
            } else {
                byte as u8
            }
        })(input)?;
        Ok((
            input,
            UrlParseResult {
                byte,
                expected_status_code: HtpUnwanted::Ignore,
                flags: 0,
                decode: true,
            },
        ))
    }
}

/// Consumes the next byte in the input string and treats it as an unencoded byte.
/// Handles raw null bytes according to the input cfg settings.
///
/// Returns decoded byte, corresponding status code, appropriate flags and whether the byte should be output.
fn unencoded_byte(cfg: &DecoderConfig) -> impl Fn(&[u8]) -> IResult<&[u8], UrlParseResult> + '_ {
    move |input| {
        let (input, byte) = be_u8(input)?;
        // One non-encoded byte.
        // Did we get a raw NUL byte?
        if byte == 0 {
            return Ok((
                if cfg.nul_raw_terminates { b"" } else { input },
                UrlParseResult {
                    byte,
                    expected_status_code: cfg.nul_raw_unwanted,
                    flags: HtpFlags::URLEN_RAW_NUL,
                    decode: !cfg.nul_raw_terminates,
                },
            ));
        }
        Ok((
            input,
            UrlParseResult {
                byte,
                expected_status_code: HtpUnwanted::Ignore,
                flags: 0,
                decode: true,
            },
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::Config;
    use rstest::rstest;

    #[rstest]
    #[case("/dest", "/dest", "/dest", "/dest")]
    #[case("/%64est", "/dest", "/dest", "/dest")]
    #[case("/%xxest", "/1est", "/%xxest", "/xxest")]
    #[case("/%a", "/%a", "/%a", "/a")]
    #[case("/%00ABC", "/\0ABC", "/\0ABC", "/\0ABC")]
    #[case("/%u0064", "/%u0064", "/%u0064", "/%u0064")]
    #[case("/%u006", "/%u006", "/%u006", "/%u006")]
    #[case("/%uXXXX", "/%uXXXX", "/%uXXXX", "/%uXXXX")]
    #[case("/%u0000ABC", "/%u0000ABC", "/%u0000ABC", "/%u0000ABC")]
    #[case("/\0ABC", "/\0ABC", "/\0ABC", "/\0ABC")]
    #[case("/one%2ftwo", "/one/two", "/one/two", "/one/two")]
    fn test_decode_uri(
        #[case] input: &str, #[case] expected_process: &str, #[case] expected_preserve: &str,
        #[case] expected_remove: &str,
    ) {
        let i = Bstr::from(input);
        let mut cfg = Config::default();

        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PROCESS_INVALID);
        assert_eq!(
            decode_uri(&i, &cfg.decoder_cfg).unwrap().1 .0,
            expected_process.as_bytes()
        );

        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
        assert_eq!(
            decode_uri(&i, &cfg.decoder_cfg).unwrap().1 .0,
            expected_preserve.as_bytes()
        );

        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::REMOVE_PERCENT);
        assert_eq!(
            decode_uri(&i, &cfg.decoder_cfg).unwrap().1 .0,
            expected_remove.as_bytes()
        );
    }

    #[rstest]
    #[case("/dest", "/dest", "/dest", "/dest")]
    #[case("/%64est", "/dest", "/dest", "/dest")]
    #[case("/%xxest", "/1est", "/%xxest", "/xxest")]
    #[case("/%a", "/%a", "/%a", "/a")]
    #[case("/%00ABC", "/\0ABC", "/\0ABC", "/\0ABC")]
    #[case("/%u0064", "/d", "/d", "/d")]
    #[case("/%U0064", "/d", "/d", "/d")]
    #[case("/%u006", "/%u006", "/%u006", "/u006")]
    #[case("/%uXXXX", "/?", "/%uXXXX", "/uXXXX")]
    #[case("/%u0000ABC", "/\0ABC", "/\0ABC", "/\0ABC")]
    #[case("/\0ABC", "/\0ABC", "/\0ABC", "/\0ABC")]
    #[case("/one%2ftwo", "/one/two", "/one/two", "/one/two")]
    fn test_decode_uri_decode(
        #[case] input: &str, #[case] expected_process: &str, #[case] expected_preserve: &str,
        #[case] expected_remove: &str,
    ) {
        let i = Bstr::from(input);
        let mut cfg = Config::default();
        cfg.set_u_encoding_decode(true);

        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PROCESS_INVALID);
        assert_eq!(
            decode_uri(&i, &cfg.decoder_cfg).unwrap().1 .0,
            expected_process.as_bytes()
        );

        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
        assert_eq!(
            decode_uri(&i, &cfg.decoder_cfg).unwrap().1 .0,
            expected_preserve.as_bytes()
        );

        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::REMOVE_PERCENT);
        assert_eq!(
            decode_uri(&i, &cfg.decoder_cfg).unwrap().1 .0,
            expected_remove.as_bytes()
        );
    }

    #[rstest]
    #[case("/%u0000ABC")]
    #[case("/%00ABC")]
    #[case("/\0ABC")]
    fn test_decode_uri_nul_terminates(#[case] input: &str) {
        let i = Bstr::from(input);
        let mut cfg = Config::default();
        cfg.set_u_encoding_decode(true);
        cfg.set_nul_encoded_terminates(true);
        cfg.set_nul_raw_terminates(true);
        assert_eq!(decode_uri(&i, &cfg.decoder_cfg).unwrap().1 .0, b"/");
    }

    #[rstest]
    #[case("/dest", "/dest", "/dest", "/dest", 0)]
    #[case("/%64est", "/dest", "/dest", "/dest", 0)]
    #[case(
        "/%xxest",
        "/1est",
        "/%xxest",
        "/xxest",
        HtpFlags::PATH_INVALID_ENCODING
    )]
    #[case("/%a", "/%a", "/%a", "/a", HtpFlags::PATH_INVALID_ENCODING)]
    #[case("/%00ABC", "/\0ABC", "/\0ABC", "/\0ABC", HtpFlags::PATH_ENCODED_NUL)]
    #[case("/%u0064", "/%u0064", "/%u0064", "/%u0064", 0)]
    #[case("/%u006", "/%u006", "/%u006", "/%u006", 0)]
    #[case("/%uXXXX", "/%uXXXX", "/%uXXXX", "/%uXXXX", 0)]
    #[case("/%u0000ABC", "/%u0000ABC", "/%u0000ABC", "/%u0000ABC", 0)]
    #[case("/\0ABC", "/\0ABC", "/\0ABC", "/\0ABC", 0)]
    #[case(
        "/one%2ftwo",
        "/one%2ftwo",
        "/one%2ftwo",
        "/one%2ftwo",
        HtpFlags::PATH_ENCODED_SEPARATOR
    )]
    fn test_path_decode_uri_inplace(
        #[case] input: &str, #[case] expected_process: &str, #[case] expected_preserve: &str,
        #[case] expected_remove: &str, #[case] flags: u64,
    ) {
        let mut cfg = Config::default();
        let mut response_status_expected_number = HtpUnwanted::Ignore;

        let mut input_process = Bstr::from(input);
        let mut flags_process = 0;
        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PROCESS_INVALID);
        path_decode_uri_inplace(
            &cfg.decoder_cfg,
            &mut flags_process,
            &mut response_status_expected_number,
            &mut input_process,
        );
        assert_eq!(input_process, Bstr::from(expected_process));
        assert_eq!(flags_process, flags);

        let mut input_preserve = Bstr::from(input);
        let mut flags_preserve = 0;
        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
        path_decode_uri_inplace(
            &cfg.decoder_cfg,
            &mut flags_preserve,
            &mut response_status_expected_number,
            &mut input_preserve,
        );
        assert_eq!(input_preserve, Bstr::from(expected_preserve));
        assert_eq!(flags_preserve, flags);

        let mut input_remove = Bstr::from(input);
        let mut flags_remove = 0;
        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::REMOVE_PERCENT);
        path_decode_uri_inplace(
            &cfg.decoder_cfg,
            &mut flags_remove,
            &mut response_status_expected_number,
            &mut input_remove,
        );
        assert_eq!(input_remove, Bstr::from(expected_remove));
        assert_eq!(flags_remove, flags);
    }

    #[rstest]
    #[case("/dest", "/dest", "/dest", "/dest", 0)]
    #[case("/%64est", "/dest", "/dest", "/dest", 0)]
    #[case(
        "/%xxest",
        "/1est",
        "/%xxest",
        "/xxest",
        HtpFlags::PATH_INVALID_ENCODING
    )]
    #[case("/%a", "/%a", "/%a", "/a", HtpFlags::PATH_INVALID_ENCODING)]
    #[case("/%00ABC", "/\0ABC", "/\0ABC", "/\0ABC", HtpFlags::PATH_ENCODED_NUL)]
    #[case("/%u0064", "/d", "/d", "/d", HtpFlags::PATH_OVERLONG_U)]
    #[case("/%U0064", "/d", "/d", "/d", HtpFlags::PATH_OVERLONG_U)]
    #[case("/%u006", "/%u006", "/%u006", "/u006", HtpFlags::PATH_INVALID_ENCODING)]
    #[case("/%uXXXX", "/?", "/%uXXXX", "/uXXXX", HtpFlags::PATH_INVALID_ENCODING)]
    #[case("/%u0000ABC", "/\0ABC", "/\0ABC", "/\0ABC", HtpFlags::PATH_ENCODED_NUL | HtpFlags::PATH_OVERLONG_U)]
    #[case("/\0ABC", "/\0ABC", "/\0ABC", "/\0ABC", 0)]
    #[case(
        "/one%2ftwo",
        "/one%2ftwo",
        "/one%2ftwo",
        "/one%2ftwo",
        HtpFlags::PATH_ENCODED_SEPARATOR
    )]
    fn test_path_decode_uri_inplace_decode(
        #[case] input: &str, #[case] expected_process: &str, #[case] expected_preserve: &str,
        #[case] expected_remove: &str, #[case] flags: u64,
    ) {
        let mut cfg = Config::default();
        cfg.set_u_encoding_decode(true);
        let mut response_status_expected_number = HtpUnwanted::Ignore;

        let mut input_process = Bstr::from(input);
        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PROCESS_INVALID);
        let mut flags_process = 0;
        path_decode_uri_inplace(
            &cfg.decoder_cfg,
            &mut flags_process,
            &mut response_status_expected_number,
            &mut input_process,
        );
        assert_eq!(input_process, Bstr::from(expected_process));
        assert_eq!(flags_process, flags);

        let mut input_preserve = Bstr::from(input);
        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
        let mut flags_preserve = 0;
        path_decode_uri_inplace(
            &cfg.decoder_cfg,
            &mut flags_preserve,
            &mut response_status_expected_number,
            &mut input_preserve,
        );
        assert_eq!(input_preserve, Bstr::from(expected_preserve));
        assert_eq!(flags_preserve, flags);

        let mut input_remove = Bstr::from(input);
        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::REMOVE_PERCENT);
        let mut flags_remove = 0;
        path_decode_uri_inplace(
            &cfg.decoder_cfg,
            &mut flags_remove,
            &mut response_status_expected_number,
            &mut input_remove,
        );
        assert_eq!(input_remove, Bstr::from(expected_remove));
        assert_eq!(flags_remove, flags);
    }

    #[rstest]
    #[case("/%u0000ABC", HtpFlags::PATH_ENCODED_NUL | HtpFlags::PATH_OVERLONG_U)]
    #[case("/%00ABC", HtpFlags::PATH_ENCODED_NUL)]
    #[case("/\0ABC", 0)]
    fn test_path_decode_inplace_nul_terminates(#[case] input: &str, #[case] expected_flags: u64) {
        let mut cfg = Config::default();
        cfg.set_u_encoding_decode(true);
        cfg.set_nul_encoded_terminates(true);
        cfg.set_nul_raw_terminates(true);
        let mut i = Bstr::from(input);
        let mut flags = 0;
        let mut response_status_expected_number = HtpUnwanted::Ignore;
        path_decode_uri_inplace(
            &cfg.decoder_cfg,
            &mut flags,
            &mut response_status_expected_number,
            &mut i,
        );
        assert_eq!(i, Bstr::from("/"));
        assert_eq!(flags, expected_flags);
    }

    #[rstest]
    #[case::encoded("/one%2ftwo")]
    #[case::convert("/one\\two")]
    #[case::compress("/one//two")]
    fn test_path_decode_inplace_seps(#[case] input: &str) {
        let mut cfg = Config::default();
        cfg.set_backslash_convert_slashes(true);
        cfg.set_path_separators_decode(true);
        cfg.set_path_separators_compress(true);
        let mut i = Bstr::from(input);
        let mut flags = 0;
        let mut response_status_expected_number = HtpUnwanted::Ignore;
        path_decode_uri_inplace(
            &cfg.decoder_cfg,
            &mut flags,
            &mut response_status_expected_number,
            &mut i,
        );
        assert_eq!(i, Bstr::from("/one/two"));
    }

    #[rstest]
    #[case(
        "/one/tw%u006f/three/%u123",
        "/one/two/three/%u123",
        "/one/two/three/%u123",
        "/one/two/three/u123"
    )]
    #[case(
        "/one/tw%u006f/three/%3",
        "/one/two/three/%3",
        "/one/two/three/%3",
        "/one/two/three/3"
    )]
    #[case(
        "/one/tw%u006f/three/%uXXXX",
        "/one/two/three/?",
        "/one/two/three/%uXXXX",
        "/one/two/three/uXXXX"
    )]
    fn test_decode_uri_inplace(
        #[case] input: &str, #[case] expected_process: &str, #[case] expected_preserve: &str,
        #[case] expected_remove: &str,
    ) {
        let mut cfg = Config::default();
        cfg.set_u_encoding_decode(true);

        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PROCESS_INVALID);
        let mut input_process = Bstr::from(input);
        decode_uri_inplace(&cfg.decoder_cfg, &mut input_process).unwrap();
        assert_eq!(input_process, Bstr::from(expected_process));

        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
        let mut input_preserve = Bstr::from(input);
        decode_uri_inplace(&cfg.decoder_cfg, &mut input_preserve).unwrap();
        assert_eq!(input_preserve, Bstr::from(expected_preserve));

        cfg.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::REMOVE_PERCENT);
        let mut input_remove = Bstr::from(input);
        decode_uri_inplace(&cfg.decoder_cfg, &mut input_remove).unwrap();
        assert_eq!(input_remove, Bstr::from(expected_remove));
    }
}
