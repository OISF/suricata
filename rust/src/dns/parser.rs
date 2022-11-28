/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//! Nom parsers for DNS.

use crate::dns::dns::*;
use nom7::combinator::{complete, rest};
use nom7::error::ErrorKind;
use nom7::multi::{count, length_data, many_m_n};
use nom7::number::streaming::{be_u16, be_u32, be_u8};
use nom7::{error_position, Err, IResult};

// Parse a DNS header.
pub fn dns_parse_header(i: &[u8]) -> IResult<&[u8], DNSHeader> {
    let (i, tx_id) = be_u16(i)?;
    let (i, flags) = be_u16(i)?;
    let (i, questions) = be_u16(i)?;
    let (i, answer_rr) = be_u16(i)?;
    let (i, authority_rr) = be_u16(i)?;
    let (i, additional_rr) = be_u16(i)?;
    Ok((
        i,
        DNSHeader {
            tx_id,
            flags,
            questions,
            answer_rr,
            authority_rr,
            additional_rr,
        },
    ))
}

/// Parse a DNS name.
///
/// Parameters:
///   start: the start of the name
///   message: the complete message that start is a part of
pub fn dns_parse_name<'b>(start: &'b [u8], message: &'b [u8]) -> IResult<&'b [u8], Vec<u8>> {
    let mut pos = start;
    let mut pivot = start;
    let mut name: Vec<u8> = Vec::with_capacity(32);
    let mut count = 0;

    loop {
        if pos.is_empty() {
            break;
        }

        let len = pos[0];

        if len == 0x00 {
            pos = &pos[1..];
            break;
        } else if len & 0b1100_0000 == 0 {
            let (rem, label) = length_data(be_u8)(pos)?;
            if !name.is_empty() {
                name.push(b'.');
            }
            name.extend(label);
            pos = rem;
        } else if len & 0b1100_0000 == 0b1100_0000 {
            let (rem, leader) = be_u16(pos)?;
            let offset = usize::from(leader) & 0x3fff;
            if offset > message.len() {
                return Err(Err::Error(error_position!(pos, ErrorKind::OctDigit)));
            }
            pos = &message[offset..];
            if pivot == start {
                pivot = rem;
            }
        } else {
            return Err(Err::Error(error_position!(pos, ErrorKind::OctDigit)));
        }

        // Return error if we've looped a certain number of times.
        count += 1;
        if count > 255 {
            return Err(Err::Error(error_position!(pos, ErrorKind::OctDigit)));
        }
    }

    // If we followed a pointer we return the position after the first
    // pointer followed. Is there a better way to see if these slices
    // diverged from each other?  A straight up comparison would
    // actually check the contents.
    if pivot.len() != start.len() {
        return Ok((pivot, name));
    }
    return Ok((pos, name));
}

/// Parse answer entries.
///
/// In keeping with the C implementation, answer values that can
/// contain multiple answers get expanded into their own answer
/// records. An example of this is a TXT record with multiple strings
/// in it - each string will be expanded to its own answer record.
///
/// This function could be a made a whole lot simpler if we logged a
/// multi-string TXT entry as a single quote string, similar to the
/// output of dig. Something to consider for a future version.
fn dns_parse_answer<'a>(
    slice: &'a [u8], message: &'a [u8], count: usize,
) -> IResult<&'a [u8], Vec<DNSAnswerEntry>> {
    let mut answers = Vec::new();
    let mut input = slice;

    fn subparser<'a>(
        i: &'a [u8], message: &'a [u8],
    ) -> IResult<&'a [u8], (Vec<u8>, u16, u16, u32, &'a [u8])> {
        let (i, name) = dns_parse_name(i, message)?;
        let (i, rrtype) = be_u16(i)?;
        let (i, rrclass) = be_u16(i)?;
        let (i, ttl) = be_u32(i)?;
        let (i, data) = length_data(be_u16)(i)?;
        Ok((i, (name, rrtype, rrclass, ttl, data)))
    }

    for _ in 0..count {
        match subparser(input, message) {
            Ok((rem, val)) => {
                let name = val.0;
                let rrtype = val.1;
                let rrclass = val.2;
                let ttl = val.3;
                let data = val.4;
                let n = match rrtype {
                    DNS_RECORD_TYPE_TXT => {
                        // For TXT records we need to run the parser
                        // multiple times. Set n high, to the maximum
                        // value based on a max txt side of 65535, but
                        // taking into considering that strings need
                        // to be quoted, so half that.
                        32767
                    }
                    _ => {
                        // For all other types we only want to run the
                        // parser once, so set n to 1.
                        1
                    }
                };
                let result: IResult<&'a [u8], Vec<DNSRData>> =
                    many_m_n(1, n, complete(|b| dns_parse_rdata(b, message, rrtype)))(data);
                match result {
                    Ok((_, rdatas)) => {
                        for rdata in rdatas {
                            answers.push(DNSAnswerEntry {
                                name: name.clone(),
                                rrtype,
                                rrclass,
                                ttl,
                                data: rdata,
                            });
                        }
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
                input = rem;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    return Ok((input, answers));
}

/// Parse a DNS response.
pub fn dns_parse_response(slice: &[u8]) -> IResult<&[u8], DNSResponse> {
    let i = slice;
    let (i, header) = dns_parse_header(i)?;
    let (i, queries) = count(|b| dns_parse_query(b, slice), header.questions as usize)(i)?;
    let (i, answers) = dns_parse_answer(i, slice, header.answer_rr as usize)?;
    let (i, authorities) = dns_parse_answer(i, slice, header.authority_rr as usize)?;
    Ok((
        i,
        DNSResponse {
            header,
            queries,
            answers,
            authorities,
        },
    ))
}

/// Parse a single DNS query.
///
/// Arguments are suitable for using with call!:
///
///    call!(complete_dns_message_buffer)
pub fn dns_parse_query<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DNSQueryEntry> {
    let i = input;
    let (i, name) = dns_parse_name(i, message)?;
    let (i, rrtype) = be_u16(i)?;
    let (i, rrclass) = be_u16(i)?;
    Ok((
        i,
        DNSQueryEntry {
            name,
            rrtype,
            rrclass,
        },
    ))
}

fn dns_parse_rdata_a(input: &[u8]) -> IResult<&[u8], DNSRData> {
    rest(input).map(|(input, data)| (input, DNSRData::A(data.to_vec())))
}

fn dns_parse_rdata_aaaa(input: &[u8]) -> IResult<&[u8], DNSRData> {
    rest(input).map(|(input, data)| (input, DNSRData::AAAA(data.to_vec())))
}

fn dns_parse_rdata_cname<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    dns_parse_name(input, message).map(|(input, name)| (input, DNSRData::CNAME(name)))
}

fn dns_parse_rdata_ns<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    dns_parse_name(input, message).map(|(input, name)| (input, DNSRData::NS(name)))
}

fn dns_parse_rdata_ptr<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    dns_parse_name(input, message).map(|(input, name)| (input, DNSRData::PTR(name)))
}

fn dns_parse_rdata_soa<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    let i = input;
    let (i, mname) = dns_parse_name(i, message)?;
    let (i, rname) = dns_parse_name(i, message)?;
    let (i, serial) = be_u32(i)?;
    let (i, refresh) = be_u32(i)?;
    let (i, retry) = be_u32(i)?;
    let (i, expire) = be_u32(i)?;
    let (i, minimum) = be_u32(i)?;
    Ok((
        i,
        DNSRData::SOA(DNSRDataSOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }),
    ))
}

fn dns_parse_rdata_mx<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    // For MX we skip over the preference field before
    // parsing out the name.
    let (i, _) = be_u16(input)?;
    let (i, name) = dns_parse_name(i, message)?;
    Ok((i, DNSRData::MX(name)))
}

fn dns_parse_rdata_srv<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    let i = input;
    let (i, priority) = be_u16(i)?;
    let (i, weight) = be_u16(i)?;
    let (i, port) = be_u16(i)?;
    let (i, target) = dns_parse_name(i, message)?;
    Ok((
        i,
        DNSRData::SRV(DNSRDataSRV {
            priority,
            weight,
            port,
            target,
        }),
    ))
}

fn dns_parse_rdata_txt(input: &[u8]) -> IResult<&[u8], DNSRData> {
    let (i, txt) = length_data(be_u8)(input)?;
    Ok((i, DNSRData::TXT(txt.to_vec())))
}

fn dns_parse_rdata_null(input: &[u8]) -> IResult<&[u8], DNSRData> {
    rest(input).map(|(input, data)| (input, DNSRData::NULL(data.to_vec())))
}

fn dns_parse_rdata_sshfp(input: &[u8]) -> IResult<&[u8], DNSRData> {
    let i = input;
    let (i, algo) = be_u8(i)?;
    let (i, fp_type) = be_u8(i)?;
    let fingerprint = i;
    Ok((
        &[],
        DNSRData::SSHFP(DNSRDataSSHFP {
            algo,
            fp_type,
            fingerprint: fingerprint.to_vec(),
        }),
    ))
}

fn dns_parse_rdata_unknown(input: &[u8]) -> IResult<&[u8], DNSRData> {
    rest(input).map(|(input, data)| (input, DNSRData::Unknown(data.to_vec())))
}

pub fn dns_parse_rdata<'a>(
    input: &'a [u8], message: &'a [u8], rrtype: u16,
) -> IResult<&'a [u8], DNSRData> {
    match rrtype {
        DNS_RECORD_TYPE_A => dns_parse_rdata_a(input),
        DNS_RECORD_TYPE_AAAA => dns_parse_rdata_aaaa(input),
        DNS_RECORD_TYPE_CNAME => dns_parse_rdata_cname(input, message),
        DNS_RECORD_TYPE_PTR => dns_parse_rdata_ptr(input, message),
        DNS_RECORD_TYPE_SOA => dns_parse_rdata_soa(input, message),
        DNS_RECORD_TYPE_MX => dns_parse_rdata_mx(input, message),
        DNS_RECORD_TYPE_NS => dns_parse_rdata_ns(input, message),
        DNS_RECORD_TYPE_TXT => dns_parse_rdata_txt(input),
        DNS_RECORD_TYPE_NULL => dns_parse_rdata_null(input),
        DNS_RECORD_TYPE_SSHFP => dns_parse_rdata_sshfp(input),
        DNS_RECORD_TYPE_SRV => dns_parse_rdata_srv(input, message),
        _ => dns_parse_rdata_unknown(input),
    }
}

/// Parse a DNS request.
pub fn dns_parse_request(input: &[u8]) -> IResult<&[u8], DNSRequest> {
    let i = input;
    let (i, header) = dns_parse_header(i)?;
    let (i, queries) = count(|b| dns_parse_query(b, input), header.questions as usize)(i)?;
    Ok((i, DNSRequest { header, queries }))
}

#[cfg(test)]
mod tests {

    use crate::dns::dns::{DNSHeader,DNSAnswerEntry};
    use crate::dns::parser::*;

    /// Parse a simple name with no pointers.
    #[test]
    fn test_dns_parse_name() {
        let buf: &[u8] = &[
                                                0x09, 0x63, /* .......c */
            0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x63, 0x66, /* lient-cf */
            0x07, 0x64, 0x72, 0x6f, 0x70, 0x62, 0x6f, 0x78, /* .dropbox */
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, /* .com.... */
        ];
        let expected_remainder: &[u8] = &[0x00, 0x01, 0x00];
        let (remainder,name) = dns_parse_name(buf, buf).unwrap();
        assert_eq!("client-cf.dropbox.com".as_bytes(), &name[..]);
        assert_eq!(remainder, expected_remainder);
    }

    /// Test parsing a name with pointers.
    #[test]
    fn test_dns_parse_name_with_pointer() {
        let buf: &[u8] = &[
            0xd8, 0xcb, 0x8a, 0xed, 0xa1, 0x46, 0x00, 0x15 /* 0   - .....F.. */,
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00 /* 8   - ......E. */,
            0x00, 0x7b, 0x71, 0x6e, 0x00, 0x00, 0x39, 0x11 /* 16  - .{qn..9. */,
            0xf4, 0xd9, 0x08, 0x08, 0x08, 0x08, 0x0a, 0x10 /* 24  - ........ */,
            0x01, 0x0b, 0x00, 0x35, 0xe1, 0x8e, 0x00, 0x67 /* 32  - ...5...g */,
            0x60, 0x00, 0xef, 0x08, 0x81, 0x80, 0x00, 0x01 /* 40  - `....... */,
            0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77 /* 48  - .......w */,
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63 /* 56  - ww.suric */,
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03 /* 64  - ata-ids. */,
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01 /* 72  - org..... */,
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00 /* 80  - ........ */,
            0x0e, 0x0f, 0x00, 0x02, 0xc0, 0x10, 0xc0, 0x10 /* 88  - ........ */,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2b /* 96  - .......+ */,
            0x00, 0x04, 0xc0, 0x00, 0x4e, 0x19, 0xc0, 0x10 /* 104 - ....N... */,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2b /* 112 - .......+ */,
            0x00, 0x04, 0xc0, 0x00, 0x4e, 0x18, 0x00, 0x00 /* 120 - ....N... */,
            0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /* 128 - )....... */,
            0x00,                                          /* 136 - . */
        ];

        // The DNS payload starts at offset 42.
        let message = &buf[42..];

        // The name at offset 54 is the complete name.
        let start1 = &buf[54..];
        let res1 = dns_parse_name(start1, message);
        assert_eq!(res1,
                   Ok((&start1[22..],
                                 "www.suricata-ids.org".as_bytes().to_vec())));

        // The second name starts at offset 80, but is just a pointer
        // to the first.
        let start2 = &buf[80..];
        let res2 = dns_parse_name(start2, message);
        assert_eq!(res2,
                   Ok((&start2[2..],
                                 "www.suricata-ids.org".as_bytes().to_vec())));

        // The third name starts at offset 94, but is a pointer to a
        // portion of the first.
        let start3 = &buf[94..];
        let res3 = dns_parse_name(start3, message);
        assert_eq!(res3,
                   Ok((&start3[2..],
                                 "suricata-ids.org".as_bytes().to_vec())));

        // The fourth name starts at offset 110, but is a pointer to a
        // portion of the first.
        let start4 = &buf[110..];
        let res4 = dns_parse_name(start4, message);
        assert_eq!(res4,
                   Ok((&start4[2..],
                                 "suricata-ids.org".as_bytes().to_vec())));
    }

    #[test]
    fn test_dns_parse_name_double_pointer() {
        let buf: &[u8] = &[
            0xd8, 0xcb, 0x8a, 0xed, 0xa1, 0x46, 0x00, 0x15 /* 0:   .....F.. */,
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00 /* 8:   ......E. */,
            0x00, 0x66, 0x5e, 0x20, 0x40, 0x00, 0x40, 0x11 /* 16:  .f^ @.@. */,
            0xc6, 0x3b, 0x0a, 0x10, 0x01, 0x01, 0x0a, 0x10 /* 24:  .;...... */,
            0x01, 0x0b, 0x00, 0x35, 0xc2, 0x21, 0x00, 0x52 /* 32:  ...5.!.R */,
            0x35, 0xc5, 0x0d, 0x4f, 0x81, 0x80, 0x00, 0x01 /* 40:  5..O.... */,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62 /* 48:  .......b */,
            0x6c, 0x6f, 0x63, 0x6b, 0x07, 0x64, 0x72, 0x6f /* 56:  lock.dro */,
            0x70, 0x62, 0x6f, 0x78, 0x03, 0x63, 0x6f, 0x6d /* 64:  pbox.com */,
            0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00 /* 72:  ........ */,
            0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00 /* 80:  ........ */,
            0x0b, 0x05, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x02 /* 88:  ..block. */,
            0x67, 0x31, 0xc0, 0x12, 0xc0, 0x2f, 0x00, 0x01 /* 96:  g1.../.. */,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04 /* 104: ........ */,
            0x2d, 0x3a, 0x46, 0x21                         /* 112: -:F!     */
        ];

        // The start of the DNS message in the above packet.
        let message: &[u8] = &buf[42..];

        // The start of the name we want to parse, 0xc0 0x2f, a
        // pointer to offset 47 in the message (or 89 in the full
        // packet).
        let start: &[u8] = &buf[100..];

        let res = dns_parse_name(start, message);
        assert_eq!(res,
                   Ok((&start[2..],
                                 "block.g1.dropbox.com".as_bytes().to_vec())));
    }

    #[test]
    fn test_dns_parse_request() {
        // DNS request from dig-a-www.suricata-ids.org.pcap.
        let pkt: &[u8] = &[
                        0x8d, 0x32, 0x01, 0x20, 0x00, 0x01, /* ...2. .. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, /* .......w */
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63, /* ww.suric */
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03, /* ata-ids. */
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01, /* org..... */
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, /* ..)..... */
            0x00, 0x00, 0x00                                /* ... */
        ];

        let res = dns_parse_request(pkt);
        match res {
            Ok((rem, request)) => {

                // For now we have some remainder data as there is an
                // additional record type we don't parse yet.
                assert!(!rem.is_empty());

                assert_eq!(request.header, DNSHeader {
                    tx_id: 0x8d32,
                    flags: 0x0120,
                    questions: 1,
                    answer_rr: 0,
                    authority_rr: 0,
                    additional_rr: 1,
                });

                assert_eq!(request.queries.len(), 1);

                let query = &request.queries[0];
                assert_eq!(query.name,
                           "www.suricata-ids.org".as_bytes().to_vec());
                assert_eq!(query.rrtype, 1);
                assert_eq!(query.rrclass, 1);
            }
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_dns_parse_response() {
        // DNS response from dig-a-www.suricata-ids.org.pcap.
        let pkt: &[u8] = &[
                        0x8d, 0x32, 0x81, 0xa0, 0x00, 0x01, /* ...2.... */
            0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, /* .......w */
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63, /* ww.suric */
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03, /* ata-ids. */
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01, /* org..... */
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, /* ........ */
            0x0d, 0xd8, 0x00, 0x12, 0x0c, 0x73, 0x75, 0x72, /* .....sur */
            0x69, 0x63, 0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, /* icata-id */
            0x73, 0x03, 0x6f, 0x72, 0x67, 0x00, 0xc0, 0x32, /* s.org..2 */
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf4, /* ........ */
            0x00, 0x04, 0xc0, 0x00, 0x4e, 0x18, 0xc0, 0x32, /* ....N..2 */
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf4, /* ........ */
            0x00, 0x04, 0xc0, 0x00, 0x4e, 0x19              /* ....N. */
        ];

        let res = dns_parse_response(pkt);
        match res {
            Ok((rem, response)) => {

                // The response should be full parsed.
                assert_eq!(rem.len(), 0);

                assert_eq!(response.header, DNSHeader{
                    tx_id: 0x8d32,
                    flags: 0x81a0,
                    questions: 1,
                    answer_rr: 3,
                    authority_rr: 0,
                    additional_rr: 0,
                });

                assert_eq!(response.answers.len(), 3);

                let answer1 = &response.answers[0];
                assert_eq!(answer1.name,
                           "www.suricata-ids.org".as_bytes().to_vec());
                assert_eq!(answer1.rrtype, 5);
                assert_eq!(answer1.rrclass, 1);
                assert_eq!(answer1.ttl, 3544);
                assert_eq!(answer1.data,
                           DNSRData::CNAME("suricata-ids.org".as_bytes().to_vec()));

                let answer2 = &response.answers[1];
                assert_eq!(answer2, &DNSAnswerEntry{
                    name: "suricata-ids.org".as_bytes().to_vec(),
                    rrtype: 1,
                    rrclass: 1,
                    ttl: 244,
                    data: DNSRData::A([192, 0, 78, 24].to_vec()),
                });

                let answer3 = &response.answers[2];
                assert_eq!(answer3, &DNSAnswerEntry{
                    name: "suricata-ids.org".as_bytes().to_vec(),
                    rrtype: 1,
                    rrclass: 1,
                    ttl: 244,
                    data: DNSRData::A([192, 0, 78, 25].to_vec()),
                })

            },
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_dns_parse_response_nxdomain_soa() {
        // DNS response with an SOA authority record from
        // dns-udp-nxdomain-soa.pcap.
        let pkt: &[u8] = &[
                        0x82, 0x95, 0x81, 0x83, 0x00, 0x01, /* j....... */
            0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x64, /* .......d */
            0x6e, 0x65, 0x04, 0x6f, 0x69, 0x73, 0x66, 0x03, /* ne.oisf. */
            0x6e, 0x65, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, /* net..... */
            0xc0, 0x10, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, /* ........ */
            0x03, 0x83, 0x00, 0x45, 0x06, 0x6e, 0x73, 0x2d, /* ...E.ns- */
            0x31, 0x31, 0x30, 0x09, 0x61, 0x77, 0x73, 0x64, /* 110.awsd */
            0x6e, 0x73, 0x2d, 0x31, 0x33, 0x03, 0x63, 0x6f, /* ns-13.co */
            0x6d, 0x00, 0x11, 0x61, 0x77, 0x73, 0x64, 0x6e, /* m..awsdn */
            0x73, 0x2d, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, /* s-hostma */
            0x73, 0x74, 0x65, 0x72, 0x06, 0x61, 0x6d, 0x61, /* ster.ama */
            0x7a, 0x6f, 0x6e, 0xc0, 0x3b, 0x00, 0x00, 0x00, /* zon.;... */
            0x01, 0x00, 0x00, 0x1c, 0x20, 0x00, 0x00, 0x03, /* .... ... */
            0x84, 0x00, 0x12, 0x75, 0x00, 0x00, 0x01, 0x51, /* ...u...Q */
            0x80, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, /* ...).... */
            0x00, 0x00, 0x00, 0x00                          /* .... */
        ];

        let res = dns_parse_response(pkt);
        match res {
            Ok((rem, response)) => {

                // For now we have some remainder data as there is an
                // additional record type we don't parse yet.
                assert!(!rem.is_empty());

                assert_eq!(response.header, DNSHeader{
                    tx_id: 0x8295,
                    flags: 0x8183,
                    questions: 1,
                    answer_rr: 0,
                    authority_rr: 1,
                    additional_rr: 1,
                });

                assert_eq!(response.authorities.len(), 1);

                let authority = &response.authorities[0];
                assert_eq!(authority.name,
                           "oisf.net".as_bytes().to_vec());
                assert_eq!(authority.rrtype, 6);
                assert_eq!(authority.rrclass, 1);
                assert_eq!(authority.ttl, 899);
                assert_eq!(authority.data,
                           DNSRData::SOA(DNSRDataSOA{
                               mname: "ns-110.awsdns-13.com".as_bytes().to_vec(),
                               rname: "awsdns-hostmaster.amazon.com".as_bytes().to_vec(),
                               serial: 1,
                               refresh: 7200,
                               retry: 900,
                               expire: 1209600,
                               minimum: 86400,
                           }));
            },
            _ => {
                assert!(false);
            }
        }
    }


    #[test]
    fn test_dns_parse_response_null() {
        // DNS response with a NULL record from
        // https://redmine.openinfosecfoundation.org/attachments/2062

        let pkt: &[u8] = &[
            0x12, 0xb0, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, /* ........ */
            0x00, 0x00, 0x00, 0x00, 0x0b, 0x76, 0x61, 0x61, /* .....vaa */
            0x61, 0x61, 0x6b, 0x61, 0x72, 0x64, 0x6c, 0x69, /* aakardli */
            0x06, 0x70, 0x69, 0x72, 0x61, 0x74, 0x65, 0x03, /* .pirate. */
            0x73, 0x65, 0x61, 0x00, 0x00, 0x0a, 0x00, 0x01, /* sea..... */
            0xc0, 0x0c, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, /* ........ */
            0x00, 0x00, 0x00, 0x09, 0x56, 0x41, 0x43, 0x4b, /* ....VACK */
            0x44, 0x03, 0xc5, 0xe9, 0x01,                   /* D.... */
        ];

        let res = dns_parse_response(pkt);
        match res {
            Ok((rem, response)) => {
                // The response should be fully parsed.
                assert_eq!(rem.len(), 0);

                assert_eq!(response.header, DNSHeader {
                    tx_id: 0x12b0,
                    flags: 0x8400,
                    questions: 1,
                    answer_rr: 1,
                    authority_rr: 0,
                    additional_rr: 0,
                });

                assert_eq!(response.queries.len(), 1);
                let query = &response.queries[0];
                assert_eq!(query.name,
                           "vaaaakardli.pirate.sea".as_bytes().to_vec());
                assert_eq!(query.rrtype, DNS_RECORD_TYPE_NULL);
                assert_eq!(query.rrclass, 1);

                assert_eq!(response.answers.len(), 1);

                let answer = &response.answers[0];
                assert_eq!(answer.name,
                           "vaaaakardli.pirate.sea".as_bytes().to_vec());
                assert_eq!(answer.rrtype, DNS_RECORD_TYPE_NULL);
                assert_eq!(answer.rrclass, 1);
                assert_eq!(answer.ttl, 0);
                assert_eq!(answer.data, DNSRData::NULL(vec![
                        0x56, 0x41, 0x43, 0x4b,       /* VACK */
                        0x44, 0x03, 0xc5, 0xe9, 0x01, /* D.... */
                        ]));
            },
            _ => {
                assert!(false);
            }
        }
    }


    #[test]
    fn test_dns_parse_rdata_sshfp() {
        // Dummy data since we don't have a pcap sample.
        let data: &[u8] = &[
            // algo: DSS
            0x02,
            // fp_type: SHA-1
            0x01,
            // fingerprint: 123456789abcdef67890123456789abcdef67890
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf6, 0x78, 0x90,
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf6, 0x78, 0x90
        ];

        let res = dns_parse_rdata_sshfp(data);
        match res {
            Ok((rem, rdata)) => {

                // The data should be fully parsed.
                assert_eq!(rem.len(), 0);

                match rdata {
                    DNSRData::SSHFP(sshfp) => {
                        assert_eq!(sshfp.algo, 2);
                        assert_eq!(sshfp.fp_type, 1);
                        assert_eq!(sshfp.fingerprint, &data[2..]);
                    },
                    _ => {
                        assert!(false);
                    }
                }
            },
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_dns_parse_rdata_srv() {
    /*  ; <<>> DiG 9.11.5-P4-5.1+deb10u2-Debian <<>> _sip._udp.sip.voice.google.com SRV
        ;; global options: +cmd
        ;; Got answer:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1524
        ;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 3

        [...]

        ;; ANSWER SECTION:
        _sip._udp.sip.voice.google.com.	300 IN	SRV	10 1 5060 sip-anycast-1.voice.google.com.
        _sip._udp.sip.voice.google.com.	300 IN	SRV	20 1 5060 sip-anycast-2.voice.google.com.

        [...]

        ;; Query time: 72 msec
        ;; MSG SIZE  rcvd: 191   */

        let pkt: &[u8] = &[
            0xeb, 0x56, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x01, 0x04, 0x5f, 0x73, 0x69, 0x70, 0x04, 0x5f, 0x75,
            0x64, 0x70, 0x03, 0x73, 0x69, 0x70, 0x05, 0x76, 0x6f, 0x69,
            0x63, 0x65, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x21, 0x00, 0x01, 0xc0, 0x0c,
            0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x01, 0x13, 0x00, 0x26,
            0x00, 0x14, 0x00, 0x01, 0x13, 0xc4, 0x0d, 0x73, 0x69, 0x70,
            0x2d, 0x61, 0x6e, 0x79, 0x63, 0x61, 0x73, 0x74, 0x2d, 0x32,
            0x05, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x06, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0xc0, 0x0c,
            0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x01, 0x13, 0x00, 0x26,
            0x00, 0x0a, 0x00, 0x01, 0x13, 0xc4, 0x0d, 0x73, 0x69, 0x70,
            0x2d, 0x61, 0x6e, 0x79, 0x63, 0x61, 0x73, 0x74, 0x2d, 0x31,
            0x05, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x06, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00
        ];

        let res = dns_parse_response(pkt);
        match res {
            Ok((rem, response)) => {

                // The data should be fully parsed.
                assert_eq!(rem.len(), 0);

                assert_eq!(response.answers.len(), 2);

                let answer1 = &response.answers[0];
                match &answer1.data {
                    DNSRData::SRV(srv) => {
                        assert_eq!(srv.priority, 20);
                        assert_eq!(srv.weight, 1);
                        assert_eq!(srv.port, 5060);
                        assert_eq!(srv.target,
                            "sip-anycast-2.voice.google.com".as_bytes().to_vec());
                    }
                    _ => {
                        assert!(false);
                    }
                }
                let answer2 = &response.answers[1];
                match &answer2.data {
                    DNSRData::SRV(srv) => {
                        assert_eq!(srv.priority, 10);
                        assert_eq!(srv.weight, 1);
                        assert_eq!(srv.port, 5060);
                        assert_eq!(srv.target,
                            "sip-anycast-1.voice.google.com".as_bytes().to_vec());
                    }
                    _ => {
                        assert!(false);
                    }
                }
            },
            _ => {
                assert!(false);
            }
        }
    }
}
