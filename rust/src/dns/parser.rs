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

use nom::{be_u8, be_u16, be_u32};
use nom;
use dns::dns::*;

/// Parse a DNS header.
named!(pub dns_parse_header<DNSHeader>,
       do_parse!(
           tx_id: be_u16 >>
           flags: be_u16 >>
           questions: be_u16 >>
           answer_rr: be_u16 >>
           authority_rr: be_u16 >>
           additional_rr: be_u16 >>
           (
               DNSHeader{
                   tx_id: tx_id,
                   flags: flags,
                   questions: questions,
                   answer_rr: answer_rr,
                   authority_rr: authority_rr,
                   additional_rr: additional_rr,
               }
           )
       )
);

/// Parse a DNS name.
///
/// Parameters:
///   start: the start of the name
///   message: the complete message that start is a part of
pub fn dns_parse_name<'a, 'b>(start: &'b [u8],
                              message: &'b [u8])
                              -> nom::IResult<&'b [u8], Vec<u8>> {
    let mut pos = start;
    let mut pivot = start;
    let mut name: Vec<u8> = Vec::with_capacity(32);
    let mut count = 0;

    loop {
        if pos.len() == 0 {
            break;
        }

        let len = pos[0];

        if len == 0x00 {
            pos = &pos[1..];
            break;
        } else if len & 0b1100_0000 == 0 {
            match length_bytes!(pos, be_u8) {
                nom::IResult::Done(rem, label) => {
                    if name.len() > 0 {
                        name.push('.' as u8);
                    }
                    name.extend(label);
                    pos = rem;
                }
                _ => {
                    return nom::IResult::Error(
                        error_position!(nom::ErrorKind::OctDigit, input));
                }
            }
        } else if len & 0b1100_0000 == 0b1100_0000 {
            match be_u16(pos) {
                nom::IResult::Done(rem, leader) => {
                    let offset = leader & 0x3fff;
                    if offset as usize > message.len() {
                        return nom::IResult::Error(
                            error_position!(nom::ErrorKind::OctDigit, input));
                    }
                    pos = &message[offset as usize..];
                    if pivot == start {
                        pivot = rem;
                    }
                }
                _ => {
                    return nom::IResult::Error(
                        error_position!(nom::ErrorKind::OctDigit, input));
                }
            }
        } else {
            return nom::IResult::Error(
                error_position!(nom::ErrorKind::OctDigit, input));
        }

        // Return error if we've looped a certain number of times.
        count += 1;
        if count > 255 {
            return nom::IResult::Error(
                error_position!(nom::ErrorKind::OctDigit, input));
        }

    }

    // If we followed a pointer we return the position after the first
    // pointer followed. Is there a better way to see if these slices
    // diverged from each other?  A straight up comparison would
    // actually check the contents.
    if pivot.len() != start.len() {
        return nom::IResult::Done(pivot, name);
    }
    return nom::IResult::Done(pos, name);

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
fn dns_parse_answer<'a>(slice: &'a [u8], message: &'a [u8], count: usize)
                        -> nom::IResult<&'a [u8], Vec<DNSAnswerEntry>> {

    let mut answers = Vec::new();
    let mut input = slice;

    for _ in 0..count {
        match closure!(&'a [u8], do_parse!(
            name: apply!(dns_parse_name, message) >>
                rrtype: be_u16 >>
                rrclass: be_u16 >>
                ttl: be_u32 >>
                data_len: be_u16 >>
                data: take!(data_len) >>
                (
                    name,
                    rrtype,
                    rrclass,
                    ttl,
                    data
                )
        ))(input) {
            nom::IResult::Done(rem, val) => {
                let name = val.0;
                let rrtype = val.1;
                let rrclass = val.2;
                let ttl = val.3;
                let data = val.4;
                let n = match rrtype {
                    DNS_RTYPE_TXT => {
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
                let result: nom::IResult<&'a [u8], Vec<Vec<u8>>> =
                    closure!(&'a [u8], do_parse!(
                        rdata: many_m_n!(1, n,
                                         apply!(dns_parse_rdata, message, rrtype))
                            >> (rdata)
                    ))(data);
                match result {
                    nom::IResult::Done(_, rdatas) => {
                        for rdata in rdatas {
                            answers.push(DNSAnswerEntry{
                                name: name.clone(),
                                rrtype: rrtype,
                                rrclass: rrclass,
                                ttl: ttl,
                                data: rdata,
                            });
                        }
                    }
                    nom::IResult::Error(err) => {
                        return nom::IResult::Error(err);
                    }
                    nom::IResult::Incomplete(needed) => {
                        return nom::IResult::Incomplete(needed);
                    }
                }
                input = rem;
            }
            nom::IResult::Error(err) => {
                return nom::IResult::Error(err);
            }
            nom::IResult::Incomplete(needed) => {
                return nom::IResult::Incomplete(needed);
            }
        }
    }

    return nom::IResult::Done(input, answers);
}


/// Parse a DNS response.
pub fn dns_parse_response<'a>(slice: &'a [u8])
                              -> nom::IResult<&[u8], DNSResponse> {
    let response = closure!(&'a [u8], do_parse!(
        header: dns_parse_header
            >> queries: count!(
                apply!(dns_parse_query, slice), header.questions as usize)
            >> answers: apply!(
                dns_parse_answer, slice, header.answer_rr as usize)
            >> authorities: apply!(
                dns_parse_answer, slice, header.authority_rr as usize)
            >> (
                DNSResponse{
                    header: header,
                    queries: queries,
                    answers: answers,
                    authorities: authorities,
                }
            )
    ))(slice);

    return response;
}

/// Parse a single DNS query.
///
/// Arguments are suitable for using with apply!:
///
///    apply!(complete_dns_message_buffer)
pub fn dns_parse_query<'a>(input: &'a [u8],
                           message: &'a [u8])
                           -> nom::IResult<&'a [u8], DNSQueryEntry> {
    return closure!(&'a [u8], do_parse!(
        name: apply!(dns_parse_name, message) >>
        rrtype: be_u16 >>
        rrclass: be_u16 >>
            (
                DNSQueryEntry{
                    name: name,
                    rrtype: rrtype,
                    rrclass: rrclass,
                }
            )
    ))(input);
}

pub fn dns_parse_rdata<'a>(input: &'a [u8], message: &'a [u8], rrtype: u16)
    -> nom::IResult<&'a [u8], Vec<u8>>
{
    match rrtype {
        DNS_RTYPE_CNAME |
        DNS_RTYPE_PTR |
        DNS_RTYPE_SOA => {
            dns_parse_name(input, message)
        },
        DNS_RTYPE_MX => {
            // For MX we we skip over the preference field before
            // parsing out the name.
            closure!(&'a [u8], do_parse!(
                be_u16 >>
                name: apply!(dns_parse_name, message) >>
                    (name)
            ))(input)
        },
        DNS_RTYPE_TXT => {
            closure!(&'a [u8], do_parse!(
                len: be_u8 >>
                txt: take!(len) >>
                    (txt.to_vec())
            ))(input)
        },
        _ => {
            closure!(&'a [u8], do_parse!(
                data: take!(input.len()) >>
                    (data.to_vec())
            ))(input)
        }
    }
}

/// Parse a DNS request.
pub fn dns_parse_request<'a>(input: &'a [u8]) -> nom::IResult<&[u8], DNSRequest> {
    return closure!(&'a [u8], do_parse!(
        header: dns_parse_header >>
        queries: count!(apply!(dns_parse_query, input),
                        header.questions as usize) >>
            (
                DNSRequest{
                    header: header,
                    queries: queries,
                }
            )
    ))(input);
}

#[cfg(test)]
mod tests {

    use dns::dns::{DNSHeader,DNSAnswerEntry};
    use dns::parser::*;
    use nom::IResult;

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
        let res = dns_parse_name(buf, buf);
        match res {
            IResult::Done(remainder, name) => {
                assert_eq!("client-cf.dropbox.com".as_bytes(), &name[..]);
                assert_eq!(remainder, expected_remainder);
            }
            _ => {
                assert!(false);
            }
        }
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
                   IResult::Done(&start1[22..],
                                 "www.suricata-ids.org".as_bytes().to_vec()));

        // The second name starts at offset 80, but is just a pointer
        // to the first.
        let start2 = &buf[80..];
        let res2 = dns_parse_name(start2, message);
        assert_eq!(res2,
                   IResult::Done(&start2[2..],
                                 "www.suricata-ids.org".as_bytes().to_vec()));

        // The third name starts at offset 94, but is a pointer to a
        // portion of the first.
        let start3 = &buf[94..];
        let res3 = dns_parse_name(start3, message);
        assert_eq!(res3,
                   IResult::Done(&start3[2..],
                                 "suricata-ids.org".as_bytes().to_vec()));

        // The fourth name starts at offset 110, but is a pointer to a
        // portion of the first.
        let start4 = &buf[110..];
        let res4 = dns_parse_name(start4, message);
        assert_eq!(res4,
                   IResult::Done(&start4[2..],
                                 "suricata-ids.org".as_bytes().to_vec()));
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
                   IResult::Done(&start[2..],
                                 "block.g1.dropbox.com".as_bytes().to_vec()));
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
            IResult::Done(rem, request) => {

                // For now we have some remainder data as there is an
                // additional record type we don't parse yet.
                assert!(rem.len() > 0);

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
            IResult::Done(rem, response) => {

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
                           "suricata-ids.org".as_bytes().to_vec());

                let answer2 = &response.answers[1];
                assert_eq!(answer2, &DNSAnswerEntry{
                    name: "suricata-ids.org".as_bytes().to_vec(),
                    rrtype: 1,
                    rrclass: 1,
                    ttl: 244,
                    data: [192, 0, 78, 24].to_vec(),
                });

                let answer3 = &response.answers[2];
                assert_eq!(answer3, &DNSAnswerEntry{
                    name: "suricata-ids.org".as_bytes().to_vec(),
                    rrtype: 1,
                    rrclass: 1,
                    ttl: 244,
                    data: [192, 0, 78, 25].to_vec(),
                })

            },
            _ => {
                assert!(false);
            }
        }
    }

}
