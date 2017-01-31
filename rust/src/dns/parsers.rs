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

use dns::*;

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

/// Parse a DNS label returning the result as a u8 slice. The label
/// must first be checked that its an actual label and not a pointer.
named!(pub dns_parse_label<&[u8]>, do_parse!(
    length: be_u8 >>
    label: take!(length) >> (label)
));

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
            match dns_parse_label(pos) {
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
            match closure!(do_parse!(leader: be_u16 >> (leader)))(pos) {
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

/// Parse a DNS response.
pub fn dns_parse_response<'a>(slice: &'a [u8])
                              -> nom::IResult<&[u8], DNSResponse> {
    let answer_parser = closure!(&'a [u8], do_parse!(
        name: apply!(dns_parse_name, slice) >>
        rrtype: be_u16 >>
        rrclass: be_u16 >>
        ttl: be_u32 >>
        data_len: be_u16 >>
        data: flat_map!(take!(data_len),
                        apply!(dns_parse_rdata, slice, rrtype)) >>
            (
                DNSAnswerEntry{
                    name: name,
                    rrtype: rrtype,
                    rrclass: rrclass,
                    ttl: ttl,
                    data_len: data_len,
                    data: data.to_vec(),
                }
            )
    ));

    let response = closure!(&'a [u8], do_parse!(
        header: dns_parse_header >>
        queries: count!(apply!(dns_parse_query, slice),
                        header.questions as usize) >>
        answers: count!(answer_parser, header.answer_rr as usize) >>
        authorities: count!(answer_parser, header.authority_rr as usize) >>
        (
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

pub fn dns_parse_rdata<'a>(data: &'a [u8], message: &'a [u8], rrtype: u16)
    -> nom::IResult<&'a [u8], Vec<u8>>
{
    match rrtype {
        DNS_RTYPE_CNAME |
        DNS_RTYPE_PTR |
        DNS_RTYPE_SOA => {
            dns_parse_name(data, message)
        },
        DNS_RTYPE_MX => {
            // For MX we we skip over the preference field before
            // parsing out the name.
            closure!(do_parse!(
                be_u16 >>
                name: apply!(dns_parse_name, message) >>
                    (name)
            ))(data)
        },
        _ => nom::IResult::Done(data, data.to_vec())
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
