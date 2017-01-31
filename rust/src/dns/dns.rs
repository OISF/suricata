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

// TODO: Log reply handling (windowed).
// TODO: Flood handling.

extern crate std;
extern crate libc;
extern crate nom;

use std::slice;
use std::mem::transmute;
use std::panic;
use std::ptr;

use core;

use dns::*;

/// DNS error codes.
pub const DNS_RCODE_NOERROR:  u16 = 0;
pub const DNS_RCODE_FORMERR:  u16 = 1;
pub const DNS_RCODE_NXDOMAIN: u16 = 3;

/// DNS record types.
pub const DNS_RTYPE_A:     u16 = 1;
pub const DNS_RTYPE_CNAME: u16 = 5;
pub const DNS_RTYPE_SOA:   u16 = 6;
pub const DNS_RTYPE_PTR:   u16 = 12;
pub const DNS_RTYPE_MX:    u16 = 15;
pub const DNS_RTYPE_SSHFP: u16 = 44;
pub const DNS_RTYPE_RRSIG: u16 = 46;

#[repr(u32)]
pub enum DNSEvents {
    UnsolicitedResponse = 1,
    MalformedData,
    NotRequest,
    NotResponse,
    ZFlagSet,
    Flooded,
    StateMemCapReached,
}

/// Expose a parsers state ::new to C.
/// TODO: Move out into some common module.
macro_rules!export_state_new {
    ($name: ident, $parser: ident) => {
        #[no_mangle]
        pub extern "C" fn $name() -> *mut $parser {
            let state = $parser::new();
            let boxed = Box::new(state);
            return unsafe{transmute(boxed)};
        }
    }
}

/// Expose a function to free a parser state to C.
/// TODO: Move out into some common module.
macro_rules!export_state_free {
    ($name: ident, $parser: ident) => {
        #[no_mangle]
        pub extern "C" fn $name(state: *mut $parser) {
            let _drop: Box<$parser> = unsafe{transmute(state)};
        }
    }
}

#[derive(Debug,PartialEq)]
pub struct DNSHeader {
    pub tx_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answer_rr: u16,
    pub authority_rr: u16,
    pub additional_rr: u16,
}

#[derive(Debug)]
pub struct DNSTransaction {
    pub id: u64,
    pub request: Option<DNSRequest>,
    pub response: Option<DNSResponse>,
    pub replied: bool,
}

#[derive(Debug)]
pub struct DNSRequest {
    pub header: DNSHeader,
    pub queries: Vec<DNSQueryEntry>,
}

#[derive(Debug)]
pub struct DNSResponse {
    pub header: DNSHeader,
    pub queries: Vec<DNSQueryEntry>,
    pub answers: Vec<DNSAnswerEntry>,
    pub authorities: Vec<DNSAnswerEntry>,
}

#[derive(Debug)]
pub struct DNSQueryEntry {
    pub name: Vec<u8>,
    pub rrtype: u16,
    pub rrclass: u16,
}

#[derive(Debug)]
pub struct DNSAnswerEntry {
    pub name: Vec<u8>,
    pub rrtype: u16,
    pub rrclass: u16,
    pub ttl: u32,
    pub data_len: u16,
    pub data: Vec<u8>,
}

pub struct DNSState {

    pub events: Vec<DNSEvents>,

    // Vector of transactions.
    pub transactions: Vec<Box<DNSTransaction>>,

    // Internal transaction ID tracker.
    pub tx_id: u64,

    pub unreplied: u64,
}

impl DNSState {

    pub fn new() -> DNSState {
        return DNSState{
            events: Vec::new(),
            transactions: Vec::new(),
            tx_id: 0,
            unreplied: 0,
        }
    }

    pub fn new_tx(&mut self) -> DNSTransaction {
        self.tx_id = self.tx_id + 1;
        let mut tx = DNSTransaction::new();
        tx.id = self.tx_id;
        return tx;
    }

    pub fn tx_free(&mut self, tx_id: u64) {
        for i in 0..self.transactions.len() {
            if self.transactions[i].id == tx_id + 1 {
                self.transactions.remove(i);
                return;
            }
        }
    }

    pub fn tx_get(&self, tx_id: u64) -> Option<&DNSTransaction> {
        // Loops through the transactions in reverse as we are most
        // likely getting the most recent. Its a bit of a
        // micro-optimization, but was visible in profiling.
        let mut len = self.transactions.len();
        loop {
            len = len - 1;
            if self.transactions[len].id == tx_id + 1 {
                return Some(&self.transactions[len]);
            }
            if len == 0 {
                break;
            }
        }

        return None;
    }

    pub fn validate_request_header(&mut self, request: &DNSRequest) -> bool {
        // XXX In the C version the header was validated prior to
        // parsing. In this Rust version the header is parsed with the
        // request so we validate it after successful parsing. We
        // could go back to the C behaviour by parsing the header,
        // validating then parsing the full request.

        if request.header.flags & 0x8000 != 0 {
            self.events.push(DNSEvents::NotRequest);
            return false;
        }

        if request.header.flags & 0x0040 != 0 {
            self.events.push(DNSEvents::ZFlagSet);
            return false;
        }

        return true;
    }

    pub fn validate_response_header(&mut self, response: &DNSResponse) -> bool {
        // XXX In the C version the header was validated prior to
        // parsing. In this Rust version the header is parsed with the
        // request so we validate it after successful parsing. We
        // could go back to the C behaviour by parsing the header,
        // validating then parsing the full request.

        if response.header.flags & 0x8000 == 0 {
            self.events.push(DNSEvents::NotResponse);
            return false;
        }

        if response.header.flags & 0x0040 != 0 {
            self.events.push(DNSEvents::ZFlagSet);
            return false;
        }

        return true;
    }

    /// Returns the ID of the new transaction.
    pub fn handle_request(&mut self, request: DNSRequest) -> u64 {

        if !self.validate_request_header(&request) {
            return 0;
        }

        let mut tx = self.new_tx();
        let id = tx.id;
        tx.request = Some(request);
        self.transactions.push(Box::new(tx));
        self.unreplied += 1;

        return id;
    }

    /// Returns the transaction ID this response belongs to, or was
    /// given in the case of an unsolicited response.
    pub fn handle_response(&mut self, response: DNSResponse) -> u64 {

        if !self.validate_response_header(&response) {
            return 0;
        }

        for tx in &mut self.transactions {
            let tx = &mut **tx;
            for request in &tx.request {
                if request.header.tx_id == response.header.tx_id {
                    tx.response = Some(response);
                    tx.replied = true;
                    self.unreplied -= 1;
                    return tx.id;
                }
            }
        }

        self.events.push(DNSEvents::UnsolicitedResponse);

        // Create a response only transaction.
        let mut tx = self.new_tx();
        let id = tx.id;
        tx.response = Some(response);
        tx.replied = true;
        self.transactions.push(Box::new(tx));

        return id;
    }

    /// Parse and handle a DNS request.
    pub fn parse_request(&mut self, input: &[u8]) -> u64 {
        match dns_parse_request(input) {
            nom::IResult::Done(_, request) => {
                return self.handle_request(request);
            },
            _ => {
                self.events.push(DNSEvents::MalformedData);
                return 0;
            }
        }
    }

    /// Parse and handle a DNS response.
    pub fn parse_response(&mut self, input: &[u8]) -> u64 {
        match dns_parse_response(input) {
            nom::IResult::Done(_, response) => {
                return self.handle_response(response);
            },
            _ => {
                self.events.push(DNSEvents::MalformedData);
                return 0;
            }
        }
    }

}

/// Expose DNSState::new.
export_state_new!(rs_dns_state_new, DNSState);

/// Expose a function to free DNSState.
export_state_free!(rs_dns_state_free, DNSState);

#[no_mangle]
pub extern fn rs_dns_state_tx_free(this: &mut DNSState, tx_id: libc::uint64_t) {
   this.tx_free(tx_id);
}

#[no_mangle]
pub extern fn rs_dns_state_tx_get(this: &mut DNSState, tx_id: libc::uint64_t)
                                  -> *mut DNSTransaction {
    match this.tx_get(tx_id) {
        Some(tx) => {
            return unsafe{transmute(tx)};
        },
        _ => {
            return ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern fn rs_dns_state_get_next_event(this: &mut DNSState) -> u32 {
    match this.events.pop() {
        Some(ev) => {
            return ev as u32;
        },
        _ => {
            return 0;
        }
    }
}

#[no_mangle]
pub extern fn rs_dns_state_get_tx_count(this: &mut DNSState) -> u64 {
    return this.tx_id;
}

#[no_mangle]
pub extern fn rs_dns_state_parse_request(state: &mut DNSState,
                                         input: *const libc::uint8_t,
                                         len: libc::uint32_t) -> libc::uint64_t
{
    let buf = unsafe{std::slice::from_raw_parts(input, len as usize)};
    let tx_id = state.parse_request(buf);
    return tx_id as libc::uint64_t;
}

#[no_mangle]
pub extern fn rs_dns_state_parse_response(state: &mut DNSState,
                                          input: *const libc::uint8_t,
                                          len: libc::uint32_t) -> libc::uint64_t
{
    let buf = unsafe{std::slice::from_raw_parts(input, len as usize)};
    let tx_id = state.parse_response(buf);
    return tx_id as libc::uint64_t;
}

impl DNSTransaction {

    pub fn new() -> DNSTransaction {
        return DNSTransaction{
            id: 0,
            request: None,
            response: None,
            replied: false,
        }
    }

}

#[no_mangle]
pub extern fn rs_dns_tx_get_alstate_progress(tx: &mut DNSTransaction,
                                             direction: libc::uint8_t)
                                             -> libc::uint8_t {
    if direction & core::STREAM_TOCLIENT > 0 {
        if tx.replied {
            return 1;
        }
        return 0;
    }
    return 1;
}

#[no_mangle]
pub extern fn rs_dns_tx_get_query_buffer(tx: &mut DNSTransaction,
                                         i: libc::uint16_t,
                                         buf: *mut *const libc::uint8_t,
                                         len: *mut libc::uint32_t)
                                         -> libc::uint8_t
{
    for request in &tx.request {
        if (i as usize) < request.queries.len() {
            let query = &request.queries[i as usize];
            if query.name.len() > 0 {
                unsafe {
                    *len = query.name.len() as libc::uint32_t;
                    *buf = query.name.as_ptr();
                }
                return 1;
            }
        }
    }
    return 0;
}

/// Probe a buffer to see if it looks like a DNS request or response.
pub fn dns_probe(input: &[u8]) -> bool {
    match dns_parse_request(input) {
        nom::IResult::Done(_, _) => {
            return true;
        },
        _ => {
            return false;
        }
    }
}

/// Expose dns_probe to C. This wrapper is an example of how to catch
/// panic's and unwind so an error code can be returned.
#[no_mangle]
pub extern "C" fn rs_dns_probe(input: *const libc::uint8_t, len: libc::uint32_t)
                               -> libc::uint8_t {
    let res = panic::catch_unwind(|| {
        let slice: &[u8] = unsafe {
            slice::from_raw_parts(input as *mut u8, len as usize)};
        match dns_probe(slice) {
            true => {
                return 1;
            },
            false => {
                return 0;
            }
        }
    });

    match res {
        Ok(rc) => {
            return rc;
        },
        _ => {
            return 0;
        },
    };
}

#[cfg(test)]
mod tests {

    use std::str;
    use dns::*;
    use nom::IResult;

    #[test]
    fn test_dns_parse_label() {
        let buf: &[u8] = &[
            // www
            0x03, 0x77, 0x77, 0x77,

            // suricata-ids
            0x0c, 0x73, 0x75, 0x72, 0x69, 0x63, 0x61, 0x74,
            0x61, 0x2d, 0x69, 0x64, 0x73,

            // org
            0x03, 0x72, 0x67, 0x00];

        let res = dns_parse_label(buf);
        let expected = IResult::Done(&buf[4..], "www".as_bytes());
        assert_eq!(res, expected);
    }

    #[test]
    fn test_dns_parse_name_simple() {
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

    #[test]
    fn test_dns_parse_name_pointer() {
        let buf: &[u8] = &[
            0xd8, 0xcb, 0x8a, 0xed, 0xa1, 0x46, 0x00, 0x15 /* .....F.. */,
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00 /* ......E. */,
            0x00, 0x7b, 0x71, 0x6e, 0x00, 0x00, 0x39, 0x11 /* .{qn..9. */,
            0xf4, 0xd9, 0x08, 0x08, 0x08, 0x08, 0x0a, 0x10 /* ........ */,
            0x01, 0x0b, 0x00, 0x35, 0xe1, 0x8e, 0x00, 0x67 /* ...5...g */,
            0x60, 0x00, 0xef, 0x08, 0x81, 0x80, 0x00, 0x01 /* `....... */,
            0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77 /* .......w */,
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63 /* ww.suric */,
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03 /* ata-ids. */,
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01 /* org..... */,
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00 /* ........ */,
            0x0e, 0x0f, 0x00, 0x02, 0xc0, 0x10, 0xc0, 0x10 /* ........ */,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2b /* .......+ */,
            0x00, 0x04, 0xc0, 0x00, 0x4e, 0x19, 0xc0, 0x10 /* ....N... */,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2b /* .......+ */,
            0x00, 0x04, 0xc0, 0x00, 0x4e, 0x18, 0x00, 0x00 /* ....N... */,
            0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /* )....... */,
            0x00,                                          /* . */
        ];
        let message = &buf[42..];

        let start = &buf[0x36..];
        let res = dns_parse_name(start, message);
        assert_eq!(res,
                   IResult::Done(&start[22..], "www.suricata-ids.org".as_bytes().to_vec()));

        let start1 = &buf[0x50..];
        let res1 = dns_parse_name(start1, message);
        assert_eq!(res1,
                   IResult::Done(&start1[2..], "www.suricata-ids.org".as_bytes().to_vec()));

        let start2 = &buf[0x5e..];
        let res2 = dns_parse_name(start2, message);
        assert_eq!(res2,
                   IResult::Done(&start2[2..], "suricata-ids.org".as_bytes().to_vec()));

        let start3 = &buf[0x6e..];
        let res3 = dns_parse_name(start3, message);
        assert_eq!(res3,
                   IResult::Done(&start3[2..], "suricata-ids.org".as_bytes().to_vec()));
    }

    #[test]
    fn test_dns_parse_name_double_pointer() {
        let buf: &[u8] = &[
            0xd8, 0xcb, 0x8a, 0xed, 0xa1, 0x46, 0x00, 0x15 /* .....F.. */,
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00 /* ......E. */,
            0x00, 0x66, 0x5e, 0x20, 0x40, 0x00, 0x40, 0x11 /* .f^ @.@. */,
            0xc6, 0x3b, 0x0a, 0x10, 0x01, 0x01, 0x0a, 0x10 /* .;...... */,
            0x01, 0x0b, 0x00, 0x35, 0xc2, 0x21, 0x00, 0x52 /* ...5.!.R */,
            0x35, 0xc5, 0x0d, 0x4f, 0x81, 0x80, 0x00, 0x01 /* 5..O.... */,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62 /* .......b */,
            0x6c, 0x6f, 0x63, 0x6b, 0x07, 0x64, 0x72, 0x6f /* lock.dro */,
            0x70, 0x62, 0x6f, 0x78, 0x03, 0x63, 0x6f, 0x6d /* pbox.com */,
            0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00 /* ........ */,
            0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00 /* ........ */,
            0x0b, 0x05, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x02 /* ..block. */,
            0x67, 0x31, 0xc0, 0x12, 0xc0, 0x2f, 0x00, 0x01 /* g1.../.. */,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04 /* ........ */,
            0x2d, 0x3a, 0x46, 0x21 /* -:F! */];

        // The start of the DNS message in the above packet.
        let message: &[u8] = &buf[42..];

        // The start of the name we want to parse.
        let start: &[u8] = &buf[0x64..];

        let res = dns_parse_name(start, message);
        assert_eq!(res,
                   IResult::Done(&start[2..], "block.g1.dropbox.com".as_bytes().to_vec()));
    }

    #[test]
    fn test_dns_parse_simple_request() {
        let input: &[u8] = &[
            0x00, 0x15, 0x17, 0x0d, 0x06, 0xf7, 0xd8, 0xcb /* ........ */,
            0x8a, 0xed, 0xa1, 0x46, 0x08, 0x00, 0x45, 0x00 /* ...F..E. */,
            0x00, 0x43, 0x9c, 0x8a, 0x40, 0x00, 0x40, 0x11 /* .C..@.@. */,
            0x87, 0xf4, 0x0a, 0x10, 0x01, 0x0b, 0x0a, 0x10 /* ........ */,
            0x01, 0x01, 0xd1, 0xaf, 0x00, 0x35, 0x00, 0x2f /* .....5./ */,
            0x16, 0x6c, 0x99, 0xab, 0x01, 0x00, 0x00, 0x01 /* .l...... */,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x63 /* .......c */,
            0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x63, 0x66 /* lient-cf */,
            0x07, 0x64, 0x72, 0x6f, 0x70, 0x62, 0x6f, 0x78 /* .dropbox */,
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00 /* .com.... */,
            0x01,                                          /* . */
        ];
        let offset = 42;

        let res = dns_parse_request(&input[offset..]);
        match res {
            IResult::Done(rem, request) => {

                // Check how much data is remaining.
                assert_eq!(rem.len(), 0);

                // Check the header.
                let header = request.header;
                assert_eq!(header,
                           DNSHeader {
                               tx_id: 0x99ab,
                               flags: 0x0100,
                               questions: 1,
                               answer_rr: 0,
                               authority_rr: 0,
                               additional_rr: 0,
                           });

                // Check the query/question section.
                assert_eq!(request.queries.len(), 1);
                let query0 = &request.queries[0];
                assert_eq!(query0.name, "client-cf.dropbox.com".as_bytes().to_vec());
                assert_eq!(query0.rrtype, 1);
                assert_eq!(query0.rrclass, 1);
            }
            IResult::Incomplete(_) => {
                assert!(false);
            }
            IResult::Error(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_dns_parse_simple_response() {
        let buf: &[u8] = &[
            0xd8, 0xcb, 0x8a, 0xed, 0xa1, 0x46, 0x00, 0x15 /* .....F.. */,
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00 /* ......E. */,
            0x00, 0x53, 0x5e, 0x1f, 0x40, 0x00, 0x40, 0x11 /* .S^.@.@. */,
            0xc6, 0x4f, 0x0a, 0x10, 0x01, 0x01, 0x0a, 0x10 /* .O...... */,
            0x01, 0x0b, 0x00, 0x35, 0xd1, 0xaf, 0x00, 0x3f /* ...5...? */,
            0xce, 0x7f, 0x99, 0xab, 0x81, 0x80, 0x00, 0x01 /* ........ */,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0x63 /* .......c */,
            0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x63, 0x66 /* lient-cf */,
            0x07, 0x64, 0x72, 0x6f, 0x70, 0x62, 0x6f, 0x78 /* .dropbox */,
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00 /* .com.... */,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00 /* ........ */,
            0x00, 0x00, 0x2f, 0x00, 0x04, 0x34, 0x55, 0x70 /* ../..4Up */,
            0x15,                                          /* . */
        ];
        let offset = 42;
        let expected_addr: &[u8] = &[0x34, 0x55, 0x70, 0x15];

        let res = dns_parse_response(&buf[offset..]);
        match res {
            IResult::Done(rem, response) => {

                // Check how much data is remaining.
                assert_eq!(rem.len(), 0);

                // Check the header.
                let header = response.header;
                assert_eq!(header,
                           DNSHeader {
                               tx_id: 0x99ab,
                               flags: 0x8180,
                               questions: 1,
                               answer_rr: 1,
                               authority_rr: 0,
                               additional_rr: 0,
                           });

                // Check the query/question section.
                assert_eq!(response.queries.len(), 1);
                let query0 = &response.queries[0];
                assert_eq!(query0.name, "client-cf.dropbox.com".as_bytes().to_vec());
                assert_eq!(query0.rrtype, 1);
                assert_eq!(query0.rrclass, 1);

                // Check the answer section.
                assert_eq!(response.answers.len(), 1);
                let answer0 = &response.answers[0];
                assert_eq!(answer0.name, "client-cf.dropbox.com".as_bytes().to_vec());
                assert_eq!(answer0.rrtype, 1);
                assert_eq!(answer0.rrclass, 1);
                assert_eq!(answer0.ttl, 47);
                assert_eq!(answer0.data_len, 4);
                assert_eq!(answer0.data, expected_addr);
            }
            IResult::Incomplete(_) => {
                assert!(false);
            }
            IResult::Error(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_dns_parse_2answer_response() {
        let buf: &[u8] = &[
            0xd8, 0xcb, 0x8a, 0xed, 0xa1, 0x46, 0x00, 0x15 /* .....F.. */,
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00 /* ......E. */,
            0x00, 0x66, 0x5e, 0x20, 0x40, 0x00, 0x40, 0x11 /* .f^ @.@. */,
            0xc6, 0x3b, 0x0a, 0x10, 0x01, 0x01, 0x0a, 0x10 /* .;...... */,
            0x01, 0x0b, 0x00, 0x35, 0xc2, 0x21, 0x00, 0x52 /* ...5.!.R */,
            0x35, 0xc5, 0x0d, 0x4f, 0x81, 0x80, 0x00, 0x01 /* 5..O.... */,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62 /* .......b */,
            0x6c, 0x6f, 0x63, 0x6b, 0x07, 0x64, 0x72, 0x6f /* lock.dro */,
            0x70, 0x62, 0x6f, 0x78, 0x03, 0x63, 0x6f, 0x6d /* pbox.com */,
            0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00 /* ........ */,
            0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00 /* ........ */,
            0x0b, 0x05, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x02 /* ..block. */,
            0x67, 0x31, 0xc0, 0x12, 0xc0, 0x2f, 0x00, 0x01 /* g1.../.. */,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04 /* ........ */,
            0x2d, 0x3a, 0x46, 0x21                         /* -:F! */
        ];
        let offset = 42;

        let res = dns_parse_response(&buf[offset..]);
        match res {
            IResult::Done(rem, response) => {

                // Check how much data is remaining.
                assert_eq!(rem.len(), 0);

                // Check the header.
                let header = response.header;
                assert_eq!(header,
                           DNSHeader {
                               tx_id: 0x0d4f,
                               flags: 0x8180,
                               questions: 1,
                               answer_rr: 2,
                               authority_rr: 0,
                               additional_rr: 0,
                           });

                // Check the query/question section.
                assert_eq!(response.queries.len(), 1);
                let query0 = &response.queries[0];
                assert_eq!(query0.name,
                           "block.dropbox.com".as_bytes().to_vec());
                assert_eq!(query0.rrtype, 1);
                assert_eq!(query0.rrclass, 1);

                // Check the answer section.
                assert_eq!(response.answers.len(), 2);

                let answer0 = &response.answers[0];
                assert_eq!(answer0.name,
                           "block.dropbox.com".as_bytes().to_vec());
                assert_eq!(answer0.rrtype, 5);
                assert_eq!(answer0.rrclass, 1);
                assert_eq!(answer0.ttl, 9);
                assert_eq!(answer0.data_len, 11);
                assert_eq!(answer0.data,
                           "block.g1.dropbox.com".as_bytes().to_vec());

                let answer1 = &response.answers[1];
                assert_eq!(answer1.name,
                           "block.g1.dropbox.com".as_bytes().to_vec());
                assert_eq!(answer1.rrtype, 1);
                assert_eq!(answer1.rrclass, 1);
                assert_eq!(answer1.ttl, 8);
                assert_eq!(answer1.data_len, 4);
                assert_eq!(answer1.data, &[0x2d, 0x3a, 0x46, 0x21]);

            }
            IResult::Incomplete(_) => {
                assert!(false);
            }
            IResult::Error(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_dns_parse_5answer_response() {
        let buf: &[u8] = &[
            0x00, 0x24, 0x8c, 0x0e, 0x31, 0x54, 0x00, 0x15 /* .$..1T.. */,
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00 /* ......E. */,
            0x00, 0xbf, 0x70, 0x65, 0x40, 0x00, 0x40, 0x11 /* ..pe@.@. */,
            0xb2, 0xc1, 0x0a, 0x10, 0x01, 0x01, 0x0a, 0x10 /* ........ */,
            0x01, 0xe7, 0x00, 0x35, 0xea, 0x32, 0x00, 0xab /* ...5.2.. */,
            0x17, 0xc4, 0x55, 0x96, 0x81, 0x80, 0x00, 0x01 /* ..U..... */,
            0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x02, 0x63 /* .......c */,
            0x37, 0x06, 0x72, 0x62, 0x78, 0x63, 0x64, 0x6e /* 7.rbxcdn */,
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00 /* .com.... */,
            0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00 /* ........ */,
            0x00, 0x31, 0x11, 0x00, 0x08, 0x05, 0x63, 0x37 /* .1....c7 */,
            0x63, 0x78, 0x73, 0xc0, 0x0f, 0xc0, 0x2b, 0x00 /* cxs...+. */,
            0x05, 0x00, 0x01, 0x00, 0x00, 0x31, 0x44, 0x00 /* .....1D. */,
            0x20, 0x0e, 0x32, 0x2d, 0x30, 0x31, 0x2d, 0x34 /*  .2-01-4 */,
            0x38, 0x37, 0x37, 0x2d, 0x30, 0x30, 0x30, 0x64 /* 877-000d */,
            0x03, 0x63, 0x64, 0x78, 0x07, 0x63, 0x65, 0x64 /* .cdx.ced */,
            0x65, 0x78, 0x69, 0x73, 0x03, 0x6e, 0x65, 0x74 /* exis.net */,
            0x00, 0xc0, 0x3f, 0x00, 0x05, 0x00, 0x01, 0x00 /* ..?..... */,
            0x00, 0x00, 0x17, 0x00, 0x07, 0x04, 0x63, 0x37 /* ......c7 */,
            0x6c, 0x6c, 0xc0, 0x0f, 0xc0, 0x6b, 0x00, 0x05 /* ll...k.. */,
            0x00, 0x01, 0x00, 0x00, 0x01, 0x26, 0x00, 0x15 /* .....&.. */,
            0x09, 0x72, 0x6f, 0x62, 0x6c, 0x6f, 0x78, 0x69 /* .robloxi */,
            0x6e, 0x63, 0x02, 0x68, 0x73, 0x05, 0x6c, 0x6c /* nc.hs.ll */,
            0x6e, 0x77, 0x64, 0xc0, 0x5a, 0xc0, 0x7e, 0x00 /* nwd.Z.~. */,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xe1, 0x00 /* ........ */,
            0x04, 0x45, 0x1c, 0xbc, 0x1e /* .E... */];
        let message = &buf[0x2a..];
        dns_parse_response(message);
    }

    #[test]
    fn test_dns_parse_6answer_response() {
        let buf: &[u8] = &[
            0x00, 0x24, 0x8c, 0x0e, 0x31, 0x54, 0x00, 0x15 /* .$..1T.. */,
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00 /* ......E. */,
            0x01, 0x54, 0x70, 0xed, 0x40, 0x00, 0x40, 0x11 /* .Tp.@.@. */,
            0xb1, 0xa4, 0x0a, 0x10, 0x01, 0x01, 0x0a, 0x10 /* ........ */,
            0x01, 0xe7, 0x00, 0x35, 0xc8, 0x0a, 0x01, 0x40 /* ...5...@ */,
            0x18, 0x59, 0xa2, 0xf2, 0x81, 0x80, 0x00, 0x01 /* .Y...... */,
            0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x73 /* .......s */,
            0x74, 0x6f, 0x72, 0x65, 0x2d, 0x69, 0x6d, 0x61 /* tore-ima */,
            0x67, 0x65, 0x73, 0x09, 0x6d, 0x69, 0x63, 0x72 /* ges.micr */,
            0x6f, 0x73, 0x6f, 0x66, 0x74, 0x03, 0x63, 0x6f /* osoft.co */,
            0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c /* m....... */,
            0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x02, 0x7a /* .......z */,
            0x00, 0x26, 0x09, 0x6d, 0x69, 0x63, 0x72, 0x6f /* .&.micro */,
            0x73, 0x6f, 0x66, 0x74, 0x03, 0x63, 0x6f, 0x6d /* soft.com */,
            0x0b, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x69, 0x6d /* .storeim */,
            0x61, 0x67, 0x65, 0x73, 0x06, 0x61, 0x6b, 0x61 /* ages.aka */,
            0x64, 0x6e, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00 /* dns.net. */,
            0xc0, 0x38, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00 /* .8...... */,
            0x00, 0x6e, 0x00, 0x23, 0x0c, 0x73, 0x74, 0x6f /* .n.#.sto */,
            0x72, 0x65, 0x2d, 0x69, 0x6d, 0x61, 0x67, 0x65 /* re-image */,
            0x73, 0x09, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73 /* s.micros */,
            0x6f, 0x66, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x05 /* oft.com. */,
            0x6e, 0x73, 0x61, 0x74, 0x63, 0xc0, 0x59, 0xc0 /* nsatc.Y. */,
            0x6a, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00 /* j....... */,
            0x7b, 0x00, 0x27, 0x0c, 0x73, 0x74, 0x6f, 0x72 /* {.'.stor */,
            0x65, 0x2d, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x73 /* e-images */,
            0x09, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f /* .microso */,
            0x66, 0x74, 0x05, 0x63, 0x6f, 0x6d, 0x2d, 0x63 /* ft.com-c */,
            0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79 /* .edgekey */,
            0xc0, 0x59, 0xc0, 0x99, 0x00, 0x05, 0x00, 0x01 /* .Y...... */,
            0x00, 0x00, 0x17, 0x0b, 0x00, 0x37, 0x0c, 0x73 /* .....7.s */,
            0x74, 0x6f, 0x72, 0x65, 0x2d, 0x69, 0x6d, 0x61 /* tore-ima */,
            0x67, 0x65, 0x73, 0x09, 0x6d, 0x69, 0x63, 0x72 /* ges.micr */,
            0x6f, 0x73, 0x6f, 0x66, 0x74, 0x05, 0x63, 0x6f /* osoft.co */,
            0x6d, 0x2d, 0x63, 0x07, 0x65, 0x64, 0x67, 0x65 /* m-c.edge */,
            0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x0b /* key.net. */,
            0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x72, 0x65 /* globalre */,
            0x64, 0x69, 0x72, 0xc0, 0x52, 0xc0, 0xcc, 0x00 /* dir.R... */,
            0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00 /* ........ */,
            0x19, 0x06, 0x65, 0x31, 0x32, 0x35, 0x36, 0x34 /* ..e12564 */,
            0x04, 0x64, 0x73, 0x70, 0x67, 0x0a, 0x61, 0x6b /* .dspg.ak */,
            0x61, 0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65 /* amaiedge */,
            0xc0, 0x59, 0xc1, 0x0f, 0x00, 0x01, 0x00, 0x01 /* .Y...... */,
            0x00, 0x00, 0x00, 0x12, 0x00, 0x04, 0x17, 0x3a /* .......: */,
            0xa1, 0xdd,                                    /* .. */];
        let message = &buf[0x2a..];
        dns_parse_response(message);
    }

    #[test]
    fn test_dns_state_tx_alloc_free() {
        let mut state = DNSState::new();
        let tx = state.new_tx();
        let tx_id = tx.id;
        state.transactions.push(Box::new(tx));
        state.tx_free(tx_id);
    }

}
