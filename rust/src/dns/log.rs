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

// TODO: log-dnslog "fast" style logging.
// TODO: rtype log filtering.

extern crate libc;

use std;
use std::ffi::CString;

use dns::*;
use json::*;

fn dns_type_string(rrtype: u16) -> std::string::String {
    match rrtype {
        DNS_RTYPE_A => "A",
        DNS_RTYPE_CNAME => "CNAME",
        DNS_RTYPE_SOA => "SOA",
        DNS_RTYPE_PTR => "PTR",
        DNS_RTYPE_MX => "MX",
        DNS_RTYPE_SSHFP => "SSHFP",
        DNS_RTYPE_RRSIG => "RRSIG",
        _ => "?",
    }.to_string()
}

fn dns_rcode_string(flags: u16) -> std::string::String {
    match flags & 0x000f {
        DNS_RCODE_NOERROR => "NOERROR",
        DNS_RCODE_FORMERR => "FORMERR",
        DNS_RCODE_NXDOMAIN => "NXDOMAIN",
        _ => "?",
    }.to_string()
}

/// Format bytes as an IP address string.
///
/// TODO: IPv6.
fn dns_print_addr(addr: &Vec<u8>) -> std::string::String {
    if addr.len() == 4 {
        return format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
    }
    else {
        println!("Unsupported address length {}", addr.len());
        return "unknown".to_string();
    }
}

pub fn dns_get_request_query(request: &DNSRequest, i: u16)
                             -> Option<&DNSQueryEntry>
{
    if (i as usize) < request.queries.len() {
        return Some(&request.queries[i as usize]);
    }
    return None
}

pub fn dns_get_response_answer(response: &DNSResponse, i: u16)
                               -> Option<&DNSAnswerEntry>
{
    if (i as usize) < response.answers.len() {
        return Some(&response.answers[i as usize]);
    }
    return None
}

pub fn dns_get_response_authority(response: &DNSResponse, i: u16)
                                  -> Option<&DNSAnswerEntry>
{
    if (i as usize) < response.authorities.len() {
        return Some(&response.authorities[i as usize]);
    }
    return None
}

#[no_mangle]
pub extern fn rs_dns_log_query(txp: *mut DNSTransaction, i: libc::uint16_t)
                               -> *mut JsonT {

    let tx = unsafe{&mut *txp};

    for request in &tx.request {

        if (i as usize) < request.queries.len() {

            let query = &request.queries[i as usize];

            let js = Json::object();

            js.set_string("type", "query");
            js.set_integer("id", request.header.tx_id as u64);

            js.set_string("rrname",
                          std::str::from_utf8(&query.name[..]).unwrap());
            js.set_string("rrtype", &dns_type_string(query.rrtype));
            //js.set_integer("rrclass", query.rrclass as u64);

            // This is - 1 as the ID stored in the transaction is one
            // greater than Suricata's app-layer idea of the ID.
            js.set_integer("tx_id", tx.id - 1);

            return js.unwrap();
        }

    }

    return std::ptr::null_mut();
}

fn dns_log_response_failure(r: &DNSResponse, i: u16) -> * mut JsonT {
    if (i as usize) >= r.queries.len() {
        return std::ptr::null_mut();
    }

    let ref query = r.queries[i as usize];

    let js = Json::object();

    js.set_string("type", "answer");
    js.set_integer("id", r.header.tx_id as u64);
    js.set_string("rcode", &dns_rcode_string(r.header.flags));
    js.set_string("rrname", std::str::from_utf8(&query.name[..]).unwrap());

    return js.unwrap();
}

fn dns_log_sshfp(js: &Json, answer: &DNSAnswerEntry)
{
    // Need at least 3 bytes - TODO: log something if we don't?
    if answer.data_len < 3 {
        return;
    }

    let sshfp = Json::object();

    let mut hex = Vec::new();
    for byte in &answer.data[2..] {
        hex.push(format!("{:02x}", byte));
    }
    sshfp.set_string("fingerprint", &hex.join(":"));

    sshfp.set_integer("algo", answer.data[0] as u64);
    sshfp.set_integer("type", answer.data[1] as u64);

    js.set("sshfp", sshfp);
}

fn dns_log_answer_entry(header: &DNSHeader, answer: &DNSAnswerEntry)
                        -> *mut JsonT {
    let js = Json::object();

    js.set_string("type", "answer");
    js.set_integer("id", header.tx_id as u64);
    js.set_string("rcode", &dns_rcode_string(header.flags));
    js.set_string("rrname",
                  std::str::from_utf8(&answer.name[..]).unwrap());
    js.set_string("rrtype", &dns_type_string(answer.rrtype));
    js.set_integer("ttl", answer.ttl as u64);

    match answer.rrtype {
        DNS_RTYPE_A => {
            js.set_string("rdata", &dns_print_addr(&answer.data));
        },
        DNS_RTYPE_CNAME |
        DNS_RTYPE_MX |
        DNS_RTYPE_PTR => {
            js.set_string("rdata",
                          std::str::from_utf8(&answer.data[..]).unwrap());
        },
        DNS_RTYPE_SOA => {},
        DNS_RTYPE_SSHFP => {
            dns_log_sshfp(&js, &answer);
        },
        _ => {
        }
    }

    return js.unwrap();
}

#[no_mangle]
pub extern fn rs_dns_log_answers(tx: &mut DNSTransaction, i: libc::uint16_t)
                                -> *mut JsonT
{
    for response in &tx.response {
        if response.header.flags & 0x000f > 0 {
            return dns_log_response_failure(response, i);
        }

        if (i as usize) >= response.answers.len() {
            return std::ptr::null_mut();
        }

        let answer = &response.answers[i as usize];
        return dns_log_answer_entry(&response.header, answer);
    }

    return std::ptr::null_mut();
}

#[no_mangle]
pub extern fn rs_dns_log_authorities(tx: &mut DNSTransaction, i: libc::uint16_t)
                                     -> *mut JsonT
{
    for response in &tx.response {
        if (i as usize) >= response.authorities.len() {
            return std::ptr::null_mut();
        }

        let answer = &response.authorities[i as usize];
        return dns_log_answer_entry(&response.header, answer);
    }

    return std::ptr::null_mut();
}

#[no_mangle]
pub extern "C" fn rs_dns_log_txt_query(tx: &mut DNSTransaction,
                                       i: libc::uint16_t)
                                       -> CString
{
    for request in &tx.request {
        for query in dns_get_request_query(request, i) {
            let log = format!("Query TX {:04x} [**] {} [**] {}",
                              request.header.tx_id,
                              std::str::from_utf8(&query.name[..]).unwrap(),
                              dns_type_string(query.rrtype));
            return CString::new(log).unwrap();
        }
    }
    return CString::default();
}

#[no_mangle]
pub extern "C" fn rs_dns_log_txt_response_rcode(tx: &mut DNSTransaction)
                                                -> CString
{
    for response in &tx.response {
        if response.header.flags & 0x000f > 0 {
            let log = format!("Response TX {:04x} [**] {}",
                              response.header.tx_id,
                              dns_rcode_string(response.header.flags));
            return CString::new(log).unwrap();
        }
    }
    return CString::default();
}

#[no_mangle]
pub extern "C" fn rs_dns_log_txt_response_recursion(tx: &mut DNSTransaction)
                                                    -> CString
{
    for response in &tx.response {
        if response.header.flags & 0x0080 > 0 {
            let log = format!("Response TX {:04x} [**] Recursion Desired",
                              response.header.tx_id);
            return CString::new(log).unwrap();
        }
    }
    return CString::default();
}

/// Check if a byte is a printable character or not.
fn isprint(byte: u8) -> bool {
    return byte >= 32 && byte <= 127;
}

pub fn dns_log_txt_format_data(answer: &DNSAnswerEntry) -> String {
    match answer.rrtype {
        _ => {
            if answer.data.len() == 0 {
                return "<no data>".to_string();
            }
            let mut raw = Vec::new();
            for byte in &answer.data[..] {
                if isprint(*byte) {
                    raw.push(format!("{}", *byte as char));
                } else {
                    raw.push(format!("\\x{:02X}", byte));
                }
            }
            return raw.join("");
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_log_txt_response_answer(tx: &mut DNSTransaction,
                                                 i: libc::uint16_t)
                                                 -> CString
{
    for response in &tx.response {
        for answer in dns_get_response_answer(response, i) {
            let log = format!(
                "Response TX {:04x} [**] {} [**] {} [**] TTL {} [**] {}",
                response.header.tx_id,
                std::str::from_utf8(&answer.name[..]).unwrap(),
                dns_type_string(answer.rrtype),
                answer.ttl,
                dns_log_txt_format_data(answer));
            return CString::new(log).unwrap();
        }
    }
    return CString::default();
}

#[no_mangle]
pub extern "C" fn rs_dns_log_txt_response_authority(tx: &mut DNSTransaction,
                                                 i: libc::uint16_t)
                                                 -> CString
{
    for response in &tx.response {
        for answer in dns_get_response_authority(response, i) {
            let log = format!(
                "Response TX {:04x} [**] {} [**] {} [**] TTL {} [**] {}",
                response.header.tx_id,
                std::str::from_utf8(&answer.name[..]).unwrap(),
                dns_type_string(answer.rrtype),
                answer.ttl,
                dns_log_txt_format_data(answer));
            return CString::new(log).unwrap();
        }
    }
    return CString::default();
}
