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

extern crate libc;

use std;
use std::string::String;

use json::*;
use dns::dns::*;
use log::*;

pub fn dns_rrtype_string(rrtype: u16) -> String {
    match rrtype {
        DNS_RTYPE_A => "A",
        DNS_RTYPE_CNAME => "CNAME",
        DNS_RTYPE_SOA => "SOA",
        DNS_RTYPE_PTR => "PTR",
        DNS_RTYPE_MX => "MX",
        DNS_RTYPE_SSHFP => "SSHFP",
        DNS_RTYPE_RRSIG => "RRSIG",
        _ => {
            return rrtype.to_string();
        }
    }.to_string()
}

fn dns_rcode_string(flags: u16) -> String {
    match flags & 0x000f {
        DNS_RCODE_NOERROR => "NOERROR",
        DNS_RCODE_FORMERR => "FORMERR",
        DNS_RCODE_NXDOMAIN => "NXDOMAIN",
        _ => {
            return (flags & 0x000f).to_string();
        }
    }.to_string()
}

/// Format bytes as an IP address string.
pub fn dns_print_addr(addr: &Vec<u8>) -> std::string::String {
    if addr.len() == 4 {
        return format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
    }
    else if addr.len() == 16 {
        return format!("{}{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}{}",
                       addr[0],
                       addr[1],
                       addr[2],
                       addr[3],
                       addr[4],
                       addr[5],
                       addr[6],
                       addr[7],
                       addr[8],
                       addr[9],
                       addr[10],
                       addr[11],
                       addr[12],
                       addr[13],
                       addr[14],
                       addr[15]);
    }
    else {
        return "".to_string();
    }
}

///  Log the SSHPF in an DNSAnswerEntry.
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

#[no_mangle]
pub extern "C" fn rs_dns_log_json_query(tx: &mut DNSTransaction,
                                        i: libc::uint16_t)
                                        -> *mut JsonT
{
    SCLogDebug!("rs_dns_log_json_query: tx_id={}, i={}", tx.id, i);
    let index = i as usize;
    for request in &tx.request {
        if index < request.queries.len() {
            let query = &request.queries[index];
            let js = Json::object();
            js.set_string("type", "query");
            js.set_integer("id", request.header.tx_id as u64);
            js.set_string("rrname", query.name());
            js.set_string("rrtype", &dns_rrtype_string(query.rrtype));
            js.set_integer("tx_id", tx.id - 1);
            return js.unwrap();
        }
    }

    return std::ptr::null_mut();
}

fn dns_log_json_answer(header: &DNSHeader, answer: &DNSAnswerEntry)
                       -> Json
{
    let js = Json::object();

    js.set_string("type", "answer");
    js.set_integer("id", header.tx_id as u64);
    js.set_string("rcode", &dns_rcode_string(header.flags));
    js.set_string("rrname", answer.name());
    js.set_string("rrtype", &dns_rrtype_string(answer.rrtype));
    js.set_integer("ttl", answer.ttl as u64);

    match answer.rrtype {
        DNS_RTYPE_A | DNS_RTYPE_AAAA => {
            js.set_string("rdata", &dns_print_addr(&answer.data));
        }
        DNS_RTYPE_CNAME |
        DNS_RTYPE_MX |
        DNS_RTYPE_PTR => {
            js.set_string("rdata", answer.data_to_string());
        },
        DNS_RTYPE_SSHFP => {
            dns_log_sshfp(&js, &answer);
        },
        _ => {}
    }

    return js;
}

fn dns_log_json_failure(r: &DNSResponse, index: usize) -> * mut JsonT {
    if index >= r.queries.len() {
        return std::ptr::null_mut();
    }

    let ref query = r.queries[index];

    let js = Json::object();

    js.set_string("type", "answer");
    js.set_integer("id", r.header.tx_id as u64);
    js.set_string("rcode", &dns_rcode_string(r.header.flags));
    js.set_string("rrname", std::str::from_utf8(&query.name[..]).unwrap());

    return js.unwrap();
}

#[no_mangle]
pub extern "C" fn rs_dns_log_json_answer(tx: &mut DNSTransaction,
                                         i: libc::uint16_t)
                                         -> *mut JsonT
{
    let index = i as usize;
    for response in &tx.response {
        if response.header.flags & 0x000f > 0 {
            if index == 0 {
                return dns_log_json_failure(response, index);
            }
            break;
        }
        if index >= response.answers.len() {
            break;
        }
        let answer = &response.answers[index];
        let js = dns_log_json_answer(&response.header, answer);
        return js.unwrap();
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub extern "C" fn rs_dns_log_json_authority(tx: &mut DNSTransaction,
                                            i: libc::uint16_t)
                                            -> *mut JsonT
{
    let index = i as usize;
    for response in &tx.response {
        if index >= response.authorities.len() {
            break;
        }
        let answer = &response.authorities[index];
        let js = dns_log_json_answer(&response.header, answer);
        return js.unwrap();
    }
    return std::ptr::null_mut();
}

