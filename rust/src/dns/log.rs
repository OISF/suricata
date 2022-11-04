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

use std;
use std::string::String;
use std::collections::HashMap;

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::dns::dns::*;

pub const LOG_QUERIES    : u64 = BIT_U64!(0);
pub const LOG_ANSWER     : u64 = BIT_U64!(1);

pub const LOG_A          : u64 = BIT_U64!(2);
pub const LOG_NS         : u64 = BIT_U64!(3);
pub const LOG_MD         : u64 = BIT_U64!(4);
pub const LOG_MF         : u64 = BIT_U64!(5);
pub const LOG_CNAME      : u64 = BIT_U64!(6);
pub const LOG_SOA        : u64 = BIT_U64!(7);
pub const LOG_MB         : u64 = BIT_U64!(8);
pub const LOG_MG         : u64 = BIT_U64!(9);
pub const LOG_MR         : u64 = BIT_U64!(10);
pub const LOG_NULL       : u64 = BIT_U64!(11);
pub const LOG_WKS        : u64 = BIT_U64!(12);
pub const LOG_PTR        : u64 = BIT_U64!(13);
pub const LOG_HINFO      : u64 = BIT_U64!(14);
pub const LOG_MINFO      : u64 = BIT_U64!(15);
pub const LOG_MX         : u64 = BIT_U64!(16);
pub const LOG_TXT        : u64 = BIT_U64!(17);
pub const LOG_RP         : u64 = BIT_U64!(18);
pub const LOG_AFSDB      : u64 = BIT_U64!(19);
pub const LOG_X25        : u64 = BIT_U64!(20);
pub const LOG_ISDN       : u64 = BIT_U64!(21);
pub const LOG_RT         : u64 = BIT_U64!(22);
pub const LOG_NSAP       : u64 = BIT_U64!(23);
pub const LOG_NSAPPTR    : u64 = BIT_U64!(24);
pub const LOG_SIG        : u64 = BIT_U64!(25);
pub const LOG_KEY        : u64 = BIT_U64!(26);
pub const LOG_PX         : u64 = BIT_U64!(27);
pub const LOG_GPOS       : u64 = BIT_U64!(28);
pub const LOG_AAAA       : u64 = BIT_U64!(29);
pub const LOG_LOC        : u64 = BIT_U64!(30);
pub const LOG_NXT        : u64 = BIT_U64!(31);
pub const LOG_SRV        : u64 = BIT_U64!(32);
pub const LOG_ATMA       : u64 = BIT_U64!(33);
pub const LOG_NAPTR      : u64 = BIT_U64!(34);
pub const LOG_KX         : u64 = BIT_U64!(35);
pub const LOG_CERT       : u64 = BIT_U64!(36);
pub const LOG_A6         : u64 = BIT_U64!(37);
pub const LOG_DNAME      : u64 = BIT_U64!(38);
pub const LOG_OPT        : u64 = BIT_U64!(39);
pub const LOG_APL        : u64 = BIT_U64!(40);
pub const LOG_DS         : u64 = BIT_U64!(41);
pub const LOG_SSHFP      : u64 = BIT_U64!(42);
pub const LOG_IPSECKEY   : u64 = BIT_U64!(43);
pub const LOG_RRSIG      : u64 = BIT_U64!(44);
pub const LOG_NSEC       : u64 = BIT_U64!(45);
pub const LOG_DNSKEY     : u64 = BIT_U64!(46);
pub const LOG_DHCID      : u64 = BIT_U64!(47);
pub const LOG_NSEC3      : u64 = BIT_U64!(48);
pub const LOG_NSEC3PARAM : u64 = BIT_U64!(49);
pub const LOG_TLSA       : u64 = BIT_U64!(50);
pub const LOG_HIP        : u64 = BIT_U64!(51);
pub const LOG_CDS        : u64 = BIT_U64!(52);
pub const LOG_CDNSKEY    : u64 = BIT_U64!(53);
pub const LOG_SPF        : u64 = BIT_U64!(54);
pub const LOG_TKEY       : u64 = BIT_U64!(55);
pub const LOG_TSIG       : u64 = BIT_U64!(56);
pub const LOG_MAILA      : u64 = BIT_U64!(57);
pub const LOG_ANY        : u64 = BIT_U64!(58);
pub const LOG_URI        : u64 = BIT_U64!(59);

pub const LOG_FORMAT_GROUPED  : u64 = BIT_U64!(60);
pub const LOG_FORMAT_DETAILED : u64 = BIT_U64!(61);
pub const LOG_HTTPS      : u64 = BIT_U64!(62);

fn dns_log_rrtype_enabled(rtype: u16, flags: u64) -> bool
{
    if flags == !0 {
        return true;
    }

    match rtype {
        DNS_RECORD_TYPE_A => {
            return flags & LOG_A != 0;
        }
        DNS_RECORD_TYPE_NS => {
            return flags & LOG_NS != 0;
        }
        DNS_RECORD_TYPE_MD => {
            return flags & LOG_MD != 0;
        }
        DNS_RECORD_TYPE_MF => {
            return flags & LOG_MF != 0;
        }
        DNS_RECORD_TYPE_CNAME => {
            return flags & LOG_CNAME != 0;
        }
        DNS_RECORD_TYPE_SOA => {
            return flags & LOG_SOA != 0;
        }
        DNS_RECORD_TYPE_MB => {
            return flags & LOG_MB != 0;
        }
        DNS_RECORD_TYPE_MG => {
            return flags & LOG_MG != 0;
        }
        DNS_RECORD_TYPE_MR => {
            return flags & LOG_MR != 0;
        }
        DNS_RECORD_TYPE_NULL => {
            return flags & LOG_NULL != 0;
        }
        DNS_RECORD_TYPE_WKS => {
            return flags & LOG_WKS != 0;
        }
        DNS_RECORD_TYPE_PTR => {
            return flags & LOG_PTR != 0;
        }
        DNS_RECORD_TYPE_HINFO => {
            return flags & LOG_HINFO != 0;
        }
        DNS_RECORD_TYPE_MINFO => {
            return flags & LOG_MINFO != 0;
        }
        DNS_RECORD_TYPE_MX => {
            return flags & LOG_MX != 0;
        }
        DNS_RECORD_TYPE_TXT => {
            return flags & LOG_TXT != 0;
        }
        DNS_RECORD_TYPE_RP => {
            return flags & LOG_RP != 0;
        }
        DNS_RECORD_TYPE_AFSDB => {
            return flags & LOG_AFSDB != 0;
        }
        DNS_RECORD_TYPE_X25 => {
            return flags & LOG_X25 != 0;
        }
        DNS_RECORD_TYPE_ISDN => {
            return flags & LOG_ISDN != 0;
        }
        DNS_RECORD_TYPE_RT => {
            return flags & LOG_RT != 0;
        }
        DNS_RECORD_TYPE_NSAP => {
            return flags & LOG_NSAP != 0;
        }
        DNS_RECORD_TYPE_NSAPPTR => {
            return flags & LOG_NSAPPTR != 0;
        }
        DNS_RECORD_TYPE_SIG => {
            return flags & LOG_SIG != 0;
        }
        DNS_RECORD_TYPE_KEY => {
            return flags & LOG_KEY != 0;
        }
        DNS_RECORD_TYPE_PX => {
            return flags & LOG_PX != 0;
        }
        DNS_RECORD_TYPE_GPOS => {
            return flags & LOG_GPOS != 0;
        }
        DNS_RECORD_TYPE_AAAA => {
            return flags & LOG_AAAA != 0;
        }
        DNS_RECORD_TYPE_LOC => {
            return flags & LOG_LOC != 0;
        }
        DNS_RECORD_TYPE_NXT => {
            return flags & LOG_NXT != 0;
        }
        DNS_RECORD_TYPE_SRV => {
            return flags & LOG_SRV != 0;
        }
        DNS_RECORD_TYPE_ATMA => {
            return flags & LOG_ATMA != 0;
        }
        DNS_RECORD_TYPE_NAPTR => {
            return flags & LOG_NAPTR != 0;
        }
        DNS_RECORD_TYPE_KX => {
            return flags & LOG_KX != 0;
        }
        DNS_RECORD_TYPE_CERT => {
            return flags & LOG_CERT != 0;
        }
        DNS_RECORD_TYPE_A6 => {
            return flags & LOG_A6 != 0;
        }
        DNS_RECORD_TYPE_DNAME => {
            return flags & LOG_DNAME != 0;
        }
        DNS_RECORD_TYPE_OPT => {
            return flags & LOG_OPT != 0;
        }
        DNS_RECORD_TYPE_APL => {
            return flags & LOG_APL != 0;
        }
        DNS_RECORD_TYPE_DS => {
            return flags & LOG_DS != 0;
        }
        DNS_RECORD_TYPE_SSHFP => {
            return flags & LOG_SSHFP != 0;
        }
        DNS_RECORD_TYPE_IPSECKEY => {
            return flags & LOG_IPSECKEY != 0;
        }
        DNS_RECORD_TYPE_RRSIG => {
            return flags & LOG_RRSIG != 0;
        }
        DNS_RECORD_TYPE_NSEC => {
            return flags & LOG_NSEC != 0;
        }
        DNS_RECORD_TYPE_DNSKEY => {
            return flags & LOG_DNSKEY != 0;
        }
        DNS_RECORD_TYPE_DHCID => {
            return flags & LOG_DHCID != 0;
        }
        DNS_RECORD_TYPE_NSEC3 => {
            return flags & LOG_NSEC3 != 0
        }
        DNS_RECORD_TYPE_NSEC3PARAM => {
            return flags & LOG_NSEC3PARAM != 0;
        }
        DNS_RECORD_TYPE_TLSA => {
            return flags & LOG_TLSA != 0;
        }
        DNS_RECORD_TYPE_HIP => {
            return flags & LOG_HIP != 0;
        }
        DNS_RECORD_TYPE_CDS => {
            return flags & LOG_CDS != 0;
        }
        DNS_RECORD_TYPE_CDNSKEY => {
            return flags & LOG_CDNSKEY != 0;
        }
        DNS_RECORD_TYPE_HTTPS => {
            return flags & LOG_HTTPS != 0;
        }
        DNS_RECORD_TYPE_SPF => {
            return flags & LOG_SPF != 0;
        }
        DNS_RECORD_TYPE_TKEY => {
            return flags & LOG_TKEY != 0;
        }
        DNS_RECORD_TYPE_TSIG => {
            return flags & LOG_TSIG != 0;
        }
        DNS_RECORD_TYPE_MAILA => {
            return flags & LOG_MAILA != 0;
        }
        DNS_RECORD_TYPE_ANY => {
            return flags & LOG_ANY != 0;
        }
        DNS_RECORD_TYPE_URI => {
            return flags & LOG_URI != 0;
        }
        _ => {
            return false;
        }
    }
}

pub fn dns_rrtype_string(rrtype: u16) -> String {
    match rrtype {
        DNS_RECORD_TYPE_A => "A",
        DNS_RECORD_TYPE_NS => "NS",
        DNS_RECORD_TYPE_AAAA => "AAAA",
        DNS_RECORD_TYPE_CNAME => "CNAME",
        DNS_RECORD_TYPE_TXT => "TXT",
        DNS_RECORD_TYPE_MX => "MX",
        DNS_RECORD_TYPE_SOA => "SOA",
        DNS_RECORD_TYPE_PTR => "PTR",
        DNS_RECORD_TYPE_SIG => "SIG",
        DNS_RECORD_TYPE_KEY => "KEY",
        DNS_RECORD_TYPE_WKS => "WKS",
        DNS_RECORD_TYPE_TKEY => "TKEY",
        DNS_RECORD_TYPE_TSIG => "TSIG",
        DNS_RECORD_TYPE_ANY => "ANY",
        DNS_RECORD_TYPE_RRSIG => "RRSIG",
        DNS_RECORD_TYPE_NSEC => "NSEC",
        DNS_RECORD_TYPE_DNSKEY => "DNSKEY",
        DNS_RECORD_TYPE_HINFO => "HINFO",
        DNS_RECORD_TYPE_MINFO => "MINFO",
        DNS_RECORD_TYPE_RP => "RP",
        DNS_RECORD_TYPE_AFSDB => "AFSDB",
        DNS_RECORD_TYPE_X25 => "X25",
        DNS_RECORD_TYPE_ISDN => "ISDN",
        DNS_RECORD_TYPE_RT => "RT",
        DNS_RECORD_TYPE_NSAP => "NSAP",
        DNS_RECORD_TYPE_NSAPPTR => "NSAPPT",
        DNS_RECORD_TYPE_PX => "PX",
        DNS_RECORD_TYPE_GPOS => "GPOS",
        DNS_RECORD_TYPE_LOC => "LOC",
        DNS_RECORD_TYPE_SRV => "SRV",
        DNS_RECORD_TYPE_ATMA => "ATMA",
        DNS_RECORD_TYPE_NAPTR => "NAPTR",
        DNS_RECORD_TYPE_KX => "KX",
        DNS_RECORD_TYPE_CERT => "CERT",
        DNS_RECORD_TYPE_A6 => "A6",
        DNS_RECORD_TYPE_DNAME => "DNAME",
        DNS_RECORD_TYPE_OPT => "OPT",
        DNS_RECORD_TYPE_APL => "APL",
        DNS_RECORD_TYPE_DS => "DS",
        DNS_RECORD_TYPE_SSHFP => "SSHFP",
        DNS_RECORD_TYPE_IPSECKEY => "IPSECKEY",
        DNS_RECORD_TYPE_DHCID => "DHCID",
        DNS_RECORD_TYPE_NSEC3 => "NSEC3",
        DNS_RECORD_TYPE_NSEC3PARAM => "NSEC3PARAM",
        DNS_RECORD_TYPE_TLSA => "TLSA",
        DNS_RECORD_TYPE_HIP => "HIP",
        DNS_RECORD_TYPE_CDS => "CDS",
        DNS_RECORD_TYPE_CDNSKEY => "CDSNKEY",
        DNS_RECORD_TYPE_HTTPS => "HTTPS",
        DNS_RECORD_TYPE_MAILA => "MAILA",
        DNS_RECORD_TYPE_URI => "URI",
        DNS_RECORD_TYPE_MB => "MB",
        DNS_RECORD_TYPE_MG => "MG",
        DNS_RECORD_TYPE_MR => "MR",
        DNS_RECORD_TYPE_NULL => "NULL",
        DNS_RECORD_TYPE_SPF => "SPF",
        DNS_RECORD_TYPE_NXT => "NXT",
        DNS_RECORD_TYPE_MD => "ND",
        DNS_RECORD_TYPE_MF => "MF",
        _ => {
            return rrtype.to_string();
        }
    }.to_string()
}

pub fn dns_rcode_string(flags: u16) -> String {
    match flags & 0x000f {
        DNS_RCODE_NOERROR => "NOERROR",
        DNS_RCODE_FORMERR => "FORMERR",
        DNS_RCODE_SERVFAIL => "SERVFAIL",
        DNS_RCODE_NXDOMAIN => "NXDOMAIN",
        DNS_RCODE_NOTIMP => "NOTIMP",
        DNS_RCODE_REFUSED => "REFUSED",
        DNS_RCODE_YXDOMAIN => "YXDOMAIN",
        DNS_RCODE_YXRRSET => "YXRRSET",
        DNS_RCODE_NXRRSET => "NXRRSET",
        DNS_RCODE_NOTAUTH => "NOTAUTH",
        DNS_RCODE_NOTZONE => "NOTZONE",
        DNS_RCODE_BADVERS => "BADVERS/BADSIG",
        DNS_RCODE_BADKEY => "BADKEY",
        DNS_RCODE_BADTIME => "BADTIME",
        DNS_RCODE_BADMODE => "BADMODE",
        DNS_RCODE_BADNAME => "BADNAME",
        DNS_RCODE_BADALG => "BADALG",
        DNS_RCODE_BADTRUNC => "BADTRUNC",
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
        return format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
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

/// Log SOA section fields.
fn dns_log_soa(soa: &DNSRDataSOA) -> Result<JsonBuilder, JsonError> {
    let mut js = JsonBuilder::new_object();

    js.set_string_from_bytes("mname", &soa.mname)?;
    js.set_string_from_bytes("rname", &soa.rname)?;
    js.set_uint("serial", soa.serial as u64)?;
    js.set_uint("refresh", soa.refresh as u64)?;
    js.set_uint("retry", soa.retry as u64)?;
    js.set_uint("expire", soa.expire as u64)?;
    js.set_uint("minimum", soa.minimum as u64)?;

    js.close()?;
    return Ok(js);
}

/// Log SSHFP section fields.
fn dns_log_sshfp(sshfp: &DNSRDataSSHFP) -> Result<JsonBuilder, JsonError>
{
    let mut js = JsonBuilder::new_object();

    let mut hex = Vec::new();
    for byte in &sshfp.fingerprint {
        hex.push(format!("{:02x}", byte));
    }

    js.set_string("fingerprint", &hex.join(":"))?;
    js.set_uint("algo", sshfp.algo as u64)?;
    js.set_uint("type", sshfp.fp_type as u64)?;

    js.close()?;
    return Ok(js);
}

/// Log SRV section fields.
fn dns_log_srv(srv: &DNSRDataSRV) -> Result<JsonBuilder, JsonError>
{
    let mut js = JsonBuilder::new_object();

    js.set_uint("priority", srv.priority as u64)?;
    js.set_uint("weight", srv.weight as u64)?;
    js.set_uint("port", srv.port as u64)?;
    js.set_string_from_bytes("name", &srv.target)?;

    js.close()?;
    return Ok(js);
}

fn dns_log_json_answer_detail(answer: &DNSAnswerEntry) -> Result<JsonBuilder, JsonError>
{
    let mut jsa = JsonBuilder::new_object();

    jsa.set_string_from_bytes("rrname", &answer.name)?;
    jsa.set_string("rrtype", &dns_rrtype_string(answer.rrtype))?;
    jsa.set_uint("ttl", answer.ttl as u64)?;

    match &answer.data {
        DNSRData::A(addr) | DNSRData::AAAA(addr) => {
            jsa.set_string("rdata", &dns_print_addr(addr))?;
        }
        DNSRData::CNAME(bytes) |
        DNSRData::MX(bytes) |
        DNSRData::NS(bytes) |
        DNSRData::TXT(bytes) |
        DNSRData::NULL(bytes) |
        DNSRData::PTR(bytes) => {
            jsa.set_string_from_bytes("rdata", bytes)?;
        }
        DNSRData::SOA(soa) => {
            jsa.set_object("soa", &dns_log_soa(soa)?)?;
        }
        DNSRData::SSHFP(sshfp) => {
            jsa.set_object("sshfp", &dns_log_sshfp(sshfp)?)?;
        }
        DNSRData::SRV(srv) => {
            jsa.set_object("srv", &dns_log_srv(srv)?)?;
        }
        _ => {}
    }

    jsa.close()?;
    return Ok(jsa);
}

fn dns_log_json_answer(js: &mut JsonBuilder, response: &DNSResponse, flags: u64)
                       -> Result<(), JsonError>
{
    let header = &response.header;

    js.set_uint("version", 2)?;
    js.set_string("type", "answer")?;
    js.set_uint("id", header.tx_id as u64)?;
    js.set_string("flags", format!("{:x}", header.flags).as_str())?;
    if header.flags & 0x8000 != 0 {
        js.set_bool("qr", true)?;
    }
    if header.flags & 0x0400 != 0 {
        js.set_bool("aa", true)?;
    }
    if header.flags & 0x0200 != 0 {
        js.set_bool("tc", true)?;
    }
    if header.flags & 0x0100 != 0 {
        js.set_bool("rd", true)?;
    }
    if header.flags & 0x0080 != 0 {
        js.set_bool("ra", true)?;
    }
    if header.flags & 0x0040 != 0 {
        js.set_bool("z", true)?;
    }

    for query in &response.queries {
        js.set_string_from_bytes("rrname", &query.name)?;
        js.set_string("rrtype", &dns_rrtype_string(query.rrtype))?;
        break;
    }
    js.set_string("rcode", &dns_rcode_string(header.flags))?;

    if !response.answers.is_empty() {
        let mut js_answers = JsonBuilder::new_array();

        // For grouped answers we use a HashMap keyed by the rrtype.
        let mut answer_types = HashMap::new();

        for answer in &response.answers {

            if flags & LOG_FORMAT_GROUPED != 0 {
                let type_string = dns_rrtype_string(answer.rrtype);
                match &answer.data {
                    DNSRData::A(addr) | DNSRData::AAAA(addr) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types.insert(type_string.to_string(),
                                                JsonBuilder::new_array());
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_string(&dns_print_addr(addr))?;
                        }
                    }
                    DNSRData::CNAME(bytes) |
                    DNSRData::MX(bytes) |
                    DNSRData::NS(bytes) |
                    DNSRData::TXT(bytes) |
                    DNSRData::NULL(bytes) |
                    DNSRData::PTR(bytes) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types.insert(type_string.to_string(),
                                                JsonBuilder::new_array());
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_string_from_bytes(bytes)?;
                        }
                    },
                    DNSRData::SOA(soa) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types.insert(type_string.to_string(),
                                                JsonBuilder::new_array());
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_object(&dns_log_soa(soa)?)?;
                        }
                    },
                    DNSRData::SSHFP(sshfp) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types.insert(type_string.to_string(),
                                                JsonBuilder::new_array());
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_object(&dns_log_sshfp(sshfp)?)?;
                        }
                    },
                    DNSRData::SRV(srv) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types.insert(type_string.to_string(),
                                                JsonBuilder::new_array());
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_object(&dns_log_srv(srv)?)?;
                        }
                    },
                    _ => {}
                }
            }

            if flags & LOG_FORMAT_DETAILED != 0 {
                js_answers.append_object(&dns_log_json_answer_detail(answer)?)?;
            }
        }

        js_answers.close()?;

        if flags & LOG_FORMAT_DETAILED != 0 {
            js.set_object("answers", &js_answers)?;
        }

        if flags & LOG_FORMAT_GROUPED != 0 {
            js.open_object("grouped")?;
            for (k, mut v) in answer_types.drain() {
                v.close()?;
                js.set_object(&k, &v)?;
            }
            js.close()?;
        }

    }

    if !response.authorities.is_empty() {
        js.open_array("authorities")?;
        for auth in &response.authorities {
            let auth_detail = dns_log_json_answer_detail(auth)?;
            js.append_object(&auth_detail)?;
        }
        js.close()?;
    }

    Ok(())
}

fn dns_log_query(tx: &mut DNSTransaction,
                 i: u16,
                 flags: u64,
                 jb: &mut JsonBuilder)
                 -> Result<bool, JsonError>
{
    let index = i as usize;
    if let &Some(ref request) = &tx.request {
        if index < request.queries.len() {
            let query = &request.queries[index];
            if dns_log_rrtype_enabled(query.rrtype, flags) {
                jb.set_string("type", "query")?;
                jb.set_uint("id", request.header.tx_id as u64)?;
                jb.set_string_from_bytes("rrname", &query.name)?;
                jb.set_string("rrtype", &dns_rrtype_string(query.rrtype))?;
                jb.set_uint("tx_id", tx.id - 1)?;
                if request.header.flags & 0x0040 != 0 {
                    jb.set_bool("z", true)?;
                }
                return Ok(true);
            }
        }
    }

    return Ok(false);
}

#[no_mangle]
pub extern "C" fn rs_dns_log_json_query(tx: &mut DNSTransaction,
                                        i: u16,
                                        flags: u64,
                                        jb: &mut JsonBuilder)
                                        -> bool
{
    match dns_log_query(tx, i, flags, jb) {
        Ok(false) | Err(_) => {
            return false;
        }
        Ok(true) => {
            return true;
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_log_json_answer(tx: &mut DNSTransaction,
                                         flags: u64, js: &mut JsonBuilder)
                                         -> bool
{
    if let &Some(ref response) = &tx.response {
        for query in &response.queries {
            if dns_log_rrtype_enabled(query.rrtype, flags) {
                return dns_log_json_answer(js, response, flags).is_ok();
            }
        }
    }
    return false;
}

#[no_mangle]
pub extern "C" fn rs_dns_do_log_answer(tx: &mut DNSTransaction,
                                       flags: u64) -> bool
{
    if let &Some(ref response) = &tx.response {
        for query in &response.queries {
            if dns_log_rrtype_enabled(query.rrtype, flags) {
                return true;
            }
        }
    }
    return false;
}
