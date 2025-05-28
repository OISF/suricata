/* Copyright (C) 2017-2024 Open Information Security Foundation
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
use std::collections::HashMap;
use std::string::String;

use crate::detect::EnumString;
use crate::dns::dns::*;
use crate::jsonbuilder::{JsonBuilder, JsonError};

pub const LOG_A: u64 = BIT_U64!(2);
pub const LOG_NS: u64 = BIT_U64!(3);
pub const LOG_MD: u64 = BIT_U64!(4);
pub const LOG_MF: u64 = BIT_U64!(5);
pub const LOG_CNAME: u64 = BIT_U64!(6);
pub const LOG_SOA: u64 = BIT_U64!(7);
pub const LOG_MB: u64 = BIT_U64!(8);
pub const LOG_MG: u64 = BIT_U64!(9);
pub const LOG_MR: u64 = BIT_U64!(10);
pub const LOG_NULL: u64 = BIT_U64!(11);
pub const LOG_WKS: u64 = BIT_U64!(12);
pub const LOG_PTR: u64 = BIT_U64!(13);
pub const LOG_HINFO: u64 = BIT_U64!(14);
pub const LOG_MINFO: u64 = BIT_U64!(15);
pub const LOG_MX: u64 = BIT_U64!(16);
pub const LOG_TXT: u64 = BIT_U64!(17);
pub const LOG_RP: u64 = BIT_U64!(18);
pub const LOG_AFSDB: u64 = BIT_U64!(19);
pub const LOG_X25: u64 = BIT_U64!(20);
pub const LOG_ISDN: u64 = BIT_U64!(21);
pub const LOG_RT: u64 = BIT_U64!(22);
pub const LOG_NSAP: u64 = BIT_U64!(23);
pub const LOG_NSAPPTR: u64 = BIT_U64!(24);
pub const LOG_SIG: u64 = BIT_U64!(25);
pub const LOG_KEY: u64 = BIT_U64!(26);
pub const LOG_PX: u64 = BIT_U64!(27);
pub const LOG_GPOS: u64 = BIT_U64!(28);
pub const LOG_AAAA: u64 = BIT_U64!(29);
pub const LOG_LOC: u64 = BIT_U64!(30);
pub const LOG_NXT: u64 = BIT_U64!(31);
pub const LOG_SRV: u64 = BIT_U64!(32);
pub const LOG_ATMA: u64 = BIT_U64!(33);
pub const LOG_NAPTR: u64 = BIT_U64!(34);
pub const LOG_KX: u64 = BIT_U64!(35);
pub const LOG_CERT: u64 = BIT_U64!(36);
pub const LOG_A6: u64 = BIT_U64!(37);
pub const LOG_DNAME: u64 = BIT_U64!(38);
pub const LOG_OPT: u64 = BIT_U64!(39);
pub const LOG_APL: u64 = BIT_U64!(40);
pub const LOG_DS: u64 = BIT_U64!(41);
pub const LOG_SSHFP: u64 = BIT_U64!(42);
pub const LOG_IPSECKEY: u64 = BIT_U64!(43);
pub const LOG_RRSIG: u64 = BIT_U64!(44);
pub const LOG_NSEC: u64 = BIT_U64!(45);
pub const LOG_DNSKEY: u64 = BIT_U64!(46);
pub const LOG_DHCID: u64 = BIT_U64!(47);
pub const LOG_NSEC3: u64 = BIT_U64!(48);
pub const LOG_NSEC3PARAM: u64 = BIT_U64!(49);
pub const LOG_TLSA: u64 = BIT_U64!(50);
pub const LOG_HIP: u64 = BIT_U64!(51);
pub const LOG_CDS: u64 = BIT_U64!(52);
pub const LOG_CDNSKEY: u64 = BIT_U64!(53);
pub const LOG_SPF: u64 = BIT_U64!(54);
pub const LOG_TKEY: u64 = BIT_U64!(55);
pub const LOG_TSIG: u64 = BIT_U64!(56);
pub const LOG_MAILA: u64 = BIT_U64!(57);
pub const LOG_ANY: u64 = BIT_U64!(58);
pub const LOG_URI: u64 = BIT_U64!(59);

pub const LOG_FORMAT_GROUPED: u64 = BIT_U64!(60);
pub const LOG_FORMAT_DETAILED: u64 = BIT_U64!(61);
pub const LOG_HTTPS: u64 = BIT_U64!(62);

pub const DNS_LOG_VERSION_1: u8 = 1;
pub const DNS_LOG_VERSION_2: u8 = 2;
pub const DNS_LOG_VERSION_3: u8 = 3;
pub const DNS_LOG_VERSION_DEFAULT: u8 = DNS_LOG_VERSION_3;

fn dns_log_rrtype_enabled(rtype: u16, flags: u64) -> bool {
    if flags == !0 {
        return true;
    }

    match DNSRecordType::from_u(rtype) {
        Some(DNSRecordType::A) => {
            return flags & LOG_A != 0;
        }
        Some(DNSRecordType::NS) => {
            return flags & LOG_NS != 0;
        }
        Some(DNSRecordType::MD) => {
            return flags & LOG_MD != 0;
        }
        Some(DNSRecordType::MF) => {
            return flags & LOG_MF != 0;
        }
        Some(DNSRecordType::CNAME) => {
            return flags & LOG_CNAME != 0;
        }
        Some(DNSRecordType::SOA) => {
            return flags & LOG_SOA != 0;
        }
        Some(DNSRecordType::MB) => {
            return flags & LOG_MB != 0;
        }
        Some(DNSRecordType::MG) => {
            return flags & LOG_MG != 0;
        }
        Some(DNSRecordType::MR) => {
            return flags & LOG_MR != 0;
        }
        Some(DNSRecordType::NULL) => {
            return flags & LOG_NULL != 0;
        }
        Some(DNSRecordType::WKS) => {
            return flags & LOG_WKS != 0;
        }
        Some(DNSRecordType::PTR) => {
            return flags & LOG_PTR != 0;
        }
        Some(DNSRecordType::HINFO) => {
            return flags & LOG_HINFO != 0;
        }
        Some(DNSRecordType::MINFO) => {
            return flags & LOG_MINFO != 0;
        }
        Some(DNSRecordType::MX) => {
            return flags & LOG_MX != 0;
        }
        Some(DNSRecordType::TXT) => {
            return flags & LOG_TXT != 0;
        }
        Some(DNSRecordType::RP) => {
            return flags & LOG_RP != 0;
        }
        Some(DNSRecordType::AFSDB) => {
            return flags & LOG_AFSDB != 0;
        }
        Some(DNSRecordType::X25) => {
            return flags & LOG_X25 != 0;
        }
        Some(DNSRecordType::ISDN) => {
            return flags & LOG_ISDN != 0;
        }
        Some(DNSRecordType::RT) => {
            return flags & LOG_RT != 0;
        }
        Some(DNSRecordType::NSAP) => {
            return flags & LOG_NSAP != 0;
        }
        Some(DNSRecordType::NSAPPTR) => {
            return flags & LOG_NSAPPTR != 0;
        }
        Some(DNSRecordType::SIG) => {
            return flags & LOG_SIG != 0;
        }
        Some(DNSRecordType::KEY) => {
            return flags & LOG_KEY != 0;
        }
        Some(DNSRecordType::PX) => {
            return flags & LOG_PX != 0;
        }
        Some(DNSRecordType::GPOS) => {
            return flags & LOG_GPOS != 0;
        }
        Some(DNSRecordType::AAAA) => {
            return flags & LOG_AAAA != 0;
        }
        Some(DNSRecordType::LOC) => {
            return flags & LOG_LOC != 0;
        }
        Some(DNSRecordType::NXT) => {
            return flags & LOG_NXT != 0;
        }
        Some(DNSRecordType::SRV) => {
            return flags & LOG_SRV != 0;
        }
        Some(DNSRecordType::ATMA) => {
            return flags & LOG_ATMA != 0;
        }
        Some(DNSRecordType::NAPTR) => {
            return flags & LOG_NAPTR != 0;
        }
        Some(DNSRecordType::KX) => {
            return flags & LOG_KX != 0;
        }
        Some(DNSRecordType::CERT) => {
            return flags & LOG_CERT != 0;
        }
        Some(DNSRecordType::A6) => {
            return flags & LOG_A6 != 0;
        }
        Some(DNSRecordType::DNAME) => {
            return flags & LOG_DNAME != 0;
        }
        Some(DNSRecordType::OPT) => {
            return flags & LOG_OPT != 0;
        }
        Some(DNSRecordType::APL) => {
            return flags & LOG_APL != 0;
        }
        Some(DNSRecordType::DS) => {
            return flags & LOG_DS != 0;
        }
        Some(DNSRecordType::SSHFP) => {
            return flags & LOG_SSHFP != 0;
        }
        Some(DNSRecordType::IPSECKEY) => {
            return flags & LOG_IPSECKEY != 0;
        }
        Some(DNSRecordType::RRSIG) => {
            return flags & LOG_RRSIG != 0;
        }
        Some(DNSRecordType::NSEC) => {
            return flags & LOG_NSEC != 0;
        }
        Some(DNSRecordType::DNSKEY) => {
            return flags & LOG_DNSKEY != 0;
        }
        Some(DNSRecordType::DHCID) => {
            return flags & LOG_DHCID != 0;
        }
        Some(DNSRecordType::NSEC3) => return flags & LOG_NSEC3 != 0,
        Some(DNSRecordType::NSEC3PARAM) => {
            return flags & LOG_NSEC3PARAM != 0;
        }
        Some(DNSRecordType::TLSA) => {
            return flags & LOG_TLSA != 0;
        }
        Some(DNSRecordType::HIP) => {
            return flags & LOG_HIP != 0;
        }
        Some(DNSRecordType::CDS) => {
            return flags & LOG_CDS != 0;
        }
        Some(DNSRecordType::CDNSKEY) => {
            return flags & LOG_CDNSKEY != 0;
        }
        Some(DNSRecordType::HTTPS) => {
            return flags & LOG_HTTPS != 0;
        }
        Some(DNSRecordType::SPF) => {
            return flags & LOG_SPF != 0;
        }
        Some(DNSRecordType::TKEY) => {
            return flags & LOG_TKEY != 0;
        }
        Some(DNSRecordType::TSIG) => {
            return flags & LOG_TSIG != 0;
        }
        Some(DNSRecordType::MAILA) => {
            return flags & LOG_MAILA != 0;
        }
        Some(DNSRecordType::ANY) => {
            return flags & LOG_ANY != 0;
        }
        Some(DNSRecordType::URI) => {
            return flags & LOG_URI != 0;
        }
        _ => {
            return false;
        }
    }
}

pub fn dns_rrtype_string(rrtype: u16) -> String {
    if let Some(rt) = DNSRecordType::from_u(rrtype) {
        return rt.to_str().to_uppercase();
    }
    return rrtype.to_string();
}

pub fn dns_rcode_string(flags: u16) -> String {
    if flags & 0x000f == DNSRcode::BADVERS as u16 {
        return "BADVERS/BADSIG".to_string();
    }
    if let Some(rc) = DNSRcode::from_u(flags & 0x000f) {
        return rc.to_str().to_uppercase();
    }
    return (flags & 0x000f).to_string();
}

/// Format bytes as an IP address string.
pub fn dns_print_addr(addr: &[u8]) -> std::string::String {
    if addr.len() == 4 {
        return format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
    } else if addr.len() == 16 {
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
    } else {
        return "".to_string();
    }
}

/// Log OPT section fields
pub(crate) fn dns_log_opt(opt: &DNSRDataOPT) -> Result<JsonBuilder, JsonError> {
    let mut js = JsonBuilder::try_new_object()?;

    js.set_uint("code", opt.code as u64)?;
    js.set_hex("data", &opt.data)?;

    js.close()?;
    Ok(js)
}

/// Log SOA section fields.
pub(crate) fn dns_log_soa(soa: &DNSRDataSOA) -> Result<JsonBuilder, JsonError> {
    let mut js = JsonBuilder::try_new_object()?;

    js.set_string_from_bytes("mname", &soa.mname.value)?;
    if soa.mname.flags.contains(DNSNameFlags::TRUNCATED) {
        js.set_bool("mname_truncated", true)?;
    }
    js.set_string_from_bytes("rname", &soa.rname.value)?;
    if soa.rname.flags.contains(DNSNameFlags::TRUNCATED) {
        js.set_bool("rname_truncated", true)?;
    }
    js.set_uint("serial", soa.serial as u64)?;
    js.set_uint("refresh", soa.refresh as u64)?;
    js.set_uint("retry", soa.retry as u64)?;
    js.set_uint("expire", soa.expire as u64)?;
    js.set_uint("minimum", soa.minimum as u64)?;

    js.close()?;
    return Ok(js);
}

/// Log SSHFP section fields.
pub(crate) fn dns_log_sshfp(sshfp: &DNSRDataSSHFP) -> Result<JsonBuilder, JsonError> {
    let mut js = JsonBuilder::try_new_object()?;

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
pub(crate) fn dns_log_srv(srv: &DNSRDataSRV) -> Result<JsonBuilder, JsonError> {
    let mut js = JsonBuilder::try_new_object()?;

    js.set_uint("priority", srv.priority as u64)?;
    js.set_uint("weight", srv.weight as u64)?;
    js.set_uint("port", srv.port as u64)?;
    js.set_string_from_bytes("name", &srv.target.value)?;

    js.close()?;
    return Ok(js);
}

/// Log a single DNS answer entry.
///
/// For items that may be array, such as TXT records, i will designate
/// which entry to log.
fn dns_log_json_answer_detail(answer: &DNSAnswerEntry, i: usize) -> Result<JsonBuilder, JsonError> {
    let mut jsa = JsonBuilder::try_new_object()?;

    jsa.set_string_from_bytes("rrname", &answer.name.value)?;
    if answer.name.flags.contains(DNSNameFlags::TRUNCATED) {
        jsa.set_bool("rrname_truncated", true)?;
    }
    jsa.set_string("rrtype", &dns_rrtype_string(answer.rrtype))?;
    jsa.set_uint("ttl", answer.ttl as u64)?;

    match &answer.data {
        DNSRData::A(addr) | DNSRData::AAAA(addr) => {
            jsa.set_string("rdata", &dns_print_addr(addr))?;
        }
        DNSRData::CNAME(name) | DNSRData::MX(name) | DNSRData::NS(name) | DNSRData::PTR(name) => {
            jsa.set_string_from_bytes("rdata", &name.value)?;
            if name.flags.contains(DNSNameFlags::TRUNCATED) {
                jsa.set_bool("rdata_truncated", true)?;
            }
        }
        DNSRData::TXT(txt) => {
            if let Some(txt) = txt.get(i) {
                jsa.set_string_from_bytes("rdata", txt)?;
            } else {
                debug_validate_fail!("txt entry does not exist");
            }
        }
        DNSRData::NULL(bytes) => {
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
        DNSRData::OPT(opt) => {
            jsa.open_array("opt")?;
            for val in opt {
                jsa.append_object(&dns_log_opt(val)?)?;
            }
            jsa.close()?;
        }
        _ => {}
    }

    jsa.close()?;
    return Ok(jsa);
}

fn dns_log_json_answer(
    js: &mut JsonBuilder, response: &DNSMessage, flags: u64,
) -> Result<(), JsonError> {
    let header = &response.header;

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

    let opcode = ((header.flags >> 11) & 0xf) as u8;
    js.set_uint("opcode", opcode as u64)?;

    if let Some(query) = response.queries.first() {
        js.set_string_from_bytes("rrname", &query.name.value)?;
        if query.name.flags.contains(DNSNameFlags::TRUNCATED) {
            js.set_bool("rrname_truncated", true)?;
        }
        js.set_string("rrtype", &dns_rrtype_string(query.rrtype))?;
    }
    js.set_string("rcode", &dns_rcode_string(header.flags))?;

    if !response.answers.is_empty() {
        let mut js_answers = JsonBuilder::try_new_array()?;

        // For grouped answers we use a HashMap keyed by the rrtype.
        let mut answer_types = HashMap::new();

        for answer in &response.answers {
            if flags & LOG_FORMAT_GROUPED != 0 {
                let type_string = dns_rrtype_string(answer.rrtype);
                match &answer.data {
                    DNSRData::A(addr) | DNSRData::AAAA(addr) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_string(&dns_print_addr(addr))?;
                        }
                    }
                    DNSRData::CNAME(name)
                    | DNSRData::MX(name)
                    | DNSRData::NS(name)
                    | DNSRData::PTR(name) => {
                        // Flags like truncated not logged here as it would break the schema.
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_string_from_bytes(&name.value)?;
                        }
                    }
                    DNSRData::TXT(txt_strings) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            for txt in txt_strings {
                                a.append_string_from_bytes(txt)?;
                            }
                        }
                    }
                    DNSRData::NULL(bytes) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_string_from_bytes(bytes)?;
                        }
                    }
                    DNSRData::SOA(soa) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_object(&dns_log_soa(soa)?)?;
                        }
                    }
                    DNSRData::SSHFP(sshfp) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_object(&dns_log_sshfp(sshfp)?)?;
                        }
                    }
                    DNSRData::SRV(srv) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_object(&dns_log_srv(srv)?)?;
                        }
                    }
                    _ => {}
                }
            }

            if flags & LOG_FORMAT_DETAILED != 0 {
                match &answer.data {
                    DNSRData::TXT(asdf) => {
                        for i in 0..asdf.len() {
                            js_answers.append_object(&dns_log_json_answer_detail(answer, i)?)?;
                        }
                    }
                    _ => {
                        js_answers.append_object(&dns_log_json_answer_detail(answer, 0)?)?;
                    }
                }
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
            match &auth.data {
                DNSRData::TXT(txt) => {
                    for i in 0..txt.len() {
                        let auth_detail = dns_log_json_answer_detail(auth, i)?;
                        js.append_object(&auth_detail)?;
                    }
                }
                _ => {
                    let auth_detail = dns_log_json_answer_detail(auth, 0)?;
                    js.append_object(&auth_detail)?;
                }
            }
        }
        js.close()?;
    }

    if !response.additionals.is_empty() {
        let mut is_js_open = false;
        for add in &response.additionals {
            if let DNSRData::OPT(rdata) = &add.data {
                if rdata.is_empty() {
                    continue;
                }
            }
            if !is_js_open {
                js.open_array("additionals")?;
                is_js_open = true;
            }
            match &add.data {
                DNSRData::TXT(txt) => {
                    for i in 0..txt.len() {
                        let add_detail = dns_log_json_answer_detail(add, i)?;
                        js.append_object(&add_detail)?;
                    }
                }
                _ => {
                    let add_detail = dns_log_json_answer_detail(add, 0)?;
                    js.append_object(&add_detail)?;
                }
            }
        }
        if is_js_open {
            js.close()?;
        }
    }

    Ok(())
}

/// V3 style answer logging.
fn dns_log_json_answers(
    jb: &mut JsonBuilder, response: &DNSMessage, flags: u64,
) -> Result<(), JsonError> {
    if !response.answers.is_empty() {
        let mut js_answers = JsonBuilder::try_new_array()?;

        // For grouped answers we use a HashMap keyed by the rrtype.
        let mut answer_types = HashMap::new();

        for answer in &response.answers {
            if flags & LOG_FORMAT_GROUPED != 0 {
                let type_string = dns_rrtype_string(answer.rrtype);
                match &answer.data {
                    DNSRData::A(addr) | DNSRData::AAAA(addr) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_string(&dns_print_addr(addr))?;
                        }
                    }
                    DNSRData::CNAME(name)
                    | DNSRData::MX(name)
                    | DNSRData::NS(name)
                    | DNSRData::PTR(name) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_string_from_bytes(&name.value)?;
                        }
                    }
                    DNSRData::TXT(txt) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            for txt in txt {
                                a.append_string_from_bytes(txt)?;
                            }
                        }
                    }
                    DNSRData::NULL(bytes) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_string_from_bytes(bytes)?;
                        }
                    }
                    DNSRData::SOA(soa) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_object(&dns_log_soa(soa)?)?;
                        }
                    }
                    DNSRData::SSHFP(sshfp) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_object(&dns_log_sshfp(sshfp)?)?;
                        }
                    }
                    DNSRData::SRV(srv) => {
                        if !answer_types.contains_key(&type_string) {
                            answer_types
                                .insert(type_string.to_string(), JsonBuilder::try_new_array()?);
                        }
                        if let Some(a) = answer_types.get_mut(&type_string) {
                            a.append_object(&dns_log_srv(srv)?)?;
                        }
                    }
                    _ => {}
                }
            }

            if flags & LOG_FORMAT_DETAILED != 0 {
                match &answer.data {
                    DNSRData::TXT(txt) => {
                        for i in 0..txt.len() {
                            js_answers.append_object(&dns_log_json_answer_detail(answer, i)?)?;
                        }
                    }
                    _ => {
                        js_answers.append_object(&dns_log_json_answer_detail(answer, 0)?)?;
                    }
                }
            }
        }

        js_answers.close()?;

        if flags & LOG_FORMAT_DETAILED != 0 {
            jb.set_object("answers", &js_answers)?;
        }

        if flags & LOG_FORMAT_GROUPED != 0 {
            jb.open_object("grouped")?;
            for (k, mut v) in answer_types.drain() {
                v.close()?;
                jb.set_object(&k, &v)?;
            }
            jb.close()?;
        }
    }
    Ok(())
}

fn dns_log_query(
    tx: &DNSTransaction, i: u16, flags: u64, jb: &mut JsonBuilder,
) -> Result<bool, JsonError> {
    let index = i as usize;
    if let Some(request) = &tx.request {
        if index < request.queries.len() {
            let query = &request.queries[index];
            if dns_log_rrtype_enabled(query.rrtype, flags) {
                jb.set_string("type", "query")?;
                jb.set_uint("id", request.header.tx_id as u64)?;
                jb.set_string_from_bytes("rrname", &query.name.value)?;
                if query.name.flags.contains(DNSNameFlags::TRUNCATED) {
                    jb.set_bool("rrname_truncated", true)?;
                }
                jb.set_string("rrtype", &dns_rrtype_string(query.rrtype))?;
                jb.set_uint("tx_id", tx.id - 1)?;
                if request.header.flags & 0x0040 != 0 {
                    jb.set_bool("z", true)?;
                }
                let opcode = ((request.header.flags >> 11) & 0xf) as u8;
                jb.set_uint("opcode", opcode as u64)?;
                return Ok(true);
            }
        }
    }

    return Ok(false);
}

#[no_mangle]
pub extern "C" fn SCDnsLogJsonQuery(
    tx: &DNSTransaction, i: u16, flags: u64, jb: &mut JsonBuilder,
) -> bool {
    match dns_log_query(tx, i, flags, jb) {
        Ok(false) | Err(_) => {
            return false;
        }
        Ok(true) => {
            return true;
        }
    }
}

/// Common logger for DNS requests and responses.
///
/// It is expected that the JsonBuilder is an open object that the DNS
/// transaction will be logged into. This function will not create the
/// "dns" object.
///
/// This logger implements V3 style DNS logging.
fn log_json(tx: &DNSTransaction, flags: u64, jb: &mut JsonBuilder) -> Result<(), JsonError> {
    jb.open_object("dns")?;
    jb.set_int("version", 3)?;

    let message = if let Some(request) = &tx.request {
        jb.set_string("type", "request")?;
        request
    } else if let Some(response) = &tx.response {
        jb.set_string("type", "response")?;
        response
    } else {
        debug_validate_fail!("unreachable");
        return Ok(());
    };

    // The internal Suricata transaction ID.
    jb.set_uint("tx_id", tx.id - 1)?;

    // The on the wire DNS transaction ID.
    jb.set_uint("id", tx.tx_id() as u64)?;

    // Log header fields. Should this be a sub-object?
    let header = &message.header;
    jb.set_string("flags", format!("{:x}", header.flags).as_str())?;
    if header.flags & 0x8000 != 0 {
        jb.set_bool("qr", true)?;
    }
    if header.flags & 0x0400 != 0 {
        jb.set_bool("aa", true)?;
    }
    if header.flags & 0x0200 != 0 {
        jb.set_bool("tc", true)?;
    }
    if header.flags & 0x0100 != 0 {
        jb.set_bool("rd", true)?;
    }
    if header.flags & 0x0080 != 0 {
        jb.set_bool("ra", true)?;
    }
    if header.flags & 0x0040 != 0 {
        jb.set_bool("z", true)?;
    }
    let opcode = ((header.flags >> 11) & 0xf) as u8;
    jb.set_uint("opcode", opcode as u64)?;
    jb.set_string("rcode", &dns_rcode_string(header.flags))?;

    if !message.queries.is_empty() {
        jb.open_array("queries")?;
        for query in &message.queries {
            if dns_log_rrtype_enabled(query.rrtype, flags) {
                jb.start_object()?
                    .set_string_from_bytes("rrname", &query.name.value)?
                    .set_string("rrtype", &dns_rrtype_string(query.rrtype))?;
                if query.name.flags.contains(DNSNameFlags::TRUNCATED) {
                    jb.set_bool("rrname_truncated", true)?;
                }
                jb.close()?;
            }
        }
        jb.close()?;
    }

    if !message.answers.is_empty() {
        dns_log_json_answers(jb, message, flags)?;
    }

    if !message.authorities.is_empty() {
        jb.open_array("authorities")?;
        for auth in &message.authorities {
            match &auth.data {
                DNSRData::TXT(txt) => {
                    for i in 0..txt.len() {
                        let auth_detail = dns_log_json_answer_detail(auth, i)?;
                        jb.append_object(&auth_detail)?;
                    }
                }
                _ => {
                    let auth_detail = dns_log_json_answer_detail(auth, 0)?;
                    jb.append_object(&auth_detail)?;
                }
            }
        }
        jb.close()?;
    }

    if !message.additionals.is_empty() {
        let mut is_jb_open = false;
        for add in &message.additionals {
            if let DNSRData::OPT(rdata) = &add.data {
                if rdata.is_empty() {
                    continue;
                }
            }
            if !is_jb_open {
                jb.open_array("additionals")?;
                is_jb_open = true;
            }
            match &add.data {
                DNSRData::TXT(txt) => {
                    for i in 0..txt.len() {
                        let add_detail = dns_log_json_answer_detail(add, i)?;
                        jb.append_object(&add_detail)?;
                    }
                }
                _ => {
                    let add_detail = dns_log_json_answer_detail(add, 0)?;
                    jb.append_object(&add_detail)?;
                }
            }
        }
        if is_jb_open {
            jb.close()?;
        }
    }

    jb.close()?;
    Ok(())
}

/// FFI wrapper around the common V3 style DNS logger.
#[no_mangle]
pub extern "C" fn SCDnsLogJson(tx: &DNSTransaction, flags: u64, jb: &mut JsonBuilder) -> bool {
    log_json(tx, flags, jb).is_ok()
}

/// Check if a DNS transaction should be logged based on the
/// configured flags.
#[no_mangle]
pub extern "C" fn SCDnsLogEnabled(tx: &DNSTransaction, flags: u64) -> bool {
    let message = if let Some(request) = &tx.request {
        request
    } else if let Some(response) = &tx.response {
        response
    } else {
        // Should be unreachable...
        return false;
    };

    for query in &message.queries {
        if dns_log_rrtype_enabled(query.rrtype, flags) {
            return true;
        }
    }
    return false;
}

/// Note: For v2 style logging.
#[no_mangle]
pub extern "C" fn SCDnsLogJsonAnswer(
    tx: &DNSTransaction, flags: u64, js: &mut JsonBuilder,
) -> bool {
    if let Some(response) = &tx.response {
        for query in &response.queries {
            if dns_log_rrtype_enabled(query.rrtype, flags) {
                return dns_log_json_answer(js, response, flags).is_ok();
            }
        }
    }
    return false;
}

/// Note: For v2 style logging.
#[no_mangle]
pub extern "C" fn SCDnsLogAnswerEnabled(tx: &DNSTransaction, flags: u64) -> bool {
    if let Some(response) = &tx.response {
        for query in &response.queries {
            if dns_log_rrtype_enabled(query.rrtype, flags) {
                return true;
            }
        }
    }
    return false;
}
