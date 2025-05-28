/* Copyright (C) 2025 Open Information Security Foundation
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

use crate::dns::dns::*;
use crate::dns::log::{
    dns_log_opt, dns_log_soa, dns_log_srv, dns_log_sshfp, dns_print_addr, dns_rrtype_string,
};
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn mdns_log_json_answer_detail(answer: &DNSAnswerEntry) -> Result<JsonBuilder, JsonError> {
    let mut jsa = JsonBuilder::try_new_object()?;

    jsa.set_string_from_bytes("rrname", &answer.name.value)?;
    if answer.name.flags.contains(DNSNameFlags::TRUNCATED) {
        jsa.set_bool("rrname_truncated", true)?;
    }
    let rrtype = dns_rrtype_string(answer.rrtype).to_lowercase();

    match &answer.data {
        DNSRData::A(addr) | DNSRData::AAAA(addr) => {
            jsa.set_string(&rrtype, &dns_print_addr(addr))?;
        }
        DNSRData::CNAME(name) | DNSRData::MX(name) | DNSRData::NS(name) | DNSRData::PTR(name) => {
            jsa.set_string_from_bytes(&rrtype, &name.value)?;
            if name.flags.contains(DNSNameFlags::TRUNCATED) {
                jsa.set_bool("rdata_truncated", true)?;
            }
        }
        DNSRData::TXT(txt) => {
            jsa.open_array(&rrtype)?;
            for txt in txt {
                jsa.append_string_from_bytes(txt)?;
            }
            jsa.close()?;
        }
        DNSRData::NULL(bytes) | DNSRData::Unknown(bytes) => {
            jsa.set_string_from_bytes(&rrtype, bytes)?;
        }
        DNSRData::SOA(soa) => {
            jsa.set_object(&rrtype, &dns_log_soa(soa)?)?;
        }
        DNSRData::SSHFP(sshfp) => {
            jsa.set_object(&rrtype, &dns_log_sshfp(sshfp)?)?;
        }
        DNSRData::SRV(srv) => {
            jsa.set_object(&rrtype, &dns_log_srv(srv)?)?;
        }
        DNSRData::OPT(opt) => {
            jsa.open_array(&rrtype)?;
            for val in opt {
                jsa.append_object(&dns_log_opt(val)?)?;
            }
            jsa.close()?;
        }
    }

    jsa.close()?;
    return Ok(jsa);
}

fn log_json(tx: &DNSTransaction, jb: &mut JsonBuilder) -> Result<(), JsonError> {
    jb.open_object("mdns")?;

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

    // The on the wire mDNS transaction ID.
    jb.set_uint("id", tx.tx_id() as u64)?;

    let header = &message.header;
    if header.flags & (0x0400 | 0x0200 | 0x0100 | 0x0080 | 0x0040 | 0x0020 | 0x0010) != 0 {
        jb.open_array("flags")?;
        if header.flags & 0x0400 != 0 {
            jb.append_string("aa")?;
        }
        if header.flags & 0x0200 != 0 {
            jb.append_string("tc")?;
        }
        if header.flags & 0x0100 != 0 {
            jb.append_string("rd")?;
        }
        if header.flags & 0x0080 != 0 {
            jb.append_string("ra")?;
        }
        if header.flags & 0x0040 != 0 {
            jb.append_string("z")?;
        }
        if header.flags & 0x0020 != 0 {
            jb.append_string("ad")?;
        }
        if header.flags & 0x0010 != 0 {
            jb.append_string("cd")?;
        }
        jb.close()?;
    }

    let opcode = ((header.flags >> 11) & 0xf) as u8;
    jb.set_uint("opcode", opcode as u64)?;
    jb.set_uint("rcode", header.flags & 0x000f)?;

    if !message.queries.is_empty() {
        jb.open_array("queries")?;
        for query in &message.queries {
            jb.start_object()?
                .set_string_from_bytes("rrname", &query.name.value)?
                .set_string("rrtype", &dns_rrtype_string(query.rrtype).to_lowercase())?;
            if query.name.flags.contains(DNSNameFlags::TRUNCATED) {
                jb.set_bool("rrname_truncated", true)?;
            }
            jb.close()?;
        }
        jb.close()?;
    }

    if !message.answers.is_empty() {
        jb.open_array("answers")?;
        for entry in &message.answers {
            jb.append_object(&mdns_log_json_answer_detail(entry)?)?;
        }
        jb.close()?;
    }

    if !message.authorities.is_empty() {
        jb.open_array("authorities")?;
        for entry in &message.authorities {
            jb.append_object(&mdns_log_json_answer_detail(entry)?)?;
        }
        jb.close()?;
    }

    if !message.additionals.is_empty() {
        let mut is_jb_open = false;
        for entry in &message.additionals {
            if let DNSRData::OPT(rdata) = &entry.data {
                if rdata.is_empty() {
                    continue;
                }
            }
            if !is_jb_open {
                jb.open_array("additionals")?;
                is_jb_open = true;
            }
            jb.append_object(&mdns_log_json_answer_detail(entry)?)?;
        }
        if is_jb_open {
            jb.close()?;
        }
    }

    jb.close()?;
    Ok(())
}

/// FFI wrapper around the common V3 style mDNS logger.
#[no_mangle]
pub extern "C" fn SCMdnsLogJson(tx: &DNSTransaction, jb: &mut JsonBuilder) -> bool {
    log_json(tx, jb).is_ok()
}
