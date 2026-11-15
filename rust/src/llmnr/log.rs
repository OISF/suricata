/* Copyright (C) 2026 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

use crate::dns::dns::*;
use crate::dns::log::{
    dns_answer_cost_all, dns_log_opt, dns_log_soa, dns_log_srv, dns_log_sshfp, dns_print_addr,
    dns_rrtype_string, DnsLogBudget, DNS_LOG_MAX_ADDITIONALS, DNS_LOG_MAX_ANSWERS,
    DNS_LOG_MAX_AUTHORITIES, DNS_LOG_MAX_QUERIES,
};
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn llmnr_log_json_answer_detail(answer: &DNSAnswerEntry) -> Result<JsonBuilder, JsonError> {
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
    let mut budget = DnsLogBudget::new();
    jb.open_object("llmnr")?;

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

    // The on the wire LLMNR transaction ID.
    jb.set_uint("id", tx.tx_id() as u64)?;

    let header = &message.header;
    if header.flags & (0x0400 | 0x0200 | 0x0100) != 0 {
        jb.open_array("flags")?;
        if header.flags & 0x0400 != 0 {
            jb.append_string("c")?;
        }
        if header.flags & 0x0200 != 0 {
            jb.append_string("tc")?;
        }
        if header.flags & 0x0100 != 0 {
            jb.append_string("t")?;
        }
        jb.close()?;
    }

    let opcode = ((header.flags >> 11) & 0xf) as u8;
    jb.set_uint("opcode", opcode as u64)?;

    let mut queries_truncated = false;
    if !message.queries.is_empty() {
        jb.open_array("queries")?;
        let mut logged = 0usize;
        for query in &message.queries {
            if logged >= DNS_LOG_MAX_QUERIES || !budget.consume(query.name.value.len() + 32) {
                queries_truncated = true;
                break;
            }
            logged += 1;
            jb.start_object()?
                .set_string_from_bytes("rrname", &query.name.value)?
                .set_string("rrtype", &dns_rrtype_string(query.rrtype).to_lowercase())?;
            if query.name.flags.contains(DNSNameFlags::TRUNCATED) {
                jb.set_bool("rrname_truncated", true)?;
            }
            jb.close()?;
        }
        jb.close()?;
        if queries_truncated {
            jb.set_bool("queries_truncated", true)?;
            budget.truncated = true;
        }
    }

    let mut answers_truncated = false;
    if !message.answers.is_empty() {
        jb.open_array("answers")?;
        let mut logged = 0usize;
        for entry in &message.answers {
            if logged >= DNS_LOG_MAX_ANSWERS || !budget.consume(dns_answer_cost_all(entry)) {
                answers_truncated = true;
                break;
            }
            logged += 1;
            jb.append_object(&llmnr_log_json_answer_detail(entry)?)?;
        }
        jb.close()?;
        if answers_truncated {
            jb.set_bool("answers_truncated", true)?;
            budget.truncated = true;
        }
    }

    let mut authorities_truncated = false;
    if !message.authorities.is_empty() {
        jb.open_array("authorities")?;
        let mut logged = 0usize;
        for entry in &message.authorities {
            if logged >= DNS_LOG_MAX_AUTHORITIES || !budget.consume(dns_answer_cost_all(entry)) {
                authorities_truncated = true;
                break;
            }
            logged += 1;
            jb.append_object(&llmnr_log_json_answer_detail(entry)?)?;
        }
        jb.close()?;
        if authorities_truncated {
            jb.set_bool("authorities_truncated", true)?;
            budget.truncated = true;
        }
    }

    let mut additionals_truncated = false;
    if !message.additionals.is_empty() {
        let mut is_jb_open = false;
        let mut logged = 0usize;
        for entry in &message.additionals {
            if let DNSRData::OPT(rdata) = &entry.data {
                if rdata.is_empty() {
                    continue;
                }
            }
            if logged >= DNS_LOG_MAX_ADDITIONALS || !budget.consume(dns_answer_cost_all(entry)) {
                additionals_truncated = true;
                break;
            }
            logged += 1;
            if !is_jb_open {
                jb.open_array("additionals")?;
                is_jb_open = true;
            }
            jb.append_object(&llmnr_log_json_answer_detail(entry)?)?;
        }
        if is_jb_open {
            jb.close()?;
        }
        if additionals_truncated {
            jb.set_bool("additionals_truncated", true)?;
            budget.truncated = true;
        }
    }

    if budget.truncated {
        jb.set_bool("truncated", true)?;
    }

    jb.close()?;
    Ok(())
}

#[no_mangle]
pub extern "C" fn SCLLMNRLogJson(tx: &mut DNSTransaction, jb: &mut JsonBuilder) -> bool {
    log_json(tx, jb).is_ok()
}
