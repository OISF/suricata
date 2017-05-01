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
extern crate nom;

use std;
use std::mem::transmute;

use log::*;
use core;
use dns::parser;

/// DNS record types.
pub const DNS_RTYPE_A:     u16 = 1;
pub const DNS_RTYPE_CNAME: u16 = 5;
pub const DNS_RTYPE_SOA:   u16 = 6;
pub const DNS_RTYPE_PTR:   u16 = 12;
pub const DNS_RTYPE_MX:    u16 = 15;
pub const DNS_RTYPE_SSHFP: u16 = 44;
pub const DNS_RTYPE_RRSIG: u16 = 46;

/// DNS error codes.
pub const DNS_RCODE_NOERROR:  u16 = 0;
pub const DNS_RCODE_FORMERR:  u16 = 1;
pub const DNS_RCODE_NXDOMAIN: u16 = 3;

#[repr(u32)]
pub enum DNSEvent {
    UnsolicitedResponse = 1,
    MalformedData,
    NotRequest,
    NotResponse,
    ZFlagSet,
    Flooded,
    StateMemCapReached,
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
pub struct DNSQueryEntry {
    pub name: Vec<u8>,
    pub rrtype: u16,
    pub rrclass: u16,
}

impl DNSQueryEntry {

    pub fn name(&self) -> &str {
        let r = std::str::from_utf8(&self.name);
        if r.is_err() {
            return "";
        }
        return r.unwrap();
    }

}

#[derive(Debug,PartialEq)]
pub struct DNSAnswerEntry {
    pub name: Vec<u8>,
    pub rrtype: u16,
    pub rrclass: u16,
    pub ttl: u32,
    pub data_len: u16,
    pub data: Vec<u8>,
}

impl DNSAnswerEntry {

    pub fn name(&self) -> &str {
        let r = std::str::from_utf8(&self.name);
        if r.is_err() {
            return "";
        }
        return r.unwrap();
    }

    pub fn data_to_string(&self) -> &str {
        let r = std::str::from_utf8(&self.data);
        if r.is_err() {
            return "";
        }
        return r.unwrap();
    }

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
pub struct DNSTransaction {
    pub id: u64,
    pub request: Option<DNSRequest>,
    pub response: Option<DNSResponse>,
    pub logged: u32,
    pub de_state: Option<*mut core::DetectEngineState>,
    pub events: *mut core::AppLayerDecoderEvents,
    pub purge: bool,
}

impl DNSTransaction {

    pub fn new() -> DNSTransaction {
        return DNSTransaction{
            id: 0,
            request: None,
            response: None,
            logged: 0,
            de_state: None,
            events: std::ptr::null_mut(),
            purge: false,
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
    }

    /// Get the DNS transactions ID (not the internal tracking ID).
    pub fn tx_id(&self) -> u16 {
        for request in &self.request {
            return request.header.tx_id;
        }
        for response in &self.response {
            return response.header.tx_id;
        }

        // Shouldn't happen.
        return 0;
    }

    /// Get the reply code of the transaction. Note that this will
    /// also return 0 if there is no reply.
    pub fn rcode(&self) -> u16 {
        for response in &self.response {
            return response.header.flags & 0x000f;
        }
        return 0;
    }

}

impl Drop for DNSTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct DNSState {
    // Internal transaction ID.
    pub tx_id: u64,

    // Transactions.
    pub transactions: Vec<Box<DNSTransaction>>,

    pub de_state_count: u64,

    pub events: u16,
}

impl DNSState {

    pub fn new() -> DNSState {
        return DNSState{
            tx_id: 1,
            transactions: Vec::new(),
            de_state_count: 0,
            events: 0,
        };
    }

    pub fn free(&mut self) {
        while self.transactions.len() > 0 {
            self.free_tx_at_index(0);
        }
        assert!(self.transactions.len() == 0);
    }

    pub fn new_tx(&mut self) -> DNSTransaction {
        let mut tx = DNSTransaction::new();
        tx.id = self.tx_id;
        self.tx_id += 1;
        return tx;
    }

    pub fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.free_tx_at_index(index);
        }
    }

    fn free_tx_at_index(&mut self, index: usize) {
        let tx = self.transactions.remove(index);
        match tx.de_state {
            Some(state) => {
                core::sc_detect_engine_state_free(state);
                self.de_state_count -= 1;
            }
            _ => {}
        }
    }

    // Purges all transactions except one. This is a stateless parser
    // so we don't need to hang onto old transactions.
    //
    // This is to actually handle an edge case where a DNS flood
    // occurs in a single direction with no response packets. In such
    // a case the functions to free a transaction are never called by
    // the app-layer as they require bidirectional traffic.
    pub fn purge(&mut self, tx_id: u64) {
        while self.transactions.len() > 1 {
            if self.transactions[0].id == tx_id + 1 {
                return;
            }
            self.free_tx_at_index(0);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&DNSTransaction> {
        self.purge(tx_id);
        for tx in &mut self.transactions {
            if tx.id == tx_id + 1 {
                return Some(tx);
            }
            tx.purge = true;
        }
        return None;
    }

    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: DNSEvent) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }

        let mut tx = &mut self.transactions[len - 1];
        core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events,
                                                        event as u8);
        self.events += 1;
    }
    
    pub fn parse_request(&mut self, input: &[u8]) -> bool {
        match parser::dns_parse_request(input) {
            nom::IResult::Done(_, request) => {
                if request.header.flags & 0x8000 != 0 {
                    SCLogDebug!("DNS message is not a request");
                    self.set_event(DNSEvent::NotRequest);
                    return false;
                }
                
                if request.header.flags & 0x0040 != 0 {
                    SCLogDebug!("Z-flag set on DNS response");
                    self.set_event(DNSEvent::ZFlagSet);
                    return false;
                }
                
                let mut tx = self.new_tx();
                tx.request = Some(request);
                self.transactions.push(Box::new(tx));
                return true;
            }
            nom::IResult::Incomplete(_) => {
                // Insufficient data.
                SCLogDebug!("Insufficient data while parsing DNS request");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
            nom::IResult::Error(_) => {
                // Error, probably malformed data.
                SCLogDebug!("An error occurred while parsing DNS request");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
        }
    }

    pub fn parse_response(&mut self, input: &[u8]) -> bool {
        match parser::dns_parse_response(input) {
            nom::IResult::Done(_, response) => {
                if response.header.flags & 0x8000 == 0 {
                    SCLogDebug!("DNS message is not a response");
                    self.set_event(DNSEvent::NotResponse);
                }

                if response.header.flags & 0x0040 != 0 {
                    SCLogDebug!("Z-flag set on DNS response");
                    self.set_event(DNSEvent::ZFlagSet);
                }

                let mut tx = self.new_tx();
                tx.response = Some(response);
                self.transactions.push(Box::new(tx));
                return true;
            }
            nom::IResult::Incomplete(_) => {
                // Insufficient data.
                SCLogDebug!("Insufficient data while parsing DNS response");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
            nom::IResult::Error(_) => {
                // Error, probably malformed data.
                SCLogDebug!("An error occurred while parsing DNS response");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
        }
    }
}

/// Implement Drop for DNSState as transactions need to do some
/// explicit cleanup.
impl Drop for DNSState {
    fn drop(&mut self) {
        self.free();
    }
}

/// Returns *mut DNSState
#[no_mangle]
pub extern "C" fn rs_dns_state_new() -> *mut libc::c_void {
    let state = DNSState::new();
    let boxed = Box::new(state);
    return unsafe{transmute(boxed)};
}

/// Params:
/// - state: *mut DNSState as void pointer
#[no_mangle]
pub extern "C" fn rs_dns_state_free(state: *mut libc::c_void) {
    // Just unbox...
    let _drop: Box<DNSState> = unsafe{transmute(state)};
}

#[no_mangle]
pub extern "C" fn rs_dns_state_tx_free(state: &mut DNSState,
                                       tx_id: libc::uint64_t)
{
    state.free_tx(tx_id);
}

/// C binding parse a DNS request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rs_dns_parse_request(_flow: *mut core::Flow,
                                       state: &mut DNSState,
                                       _pstate: *mut libc::c_void,
                                       input: *mut libc::uint8_t,
                                       input_len: libc::uint32_t,
                                       _data: *mut libc::c_void)
                                       -> libc::int8_t {
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    if state.parse_request(buf) {
        1
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_parse_response(_flow: *mut core::Flow,
                                        state: &mut DNSState,
                                        _pstate: *mut libc::c_void,
                                        input: *mut libc::uint8_t,
                                        input_len: libc::uint32_t,
                                        _data: *mut libc::c_void)
                                        -> libc::int8_t {
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    if state.parse_response(buf) {
        1
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_get_alstate_progress(_tx: &mut DNSTransaction,
                                                 _direction: libc::uint8_t)
                                                 -> libc::uint8_t
{
    // This is a stateless parser, just the existence of a transaction
    // means its complete.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_set_logged(_state: &mut DNSState,
                                       tx: &mut DNSTransaction,
                                       logger: libc::uint32_t)
{
    tx.logged |= logger;
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_get_logged(_state: &mut DNSState,
                                       tx: &mut DNSTransaction,
                                       logger: libc::uint32_t)
                                       -> i8
{
    if tx.logged & logger != 0 {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_state_get_tx_count(state: &mut DNSState)
                                            -> libc::uint64_t
{
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_dns_state_get_tx(state: &mut DNSState,
                                      tx_id: libc::uint64_t)
                                      -> *mut DNSTransaction
{
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe{transmute(tx)};
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_state_has_detect_state(state: &mut DNSState) -> u8
{
    if state.de_state_count > 0 {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_state_set_tx_detect_state(
    state: &mut DNSState,
    tx: &mut DNSTransaction,
    de_state: &mut core::DetectEngineState)
{
    state.de_state_count += 1;
    tx.de_state = Some(de_state);
}

#[no_mangle]
pub extern "C" fn rs_dns_state_get_tx_detect_state(
    tx: &mut DNSTransaction)
    -> *mut core::DetectEngineState
{
    match tx.de_state {
        Some(ds) => {
            return ds;
        },
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_state_has_events(state: &mut DNSState) -> u8 {
    if state.events > 0 {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_state_get_events(state: &mut DNSState,
                                          tx_id: libc::uint64_t)
                                          -> *mut core::AppLayerDecoderEvents
{
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx.events;
        }
        _ => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_get_query_name(tx: &mut DNSTransaction,
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

/// Get the DNS transaction ID of a transaction.
//
/// extern uint16_t rs_dns_tx_get_tx_id(RSDNSTransaction *);
#[no_mangle]
pub extern "C" fn rs_dns_tx_get_tx_id(tx: &mut DNSTransaction) -> libc::uint16_t
{
    return tx.tx_id()
}

/// Get the DNS response flags for a transaction.
///
/// extern uint16_t rs_dns_tx_get_response_flags(RSDNSTransaction *);
#[no_mangle]
pub extern "C" fn rs_dns_tx_get_response_flags(tx: &mut DNSTransaction)
                                           -> libc::uint16_t
{
    return tx.rcode();
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_get_query_rrtype(tx: &mut DNSTransaction,
                                         i: libc::uint16_t,
                                         rrtype: *mut libc::uint16_t)
                                         -> libc::uint8_t
{
    for request in &tx.request {
        if (i as usize) < request.queries.len() {
            let query = &request.queries[i as usize];
            if query.name.len() > 0 {
                unsafe {
                    *rrtype = query.rrtype;
                }
                return 1;
            }
        }
    }
    return 0;
}
