/* Copyright (C) 2017-2022 Open Information Security Foundation
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
use std::ffi::CString;
use std::collections::HashMap;
use std::collections::VecDeque;

use crate::applayer::*;
use crate::core::{self, *};
use crate::dns::parser;
use crate::frames::Frame;

use nom7::{Err, IResult};
use nom7::number::streaming::be_u16;

/// DNS record types.
pub const DNS_RECORD_TYPE_A           : u16 = 1;
pub const DNS_RECORD_TYPE_NS          : u16 = 2;
pub const DNS_RECORD_TYPE_MD          : u16 = 3;   // Obsolete
pub const DNS_RECORD_TYPE_MF          : u16 = 4;   // Obsolete
pub const DNS_RECORD_TYPE_CNAME       : u16 = 5;
pub const DNS_RECORD_TYPE_SOA         : u16 = 6;
pub const DNS_RECORD_TYPE_MB          : u16 = 7;   // Experimental
pub const DNS_RECORD_TYPE_MG          : u16 = 8;   // Experimental
pub const DNS_RECORD_TYPE_MR          : u16 = 9;   // Experimental
pub const DNS_RECORD_TYPE_NULL        : u16 = 10;  // Experimental
pub const DNS_RECORD_TYPE_WKS         : u16 = 11;
pub const DNS_RECORD_TYPE_PTR         : u16 = 12;
pub const DNS_RECORD_TYPE_HINFO       : u16 = 13;
pub const DNS_RECORD_TYPE_MINFO       : u16 = 14;
pub const DNS_RECORD_TYPE_MX          : u16 = 15;
pub const DNS_RECORD_TYPE_TXT         : u16 = 16;
pub const DNS_RECORD_TYPE_RP          : u16 = 17;
pub const DNS_RECORD_TYPE_AFSDB       : u16 = 18;
pub const DNS_RECORD_TYPE_X25         : u16 = 19;
pub const DNS_RECORD_TYPE_ISDN        : u16 = 20;
pub const DNS_RECORD_TYPE_RT          : u16 = 21;
pub const DNS_RECORD_TYPE_NSAP        : u16 = 22;
pub const DNS_RECORD_TYPE_NSAPPTR     : u16 = 23;
pub const DNS_RECORD_TYPE_SIG         : u16 = 24;
pub const DNS_RECORD_TYPE_KEY         : u16 = 25;
pub const DNS_RECORD_TYPE_PX          : u16 = 26;
pub const DNS_RECORD_TYPE_GPOS        : u16 = 27;
pub const DNS_RECORD_TYPE_AAAA        : u16 = 28;
pub const DNS_RECORD_TYPE_LOC         : u16 = 29;
pub const DNS_RECORD_TYPE_NXT         : u16 = 30;  // Obsolete
pub const DNS_RECORD_TYPE_SRV         : u16 = 33;
pub const DNS_RECORD_TYPE_ATMA        : u16 = 34;
pub const DNS_RECORD_TYPE_NAPTR       : u16 = 35;
pub const DNS_RECORD_TYPE_KX          : u16 = 36;
pub const DNS_RECORD_TYPE_CERT        : u16 = 37;
pub const DNS_RECORD_TYPE_A6          : u16 = 38;  // Obsolete
pub const DNS_RECORD_TYPE_DNAME       : u16 = 39;
pub const DNS_RECORD_TYPE_OPT         : u16 = 41;
pub const DNS_RECORD_TYPE_APL         : u16 = 42;
pub const DNS_RECORD_TYPE_DS          : u16 = 43;
pub const DNS_RECORD_TYPE_SSHFP       : u16 = 44;
pub const DNS_RECORD_TYPE_IPSECKEY    : u16 = 45;
pub const DNS_RECORD_TYPE_RRSIG       : u16 = 46;
pub const DNS_RECORD_TYPE_NSEC        : u16 = 47;
pub const DNS_RECORD_TYPE_DNSKEY      : u16 = 48;
pub const DNS_RECORD_TYPE_DHCID       : u16 = 49;
pub const DNS_RECORD_TYPE_NSEC3       : u16 = 50;
pub const DNS_RECORD_TYPE_NSEC3PARAM  : u16 = 51;
pub const DNS_RECORD_TYPE_TLSA        : u16 = 52;
pub const DNS_RECORD_TYPE_HIP         : u16 = 55;
pub const DNS_RECORD_TYPE_CDS         : u16 = 59;
pub const DNS_RECORD_TYPE_CDNSKEY     : u16 = 60;
pub const DNS_RECORD_TYPE_SPF         : u16 = 99;  // Obsolete
pub const DNS_RECORD_TYPE_TKEY        : u16 = 249;
pub const DNS_RECORD_TYPE_TSIG        : u16 = 250;
pub const DNS_RECORD_TYPE_MAILA       : u16 = 254; // Obsolete
pub const DNS_RECORD_TYPE_ANY         : u16 = 255;
pub const DNS_RECORD_TYPE_URI         : u16 = 256;

/// DNS error codes.
pub const DNS_RCODE_NOERROR:  u16 = 0;
pub const DNS_RCODE_FORMERR:  u16 = 1;
pub const DNS_RCODE_SERVFAIL: u16 = 2;
pub const DNS_RCODE_NXDOMAIN: u16 = 3;
pub const DNS_RCODE_NOTIMP:   u16 = 4;
pub const DNS_RCODE_REFUSED:  u16 = 5;
pub const DNS_RCODE_YXDOMAIN: u16 = 6;
pub const DNS_RCODE_YXRRSET:  u16 = 7;
pub const DNS_RCODE_NXRRSET:  u16 = 8;
pub const DNS_RCODE_NOTAUTH:  u16 = 9;
pub const DNS_RCODE_NOTZONE:  u16 = 10;
// Support for OPT RR from RFC6891 will be needed to
// parse RCODE values over 15
pub const DNS_RCODE_BADVERS:  u16 = 16;
pub const DNS_RCODE_BADSIG:   u16 = 16;
pub const DNS_RCODE_BADKEY:   u16 = 17;
pub const DNS_RCODE_BADTIME:  u16 = 18;
pub const DNS_RCODE_BADMODE:  u16 = 19;
pub const DNS_RCODE_BADNAME:  u16 = 20;
pub const DNS_RCODE_BADALG:   u16 = 21;
pub const DNS_RCODE_BADTRUNC: u16 = 22;


static mut ALPROTO_DNS: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerFrameType)]
pub enum DnsFrameType {
    /// DNS PDU frame. For UDP DNS this is the complete UDP payload, for TCP
    /// this is the DNS payload not including the leading length field allowing
    /// this frame to be used for UDP and TCP DNS.
    Pdu,
}


#[derive(Debug, PartialEq, AppLayerEvent)]
pub enum DNSEvent {
    MalformedData,
    NotRequest,
    NotResponse,
    ZFlagSet,
}

#[derive(Debug,PartialEq)]
#[repr(C)]
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

#[derive(Debug,PartialEq)]
pub struct DNSRDataSOA {
    /// Primary name server for this zone
    pub mname: Vec<u8>,
    /// Authority's mailbox
    pub rname: Vec<u8>,
    /// Serial version number
    pub serial: u32,
    /// Refresh interval (seconds)
    pub refresh: u32,
    /// Retry interval (seconds)
    pub retry: u32,
    /// Upper time limit until zone is no longer authoritative (seconds)
    pub expire: u32,
    /// Minimum ttl for records in this zone (seconds)
    pub minimum: u32,
}

#[derive(Debug,PartialEq)]
pub struct DNSRDataSSHFP {
    /// Algorithm number
    pub algo: u8,
    /// Fingerprint type
    pub fp_type: u8,
    /// Fingerprint
    pub fingerprint: Vec<u8>,
}

#[derive(Debug,PartialEq)]
pub struct DNSRDataSRV {
    /// Priority
    pub priority: u16,
    /// Weight
    pub weight: u16,
    /// Port
    pub port: u16,
    /// Target
    pub target: Vec<u8>,
}

/// Represents RData of various formats
#[derive(Debug,PartialEq)]
pub enum DNSRData {
    // RData is an address
    A(Vec<u8>),
    AAAA(Vec<u8>),
    // RData is a domain name
    CNAME(Vec<u8>),
    PTR(Vec<u8>),
    MX(Vec<u8>),
    NS(Vec<u8>),
    // RData is text
    TXT(Vec<u8>),
    NULL(Vec<u8>),
    // RData has several fields
    SOA(DNSRDataSOA),
    SRV(DNSRDataSRV),
    SSHFP(DNSRDataSSHFP),
    // RData for remaining types is sometimes ignored
    Unknown(Vec<u8>),
}

#[derive(Debug,PartialEq)]
pub struct DNSAnswerEntry {
    pub name: Vec<u8>,
    pub rrtype: u16,
    pub rrclass: u16,
    pub ttl: u32,
    pub data: DNSRData,
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
    pub tx_data: AppLayerTxData,
}

impl Transaction for DNSTransaction {
    fn id(&self) -> u64 {
        self.id
    }
}

impl DNSTransaction {

    pub fn new() -> Self {
        return Self {
            id: 0,
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }

    /// Get the DNS transactions ID (not the internal tracking ID).
    pub fn tx_id(&self) -> u16 {
        if let &Some(ref request) = &self.request {
            return request.header.tx_id;
        }
        if let &Some(ref response) = &self.response {
            return response.header.tx_id;
        }

        // Shouldn't happen.
        return 0;
    }

    /// Get the reply code of the transaction. Note that this will
    /// also return 0 if there is no reply.
    pub fn rcode(&self) -> u16 {
        if let &Some(ref response) = &self.response {
            return response.header.flags & 0x000f;
        }
        return 0;
    }

}

struct ConfigTracker {
    map: HashMap<u16, AppLayerTxConfig>,
    queue: VecDeque<u16>,
}

impl ConfigTracker {
    fn new() -> ConfigTracker {
        ConfigTracker {
            map: HashMap::new(),
            queue: VecDeque::new(),
        }
    }

    fn add(&mut self, id: u16, config: AppLayerTxConfig) {
        // If at size limit, remove the oldest entry.
        if self.queue.len() > 499 {
            if let Some(id) = self.queue.pop_front() {
                self.map.remove(&id);
            }
        }

        self.map.insert(id, config);
        self.queue.push_back(id);
    }

    fn remove(&mut self, id: &u16) -> Option<AppLayerTxConfig> {
        self.map.remove(id)
    }
}

#[derive(Default)]
pub struct DNSState {
    // Internal transaction ID.
    pub tx_id: u64,

    // Transactions.
    pub transactions: VecDeque<DNSTransaction>,

    config: Option<ConfigTracker>,

    gap: bool,
}

impl State<DNSTransaction> for DNSState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&DNSTransaction> {
        self.transactions.get(index)
    }
}

impl DNSState {

    pub fn new() -> Self {
            Default::default()
    }

    pub fn new_tcp() -> Self {
            Default::default()
    }

    pub fn new_tx(&mut self) -> DNSTransaction {
        let mut tx = DNSTransaction::new();
        self.tx_id += 1;
        tx.id = self.tx_id;
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
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&DNSTransaction> {
        SCLogDebug!("get_tx: tx_id={}", tx_id);
        for tx in &mut self.transactions {
            if tx.id == tx_id + 1 {
                SCLogDebug!("Found DNS TX with ID {}", tx_id);
                return Some(tx);
            }
        }
        SCLogDebug!("Failed to find DNS TX with ID {}", tx_id);
        return None;
    }

    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: DNSEvent) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }

        let tx = &mut self.transactions[len - 1];
        tx.tx_data.set_event(event as u8);
    }

    fn parse_request(&mut self, input: &[u8]) -> bool {
        match parser::dns_parse_request(input) {
            Ok((_, request)) => {
                if request.header.flags & 0x8000 != 0 {
                    SCLogDebug!("DNS message is not a request");
                    self.set_event(DNSEvent::NotRequest);
                    return false;
                }

                let z_flag = request.header.flags & 0x0040 != 0;

                let mut tx = self.new_tx();
                tx.request = Some(request);
                self.transactions.push_back(tx);

                if z_flag {
                    SCLogDebug!("Z-flag set on DNS response");
                    self.set_event(DNSEvent::ZFlagSet);
                }

                return true;
            }
            Err(Err::Incomplete(_)) => {
                // Insufficient data.
                SCLogDebug!("Insufficient data while parsing DNS request");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
            Err(_) => {
                // Error, probably malformed data.
                SCLogDebug!("An error occurred while parsing DNS request");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
        }
    }

    fn parse_request_udp(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> bool {
        let input = stream_slice.as_slice();
        let _pdu = Frame::new(flow, &stream_slice, input, input.len() as i64, DnsFrameType::Pdu as u8);
        self.parse_request(input)
    }

    fn parse_response_udp(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> bool {
        let input = stream_slice.as_slice();
        let _pdu = Frame::new(flow, &stream_slice, input, input.len() as i64, DnsFrameType::Pdu as u8);
        self.parse_response(input)
    }

    pub fn parse_response(&mut self, input: &[u8]) -> bool {
        match parser::dns_parse_response(input) {
            Ok((_, response)) => {

                SCLogDebug!("Response header flags: {}", response.header.flags);

                if response.header.flags & 0x8000 == 0 {
                    SCLogDebug!("DNS message is not a response");
                    self.set_event(DNSEvent::NotResponse);
                }

                let z_flag = response.header.flags & 0x0040 != 0;

                let mut tx = self.new_tx();
                if let Some(ref mut config) = &mut self.config {
                    if let Some(config) = config.remove(&response.header.tx_id) {
                        tx.tx_data.config = config;
                    }
                }
                tx.response = Some(response);
                self.transactions.push_back(tx);

                if z_flag {
                    SCLogDebug!("Z-flag set on DNS response");
                    self.set_event(DNSEvent::ZFlagSet);
                }

                return true;
            }
            Err(Err::Incomplete(_)) => {
                // Insufficient data.
                SCLogDebug!("Insufficient data while parsing DNS response");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
            Err(_) => {
                // Error, probably malformed data.
                SCLogDebug!("An error occurred while parsing DNS response");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
        }
    }

    /// TCP variation of response request parser to handle the length
    /// prefix.
    ///
    /// Returns the number of messages parsed.
    pub fn parse_request_tcp(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if self.gap {
            let (is_dns, _, is_incomplete) = probe_tcp(input);
            if is_dns || is_incomplete {
                self.gap = false;
            } else {
                AppLayerResult::ok();
            }
        }

        let mut cur_i = input;
        let mut consumed = 0;
        while cur_i.len() > 0 {
            if cur_i.len() == 1 {
                return AppLayerResult::incomplete(consumed as u32, 2 as u32);
            }
            let size = match be_u16(cur_i) as IResult<&[u8],u16> {
                Ok((_, len)) => len,
                _ => 0
            } as usize;
            SCLogDebug!("[request] Have {} bytes, need {} to parse",
                        cur_i.len(), size + 2);
            if size > 0 && cur_i.len() >= size + 2 {
                let msg = &cur_i[2..(size + 2)];
                let _pdu = Frame::new(flow, &stream_slice, msg, msg.len() as i64, DnsFrameType::Pdu as u8);
                if self.parse_request(msg) {
                    cur_i = &cur_i[(size + 2)..];
                    consumed += size  + 2;
                } else {
                    return AppLayerResult::err();
                }
            } else if size == 0 {
                cur_i = &cur_i[2..];
                consumed += 2;
            } else {
                SCLogDebug!("[request]Not enough DNS traffic to parse. Returning {}/{}",
                            consumed as u32, (size + 2) as u32);
                return AppLayerResult::incomplete(consumed as u32,
                    (size  + 2) as u32);
            }
        }
        AppLayerResult::ok()
    }

    /// TCP variation of the response parser to handle the length
    /// prefix.
    ///
    /// Returns the number of messages parsed.
    pub fn parse_response_tcp(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if self.gap {
            let (is_dns, _, is_incomplete) = probe_tcp(input);
            if is_dns || is_incomplete {
                self.gap = false;
            } else {
                return AppLayerResult::ok();
            }
        }

        let mut cur_i = input;
        let mut consumed = 0;
        while cur_i.len() > 0 {
            if cur_i.len() == 1 {
                return AppLayerResult::incomplete(consumed as u32, 2 as u32);
            }
            let size = match be_u16(cur_i) as IResult<&[u8],u16> {
                Ok((_, len)) => len,
                _ => 0
            } as usize;
            SCLogDebug!("[response] Have {} bytes, need {} to parse",
                        cur_i.len(), size + 2);
            if size > 0 && cur_i.len() >= size + 2 {
                let msg = &cur_i[2..(size + 2)];
                let _pdu = Frame::new(flow, &stream_slice, msg, msg.len() as i64, DnsFrameType::Pdu as u8);
                if self.parse_response(msg) {
                    cur_i = &cur_i[(size + 2)..];
                    consumed += size + 2;
                } else {
                    return AppLayerResult::err();
                }
            } else if size == 0 {
                cur_i = &cur_i[2..];
                consumed += 2;
            } else  {
                SCLogDebug!("[response]Not enough DNS traffic to parse. Returning {}/{}",
                    consumed as u32, (cur_i.len() - consumed) as u32);
                return AppLayerResult::incomplete(consumed as u32,
                    (size + 2) as u32);
            }
        }
        AppLayerResult::ok()
    }

    /// A gap has been seen in the request direction. Set the gap flag.
    pub fn request_gap(&mut self, gap: u32) {
        if gap > 0 {
            self.gap = true;
        }
    }

    /// A gap has been seen in the response direction. Set the gap
    /// flag.
    pub fn response_gap(&mut self, gap: u32) {
        if gap > 0 {
            self.gap = true;
        }
    }
}

const DNS_HEADER_SIZE: usize = 12;

fn probe_header_validity(header: DNSHeader, rlen: usize) -> (bool, bool, bool) {
    let opcode = ((header.flags >> 11) & 0xf) as u8;
    if opcode >= 7 {
        //unassigned opcode
        return (false, false, false);
    }
    if 2 * (header.additional_rr as usize
        + header.answer_rr as usize
        + header.authority_rr as usize
        + header.questions as usize)
        + DNS_HEADER_SIZE
        > rlen
    {
        //not enough data for such a DNS record
        return (false, false, false);
    }
    let is_request = header.flags & 0x8000 == 0;
    return (true, is_request, false);
}

/// Probe input to see if it looks like DNS.
///
/// Returns a tuple of booleans: (is_dns, is_request, incomplete)
fn probe(input: &[u8], dlen: usize) -> (bool, bool, bool) {
    // Trim input to dlen if larger.
    let input = if input.len() <= dlen { input } else { &input[..dlen] };

    // If input is less than dlen then we know we don't have enough data to
    // parse a complete message, so perform header validation only.
    if input.len() < dlen {
        if let Ok((_, header)) = parser::dns_parse_header(input) {
            return probe_header_validity(header, dlen);
        } else {
            return (false, false, false);
        }
    }

    match parser::dns_parse_request(input) {
        Ok((_, request)) => {
            return probe_header_validity(request.header, dlen);
        },
        Err(Err::Incomplete(_)) => {
            match parser::dns_parse_header(input) {
                Ok((_, header)) => {
                    return probe_header_validity(header, dlen);
                }
                Err(Err::Incomplete(_)) => (false, false, true),
                Err(_) => (false, false, false),
            }
        }
        Err(_) => (false, false, false),
    }
}

/// Probe TCP input to see if it looks like DNS.
pub fn probe_tcp(input: &[u8]) -> (bool, bool, bool) {
    match be_u16(input) as IResult<&[u8],u16> {
        Ok((rem, dlen)) => {
            return probe(rem, dlen as usize);
        },
        Err(Err::Incomplete(_)) => {
            return (false, false, true);
        }
        _ => {}
    }
    return (false, false, false);
}

/// Returns *mut DNSState
#[no_mangle]
pub extern "C" fn rs_dns_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = DNSState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

/// Returns *mut DNSState
#[no_mangle]
pub extern "C" fn rs_dns_state_tcp_new() -> *mut std::os::raw::c_void {
    let state = DNSState::new_tcp();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

/// Params:
/// - state: *mut DNSState as void pointer
#[no_mangle]
pub extern "C" fn rs_dns_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    std::mem::drop(unsafe { Box::from_raw(state as *mut DNSState) });
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_state_tx_free(state: *mut std::os::raw::c_void,
                                       tx_id: u64)
{
    let state = cast_pointer!(state, DNSState);
    state.free_tx(tx_id);
}

/// C binding parse a DNS request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn rs_dns_parse_request(flow: *const core::Flow,
                                        state: *mut std::os::raw::c_void,
                                       _pstate: *mut std::os::raw::c_void,
                                       stream_slice: StreamSlice,
                                       _data: *const std::os::raw::c_void,
                                       )
                                       -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);
    if state.parse_request_udp(flow, stream_slice) {
        AppLayerResult::ok()
    } else {
        AppLayerResult::err()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_parse_response(flow: *const core::Flow,
                                        state: *mut std::os::raw::c_void,
                                        _pstate: *mut std::os::raw::c_void,
                                        stream_slice: StreamSlice,
                                        _data: *const std::os::raw::c_void,
                                        )
                                        -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);
    if state.parse_response_udp(flow, stream_slice) {
        AppLayerResult::ok()
    } else {
        AppLayerResult::err()
    }
}

/// C binding parse a DNS request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn rs_dns_parse_request_tcp(flow: *const core::Flow,
                                           state: *mut std::os::raw::c_void,
                                           _pstate: *mut std::os::raw::c_void,
                                           stream_slice: StreamSlice,
                                           _data: *const std::os::raw::c_void,
                                           )
                                           -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);
    if stream_slice.is_gap() {
        state.request_gap(stream_slice.gap_size());
    } else if stream_slice.len() > 0 {
        return state.parse_request_tcp(flow, stream_slice);
    }
    AppLayerResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_parse_response_tcp(flow: *const core::Flow,
                                            state: *mut std::os::raw::c_void,
                                            _pstate: *mut std::os::raw::c_void,
                                            stream_slice: StreamSlice,
                                            _data: *const std::os::raw::c_void,
                                            )
                                            -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);
    if stream_slice.is_gap() {
        state.response_gap(stream_slice.gap_size());
    } else if stream_slice.len() > 0 {
        return state.parse_response_tcp(flow, stream_slice);
    }
    AppLayerResult::ok()
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_get_alstate_progress(_tx: *mut std::os::raw::c_void,
                                                 _direction: u8)
                                                 -> std::os::raw::c_int
{
    // This is a stateless parser, just the existence of a transaction
    // means its complete.
    SCLogDebug!("rs_dns_tx_get_alstate_progress");
    return 1;
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_state_get_tx_count(state: *mut std::os::raw::c_void)
                                            -> u64
{
    let state = cast_pointer!(state, DNSState);
    SCLogDebug!("rs_dns_state_get_tx_count: returning {}", state.tx_id);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_state_get_tx(state: *mut std::os::raw::c_void,
                                      tx_id: u64)
                                      -> *mut std::os::raw::c_void
{
    let state = cast_pointer!(state, DNSState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_is_request(tx: &mut DNSTransaction) -> bool {
    tx.request.is_some()
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_is_response(tx: &mut DNSTransaction) -> bool {
    tx.response.is_some()
}

pub unsafe extern "C" fn rs_dns_state_get_tx_data(
    tx: *mut std::os::raw::c_void)
    -> *mut AppLayerTxData
{
    let tx = cast_pointer!(tx, DNSTransaction);
    return &mut tx.tx_data;
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_tx_get_query_name(tx: &mut DNSTransaction,
                                       i: u32,
                                       buf: *mut *const u8,
                                       len: *mut u32)
                                       -> u8
{
    if let &Some(ref request) = &tx.request {
        if (i as usize) < request.queries.len() {
            let query = &request.queries[i as usize];
            if query.name.len() > 0 {
                *len = query.name.len() as u32;
                *buf = query.name.as_ptr();
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
pub extern "C" fn rs_dns_tx_get_tx_id(tx: &mut DNSTransaction) -> u16
{
    return tx.tx_id()
}

/// Get the DNS response flags for a transaction.
///
/// extern uint16_t rs_dns_tx_get_response_flags(RSDNSTransaction *);
#[no_mangle]
pub extern "C" fn rs_dns_tx_get_response_flags(tx: &mut DNSTransaction)
                                           -> u16
{
    return tx.rcode();
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_tx_get_query_rrtype(tx: &mut DNSTransaction,
                                         i: u16,
                                         rrtype: *mut u16)
                                         -> u8
{
    if let &Some(ref request) = &tx.request {
        if (i as usize) < request.queries.len() {
            let query = &request.queries[i as usize];
            if query.name.len() > 0 {
                *rrtype = query.rrtype;
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_probe(
    _flow: *const core::Flow,
    _dir: u8,
    input: *const u8,
    len: u32,
    rdir: *mut u8,
) -> AppProto {
    if len == 0 || len < std::mem::size_of::<DNSHeader>() as u32 {
        return core::ALPROTO_UNKNOWN;
    }
    let slice: &[u8] = std::slice::from_raw_parts(input as *mut u8, len as usize);
    let (is_dns, is_request, _) = probe(slice, slice.len());
    if is_dns {
        let dir = if is_request {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        *rdir = dir as u8;
        return ALPROTO_DNS;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_probe_tcp(
    _flow: *const core::Flow,
    direction: u8,
    input: *const u8,
    len: u32,
    rdir: *mut u8
) -> AppProto {
    if len == 0 || len < std::mem::size_of::<DNSHeader>() as u32 + 2 {
        return core::ALPROTO_UNKNOWN;
    }
    let slice: &[u8] = std::slice::from_raw_parts(input as *mut u8, len as usize);
    //is_incomplete is checked by caller
    let (is_dns, is_request, _) = probe_tcp(slice);
    if is_dns {
        let dir = if is_request {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        if (direction & DIR_BOTH) != dir.into() {
            *rdir = dir as u8;
        }
        return ALPROTO_DNS;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_apply_tx_config(
    _state: *mut std::os::raw::c_void, _tx: *mut std::os::raw::c_void,
    _mode: std::os::raw::c_int, config: AppLayerTxConfig
) {
    let tx = cast_pointer!(_tx, DNSTransaction);
    let state = cast_pointer!(_state, DNSState);
    if let Some(request) = &tx.request {
        if state.config.is_none() {
            state.config = Some(ConfigTracker::new());
        }
        if let Some(ref mut tracker) = &mut state.config {
            tracker.add(request.header.tx_id, config);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_udp_register_parser() {
    let default_port = std::ffi::CString::new("[53]").unwrap();
    let parser = RustParser{
        name: b"dns\0".as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(rs_dns_probe),
        probe_tc: Some(rs_dns_probe),
        min_depth: 0,
        max_depth: std::mem::size_of::<DNSHeader>() as u16,
        state_new: rs_dns_state_new,
        state_free: rs_dns_state_free,
        tx_free: rs_dns_state_tx_free,
        parse_ts: rs_dns_parse_request,
        parse_tc: rs_dns_parse_response,
        get_tx_count: rs_dns_state_get_tx_count,
        get_tx: rs_dns_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_dns_tx_get_alstate_progress,
        get_eventinfo: Some(DNSEvent::get_event_info),
        get_eventinfo_byid: Some(DNSEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(crate::applayer::state_get_tx_iterator::<DNSState, DNSTransaction>),
        get_tx_data: rs_dns_state_get_tx_data,
        apply_tx_config: Some(rs_dns_apply_tx_config),
        flags: APP_LAYER_PARSER_OPT_UNIDIR_TXS,
        truncate: None,
        get_frame_id_by_name: Some(DnsFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(DnsFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("udp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_DNS = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_tcp_register_parser() {
    let default_port = std::ffi::CString::new("53").unwrap();
    let parser = RustParser{
        name: b"dns\0".as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_dns_probe_tcp),
        probe_tc: Some(rs_dns_probe_tcp),
        min_depth: 0,
        max_depth: std::mem::size_of::<DNSHeader>() as u16 + 2,
        state_new: rs_dns_state_new,
        state_free: rs_dns_state_free,
        tx_free: rs_dns_state_tx_free,
        parse_ts: rs_dns_parse_request_tcp,
        parse_tc: rs_dns_parse_response_tcp,
        get_tx_count: rs_dns_state_get_tx_count,
        get_tx: rs_dns_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_dns_tx_get_alstate_progress,
        get_eventinfo: Some(DNSEvent::get_event_info),
        get_eventinfo_byid: Some(DNSEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(crate::applayer::state_get_tx_iterator::<DNSState, DNSTransaction>),
        get_tx_data: rs_dns_state_get_tx_data,
        apply_tx_config: Some(rs_dns_apply_tx_config),
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS | APP_LAYER_PARSER_OPT_UNIDIR_TXS,
        truncate: None,
        get_frame_id_by_name: Some(DnsFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(DnsFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_DNS = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_dns_parse_request_tcp_valid() {
        // A UDP DNS request with the DNS payload starting at byte 42.
        // From pcap: https://github.com/jasonish/suricata-verify/blob/7cc0e1bd0a5249b52e6e87d82d57c0b6aaf75fce/dns-udp-dig-a-www-suricata-ids-org/dig-a-www.suricata-ids.org.pcap
        let buf: &[u8] = &[
            0x00, 0x15, 0x17, 0x0d, 0x06, 0xf7, 0xd8, 0xcb, /* ........ */
            0x8a, 0xed, 0xa1, 0x46, 0x08, 0x00, 0x45, 0x00, /* ...F..E. */
            0x00, 0x4d, 0x23, 0x11, 0x00, 0x00, 0x40, 0x11, /* .M#...@. */
            0x41, 0x64, 0x0a, 0x10, 0x01, 0x0b, 0x0a, 0x10, /* Ad...... */
            0x01, 0x01, 0xa3, 0x4d, 0x00, 0x35, 0x00, 0x39, /* ...M.5.9 */
            0xb2, 0xb3, 0x8d, 0x32, 0x01, 0x20, 0x00, 0x01, /* ...2. .. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, /* .......w */
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63, /* ww.suric */
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03, /* ata-ids. */
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01, /* org..... */
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, /* ..)..... */
            0x00, 0x00, 0x00                                /* ... */
        ];

        // The DNS payload starts at offset 42.
        let dns_payload = &buf[42..];

        // Make a TCP DNS request payload.
        let mut request = Vec::new();
        request.push(((dns_payload.len() as u16) >> 8) as u8);
        request.push(((dns_payload.len() as u16) & 0xff) as u8);
        request.extend(dns_payload);

        let mut state = DNSState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request_tcp(std::ptr::null(), StreamSlice::from_slice(&request, STREAM_TOSERVER, 0))
        );
    }

    #[test]
    fn test_dns_parse_request_tcp_short_payload() {
        // A UDP DNS request with the DNS payload starting at byte 42.
        // From pcap: https://github.com/jasonish/suricata-verify/blob/7cc0e1bd0a5249b52e6e87d82d57c0b6aaf75fce/dns-udp-dig-a-www-suricata-ids-org/dig-a-www.suricata-ids.org.pcap
        let buf: &[u8] = &[
            0x00, 0x15, 0x17, 0x0d, 0x06, 0xf7, 0xd8, 0xcb, /* ........ */
            0x8a, 0xed, 0xa1, 0x46, 0x08, 0x00, 0x45, 0x00, /* ...F..E. */
            0x00, 0x4d, 0x23, 0x11, 0x00, 0x00, 0x40, 0x11, /* .M#...@. */
            0x41, 0x64, 0x0a, 0x10, 0x01, 0x0b, 0x0a, 0x10, /* Ad...... */
            0x01, 0x01, 0xa3, 0x4d, 0x00, 0x35, 0x00, 0x39, /* ...M.5.9 */
            0xb2, 0xb3, 0x8d, 0x32, 0x01, 0x20, 0x00, 0x01, /* ...2. .. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, /* .......w */
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63, /* ww.suric */
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03, /* ata-ids. */
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01, /* org..... */
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, /* ..)..... */
            0x00, 0x00, 0x00                                /* ... */
        ];

        // The DNS payload starts at offset 42.
        let dns_payload = &buf[42..];

        // Make a TCP DNS request payload but with the length 1 larger
        // than the available data.
        let mut request = Vec::new();
        request.push(((dns_payload.len() as u16) >> 8) as u8);
        request.push(((dns_payload.len() as u16) & 0xff) as u8 + 1);
        request.extend(dns_payload);

        let mut state = DNSState::new();
        assert_eq!(
            AppLayerResult::incomplete(0, 52),
            state.parse_request_tcp(std::ptr::null(), StreamSlice::from_slice(&request, STREAM_TOSERVER, 0))
        );
    }

    #[test]
    fn test_dns_parse_response_tcp_valid() {
        // A UDP DNS response with the DNS payload starting at byte 42.
        // From pcap: https://github.com/jasonish/suricata-verify/blob/7cc0e1bd0a5249b52e6e87d82d57c0b6aaf75fce/dns-udp-dig-a-www-suricata-ids-org/dig-a-www.suricata-ids.org.pcap
        let buf: &[u8] = &[
            0xd8, 0xcb, 0x8a, 0xed, 0xa1, 0x46, 0x00, 0x15, /* .....F.. */
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00, /* ......E. */
            0x00, 0x80, 0x65, 0x4e, 0x40, 0x00, 0x40, 0x11, /* ..eN@.@. */
            0xbe, 0xf3, 0x0a, 0x10, 0x01, 0x01, 0x0a, 0x10, /* ........ */
            0x01, 0x0b, 0x00, 0x35, 0xa3, 0x4d, 0x00, 0x6c, /* ...5.M.l */
            0x8d, 0x8c, 0x8d, 0x32, 0x81, 0xa0, 0x00, 0x01, /* ...2.... */
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

        // The DNS payload starts at offset 42.
        let dns_payload = &buf[42..];

        // Make a TCP DNS response payload.
        let mut request = Vec::new();
        request.push(((dns_payload.len() as u16) >> 8) as u8);
        request.push(((dns_payload.len() as u16) & 0xff) as u8);
        request.extend(dns_payload);

        let mut state = DNSState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_response_tcp(std::ptr::null(), StreamSlice::from_slice(&request, STREAM_TOCLIENT, 0))
        );
    }

    // Test that a TCP DNS payload won't be parsed if there is not
    // enough data.
    #[test]
    fn test_dns_parse_response_tcp_short_payload() {
        // A UDP DNS response with the DNS payload starting at byte 42.
        // From pcap: https://github.com/jasonish/suricata-verify/blob/7cc0e1bd0a5249b52e6e87d82d57c0b6aaf75fce/dns-udp-dig-a-www-suricata-ids-org/dig-a-www.suricata-ids.org.pcap
        let buf: &[u8] = &[
            0xd8, 0xcb, 0x8a, 0xed, 0xa1, 0x46, 0x00, 0x15, /* .....F.. */
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00, /* ......E. */
            0x00, 0x80, 0x65, 0x4e, 0x40, 0x00, 0x40, 0x11, /* ..eN@.@. */
            0xbe, 0xf3, 0x0a, 0x10, 0x01, 0x01, 0x0a, 0x10, /* ........ */
            0x01, 0x0b, 0x00, 0x35, 0xa3, 0x4d, 0x00, 0x6c, /* ...5.M.l */
            0x8d, 0x8c, 0x8d, 0x32, 0x81, 0xa0, 0x00, 0x01, /* ...2.... */
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

        // The DNS payload starts at offset 42.
        let dns_payload = &buf[42..];

        // Make a TCP DNS response payload, but make the length 1 byte
        // larger than the actual size.
        let mut request = Vec::new();
        request.push(((dns_payload.len() as u16) >> 8) as u8);
        request.push((((dns_payload.len() as u16) & 0xff) + 1) as u8);
        request.extend(dns_payload);

        let mut state = DNSState::new();
        assert_eq!(
            AppLayerResult::incomplete(0, 103),
            state.parse_response_tcp(std::ptr::null(), StreamSlice::from_slice(&request, STREAM_TOCLIENT, 0))
        );
    }

    // Port of the C RustDNSUDPParserTest02 unit test.
    #[test]
    fn test_dns_udp_parser_test_01() {
        /* query: abcdefghijk.com
         * TTL: 86400
         * serial 20130422 refresh 28800 retry 7200 exp 604800 min ttl 86400
         * ns, hostmaster */
        let buf: &[u8] = &[
            0x00, 0x3c, 0x85, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x0b, 0x61, 0x62, 0x63,
            0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x0f, 0x00,
            0x01, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01,
            0x51, 0x80, 0x00, 0x25, 0x02, 0x6e, 0x73, 0x00,
            0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73,
            0x74, 0x65, 0x72, 0xc0, 0x2f, 0x01, 0x33, 0x2a,
            0x76, 0x00, 0x00, 0x70, 0x80, 0x00, 0x00, 0x1c,
            0x20, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01, 0x51,
            0x80,
        ];
        let mut state = DNSState::new();
        assert!(state.parse_response(buf));
    }

    // Port of the C RustDNSUDPParserTest02 unit test.
    #[test]
    fn test_dns_udp_parser_test_02() {
        let buf: &[u8] = &[
            0x6D,0x08,0x84,0x80,0x00,0x01,0x00,0x08,0x00,0x00,0x00,0x01,0x03,0x57,0x57,0x57,
            0x04,0x54,0x54,0x54,0x54,0x03,0x56,0x56,0x56,0x03,0x63,0x6F,0x6D,0x02,0x79,0x79,
            0x00,0x00,0x01,0x00,0x01,0xC0,0x0C,0x00,0x05,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,
            0x02,0xC0,0x0C,0xC0,0x31,0x00,0x05,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x02,0xC0,
            0x31,0xC0,0x3F,0x00,0x05,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x02,0xC0,0x3F,0xC0,
            0x4D,0x00,0x05,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x02,0xC0,0x4D,0xC0,0x5B,0x00,
            0x05,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x02,0xC0,0x5B,0xC0,0x69,0x00,0x05,0x00,
            0x01,0x00,0x00,0x0E,0x10,0x00,0x02,0xC0,0x69,0xC0,0x77,0x00,0x05,0x00,0x01,0x00,
            0x00,0x0E,0x10,0x00,0x02,0xC0,0x77,0xC0,0x85,0x00,0x05,0x00,0x01,0x00,0x00,0x0E,
            0x10,0x00,0x02,0xC0,0x85,0x00,0x00,0x29,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        ];
        let mut state = DNSState::new();
        assert!(state.parse_response(buf));
    }

    // Port of the C RustDNSUDPParserTest03 unit test.
    #[test]
    fn test_dns_udp_parser_test_03() {
        let buf: &[u8] = &[
            0x6F,0xB4,0x84,0x80,0x00,0x01,0x00,0x02,0x00,0x02,0x00,0x03,0x03,0x57,0x57,0x77,
            0x0B,0x56,0x56,0x56,0x56,0x56,0x56,0x56,0x56,0x56,0x56,0x56,0x03,0x55,0x55,0x55,
            0x02,0x79,0x79,0x00,0x00,0x01,0x00,0x01,0xC0,0x0C,0x00,0x05,0x00,0x01,0x00,0x00,
            0x0E,0x10,0x00,0x02,0xC0,0x10,0xC0,0x34,0x00,0x01,0x00,0x01,0x00,0x00,0x0E,0x10,
            0x00,0x04,0xC3,0xEA,0x04,0x19,0xC0,0x34,0x00,0x02,0x00,0x01,0x00,0x00,0x0E,0x10,
            0x00,0x0A,0x03,0x6E,0x73,0x31,0x03,0x61,0x67,0x62,0xC0,0x20,0xC0,0x46,0x00,0x02,
            0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x06,0x03,0x6E,0x73,0x32,0xC0,0x56,0xC0,0x52,
            0x00,0x01,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x04,0xC3,0xEA,0x04,0x0A,0xC0,0x68,
            0x00,0x01,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x04,0xC3,0xEA,0x05,0x14,0x00,0x00,
            0x29,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        ];
        let mut state = DNSState::new();
        assert!(state.parse_response(buf));
    }

    // Port of the C RustDNSUDPParserTest04 unit test.
    //
    // Test the TXT records in an answer.
    #[test]
    fn test_dns_udp_parser_test_04() {
        let buf: &[u8] = &[
            0xc2,0x2f,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,0x0a,0x41,0x41,0x41,
            0x41,0x41,0x4f,0x31,0x6b,0x51,0x41,0x05,0x3d,0x61,0x75,0x74,0x68,0x03,0x73,0x72,
            0x76,0x06,0x74,0x75,0x6e,0x6e,0x65,0x6c,0x03,0x63,0x6f,0x6d,0x00,0x00,0x10,0x00,
            0x01,
            /* answer record start */
            0xc0,0x0c,0x00,0x10,0x00,0x01,0x00,0x00,0x00,0x03,0x00,0x22,
            /* txt record starts: */
            0x20, /* <txt len 32 */  0x41,0x68,0x76,0x4d,0x41,0x41,0x4f,0x31,0x6b,0x41,0x46,
            0x45,0x35,0x54,0x45,0x39,0x51,0x54,0x6a,0x46,0x46,0x4e,0x30,0x39,0x52,0x4e,0x31,
            0x6c,0x59,0x53,0x44,0x6b,0x00, /* <txt len 0 */   0xc0,0x1d,0x00,0x02,0x00,0x01,
            0x00,0x09,0x3a,0x80,0x00,0x09,0x06,0x69,0x6f,0x64,0x69,0x6e,0x65,0xc0,0x21,0xc0,
            0x6b,0x00,0x01,0x00,0x01,0x00,0x09,0x3a,0x80,0x00,0x04,0x0a,0x1e,0x1c,0x5f
        ];
        let mut state = DNSState::new();
        assert!(state.parse_response(buf));
    }

    // Port of the C RustDNSUDPParserTest05 unit test.
    //
    // Test TXT records in answer with a bad length.
    #[test]
    fn test_dns_udp_parser_test_05() {
        let buf: &[u8] = &[
            0xc2,0x2f,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,0x0a,0x41,0x41,0x41,
            0x41,0x41,0x4f,0x31,0x6b,0x51,0x41,0x05,0x3d,0x61,0x75,0x74,0x68,0x03,0x73,0x72,
            0x76,0x06,0x74,0x75,0x6e,0x6e,0x65,0x6c,0x03,0x63,0x6f,0x6d,0x00,0x00,0x10,0x00,
            0x01,
            /* answer record start */
            0xc0,0x0c,0x00,0x10,0x00,0x01,0x00,0x00,0x00,0x03,0x00,0x22,
            /* txt record starts: */
            0x40, /* <txt len 64 */  0x41,0x68,0x76,0x4d,0x41,0x41,0x4f,0x31,0x6b,0x41,0x46,
            0x45,0x35,0x54,0x45,0x39,0x51,0x54,0x6a,0x46,0x46,0x4e,0x30,0x39,0x52,0x4e,0x31,
            0x6c,0x59,0x53,0x44,0x6b,0x00, /* <txt len 0 */   0xc0,0x1d,0x00,0x02,0x00,0x01,
            0x00,0x09,0x3a,0x80,0x00,0x09,0x06,0x69,0x6f,0x64,0x69,0x6e,0x65,0xc0,0x21,0xc0,
            0x6b,0x00,0x01,0x00,0x01,0x00,0x09,0x3a,0x80,0x00,0x04,0x0a,0x1e,0x1c,0x5f
        ];
        let mut state = DNSState::new();
        assert!(!state.parse_response(buf));
    }

    // Port of the C RustDNSTCPParserTestMultiRecord unit test.
    #[test]
    fn test_dns_tcp_parser_multi_record() {
        let buf: &[u8] = &[
            0x00, 0x1e, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1e, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x31,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1e, 0x00, 0x02, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x32,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1e, 0x00, 0x03, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x33,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1e, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x34,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1e, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x35,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1e, 0x00, 0x06, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x36,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1e, 0x00, 0x07, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x37,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1e, 0x00, 0x08, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x38,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1e, 0x00, 0x09, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x39,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1f, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31,
            0x30, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x1f, 0x00, 0x0b, 0x01, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x31, 0x31, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
            0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x1f, 0x00, 0x0c, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x31, 0x32, 0x06, 0x67, 0x6f, 0x6f, 0x67,
            0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x1f, 0x00, 0x0d, 0x01,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x31, 0x33, 0x06, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x1f, 0x00, 0x0e,
            0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x31, 0x34, 0x06, 0x67, 0x6f,
            0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x1f, 0x00,
            0x0f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x31, 0x35, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
            0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x1f,
            0x00, 0x10, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x31, 0x36, 0x06,
            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x1f, 0x00, 0x11, 0x01, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31, 0x37,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x1f, 0x00, 0x12, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31,
            0x38, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x1f, 0x00, 0x13, 0x01, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x31, 0x39, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
            0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
            0x00, 0x01
        ];

        // A NULL flow.
        let flow = std::ptr::null();

        let mut state = DNSState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request_tcp(flow, StreamSlice::from_slice(buf, STREAM_TOSERVER, 0))
        );
    }

    #[test]
    fn test_dns_tcp_parser_split_payload() {
        // A NULL flow.
        let flow = std::ptr::null();

        /* incomplete payload */
        let buf1: &[u8] = &[
            0x00, 0x1c, 0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];
        /* complete payload plus the start of a new payload */
        let buf2: &[u8] = &[
            0x00, 0x1c, 0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03,
            0x63, 0x6F, 0x6D, 0x00, 0x00, 0x10, 0x00, 0x01,

            // next.
            0x00, 0x1c, 0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        /* and the complete payload again with no trailing data. */
        let buf3: &[u8] = &[
            0x00, 0x1c, 0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03,
            0x63, 0x6F, 0x6D, 0x00, 0x00, 0x10, 0x00, 0x01,
        ];

        let mut state = DNSState::new();
        assert_eq!(
            AppLayerResult::incomplete(0, 30),
            state.parse_request_tcp(flow, StreamSlice::from_slice(buf1, STREAM_TOSERVER, 0))
        );
        assert_eq!(
            AppLayerResult::incomplete(30, 30),
            state.parse_request_tcp(flow, StreamSlice::from_slice(buf2, STREAM_TOSERVER, 0))
        );
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request_tcp(flow, StreamSlice::from_slice(buf3, STREAM_TOSERVER, 0))
        );
    }

    #[test]
    fn test_dns_event_from_id() {
        assert_eq!(DNSEvent::from_id(0), Some(DNSEvent::MalformedData));
        assert_eq!(DNSEvent::from_id(3), Some(DNSEvent::ZFlagSet));
        assert_eq!(DNSEvent::from_id(9), None);
    }

    #[test]
    fn test_dns_event_to_cstring() {
        assert_eq!(DNSEvent::MalformedData.to_cstring(), "malformed_data\0");
    }

    #[test]
    fn test_dns_event_from_string() {
        let name = "malformed_data";
        let event = DNSEvent::from_string(&name).unwrap();
        assert_eq!(event, DNSEvent::MalformedData);
        assert_eq!(event.to_cstring(), format!("{}\0", name));
    }
}
