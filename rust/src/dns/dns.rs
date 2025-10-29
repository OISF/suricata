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
use std::collections::HashMap;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::c_void;

use crate::applayer::*;
use crate::core::{self, *};
use crate::direction::Direction;
use crate::direction::DIR_BOTH;
use crate::dns::parser;
use crate::flow::Flow;
use crate::frames::Frame;

use nom8::number::streaming::be_u16;
use nom8::{Err, IResult};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, DetectEngineThreadCtx, SCAppLayerParserConfParserEnabled,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

/// DNS record types.
/// DNS error codes.
#[derive(Clone, Debug, EnumStringU16)]
pub enum DNSRecordType {
    A = 1,
    NS = 2,
    MD = 3, // Obsolete
    MF = 4, // Obsolete
    CNAME = 5,
    SOA = 6,
    MB = 7,    // Experimental
    MG = 8,    // Experimental
    MR = 9,    // Experimental
    NULL = 10, // Experimental
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    X25 = 19,
    ISDN = 20,
    RT = 21,
    NSAP = 22,
    NSAPPTR = 23,
    SIG = 24,
    KEY = 25,
    PX = 26,
    GPOS = 27,
    AAAA = 28,
    LOC = 29,
    NXT = 30, // Obsolete
    SRV = 33,
    ATMA = 34,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    A6 = 38, // Obsolete
    DNAME = 39,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    HIP = 55,
    CDS = 59,
    CDNSKEY = 60,
    HTTPS = 65,
    SPF = 99, // Obsolete
    TKEY = 249,
    TSIG = 250,
    MAILA = 254, // Obsolete
    ANY = 255,
    URI = 256,
}

/// DNS error codes.
#[derive(Clone, Debug, EnumStringU16)]
pub enum DNSRcode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    YXRRSET = 7,
    NXRRSET = 8,
    NOTAUTH = 9,
    NOTZONE = 10,
    // Support for OPT RR from RFC6891 will be needed to
    // parse RCODE values over 15
    BADVERS = 16,
    //also pub const DNS_RCODE_BADSIG: u16 = 16;
    BADKEY = 17,
    BADTIME = 18,
    BADMODE = 19,
    BADNAME = 20,
    BADALG = 21,
    BADTRUNC = 22,
}

pub(super) static mut ALPROTO_DNS: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerFrameType)]
pub(crate) enum DnsFrameType {
    /// DNS PDU frame. For UDP DNS this is the complete UDP payload, for TCP
    /// this is the DNS payload not including the leading length field allowing
    /// this frame to be used for UDP and TCP DNS.
    Pdu,
}

#[derive(Debug, PartialEq, Eq, AppLayerEvent)]
pub enum DNSEvent {
    MalformedData,
    NotRequest,
    NotResponse,
    ZFlagSet,
    InvalidOpcode,
    /// A DNS resource name was exessively long and was truncated.
    NameTooLong,
    /// An infinite loop was found while parsing a name.
    InfiniteLoop,
    /// Too many labels were found.
    TooManyLabels,
    InvalidAdditionals,
    InvalidAuthorities,
}

#[derive(Debug, PartialEq, Eq)]
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
    pub name: DNSName,
    pub rrtype: u16,
    pub rrclass: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSRDataOPT {
    /// Option Code
    pub code: u16,
    /// Option Data
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSRDataSOA {
    /// Primary name server for this zone
    pub mname: DNSName,
    /// Authority's mailbox
    pub rname: DNSName,
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

#[derive(Debug, PartialEq, Eq)]
pub struct DNSRDataSSHFP {
    /// Algorithm number
    pub algo: u8,
    /// Fingerprint type
    pub fp_type: u8,
    /// Fingerprint
    pub fingerprint: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSRDataSRV {
    /// Priority
    pub priority: u16,
    /// Weight
    pub weight: u16,
    /// Port
    pub port: u16,
    /// Target
    pub target: DNSName,
}

bitflags! {
    #[derive(Default)]
    pub struct DNSNameFlags: u8 {
        const INFINITE_LOOP = 0b0000_0001;
        const TRUNCATED     = 0b0000_0010;
        const LABEL_LIMIT   = 0b0000_0100;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSName {
    pub value: Vec<u8>,
    pub flags: DNSNameFlags,
}

/// Represents RData of various formats
#[derive(Debug, PartialEq, Eq)]
pub enum DNSRData {
    // RData is an address
    A(Vec<u8>),
    AAAA(Vec<u8>),
    // RData is a domain name
    CNAME(DNSName),
    PTR(DNSName),
    MX(DNSName),
    NS(DNSName),
    // TXT records are an array of TXT entries
    TXT(Vec<Vec<u8>>),
    NULL(Vec<u8>),
    // RData has several fields
    SOA(DNSRDataSOA),
    SRV(DNSRDataSRV),
    SSHFP(DNSRDataSSHFP),
    OPT(Vec<DNSRDataOPT>),
    // RData for remaining types is sometimes ignored
    Unknown(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAnswerEntry {
    pub name: DNSName,
    pub rrtype: u16,
    pub rrclass: u16,
    pub ttl: u32,
    pub data: DNSRData,
}

#[derive(Debug)]
pub struct DNSMessage {
    pub header: DNSHeader,
    pub queries: Vec<DNSQueryEntry>,
    pub answers: Vec<DNSAnswerEntry>,
    pub authorities: Vec<DNSAnswerEntry>,
    pub invalid_authorities: bool,
    pub additionals: Vec<DNSAnswerEntry>,
    pub invalid_additionals: bool,
}

#[derive(Debug, Default)]
pub struct DNSTransaction {
    pub id: u64,
    pub request: Option<DNSMessage>,
    pub response: Option<DNSMessage>,
    pub tx_data: AppLayerTxData,
}

impl Transaction for DNSTransaction {
    fn id(&self) -> u64 {
        self.id
    }
}

impl DNSTransaction {
    pub(crate) fn new(direction: Direction) -> Self {
        Self {
            tx_data: AppLayerTxData::for_direction(direction),
            ..Default::default()
        }
    }

    /// Get the DNS transactions ID (not the internal tracking ID).
    pub fn tx_id(&self) -> u16 {
        if let Some(request) = &self.request {
            return request.header.tx_id;
        }
        if let Some(response) = &self.response {
            return response.header.tx_id;
        }

        // Shouldn't happen.
        return 0;
    }

    /// Get the reply code of the transaction. Note that this will
    /// also return 0 if there is no reply.
    pub fn rcode(&self) -> u16 {
        if let Some(response) = &self.response {
            return response.header.flags & 0x000f;
        }
        return 0;
    }

    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: DNSEvent) {
        self.tx_data.set_event(event as u8);
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

pub(crate) enum DnsVariant {
    Dns,
    MulticastDns,
}

impl DnsVariant {
    pub fn is_dns(&self) -> bool {
        matches!(self, DnsVariant::Dns)
    }

    pub fn is_mdns(&self) -> bool {
        matches!(self, DnsVariant::MulticastDns)
    }
}

//#[derive(Default)]
pub struct DNSState {
    variant: DnsVariant,
    state_data: AppLayerStateData,

    // Internal transaction ID.
    tx_id: u64,

    // Transactions.
    transactions: VecDeque<DNSTransaction>,

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

fn dns_validate_header(input: &[u8]) -> Option<(&[u8], DNSHeader)> {
    if let Ok((body, header)) = parser::dns_parse_header(input) {
        if probe_header_validity(&header, input.len()).0 {
            return Some((body, header));
        }
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DNSParseError {
    HeaderValidation,
    NotRequest,
    Incomplete,
    OtherError,
}

pub(crate) fn dns_parse_request(
    input: &[u8], variant: &DnsVariant,
) -> Result<DNSTransaction, DNSParseError> {
    let (body, header) = if let Some((body, header)) = dns_validate_header(input) {
        (body, header)
    } else {
        return Err(DNSParseError::HeaderValidation);
    };

    match parser::dns_parse_body(body, input, header) {
        Ok((_, (request, parse_flags))) => {
            if variant.is_dns() && request.header.flags & 0x8000 != 0 {
                SCLogDebug!("DNS message is not a request");
                return Err(DNSParseError::NotRequest);
            }

            let z_flag = request.header.flags & 0x0040 != 0;
            let opcode = ((request.header.flags >> 11) & 0xf) as u8;

            let mut tx = DNSTransaction::new(Direction::ToServer);
            if request.invalid_additionals {
                tx.set_event(DNSEvent::InvalidAdditionals);
            }
            if request.invalid_authorities {
                tx.set_event(DNSEvent::InvalidAuthorities);
            }

            if variant.is_mdns() && request.header.flags & 0x8000 != 0 {
                tx.response = Some(request);
            } else {
                tx.request = Some(request);
            }

            if z_flag {
                SCLogDebug!("Z-flag set on DNS request");
                tx.set_event(DNSEvent::ZFlagSet);
            }

            if opcode >= 7 {
                tx.set_event(DNSEvent::InvalidOpcode);
            }

            if parse_flags.contains(DNSNameFlags::TRUNCATED) {
                tx.set_event(DNSEvent::NameTooLong);
            }

            if parse_flags.contains(DNSNameFlags::INFINITE_LOOP) {
                tx.set_event(DNSEvent::InfiniteLoop);
            }

            if parse_flags.contains(DNSNameFlags::LABEL_LIMIT) {
                tx.set_event(DNSEvent::TooManyLabels);
            }

            return Ok(tx);
        }
        Err(Err::Incomplete(_)) => {
            // Insufficient data.
            SCLogDebug!("Insufficient data while parsing DNS request");
            return Err(DNSParseError::Incomplete);
        }
        Err(_) => {
            // Error, probably malformed data.
            SCLogDebug!("An error occurred while parsing DNS request");
            return Err(DNSParseError::OtherError);
        }
    }
}

pub(crate) fn dns_parse_response(input: &[u8]) -> Result<DNSTransaction, DNSParseError> {
    let (body, header) = if let Some((body, header)) = dns_validate_header(input) {
        (body, header)
    } else {
        return Err(DNSParseError::HeaderValidation);
    };

    match parser::dns_parse_body(body, input, header) {
        Ok((_, (response, parse_flags))) => {
            SCLogDebug!("Response header flags: {}", response.header.flags);
            let z_flag = response.header.flags & 0x0040 != 0;
            let opcode = ((response.header.flags >> 11) & 0xf) as u8;
            let flags = response.header.flags;

            let mut tx = DNSTransaction::new(Direction::ToClient);
            if response.invalid_additionals {
                tx.set_event(DNSEvent::InvalidAdditionals);
            }
            if response.invalid_authorities {
                tx.set_event(DNSEvent::InvalidAuthorities);
            }
            tx.response = Some(response);

            if flags & 0x8000 == 0 {
                SCLogDebug!("DNS message is not a response");
                tx.set_event(DNSEvent::NotResponse);
            }

            if z_flag {
                SCLogDebug!("Z-flag set on DNS response");
                tx.set_event(DNSEvent::ZFlagSet);
            }

            if opcode >= 7 {
                tx.set_event(DNSEvent::InvalidOpcode);
            }

            if parse_flags.contains(DNSNameFlags::TRUNCATED) {
                tx.set_event(DNSEvent::NameTooLong);
            }

            if parse_flags.contains(DNSNameFlags::INFINITE_LOOP) {
                tx.set_event(DNSEvent::InfiniteLoop);
            }

            if parse_flags.contains(DNSNameFlags::LABEL_LIMIT) {
                tx.set_event(DNSEvent::TooManyLabels);
            }

            return Ok(tx);
        }
        Err(Err::Incomplete(_)) => {
            // Insufficient data.
            SCLogDebug!("Insufficient data while parsing DNS request");
            return Err(DNSParseError::Incomplete);
        }
        Err(_) => {
            // Error, probably malformed data.
            SCLogDebug!("An error occurred while parsing DNS request");
            return Err(DNSParseError::OtherError);
        }
    }
}

impl DNSState {
    fn new() -> Self {
        Self {
            variant: DnsVariant::Dns,
            state_data: AppLayerStateData::default(),
            tx_id: 0,
            transactions: VecDeque::default(),
            config: None,
            gap: false,
        }
    }

    pub(crate) fn new_variant(variant: DnsVariant) -> Self {
        Self {
            variant,
            state_data: AppLayerStateData::default(),
            tx_id: 0,
            transactions: VecDeque::default(),
            config: None,
            gap: false,
        }
    }

    fn free_tx(&mut self, tx_id: u64) {
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

    fn get_tx(&mut self, tx_id: u64) -> Option<&DNSTransaction> {
        return self.transactions.iter().find(|&tx| tx.id == tx_id + 1);
    }

    /// Set an event. The event is set on the most recent transaction.
    fn set_event(&mut self, event: DNSEvent) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }

        let tx = &mut self.transactions[len - 1];
        tx.tx_data.set_event(event as u8);
    }

    fn parse_request(
        &mut self, input: &[u8], is_tcp: bool, frame: Option<Frame>, flow: *const Flow,
    ) -> bool {
        match dns_parse_request(input, &self.variant) {
            Ok(mut tx) => {
                self.tx_id += 1;
                tx.id = self.tx_id;
                if let Some(frame) = frame {
                    frame.set_tx(flow, tx.id);
                }
                self.transactions.push_back(tx);
                return true;
            }
            Err(e) => match e {
                DNSParseError::HeaderValidation => {
                    return !is_tcp;
                }
                DNSParseError::NotRequest => {
                    self.set_event(DNSEvent::NotRequest);
                    return false;
                }
                DNSParseError::Incomplete => {
                    self.set_event(DNSEvent::MalformedData);
                    return false;
                }
                DNSParseError::OtherError => {
                    self.set_event(DNSEvent::MalformedData);
                    return false;
                }
            },
        }
    }

    pub(crate) fn parse_request_udp(
        &mut self, flow: *mut Flow, stream_slice: StreamSlice,
    ) -> bool {
        let input = stream_slice.as_slice();
        let frame = Frame::new(
            flow,
            &stream_slice,
            input,
            input.len() as i64,
            DnsFrameType::Pdu as u8,
            None,
        );
        self.parse_request(input, false, frame, flow)
    }

    fn parse_response_udp(&mut self, flow: *mut Flow, stream_slice: StreamSlice) -> bool {
        let input = stream_slice.as_slice();
        let frame = Frame::new(
            flow,
            &stream_slice,
            input,
            input.len() as i64,
            DnsFrameType::Pdu as u8,
            None,
        );
        self.parse_response(input, false, frame, flow)
    }

    fn parse_response(
        &mut self, input: &[u8], is_tcp: bool, frame: Option<Frame>, flow: *const Flow,
    ) -> bool {
        match dns_parse_response(input) {
            Ok(mut tx) => {
                self.tx_id += 1;
                tx.id = self.tx_id;
                if let Some(ref mut config) = &mut self.config {
                    if let Some(response) = &tx.response {
                        if let Some(config) = config.remove(&response.header.tx_id) {
                            tx.tx_data.config = config;
                        }
                    }
                }
                if let Some(frame) = frame {
                    frame.set_tx(flow, tx.id);
                }
                self.transactions.push_back(tx);
                return true;
            }
            Err(e) => match e {
                DNSParseError::HeaderValidation => {
                    return !is_tcp;
                }
                _ => {
                    self.set_event(DNSEvent::MalformedData);
                    return false;
                }
            },
        }
    }

    /// TCP variation of response request parser to handle the length
    /// prefix.
    ///
    /// Returns the number of messages parsed.
    fn parse_request_tcp(
        &mut self, flow: *mut Flow, stream_slice: StreamSlice,
    ) -> AppLayerResult {
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
        while !cur_i.is_empty() {
            if cur_i.len() == 1 {
                return AppLayerResult::incomplete(consumed as u32, 2_u32);
            }
            let size = match be_u16(cur_i) as IResult<&[u8], u16> {
                Ok((_, len)) => len,
                _ => 0,
            } as usize;
            SCLogDebug!(
                "[request] Have {} bytes, need {} to parse",
                cur_i.len(),
                size + 2
            );
            if size > 0 && cur_i.len() >= size + 2 {
                let msg = &cur_i[2..(size + 2)];
                sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToServer as i32);
                let frame = Frame::new(
                    flow,
                    &stream_slice,
                    msg,
                    msg.len() as i64,
                    DnsFrameType::Pdu as u8,
                    None,
                );
                if self.parse_request(msg, true, frame, flow) {
                    cur_i = &cur_i[(size + 2)..];
                    consumed += size + 2;
                } else {
                    return AppLayerResult::err();
                }
            } else if size == 0 {
                cur_i = &cur_i[2..];
                consumed += 2;
            } else {
                SCLogDebug!(
                    "[request]Not enough DNS traffic to parse. Returning {}/{}",
                    consumed as u32,
                    (size + 2) as u32
                );
                return AppLayerResult::incomplete(consumed as u32, (size + 2) as u32);
            }
        }
        AppLayerResult::ok()
    }

    /// TCP variation of the response parser to handle the length
    /// prefix.
    ///
    /// Returns the number of messages parsed.
    fn parse_response_tcp(
        &mut self, flow: *mut Flow, stream_slice: StreamSlice,
    ) -> AppLayerResult {
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
        while !cur_i.is_empty() {
            if cur_i.len() == 1 {
                return AppLayerResult::incomplete(consumed as u32, 2_u32);
            }
            let size = match be_u16(cur_i) as IResult<&[u8], u16> {
                Ok((_, len)) => len,
                _ => 0,
            } as usize;
            SCLogDebug!(
                "[response] Have {} bytes, need {} to parse",
                cur_i.len(),
                size + 2
            );
            if size > 0 && cur_i.len() >= size + 2 {
                let msg = &cur_i[2..(size + 2)];
                sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToClient as i32);
                let frame = Frame::new(
                    flow,
                    &stream_slice,
                    msg,
                    msg.len() as i64,
                    DnsFrameType::Pdu as u8,
                    None,
                );
                if self.parse_response(msg, true, frame, flow) {
                    cur_i = &cur_i[(size + 2)..];
                    consumed += size + 2;
                } else {
                    return AppLayerResult::err();
                }
            } else if size == 0 {
                cur_i = &cur_i[2..];
                consumed += 2;
            } else {
                SCLogDebug!(
                    "[response]Not enough DNS traffic to parse. Returning {}/{}",
                    consumed as u32,
                    (cur_i.len() - consumed) as u32
                );
                return AppLayerResult::incomplete(consumed as u32, (size + 2) as u32);
            }
        }
        AppLayerResult::ok()
    }

    /// A gap has been seen in the request direction. Set the gap flag.
    fn request_gap(&mut self, gap: u32) {
        if gap > 0 {
            self.gap = true;
        }
    }

    /// A gap has been seen in the response direction. Set the gap
    /// flag.
    fn response_gap(&mut self, gap: u32) {
        if gap > 0 {
            self.gap = true;
        }
    }
}

const DNS_HEADER_SIZE: usize = 12;

pub(crate) fn probe_header_validity(header: &DNSHeader, rlen: usize) -> (bool, bool, bool) {
    let nb_records = header.additional_rr as usize
        + header.answer_rr as usize
        + header.authority_rr as usize
        + header.questions as usize;

    let min_msg_size = 2 * nb_records;
    if min_msg_size > rlen {
        // Not enough data for records defined in the header, or
        // impossibly large.
        return (false, false, false);
    }

    if nb_records == 0 && rlen > DNS_HEADER_SIZE {
        // zero fields, data size should be just DNS_HEADER_SIZE
        // happens when DNS server returns format error
        return (false, false, false);
    }

    let is_request = header.flags & 0x8000 == 0;
    if is_request && header.questions == 0 {
        return (false, false, false);
    }
    return (true, is_request, false);
}

/// Probe input to see if it looks like DNS.
///
/// Returns a tuple of booleans: (is_dns, is_request, incomplete)
fn probe(input: &[u8], dlen: usize) -> (bool, bool, bool) {
    // Trim input to dlen if larger.
    let input = if input.len() <= dlen {
        input
    } else {
        &input[..dlen]
    };

    // If input is less than dlen then we know we don't have enough data to
    // parse a complete message, so perform header validation only.
    if input.len() < dlen {
        if let Ok((_, header)) = parser::dns_parse_header(input) {
            return probe_header_validity(&header, dlen);
        } else {
            return (false, false, false);
        }
    }

    match parser::dns_parse_header(input) {
        Ok((body, header)) => match parser::dns_parse_body(body, input, header) {
            Ok((_, (request, _flags))) => probe_header_validity(&request.header, dlen),
            Err(Err::Incomplete(_)) => (false, false, true),
            Err(_) => (false, false, false),
        },
        Err(_) => (false, false, false),
    }
}

/// Probe TCP input to see if it looks like DNS.
fn probe_tcp(input: &[u8]) -> (bool, bool, bool) {
    match be_u16(input) as IResult<&[u8], u16> {
        Ok((rem, dlen)) => {
            return probe(rem, dlen as usize);
        }
        Err(Err::Incomplete(_)) => {
            return (false, false, true);
        }
        _ => {}
    }
    return (false, false, false);
}

/// Returns *mut DNSState
pub(crate) extern "C" fn state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = DNSState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

/// Params:
/// - state: *mut DNSState as void pointer
pub(crate) extern "C" fn state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    std::mem::drop(unsafe { Box::from_raw(state as *mut DNSState) });
}

pub(crate) unsafe extern "C" fn state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, DNSState);
    state.free_tx(tx_id);
}

/// C binding parse a DNS request. Returns 1 on success, -1 on failure.
pub(crate) unsafe extern "C" fn parse_request(
    flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);
    state.parse_request_udp(flow, stream_slice);
    AppLayerResult::ok()
}

unsafe extern "C" fn parse_response(
    flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);
    state.parse_response_udp(flow, stream_slice);
    AppLayerResult::ok()
}

/// C binding parse a DNS request. Returns 1 on success, -1 on failure.
unsafe extern "C" fn parse_request_tcp(
    flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);
    if stream_slice.is_gap() {
        state.request_gap(stream_slice.gap_size());
    } else if !stream_slice.is_empty() {
        return state.parse_request_tcp(flow, stream_slice);
    }
    AppLayerResult::ok()
}

unsafe extern "C" fn parse_response_tcp(
    flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);
    if stream_slice.is_gap() {
        state.response_gap(stream_slice.gap_size());
    } else if !stream_slice.is_empty() {
        return state.parse_response_tcp(flow, stream_slice);
    }
    AppLayerResult::ok()
}

pub(crate) extern "C" fn tx_get_alstate_progress(
    _tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    // This is a stateless parser, just the existence of a transaction
    // means its complete.
    SCLogDebug!("tx_get_alstate_progress");
    return 1;
}

pub(crate) unsafe extern "C" fn state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, DNSState);
    SCLogDebug!("state_get_tx_count: returning {}", state.tx_id);
    return state.tx_id;
}

pub(crate) unsafe extern "C" fn state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
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
pub extern "C" fn SCDnsTxIsRequest(tx: &mut DNSTransaction) -> bool {
    tx.request.is_some()
}

#[no_mangle]
pub extern "C" fn SCDnsTxIsResponse(tx: &mut DNSTransaction) -> bool {
    tx.response.is_some()
}

pub(crate) unsafe extern "C" fn state_get_tx_data(
    tx: *mut std::os::raw::c_void,
) -> *mut AppLayerTxData {
    let tx = cast_pointer!(tx, DNSTransaction);
    return &mut tx.tx_data;
}

pub(crate) unsafe extern "C" fn dns_get_state_data(
    state: *mut std::os::raw::c_void,
) -> *mut AppLayerStateData {
    let state = cast_pointer!(state, DNSState);
    return &mut state.state_data;
}

/// Get the DNS query name at index i.
#[no_mangle]
pub unsafe extern "C" fn SCDnsTxGetQueryName(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, i: u32,
    buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, DNSTransaction);
    let queries = if (flow_flags & STREAM_TOSERVER) == 0 {
        tx.response.as_ref().map(|response| &response.queries)
    } else {
        tx.request.as_ref().map(|request| &request.queries)
    };
    let index = i as usize;

    if let Some(queries) = queries {
        if let Some(query) = queries.get(index) {
            if !query.name.value.is_empty() {
                *buf = query.name.value.as_ptr();
                *len = query.name.value.len() as u32;
                return true;
            }
        }
    }

    false
}

/// Get the DNS response answer name and index i.
#[no_mangle]
pub unsafe extern "C" fn SCDnsTxGetAnswerName(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, i: u32,
    buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, DNSTransaction);
    let answers = if (flow_flags & STREAM_TOSERVER) == 0 {
        tx.response.as_ref().map(|response| &response.answers)
    } else {
        tx.request.as_ref().map(|request| &request.answers)
    };
    let index = i as usize;

    if let Some(answers) = answers {
        if let Some(answer) = answers.get(index) {
            if !answer.name.value.is_empty() {
                *buf = answer.name.value.as_ptr();
                *len = answer.name.value.len() as u32;
                return true;
            }
        }
    }

    false
}

/// Get the DNS response authority name at index i.
#[no_mangle]
pub unsafe extern "C" fn SCDnsTxGetAuthorityName(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flow_flags: u8, i: u32,
    buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, DNSTransaction);
    let index = i as usize;

    if let Some(response) = &tx.response {
        if let Some(record) = response.authorities.get(index) {
            if !record.name.value.is_empty() {
                *buf = record.name.value.as_ptr();
                *len = record.name.value.len() as u32;
                return true;
            }
        }
    }

    false
}

/// Get the DNS response additional name at index i.
#[no_mangle]
pub unsafe extern "C" fn SCDnsTxGetAdditionalName(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flow_flags: u8, i: u32,
    buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, DNSTransaction);
    let index = i as usize;

    if let Some(response) = &tx.response {
        if let Some(record) = response.additionals.get(index) {
            if !record.name.value.is_empty() {
                *buf = record.name.value.as_ptr();
                *len = record.name.value.len() as u32;
                return true;
            }
        }
    }

    false
}

fn get_rdata_name(data: &DNSRData) -> Option<&DNSName> {
    match data {
        DNSRData::CNAME(name) | DNSRData::PTR(name) | DNSRData::MX(name) | DNSRData::NS(name) => {
            Some(name)
        }
        DNSRData::SOA(soa) => Some(&soa.mname),
        _ => None,
    }
}

/// Get the DNS response answer rdata at index i that could be a domain name.
#[no_mangle]
pub unsafe extern "C" fn SCDnsTxGetAnswerRdata(
    tx: &mut DNSTransaction, i: u32, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let index = i as usize;

    if let Some(response) = &tx.response {
        if let Some(record) = response.answers.get(index) {
            if let Some(name) = get_rdata_name(&record.data) {
                if !name.value.is_empty() {
                    *buf = name.value.as_ptr();
                    *len = name.value.len() as u32;
                    return true;
                }
            }
        }
    }

    false
}

/// Get the DNS response authority rdata at index i that could be a domain name.
#[no_mangle]
pub unsafe extern "C" fn SCDnsTxGetAuthorityRdata(
    tx: &mut DNSTransaction, i: u32, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let index = i as usize;

    if let Some(response) = &tx.response {
        if let Some(record) = response.authorities.get(index) {
            if let Some(name) = get_rdata_name(&record.data) {
                if !name.value.is_empty() {
                    *buf = name.value.as_ptr();
                    *len = name.value.len() as u32;
                    return true;
                }
            }
        }
    }

    false
}

/// Get the DNS response additional rdata at index i that could be a domain name.
#[no_mangle]
pub unsafe extern "C" fn SCDnsTxGetAdditionalRdata(
    tx: &mut DNSTransaction, i: u32, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let index = i as usize;

    if let Some(response) = &tx.response {
        if let Some(record) = response.additionals.get(index) {
            if let Some(name) = get_rdata_name(&record.data) {
                if !name.value.is_empty() {
                    *buf = name.value.as_ptr();
                    *len = name.value.len() as u32;
                    return true;
                }
            }
        }
    }

    false
}

/// Get the DNS response flags for a transaction.
#[no_mangle]
pub extern "C" fn SCDnsTxGetResponseFlags(tx: &mut DNSTransaction) -> u16 {
    return tx.rcode();
}

pub(crate) unsafe extern "C" fn probe_udp(
    _flow: *const Flow, _dir: u8, input: *const u8, len: u32, rdir: *mut u8,
) -> AppProto {
    if input.is_null() || len < std::mem::size_of::<DNSHeader>() as u32 {
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

unsafe extern "C" fn c_probe_tcp(
    _flow: *const Flow, direction: u8, input: *const u8, len: u32, rdir: *mut u8,
) -> AppProto {
    if input.is_null() || len < std::mem::size_of::<DNSHeader>() as u32 + 2 {
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
        if (direction & DIR_BOTH) != u8::from(dir) {
            *rdir = dir as u8;
        }
        return ALPROTO_DNS;
    }
    return 0;
}

unsafe extern "C" fn apply_tx_config(
    _state: *mut std::os::raw::c_void, _tx: *mut std::os::raw::c_void, _mode: std::os::raw::c_int,
    config: AppLayerTxConfig,
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
pub unsafe extern "C" fn SCRegisterDnsUdpParser() {
    let default_port = std::ffi::CString::new("[53]").unwrap();
    let parser = RustParser {
        name: b"dns\0".as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(probe_udp),
        probe_tc: Some(probe_udp),
        min_depth: 0,
        max_depth: std::mem::size_of::<DNSHeader>() as u16,
        state_new,
        state_free,
        tx_free: state_tx_free,
        parse_ts: parse_request,
        parse_tc: parse_response,
        get_tx_count: state_get_tx_count,
        get_tx: state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: tx_get_alstate_progress,
        get_eventinfo: Some(DNSEvent::get_event_info),
        get_eventinfo_byid: Some(DNSEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(crate::applayer::state_get_tx_iterator::<DNSState, DNSTransaction>),
        get_tx_data: state_get_tx_data,
        get_state_data: dns_get_state_data,
        apply_tx_config: Some(apply_tx_config),
        flags: 0,
        get_frame_id_by_name: Some(DnsFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(DnsFrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_DNS = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCRegisterDnsTcpParser() {
    let default_port = std::ffi::CString::new("53").unwrap();
    let parser = RustParser {
        name: b"dns\0".as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(c_probe_tcp),
        probe_tc: Some(c_probe_tcp),
        min_depth: 0,
        max_depth: std::mem::size_of::<DNSHeader>() as u16 + 2,
        state_new,
        state_free,
        tx_free: state_tx_free,
        parse_ts: parse_request_tcp,
        parse_tc: parse_response_tcp,
        get_tx_count: state_get_tx_count,
        get_tx: state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: tx_get_alstate_progress,
        get_eventinfo: Some(DNSEvent::get_event_info),
        get_eventinfo_byid: Some(DNSEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(crate::applayer::state_get_tx_iterator::<DNSState, DNSTransaction>),
        get_tx_data: state_get_tx_data,
        get_state_data: dns_get_state_data,
        apply_tx_config: Some(apply_tx_config),
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: Some(DnsFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(DnsFrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_DNS = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
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
        #[rustfmt::skip]
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
            state.parse_request_tcp(
                std::ptr::null_mut(),
                StreamSlice::from_slice(&request, STREAM_TOSERVER, 0)
            )
        );
    }

    #[test]
    fn test_dns_parse_request_tcp_short_payload() {
        // A UDP DNS request with the DNS payload starting at byte 42.
        // From pcap: https://github.com/jasonish/suricata-verify/blob/7cc0e1bd0a5249b52e6e87d82d57c0b6aaf75fce/dns-udp-dig-a-www-suricata-ids-org/dig-a-www.suricata-ids.org.pcap
        #[rustfmt::skip]
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
            state.parse_request_tcp(
                std::ptr::null_mut(),
                StreamSlice::from_slice(&request, STREAM_TOSERVER, 0)
            )
        );
    }

    #[test]
    fn test_dns_parse_response_tcp_valid() {
        // A UDP DNS response with the DNS payload starting at byte 42.
        // From pcap: https://github.com/jasonish/suricata-verify/blob/7cc0e1bd0a5249b52e6e87d82d57c0b6aaf75fce/dns-udp-dig-a-www-suricata-ids-org/dig-a-www.suricata-ids.org.pcap
        #[rustfmt::skip]
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
            state.parse_response_tcp(
                std::ptr::null_mut(),
                StreamSlice::from_slice(&request, STREAM_TOCLIENT, 0)
            )
        );
    }

    // Test that a TCP DNS payload won't be parsed if there is not
    // enough data.
    #[test]
    fn test_dns_parse_response_tcp_short_payload() {
        // A UDP DNS response with the DNS payload starting at byte 42.
        // From pcap: https://github.com/jasonish/suricata-verify/blob/7cc0e1bd0a5249b52e6e87d82d57c0b6aaf75fce/dns-udp-dig-a-www-suricata-ids-org/dig-a-www.suricata-ids.org.pcap
        #[rustfmt::skip]
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
            state.parse_response_tcp(
                std::ptr::null_mut(),
                StreamSlice::from_slice(&request, STREAM_TOCLIENT, 0)
            )
        );
    }

    // Port of the C RustDNSUDPParserTest02 unit test.
    #[test]
    fn test_dns_udp_parser_test_01() {
        /* query: abcdefghijk.com
         * TTL: 86400
         * serial 20130422 refresh 28800 retry 7200 exp 604800 min ttl 86400
         * ns, hostmaster */
        #[rustfmt::skip]
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
        assert!(state.parse_response(buf, false, None, std::ptr::null()));
    }

    // Port of the C RustDNSUDPParserTest02 unit test.
    #[test]
    fn test_dns_udp_parser_test_02() {
        #[rustfmt::skip]
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
        assert!(state.parse_response(buf, false, None, std::ptr::null()));
    }

    // Port of the C RustDNSUDPParserTest03 unit test.
    #[test]
    fn test_dns_udp_parser_test_03() {
        #[rustfmt::skip]
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
        assert!(state.parse_response(buf, false, None, std::ptr::null()));
    }

    // Port of the C RustDNSUDPParserTest04 unit test.
    //
    // Test the TXT records in an answer.
    #[test]
    fn test_dns_udp_parser_test_04() {
        #[rustfmt::skip]
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
        assert!(state.parse_response(buf, false, None, std::ptr::null()));
    }

    // Port of the C RustDNSUDPParserTest05 unit test.
    //
    // Test TXT records in answer with a bad length.
    #[test]
    fn test_dns_udp_parser_test_05() {
        #[rustfmt::skip]
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
        assert!(!state.parse_response(buf, false, None, std::ptr::null()));
    }

    // Port of the C RustDNSTCPParserTestMultiRecord unit test.
    #[test]
    fn test_dns_tcp_parser_multi_record() {
        #[rustfmt::skip]
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
        let flow = std::ptr::null_mut();

        let mut state = DNSState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request_tcp(flow, StreamSlice::from_slice(buf, STREAM_TOSERVER, 0))
        );
    }

    #[test]
    fn test_dns_tcp_parser_split_payload() {
        // A NULL flow.
        let flow = std::ptr::null_mut();

        /* incomplete payload */
        #[rustfmt::skip]
        let buf1: &[u8] = &[
            0x00, 0x1c, 0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];
        /* complete payload plus the start of a new payload */
        #[rustfmt::skip]
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
        #[rustfmt::skip]
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
        assert_eq!(DNSEvent::from_id(99), None);
    }

    #[test]
    fn test_dns_event_to_cstring() {
        assert_eq!(DNSEvent::MalformedData.to_cstring(), "malformed_data\0");
    }

    #[test]
    fn test_dns_event_from_string() {
        let name = "malformed_data";
        let event = DNSEvent::from_string(name).unwrap();
        assert_eq!(event, DNSEvent::MalformedData);
        assert_eq!(event.to_cstring(), format!("{}\0", name));
    }
}
