//! TLS parser
//!
//! The TLS parser is based on the `tls-parser` crate to parse the handshake phase
//! of a TLS connection. It stores the selected parameters (like the negociated ciphersuite,
//! compression method, etc.) in the parser state.
//!
//! It handles defragmentation (TCP chunks, or TLS record and messages fragmentation), and
//! updates the TLS state machine to detect invalid transitions (for ex, unexpected messages,
//! or messages sent in wrong order).
//!
//! When the session becomes encrypted, messages are not parsed anymore.

extern crate libc;

use std;
use std::{mem,str};
use libc::c_char;
use std::ffi::CStr;

use nom::*;

use num_traits::FromPrimitive;

use suricata_interface::rparser::*;

use tls_parser::tls::{TlsMessage,TlsMessageHandshake,TlsRecordType,TlsRawRecord,parse_tls_raw_record,parse_tls_record_with_header};
use tls_parser::tls_ciphers::*;
use tls_parser::tls_dh::*;
use tls_parser::tls_ec::*;
use tls_parser::tls_extensions::*;
use tls_parser::tls_sign_hash::*;
use tls_parser::tls_states::{TlsState,tls_state_transition};

/// TLS parser events
#[repr(u32)]
pub enum TlsParserEvents {
    /// Heartbeat record wrong length (heartbleed attack)
    HeartbeatOverflow = 1,
    /// Transition not allowed by TLS state machine
    InvalidState = 2,

    /// Incomplete record
    RecordIncomplete = 3,
    /// Record contains extra bytes after message(s)
    RecordWithExtraBytes = 4,
    /// TLS record exceeds allowed size (2^24 bytes)
    RecordOverflow = 5,
}

#[no_mangle]
pub static TLS_EVENTS: &[MyEvent]  = &[
    r_event!( b"EMPTY_MESSAGE\0", 0 ),
    r_event!( b"OVERFLOW_HEARTBEAT_MESSAGE\0", 1 ),
    r_event!( b"INVALID_STATE\0", 2 ),
    r_event!( b"RECORD_INCOMPLETE\0", 3 ),
    r_event!( b"RECORD_WITH_EXTRA_BYTES\0", 4 ),
    r_event!( b"RECORD_OVERFLOW\0", 5 ),
    r_event!(0, -1),
];

/// TLS parser state
pub struct TlsParser<'a> {
    _o: Option<&'a[u8]>,

    /// Events raised during parsing. These events should be read (and removed)
    /// by the client application after checking the parsing return value.
    pub events: Vec<u32>,

    /// Selected compression method
    ///
    /// Only valid after the ServerHello message
    pub compression: Option<u8>,
    /// Selected ciphersuite
    ///
    /// Only valid after the ServerHello message
    pub cipher: Option<&'a TlsCipherSuite>,
    /// TLS state
    pub state: TlsState,

    /// Exchanged key size
    ///
    /// This value is known only for Diffie-Hellman ciphersuites, and after
    /// the ServerKeyExchange message.
    pub kx_bits: Option<u32>,

    pub sni: Vec<String>,

    /// TCP chunks defragmentation buffer
    pub tcp_buffer: Vec<u8>,

    /// Handshake defragmentation buffer
    pub buffer: Vec<u8>,

    /// Flag set if the signature_algorithms extension was sent by the client
    pub has_signature_algorithms: bool,
}

impl<'a> TlsParser<'a> {
    /// Allocation function for a new TLS parser instance
    pub fn new(i: &'a[u8]) -> TlsParser<'a> {
        TlsParser{
            _o:Some(i),
            events:Vec::new(),
            compression:None,
            cipher:None,
            state:TlsState::None,
            kx_bits: None,
            sni: Vec::new(),
            // capacity is the amount of space allocated, which means elements can be added
            // without reallocating the vector
            tcp_buffer:Vec::with_capacity(16384),
            buffer:Vec::with_capacity(16384),
            has_signature_algorithms:false,
        }
    }

    /// Message-level TLS parsing
    fn parse_message_level(&mut self, msg: &TlsMessage) -> u32 {
        debug!("parse_message_level {:?}",msg);
        let mut status = R_STATUS_OK;
        if self.state == TlsState::ClientChangeCipherSpec {
            // Ignore records from now on, they are encrypted
            return status;
        };
        // update state machine
        match tls_state_transition(self.state, msg) {
            Ok(s)  => self.state = s,
            Err(_) => {
                self.state = TlsState::Invalid;
                self.events.push(TlsParserEvents::InvalidState as u32);
                status |= R_STATUS_EVENTS;
            },
        };
        debug!("TLS new state: {:?}",self.state);
        // extract variables
        match *msg {
            TlsMessage::Handshake(ref m) => {
                match *m {
                    TlsMessageHandshake::ClientHello(ref content) => {
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        match &ext {
                            &IResult::Done(_,ref l) => {
                                for extension in l {
                                    match *extension {
                                        TlsExtension::SignatureAlgorithms(_) => self.has_signature_algorithms = true,
                                        TlsExtension::SNI(ref v) => {
                                            for &(t,sni) in v {
                                                let s = String::from_utf8(sni.to_vec());
                                                match s {
                                                    Ok(name) => {
                                                        debug!("SNI: {} {:?}",t,name);
                                                        self.sni.push(name)
                                                    },
                                                    Err(e) => {
                                                        warn!("Invalid UTF-8 data in SNI ({})",e);
                                                        self.sni.push("<Invalid UTF-8 data>".to_string())
                                                    },
                                                };
                                            }
                                        },
                                        _ => (),
                                    }
                                }
                            },
                            e @ _ => error!("Could not parse extentions: {:?}",e),
                        };
                        debug!("ext {:?}", ext);
                    },
                    TlsMessageHandshake::ServerHello(ref content) => {
                        self.compression = Some(content.compression);
                        self.cipher = TlsCipherSuite::from_id(content.cipher);
                        match self.cipher {
                            Some(c) => {
                                debug!("Selected cipher: {:?}", c)
                            },
                            _ => warn!("Unknown cipher 0x{:x}", content.cipher),
                        };
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        debug!("extensions: {:?}", ext);
                    },
                    TlsMessageHandshake::ServerHelloV13(ref content) => {
                        // XXX Tls 1.3 ciphers are different
                        self.cipher = TlsCipherSuite::from_id(content.cipher);
                        match self.cipher {
                            Some(c) => {
                                debug!("Selected cipher: {:?}", c)
                            },
                            _ => warn!("Unknown cipher 0x{:x}", content.cipher),
                        };
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        debug!("extensions: {:?}", ext);
                    },
                    TlsMessageHandshake::Certificate(ref content) => {
                        debug!("cert chain length: {}",content.cert_chain.len());
                        for cert in &content.cert_chain {
                            debug!("cert: {:?}",cert);
                        }
                    },
                    TlsMessageHandshake::ServerKeyExchange(ref content) => {
                        // The SKE contains the chosen algorithm for the ephemeral key
                        match self.cipher {
                            None => (),
                            Some (c) => { self.kx_bits = rusticata_tls_get_kx_bits(c,content.parameters,self.has_signature_algorithms) },
                        }
                    },
                    _ => (),
                }
            },
            TlsMessage::Heartbeat(ref d) => {
                if d.payload_len as usize > d.payload.len() {
                    warn!("Heartbeat message with incorrect length {}. Heartbleed attempt ?",d.payload.len());
                    self.events.push(TlsParserEvents::HeartbeatOverflow as u32);
                    status |= R_STATUS_EVENTS;
                }
            },
            _ => (),
        }

        status
    }

    fn parse_record_level<'b>(&mut self, r: &TlsRawRecord<'b>) -> u32 {
        let mut v : Vec<u8>;
        let mut status = R_STATUS_OK;

        debug!("parse_record_level {}",r.data.len());
        // debug!("{:?}",r.hdr);
        // debug!("{:?}",r.data);

        // only parse some message types
        match TlsRecordType::from_u8(r.hdr.record_type) {
            Some(TlsRecordType::ChangeCipherSpec) => (),
            Some(TlsRecordType::Handshake)        => (),
            _ => return status,
        }

        // Check if a record is being defragmented
        let record_buffer = match self.buffer.len() {
            0 => r.data,
            _ => {
                v = self.buffer.split_off(0);
                // sanity check vector length to avoid memory exhaustion
                // maximum length may be 2^24 (handshake message)
                if self.buffer.len() + r.data.len() > 16777216 {
                    self.events.push(TlsParserEvents::RecordOverflow as u32);
                    return R_STATUS_EVENTS;
                };
                v.extend_from_slice(r.data);
                v.as_slice()
            },
        };
        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            return status;
        };
        // XXX record may be compressed
        //
        // Parse record contents as plaintext
        match parse_tls_record_with_header(record_buffer,r.hdr.clone()) {
            IResult::Done(rem2,ref msg_list) => {
                for msg in msg_list {
                    status |= self.parse_message_level(msg);
                };
                if rem2.len() > 0 {
                    warn!("extra bytes in TLS record: {:?}",rem2);
                    self.events.push(TlsParserEvents::RecordWithExtraBytes as u32);
                    status |= R_STATUS_EVENTS;
                };
            }
            IResult::Incomplete(_) => {
                debug!("Defragmentation required (TLS record)");
                // Record is fragmented
                self.buffer.extend_from_slice(r.data);
            },
            IResult::Error(e) => { warn!("parse_tls_record_with_header failed: {:?}",e); status |= R_STATUS_FAIL; },
        };

        status
    }

    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_level<'b>(&mut self, i: &'b[u8]) -> u32 {
        let mut v : Vec<u8>;
        let mut status = R_STATUS_OK;
        debug!("parse_tcp_level ({})",i.len());
        // debug!("{:?}",i);
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer.len() {
            0 => i,
            _ => {
                v = self.tcp_buffer.split_off(0);
                // sanity check vector length to avoid memory exhaustion
                // maximum length may be 2^24 (handshake message)
                if self.tcp_buffer.len() + i.len() > 16777216 {
                    self.events.push(TlsParserEvents::RecordOverflow as u32);
                    return R_STATUS_EVENTS;
                };
                v.extend_from_slice(i);
                v.as_slice()
            },
        };
        // debug!("tcp_buffer ({})",tcp_buffer.len());
        let mut cur_i = tcp_buffer;
        while cur_i.len() > 0 {
            match parse_tls_raw_record(cur_i) {
                IResult::Done(rem, ref r) => {
                    // debug!("rem: {:?}",rem);
                    cur_i = rem;
                    status |= self.parse_record_level(r);
                },
                IResult::Incomplete(_) => {
                    debug!("Fragmentation required (TCP level)");
                    self.tcp_buffer.extend_from_slice(cur_i);
                    break;
                },
                IResult::Error(e) => { warn!("Parsing failed: {:?}",e); break },
            }
        };
        status
    }
}

r_declare_state_new!(r_tls_state_new,TlsParser,b"TLS parser");
r_declare_state_free!(r_tls_state_free,TlsParser,{ () });

impl<'a> RParser for TlsParser<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        debug!("[TLS->parse: direction={}, len={}]",direction,i.len());

        if i.len() == 0 {
            // Connection closed ?
            return R_STATUS_OK;
        };

        self.parse_tcp_level(i)
    }

    fn get_next_event(&mut self) -> u32 {
        match self.events.pop() {
            None     => R_NO_MORE_EVENTS,
            Some(ev) => ev,
        }
    }
}

fn tls_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    // first byte is record type (between 0x14 and 0x17, 0x16 is handhake)
    // second is TLS version major (0x3)
    // third is TLS version minor (0x0 for SSLv3, 0x1 for TLSv1.0, etc.)
    match (i[0],i[1],i[2]) {
        (0x14...0x17,0x03,0...3) => true,
        _ => false,
    }
}

r_implement_probe!(r_tls_probe,tls_probe,ALPROTO_TLS);
r_implement_parse!(r_tls_parse,TlsParser);

// --------------------------------------------





/// Get the select ciphersuite
///
/// Returns the selected ciphersuite identifier, or 0 if not yet known.
#[no_mangle]
pub extern fn rusticata_tls_get_cipher(this: &TlsParser) -> u32
{
    match this.cipher {
        None    => 0,
        Some(c) => c.id.into(),
    }
}

/// Get the select compression method
///
/// Returns the selected compression method, or 0 if not yet known.
#[no_mangle]
pub extern fn rusticata_tls_get_compression(this: &TlsParser) -> u32
{
    this.compression.unwrap_or(0) as u32
}

/// Get the exchanged key size
///
/// Returns the selected size of the key exchange, or 0 if not yet known.
#[no_mangle]
pub extern fn rusticata_tls_get_dh_key_bits(this: &TlsParser) -> u32
{
    this.kx_bits.unwrap_or(0) as u32
}




/// Get the ciphersuite IANA identifier
///
/// Given a ciphersuite name, return the IANA identifier, or 0 if not found
#[no_mangle]
pub extern fn rusticata_tls_cipher_of_string(value: *const c_char) -> u32
{
    let c_str = unsafe { CStr::from_ptr(value) };
    let s = c_str.to_str().unwrap();
    match TlsCipherSuite::from_name(s) {
        Some(c) => c.id as u32,
        None    => 0,
    }
}

/// Get the ciphersuite key exchange method
#[no_mangle]
pub extern fn rusticata_tls_kx_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.kx.clone() as u32,
        None    => 0,
    }
}

/// Get the ciphersuite authentication method
#[no_mangle]
pub extern fn rusticata_tls_au_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.au.clone() as u32,
        None    => 0,
    }
}

/// Get the ciphersuite encryption method
#[no_mangle]
pub extern fn rusticata_tls_enc_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.enc.clone() as u32,
        None    => 0,
    }
}

/// Get the ciphersuite encryption mode
#[no_mangle]
pub extern fn rusticata_tls_encmode_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.enc_mode.clone() as u32,
        None    => 0,
    }
}

/// Get the ciphersuite MAC method
#[no_mangle]
pub extern fn rusticata_tls_mac_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.mac.clone() as u32,
        None    => 0,
    }
}

fn rusticata_tls_get_kx_bits(cipher: &TlsCipherSuite, parameters: &[u8], extended: bool) -> Option<u32> {
    match cipher.kx {
        TlsCipherKx::Ecdhe |
        TlsCipherKx::Ecdh    => {
            // Signed ECDH params
            match parse_content_and_signature(parameters,parse_ecdh_params,extended) {
                IResult::Done(_,ref parsed) => {
                    debug!("ECDHE Parameters: {:?}",parsed);
                    info!("Temp key: using cipher {:?}",parsed.0.curve_params);
                    match &parsed.0.curve_params.params_content {
                        &ECParametersContent::NamedGroup(group_id) => {
                            match NamedGroup::from_u16(group_id) {
                                None => (),
                                Some(named_group) => {
                                    let key_bits = named_group.key_bits().unwrap_or(0);
                                    debug!("NamedGroup: {:?}, key={:?} bits",named_group,key_bits);
                                    return Some(key_bits as u32);
                                },
                            }
                        },
                        c @ _ => info!("Request for key_bits of unknown group {:?}",c),
                    }
                },
                e @ _ => error!("Could not parse ECDHE parameters {:?}",e),
            };
            ()
        },
        TlsCipherKx::Dhe => {
            // Signed DH params
            match parse_content_and_signature(parameters,parse_dh_params,extended) {
                IResult::Done(_,ref parsed) => {
                    debug!("DHE Parameters: {:?}",parsed);
                    info!("Temp key: using DHE size_p={:?} bits",parsed.0.dh_p.len() * 8);
                    return Some((parsed.0.dh_p.len() * 8) as u32);
                },
                e @ _ => error!("Could not parse DHE parameters {:?}",e),
            };
            ()
        },
        TlsCipherKx::Dh => {
            // Anonymous DH params
            match parse_dh_params(parameters) {
                IResult::Done(_,ref parsed) => {
                    debug!("ADH Parameters: {:?}",parsed);
                    info!("Temp key: using ADH size_p={:?} bits",parsed.dh_p.len() * 8);
                    return Some((parsed.dh_p.len() * 8) as u32);
                },
                e @ _ => error!("Could not parse ADH parameters {:?}",e),
            };
            ()
        },
        ref kx @ _ => debug!("unhandled KX algorithm: {:?}",kx),
    };
    None
}
