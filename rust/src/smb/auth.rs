/* Copyright (C) 2018 Open Information Security Foundation
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

use log::*;
use smb::ntlmssp_records::*;
use smb::smb::*;

use nom;
use nom::{IResult, ErrorKind};
use der_parser;

#[derive(Debug,PartialEq)]
pub struct Kerberos5Ticket {
    pub realm: Vec<u8>,
    pub snames: Vec<Vec<u8>>,
}

/// ticket starts with custom header [APPLICATION 1]
fn parse_kerberos5_request_ticket(blob: &[u8]) -> IResult<&[u8], Kerberos5Ticket>
{
    let (rem, ticket_hdr) = match der_parser::der_read_element_header(blob) {
        IResult::Done(rem, o) => (rem, o),
        IResult::Incomplete(needed) => {  return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("parse_kerberos5_request_ticket: ticket {:?}, remaining data {}", ticket_hdr, rem.len());

    if !(ticket_hdr.class == 1 && ticket_hdr.structured == 1 && ticket_hdr.tag == 1 && ticket_hdr.len == rem.len() as u64) {
        SCLogDebug!("parse_kerberos5_request_ticket: bad data");
        return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
    }
    let (_, ticket_seq) = match der_parser::parse_der_sequence(rem) {
        IResult::Done(rem, o) => (rem, o),
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("parse_kerberos5_request_ticket: ticket {:?}", ticket_seq);

    let ticket_vec = ticket_seq.as_sequence().unwrap(); // parse_der_sequence is checked
    SCLogDebug!("parse_kerberos5_request_ticket: ticket_vec {:?}", ticket_vec);
    if ticket_vec.len() != 4 {
        SCLogDebug!("parse_kerberos5_request_ticket: unexpected format");
        return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
    }

    SCLogDebug!("parse_kerberos5_request_ticket: tkt-vno {:?}", ticket_vec[0]);
    SCLogDebug!("parse_kerberos5_request_ticket: realm {:?}", ticket_vec[1]);
    SCLogDebug!("parse_kerberos5_request_ticket: sname {:?}", ticket_vec[2]);
    SCLogDebug!("parse_kerberos5_request_ticket: enc-part {:?}", ticket_vec[3]);

    let gs = match ticket_vec[1].content.as_slice() {
        Ok(s) => s,
        Err(_) => {
            return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
        },
    };
    let realm = match der_parser::parse_der_generalstring(gs) {
        IResult::Done(_, o) => o,
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("parse_kerberos5_request_ticket: realm {:?}", realm);

    if !(realm.class == 0 && realm.structured == 0 && realm.tag == 27) {
        SCLogDebug!("bad realm data");
        return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
    }
    let realm_v = realm.content.as_slice().unwrap().to_vec();
    SCLogDebug!("parse_kerberos5_request_ticket: realm_v {:?}", realm_v);

    let sname = match der_parser::parse_der_sequence(ticket_vec[2].content.as_slice().unwrap()) {
        IResult::Done(_, o) => o,
        IResult::Incomplete(needed) => {
            SCLogDebug!("parse_kerberos5_request_ticket: needed {:?}", needed);
            return IResult::Incomplete(needed);
        },
        IResult::Error(err) => {
            SCLogDebug!("parse_kerberos5_request_ticket: err {:?}", err);
            return IResult::Error(err);
        },
    };
    SCLogDebug!("parse_kerberos5_request_ticket: sname {:?}", sname);

    let sname_vec = sname.as_sequence().unwrap(); // parse_der_sequence is checked
    SCLogDebug!("parse_kerberos5_request_ticket: sname_vec {:?}", sname_vec);

    if sname_vec.len() != 2 {
        SCLogDebug!("parse_kerberos5_request_ticket: unexpected format");
        return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
    }
    let sname_seq = match der_parser::parse_der_sequence(sname_vec[1].content.as_slice().unwrap()) {
        IResult::Done(_, o) => o,
        IResult::Incomplete(needed) => {
            SCLogDebug!("parse_kerberos5_request_ticket: needed {:?}", needed);
            return IResult::Incomplete(needed);
        },
        IResult::Error(err) => {
            SCLogDebug!("parse_kerberos5_request_ticket: err {:?}", err);
            return IResult::Error(err);
        },
    };
    SCLogDebug!("parse_kerberos5_request_ticket: sname_seq {:?}", sname_seq);
    let snamestr_vec = sname_seq.as_sequence().unwrap(); // parse_der_sequence is checked

    let mut snames : Vec<Vec<u8>> = Vec::new();
    for o in snamestr_vec {
        SCLogDebug!("parse_kerberos5_request_ticket: sname o {:?}", o);
        if o.tag == 27 {
            let v = o.content.as_slice().unwrap().to_vec();
            SCLogDebug!("sname {:?}", v);
            snames.push(v);
        }
    }

    let t = Kerberos5Ticket {
        realm: realm_v,
        snames: snames,
    };
    SCLogDebug!("ticket {:?}", t);
    IResult::Done(&[],t)
}

// get SPNEGO
// get OIDS
// if OID has KERBEROS get KERBEROS data
// else if OID has NTLMSSP get NTLMSSP
// else bruteforce NTLMSSP

fn parse_kerberos5_request(blob: &[u8]) -> IResult<&[u8], Kerberos5Ticket>
{
    let blob = match der_parser::parse_der(blob) {
        IResult::Done(_, b) => {
            match b.content.as_slice() {
                Ok(b) => { b },
                _ => { return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR))); },
            }
        },
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    let (rem, base_o) = match der_parser::parse_der_oid(blob) {
        IResult::Done(rem, o) => (rem, o),
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("parse_kerberos5_request: base_o {:?}", base_o);

    // not DER encoded 2 byte length field
    let (rem, tok_id) = match nom::le_u16(rem) {
        IResult::Done(rem, o) => (rem, o),
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("parse_kerberos5_request: tok_id {}", tok_id);

    // APPLICATION 14
    let (rem, base_o) = match der_parser::der_read_element_header(rem) {
        IResult::Done(rem, o) => (rem, o),
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    if !(base_o.class == 1 && base_o.structured == 1 && base_o.tag == 14 && base_o.len == rem.len() as u64) {
        SCLogDebug!("parse_kerberos5_request_ticket: bad data");
        return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
    }

    let base_seq = match der_parser::parse_der_sequence(rem) {
        IResult::Done(_, o) => o,
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("parse_kerberos5_request: base_seq {:?}", base_seq);

    if base_seq.as_sequence().unwrap().len() < 4 {
        SCLogDebug!("parse_kerberos5_request_ticket: bad data");
        return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
    }

    let pvno_s = match base_seq[0].content.as_slice() {
        Ok(s) => s,
        Err(_) => {
            return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
        },
    };
    let pvno = match der_parser::parse_der_integer(pvno_s) {
        IResult::Done(_, o) => o,
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("pvno {:?}", pvno);

    let msg_type_s = match base_seq[1].content.as_slice() {
        Ok(s) => s,
        Err(_) => {
            return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
        },
    };
    let msg_type = match der_parser::parse_der_integer(msg_type_s) {
        IResult::Done(_, o) => o,
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("msg_type {:?}", msg_type);

    let padding_s = match base_seq[2].content.as_slice() {
        Ok(s) => s,
        Err(_) => {
            return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
        },
    };
    let padding = match der_parser::parse_der_bitstring(padding_s) {
        IResult::Done(_, o) => o,
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("padding {:?}", padding);

    let ticket_s = match base_seq[3].content.as_slice() {
        Ok(s) => s,
        Err(_) => {
            return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_KRB_FMT_ERR)));
        },
    };
    parse_kerberos5_request_ticket(ticket_s)
}


pub const SECBLOB_NOT_SPNEGO :  u32 = 128;
pub const SECBLOB_KRB_FMT_ERR : u32 = 129;

fn parse_secblob_get_spnego(blob: &[u8]) -> IResult<&[u8], &[u8]>
{
    let (rem, base_o) = match der_parser::parse_der(blob) {
        IResult::Done(rem, o) => (rem, o),
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("parse_secblob_get_spnego: base_o {:?}", base_o);
    let d = match base_o.content.as_slice() {
        Err(_) => { return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_NOT_SPNEGO))); },
        Ok(d) => d,
    };
    let (next, o) = match der_parser::parse_der_oid(d) {
        IResult::Done(rem,y) => { (rem,y) },
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    SCLogDebug!("parse_secblob_get_spnego: sub_o {:?}", o);

    let oid = match o.content.as_oid() {
        Ok(oid) => oid,
        Err(_) => {
            return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_NOT_SPNEGO)));
        },
    };
    SCLogDebug!("oid {}", oid.to_string());

    match oid.to_string().as_str() {
        "1.3.6.1.5.5.2" => {
            SCLogDebug!("SPNEGO {}", oid);
        },
        _ => {
            return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_NOT_SPNEGO)));
        },
    }

    SCLogDebug!("parse_secblob_get_spnego: next {:?}", next);
    SCLogDebug!("parse_secblob_get_spnego: DONE");
    IResult::Done(rem, next)
}

fn parse_secblob_spnego_start(blob: &[u8]) -> IResult<&[u8], &[u8]>
{
    let (rem, o) = match der_parser::parse_der(blob) {
        IResult::Done(rem,o) => {
            SCLogDebug!("o {:?}", o);
            (rem, o)
        },
        IResult::Incomplete(needed) => { return IResult::Incomplete(needed); },
        IResult::Error(err) => { return IResult::Error(err); },
    };
    let d = match o.content.as_slice() {
        Ok(d) => {
            SCLogDebug!("d: next data len {}",d.len());
            d
        },
        _ => {
            return IResult::Error(error_code!(ErrorKind::Custom(SECBLOB_NOT_SPNEGO)));
        },
    };
    IResult::Done(rem, d)
}

pub struct SpnegoRequest {
    pub krb: Option<Kerberos5Ticket>,
    pub ntlmssp: Option<NtlmsspData>,
}

fn parse_secblob_spnego(blob: &[u8]) -> Option<SpnegoRequest>
{
    let mut have_ntlmssp = false;
    let mut have_kerberos = false;
    let mut kticket : Option<Kerberos5Ticket> = None;
    let mut ntlmssp : Option<NtlmsspData> = None;

    let o = match der_parser::parse_der_sequence(blob) {
        IResult::Done(_, o) => o,
        _ => { return None; },
    };
    for s in o {
        SCLogDebug!("s {:?}", s);

        let n = match s.content.as_slice() {
            Ok(s) => s,
            _ => { continue; },
        };
        let o = match der_parser::parse_der(n) {
            IResult::Done(_,x) => x,
            _ => { continue; },
        };
        SCLogDebug!("o {:?}", o);
        match o.content {
            der_parser::DerObjectContent::Sequence(ref seq) => {
                for se in seq {
                    SCLogDebug!("SEQ {:?}", se);
                    match se.content {
                        der_parser::DerObjectContent::OID(ref oid) => {
                            SCLogDebug!("OID {:?}", oid);
                            match oid.to_string().as_str() {
                                "1.2.840.48018.1.2.2" => { SCLogDebug!("Microsoft Kerberos 5"); },
                                "1.2.840.113554.1.2.2" => { SCLogDebug!("Kerberos 5"); have_kerberos = true; },
                                "1.2.840.113554.1.2.2.1" => { SCLogDebug!("krb5-name"); },
                                "1.2.840.113554.1.2.2.2" => { SCLogDebug!("krb5-principal"); },
                                "1.2.840.113554.1.2.2.3" => { SCLogDebug!("krb5-user-to-user-mech"); },
                                "1.3.6.1.4.1.311.2.2.10" => { SCLogDebug!("NTLMSSP"); have_ntlmssp = true; },
                                "1.3.6.1.4.1.311.2.2.30" => { SCLogDebug!("NegoEx"); },
                                _ => { SCLogNotice!("unexpected OID {:?}", oid); },
                            }
                        },
                        _ => { SCLogNotice!("expected OID, got {:?}", se); },
                    }
                }
            },
            der_parser::DerObjectContent::OctetString(ref os) => {
                if have_kerberos {
                    match parse_kerberos5_request(os) {
                        IResult::Done(_, t) => {
                            kticket = Some(t)
                        },
                        _ => { },
                    }
                }

                if have_ntlmssp && kticket == None {
                    SCLogDebug!("parsing expected NTLMSSP");
                    ntlmssp = parse_ntlmssp_blob(os);
                }
            },
            _ => {},
        }
    }

    let s = SpnegoRequest {
        krb: kticket,
        ntlmssp: ntlmssp,
    };
    Some(s)
}

#[derive(Debug,PartialEq)]
pub struct NtlmsspData {
    pub host: Vec<u8>,
    pub user: Vec<u8>,
    pub domain: Vec<u8>,
    pub version: Option<NTLMSSPVersion>,
}

/// take in blob, search for the header and parse it
fn parse_ntlmssp_blob(blob: &[u8]) -> Option<NtlmsspData>
{
    let mut ntlmssp_data : Option<NtlmsspData> = None;

    SCLogDebug!("NTLMSSP {:?}", blob);
    match parse_ntlmssp(blob) {
        IResult::Done(_, nd) => {
            SCLogDebug!("NTLMSSP TYPE {}/{} nd {:?}",
                    nd.msg_type, &ntlmssp_type_string(nd.msg_type), nd);
            match nd.msg_type {
                NTLMSSP_NEGOTIATE => {
                },
                NTLMSSP_AUTH => {
                    match parse_ntlm_auth_record(nd.data) {
                        IResult::Done(_, ad) => {
                            SCLogDebug!("auth data {:?}", ad);
                            let mut host = ad.host.to_vec();
                            host.retain(|&i|i != 0x00);
                            let mut user = ad.user.to_vec();
                            user.retain(|&i|i != 0x00);
                            let mut domain = ad.domain.to_vec();
                            domain.retain(|&i|i != 0x00);

                            let d = NtlmsspData {
                                host: host,
                                user: user,
                                domain: domain,
                                version: ad.version,
                            };
                            ntlmssp_data = Some(d);
                        },
                        _ => {},
                    }
                },
                _ => {},
            }
        },
        _ => {},
    }
    return ntlmssp_data;
}

// if spnego parsing fails try to fall back to ntlmssp
pub fn parse_secblob(blob: &[u8]) -> Option<SpnegoRequest>
{
    match parse_secblob_get_spnego(blob) {
        IResult::Done(_, spnego) => {
            match parse_secblob_spnego_start(spnego) {
                IResult::Done(_, spnego_start) => {
                    parse_secblob_spnego(spnego_start)
                },
                _ => {
                    match parse_ntlmssp_blob(blob) {
                        Some(n) => {
                            let s = SpnegoRequest {
                                krb: None,
                                ntlmssp: Some(n),
                            };
                            Some(s)
                        },
                        None => { None },
                    }
                },
            }
        },
        _ => {
            match parse_ntlmssp_blob(blob) {
                Some(n) => {
                    let s = SpnegoRequest {
                        krb: None,
                         ntlmssp: Some(n),
                    };
                    Some(s)
                },
                None => { None },
            }
        },
    }
}
