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

use smb::kerberos_parser::krb5_parser::parse_ap_req;
use smb::kerberos_parser::krb5::{ApReq,Realm,PrincipalName};

use log::*;
use smb::ntlmssp_records::*;
use smb::smb::*;

use nom::{IResult, ErrorKind, le_u16};
use der_parser;
use der_parser::parse_der_oid;

#[derive(Debug,PartialEq)]
pub struct Kerberos5Ticket {
    pub realm: Realm,
    pub sname: PrincipalName,
}

// get SPNEGO
// get OIDS
// if OID has KERBEROS get KERBEROS data
// else if OID has NTLMSSP get NTLMSSP
// else bruteforce NTLMSSP

fn parse_kerberos5_request(blob: &[u8]) -> IResult<&[u8], ApReq>
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
    do_parse!(
        blob,
        base_o: parse_der_oid >>
        tok_id: le_u16 >>
        ap_req: parse_ap_req >>
        ({
            SCLogDebug!("parse_kerberos5_request: base_o {:?}", base_o.as_oid());
            SCLogDebug!("parse_kerberos5_request: tok_id {}", tok_id);
            ap_req
        })
    )
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
                                _ => { SCLogDebug!("unexpected OID {:?}", oid); },
                            }
                        },
                        _ => { SCLogDebug!("expected OID, got {:?}", se); },
                    }
                }
            },
            der_parser::DerObjectContent::OctetString(ref os) => {
                if have_kerberos {
                    match parse_kerberos5_request(os) {
                        IResult::Done(_, req) => {
                            let t = Kerberos5Ticket {
                                realm: req.ticket.realm,
                                sname: req.ticket.sname,
                            };
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
