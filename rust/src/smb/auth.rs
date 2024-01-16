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

use crate::kerberos::*;

use crate::smb::ntlmssp_records::*;
use crate::smb::smb::*;

use nom7::{Err, IResult};
use der_parser6::ber::BerObjectContent;
use der_parser6::der::{parse_der_oid, parse_der_sequence};

fn parse_secblob_get_spnego(blob: &[u8]) -> IResult<&[u8], &[u8], SecBlobError>
{
    let (rem, base_o) = der_parser6::parse_der(blob).map_err(Err::convert)?;
    SCLogDebug!("parse_secblob_get_spnego: base_o {:?}", base_o);
    let d = match base_o.content.as_slice() {
        Err(_) => { return Err(Err::Error(SecBlobError::NotSpNego)); },
        Ok(d) => d,
    };
    let (next, o) = parse_der_oid(d).map_err(Err::convert)?;
    SCLogDebug!("parse_secblob_get_spnego: sub_o {:?}", o);

    let oid = match o.content.as_oid() {
        Ok(oid) => oid,
        Err(_) => {
            return Err(Err::Error(SecBlobError::NotSpNego));
        },
    };
    SCLogDebug!("oid {}", oid.to_string());

    match oid.to_string().as_str() {
        "1.3.6.1.5.5.2" => {
            SCLogDebug!("SPNEGO {}", oid);
        },
        _ => {
            return Err(Err::Error(SecBlobError::NotSpNego));
        },
    }

    SCLogDebug!("parse_secblob_get_spnego: next {:?}", next);
    SCLogDebug!("parse_secblob_get_spnego: DONE");
    Ok((rem, next))
}

fn parse_secblob_spnego_start(blob: &[u8]) -> IResult<&[u8], &[u8], SecBlobError>
{
    let (rem, o) = der_parser6::parse_der(blob).map_err(Err::convert)?;
    let d = match o.content.as_slice() {
        Ok(d) => {
            SCLogDebug!("d: next data len {}",d.len());
            d
        },
        _ => {
            return Err(Err::Error(SecBlobError::NotSpNego));
        },
    };
    Ok((rem, d))
}

#[derive(Debug, PartialEq)]
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

    let o = match parse_der_sequence(blob) {
        Ok((_, o)) => o,
        _ => { return None; },
    };
    for s in o {
        SCLogDebug!("s {:?}", s);

        let n = match s.content.as_slice() {
            Ok(s) => s,
            _ => { continue; },
        };
        let o = match der_parser6::parse_der(n) {
            Ok((_,x)) => x,
            _ => { continue; },
        };
        SCLogDebug!("o {:?}", o);
        match o.content {
            BerObjectContent::Sequence(ref seq) => {
                for se in seq {
                    SCLogDebug!("SEQ {:?}", se);
                    if let BerObjectContent::OID(ref oid) = se.content {
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
                    } else {
                        SCLogDebug!("expected OID, got {:?}", se);
                    }
                }
            },
            BerObjectContent::OctetString(os) => {
                if have_kerberos {
                    if let Ok((_, t)) = parse_kerberos5_request(os) {
                        kticket = Some(t)
                    }
                }

                if have_ntlmssp && kticket.is_none() {
                    SCLogDebug!("parsing expected NTLMSSP");
                    ntlmssp = parse_ntlmssp_blob(os);
                }
            },
            _ => {},
        }
    }

    let s = SpnegoRequest {
        krb: kticket,
        ntlmssp,
    };
    Some(s)
}

#[derive(Debug,PartialEq, Eq)]
pub struct NtlmsspData {
    pub host: Vec<u8>,
    pub user: Vec<u8>,
    pub domain: Vec<u8>,
    pub version: Option<NTLMSSPVersion>,
    pub warning: bool,
}

/// take in blob, search for the header and parse it
fn parse_ntlmssp_blob(blob: &[u8]) -> Option<NtlmsspData>
{
    let mut ntlmssp_data : Option<NtlmsspData> = None;

    SCLogDebug!("NTLMSSP {:?}", blob);
    if let Ok((_, nd)) = parse_ntlmssp(blob) {
        SCLogDebug!("NTLMSSP TYPE {}/{} nd {:?}",
                    nd.msg_type, &ntlmssp_type_string(nd.msg_type), nd);
        match nd.msg_type {
            NTLMSSP_NEGOTIATE => {
            },
            NTLMSSP_AUTH => {
                if let Ok((_, ad)) = parse_ntlm_auth_record(nd.data) {
                    SCLogDebug!("auth data {:?}", ad);
                    let mut host = ad.host.to_vec();
                    host.retain(|&i|i != 0x00);
                    let mut user = ad.user.to_vec();
                    user.retain(|&i|i != 0x00);
                    let mut domain = ad.domain.to_vec();
                    domain.retain(|&i|i != 0x00);
                    
                    let d = NtlmsspData {
                        host,
                        user,
                        domain,
                        warning: ad.warning,
                        version: ad.version,
                    };
                    ntlmssp_data = Some(d);
                }
            },
            _ => {},
        }
    }
    return ntlmssp_data;
}

// if spnego parsing fails try to fall back to ntlmssp
pub fn parse_secblob(blob: &[u8]) -> Option<SpnegoRequest>
{
    match parse_secblob_get_spnego(blob) {
        Ok((_, spnego)) => {
            match parse_secblob_spnego_start(spnego) {
                Ok((_, spnego_start)) => {
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_secblob() {
        // smb2.security_blob
        let blob = hex::decode("a18202313082022da0030a0101a28202100482020c4e544c4d5353500003000000180018009c00000048014801b40000001e001e005800000008000800760000001e001e007e00000010001000fc010000158288e20a005a290000000fc6107a73184fb65fe684f6a1641464be4400450053004b0054004f0050002d0032004100450046004d003700470075007300650072004400450053004b0054004f0050002d0032004100450046004d003700470000000000000000000000000000000000000000000000000028a0c9f4e792c408913d2878feaa9a22010100000000000078a7ed218527d2010cf876f08a0b3bfa0000000002001e004400450053004b0054004f0050002d00560031004600410030005500510001001e004400450053004b0054004f0050002d00560031004600410030005500510004001e004400450053004b0054004f0050002d00560031004600410030005500510003001e004400450053004b0054004f0050002d0056003100460041003000550051000700080078a7ed218527d20106000400020000000800300030000000000000000100000000200000ad865b6d08a95d0e76a94e2ca013ab3f69c4fd945cca01b277700fd2b305ca010a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003100390039002e003100330033000000000000000000000000005858824ec4a47b3b42ad3132ab84a5c3a31204100100000092302d756840453f00000000").unwrap();
        let result = parse_secblob(&blob);
        assert_eq!(
            result,
            Some(SpnegoRequest {
                krb: None,
                ntlmssp: Some(NtlmsspData {
                    host: b"DESKTOP-2AEFM7G".to_vec(),
                    user: b"user".to_vec(),
                    domain: b"DESKTOP-2AEFM7G".to_vec(),
                    version: Some(NTLMSSPVersion {
                        ver_major: 10,
                        ver_minor: 0,
                        ver_build: 10586,
                        ver_ntlm_rev: 15,
                    },),
                    warning: false,
                }),
            })
        );
    }
}
