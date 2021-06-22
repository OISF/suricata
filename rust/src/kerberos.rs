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

use kerberos_parser::krb5_parser::parse_ap_req;
use kerberos_parser::krb5::{ApReq,Realm,PrincipalName};
use nom;
use nom::IResult;
use nom::error::{ErrorKind, ParseError};
use nom::number::streaming::le_u16;
use der_parser;
use der_parser::error::BerError;
use der_parser::der::parse_der_oid;

#[derive(Debug)]
pub enum SecBlobError {
    NotSpNego,
    KrbFmtError,
    Ber(BerError),
    NomError(ErrorKind),
}

impl From<BerError> for SecBlobError {
    fn from(error: BerError) -> Self {
        SecBlobError::Ber(error)
    }
}

impl<I> ParseError<I> for SecBlobError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        SecBlobError::NomError(kind)
    }
    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        SecBlobError::NomError(kind)
    }
}

#[derive(Debug,PartialEq)]
pub struct Kerberos5Ticket {
    pub realm: Realm,
    pub sname: PrincipalName,
}

fn parse_kerberos5_request_do(blob: &[u8]) -> IResult<&[u8], ApReq, SecBlobError>
{
    let (_,b) = der_parser::parse_der(blob).map_err(|e| nom::Err::convert(e))?;
    let blob = b.as_slice().or(
        Err(nom::Err::Error(SecBlobError::KrbFmtError))
    )?;
    do_parse!(
        blob,
        // marking those as potentially unused because they are only used in
        // debug messages
        _base_o: parse_der_oid >>
        _tok_id: le_u16 >>
        ap_req: parse_ap_req >>
        ({
            SCLogDebug!("parse_kerberos5_request: base_o {:?}", _base_o.as_oid());
            SCLogDebug!("parse_kerberos5_request: tok_id {}", _tok_id);
            ap_req
        })
    )
    .map_err(|e| nom::Err::convert(e))
}

pub fn parse_kerberos5_request(blob: &[u8]) -> IResult<&[u8], Kerberos5Ticket, SecBlobError>
{
    let (rem, req) = parse_kerberos5_request_do(blob)?;
    let t = Kerberos5Ticket {
        realm: req.ticket.realm,
        sname: req.ticket.sname,
    };
    return Ok((rem, t));
}
