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
use nom::number::complete::le_u16;
use der_parser;
use der_parser::error::BerError;
use der_parser::der::parse_der_oid;

#[derive(Debug)]
pub enum SecBlobError {
    NotSpNego,
    KrbFmtError,
    KrbReqError,
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
    let (_,b) = der_parser::parse_der(blob).map_err(nom::Err::convert)?;
    let blob = b.as_slice().or(
        Err(nom::Err::Error(SecBlobError::KrbFmtError))
    )?;
    let (blob, _) = parse_der_oid(blob).map_err(nom::Err::convert)?;
    let (blob, _) = le_u16(blob)?;
    // Should be parse_ap_req(blob).map_err(nom::Err::convert)
    // But upgraded kerberos parser uses a newer der_parser crate
    // Hence the enum `der_parser::error::BerError` are different
    // and we cannot convert to SecBlobError with the From impl
    // Next is to upgrade the der_parser crate (and nom to nom7 by the way)
    match parse_ap_req(blob) {
        Ok((blob, ap_req)) => Ok((blob, ap_req)),
        _ => Err(nom::Err::Error(SecBlobError::KrbReqError)),
    }
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
