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

use nom7::IResult;
use nom7::error::{ErrorKind, ParseError};
use nom7::number::streaming::le_u16;
use der_parser;
use der_parser::der::parse_der_oid;
use der_parser::error::BerError;
use kerberos_parser::krb5::{ApReq, PrincipalName, Realm};
use kerberos_parser::krb5_parser::parse_ap_req;

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

#[derive(Debug, PartialEq)]
pub struct Kerberos5Ticket {
    pub realm: Realm,
    pub sname: PrincipalName,
}

fn parse_kerberos5_request_do(blob: &[u8]) -> IResult<&[u8], ApReq, SecBlobError>
{
    let (_,b) = der_parser::parse_der(blob).map_err(nom7::Err::convert)?;
    let blob = b.as_slice().or(
        Err(nom7::Err::Error(SecBlobError::KrbFmtError))
    )?;
    let parser = |i| {
        let (i, _base_o) = parse_der_oid(i)?;
        let (i, _tok_id) = le_u16(i)?;
        let (i, ap_req) = parse_ap_req(i)?;
        Ok((i, ap_req))
    };
    parser(blob).map_err(nom7::Err::convert)
}

pub fn parse_kerberos5_request(blob: &[u8]) -> IResult<&[u8], Kerberos5Ticket, SecBlobError> {
    let (rem, req) = parse_kerberos5_request_do(blob)?;
    let t = Kerberos5Ticket {
        realm: req.ticket.realm,
        sname: req.ticket.sname,
    };
    Ok((rem, t))
}
