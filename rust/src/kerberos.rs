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
use nom::{ErrorKind, IResult, le_u16};
use der_parser;
use der_parser::parse_der_oid;

use log::*;

pub const SECBLOB_NOT_SPNEGO :  u32 = 128;
pub const SECBLOB_KRB_FMT_ERR : u32 = 129;

#[derive(Debug,PartialEq)]
pub struct Kerberos5Ticket {
    pub realm: Realm,
    pub sname: PrincipalName,
}

fn parse_kerberos5_request_do(blob: &[u8]) -> IResult<&[u8], ApReq>
{
    let (_,b) = der_parser::parse_der(blob)?;
    let blob = b.as_slice().or(
        Err(nom::Err::Error(error_position!(blob, ErrorKind::Custom(SECBLOB_KRB_FMT_ERR))))
    )?;
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

pub fn parse_kerberos5_request(blob: &[u8]) -> IResult<&[u8], Kerberos5Ticket>
{
    let (rem, req) = parse_kerberos5_request_do(blob)?;
    let t = Kerberos5Ticket {
        realm: req.ticket.realm,
        sname: req.ticket.sname,
    };
    return Ok((rem, t));
}
