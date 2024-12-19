/* Copyright (C) 2024 Open Information Security Foundation
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

use nom7::{
    bytes::streaming::take,
    combinator::verify,
    error::{make_error, ErrorKind},
    multi::count,
    number::streaming::{be_u16, be_u8},
    Err, IResult,
};

pub struct SocksConnectRequest {
    pub _ver: u8,
    pub auth_methods: Vec<u8>,
}

#[derive(Debug)]
pub struct SocksAuthRequest<'a> {
    pub subver: u8,
    pub user: &'a [u8],
    pub pass: &'a [u8],
}

pub fn parse_connect_request(i: &[u8]) -> IResult<&[u8], SocksConnectRequest> {
    let (i, ver) = verify(be_u8, |&v| v == 5)(i)?;
    let (i, n) = be_u8(i)?;
    let (i, auth_methods_vec) = count(be_u8, n as usize)(i)?;
    let record = SocksConnectRequest {
        _ver: ver,
        auth_methods: auth_methods_vec,
    };
    Ok((i, record))
}

pub fn parse_connect_response(i: &[u8]) -> IResult<&[u8], u8> {
    let (i, _ver) = verify(be_u8, |&v| v == 5)(i)?;
    let (i, method) = be_u8(i)?;
    Ok((i, method))
}

pub fn parse_auth_request(i: &[u8]) -> IResult<&[u8], SocksAuthRequest> {
    let (i, subver) = verify(be_u8, |&v| v == 1)(i)?;
    let (i, len) = be_u8(i)?;
    let (i, user) = take(len)(i)?;
    let (i, len) = be_u8(i)?;
    let (i, pass) = take(len)(i)?;
    let record = SocksAuthRequest { subver, user, pass };
    Ok((i, record))
}

pub fn parse_auth_response(i: &[u8]) -> IResult<&[u8], u8> {
    let (i, _subver) = be_u8(i)?;
    let (i, status) = be_u8(i)?;
    Ok((i, status))
}

pub struct SocksConnectCommandRequest {
    pub domain: Option<Vec<u8>>,
    pub ipv4: Option<Vec<u8>>,
    /// TODO
    pub _ipv6: Option<Vec<u8>>,
    pub port: u16,
}

fn parse_connect_command_request_ipv4(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, dst) = take(4_usize)(i)?;
    Ok((i, dst))
}

fn parse_connect_command_request_ipv6(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, dst) = take(16_usize)(i)?;
    Ok((i, dst))
}

fn parse_connect_command_request_domain(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, dlen) = be_u8(i)?; // domain
    let (i, domain) = take(dlen)(i)?;
    Ok((i, domain))
}

pub fn parse_connect_command_request(i: &[u8]) -> IResult<&[u8], SocksConnectCommandRequest> {
    let (i, _ver) = verify(be_u8, |&v| v == 5)(i)?;
    let (i, _cmd) = verify(be_u8, |&v| v == 1)(i)?;
    let (i, _res) = verify(be_u8, |&v| v == 0)(i)?;
    // RFC 1928 defines: 1: ipv4, 3: domain, 4: ipv6. Consider all else invalid.
    let (i, t) = verify(be_u8, |&v| v == 1 || v == 3 || v == 4)(i)?;
    let (i, dst) = if t == 1 {
        parse_connect_command_request_ipv4(i)?
    } else if t == 3 {
        parse_connect_command_request_domain(i)?
    } else if t == 4 {
        parse_connect_command_request_ipv6(i)?
    } else {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    };
    let (i, port) = be_u16(i)?;

    let record = if t == 1 {
        SocksConnectCommandRequest {
            domain: None,
            ipv4: Some(dst.to_vec()),
            _ipv6: None,
            port,
        }
    } else if t == 3 {
        SocksConnectCommandRequest {
            domain: Some(dst.to_vec()),
            ipv4: None,
            _ipv6: None,
            port,
        }
    } else if t == 4 {
        SocksConnectCommandRequest {
            domain: None,
            ipv4: None,
            _ipv6: Some(dst.to_vec()),
            port,
        }
    } else {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    };
    Ok((i, record))
}

pub struct SocksConnectCommandResponse<'a> {
    pub results: u8,
    pub _address_type: u8,
    pub _address: &'a [u8],
    pub _port: u16,
}

pub fn parse_connect_command_response(i: &[u8]) -> IResult<&[u8], SocksConnectCommandResponse> {
    let (i, _ver) = verify(be_u8, |&v| v == 5)(i)?;
    let (i, results) = be_u8(i)?;
    let (i, _res) = verify(be_u8, |&v| v == 0)(i)?;
    let (i, at) = verify(be_u8, |&v| v == 1)(i)?; // domain
    let (i, address) = take(4usize)(i)?;
    let (i, port) = be_u16(i)?;
    let record = SocksConnectCommandResponse {
        results,
        _address_type: at,
        _address: address,
        _port: port,
    };
    Ok((i, record))
}
