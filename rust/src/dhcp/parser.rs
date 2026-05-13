/* Copyright (C) 2018-2025 Open Information Security Foundation
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

use std::cmp::min;

use crate::dhcp::dhcp::*;
use nom8::bytes::streaming::take;
use nom8::combinator::verify;
use nom8::number::streaming::{be_u16, be_u32, be_u8};
use nom8::{IResult, Parser};

pub struct DHCPMessage {
    pub header: DHCPHeader,

    pub options: Vec<DHCPOption>,

    // Set to true if the options were found to be malformed. That is
    // failing to parse with enough data.
    pub malformed_options: bool,

    // Set to true if the options failed to parse due to not enough
    // data.
    pub truncated_options: bool,
}

pub struct DHCPHeader {
    pub opcode: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub txid: u32,
    pub seconds: u16,
    pub flags: u16,
    pub clientip: Vec<u8>,
    pub yourip: Vec<u8>,
    pub serverip: Vec<u8>,
    pub giaddr: Vec<u8>,
    pub clienthw: Vec<u8>,
    pub servername: Vec<u8>,
    pub bootfilename: Vec<u8>,
    pub magic: Vec<u8>,
}

pub struct DHCPOptClientId {
    pub htype: u8,
    pub data: Vec<u8>,
}

/// Option type for time values.
pub struct DHCPOptTimeValue {
    pub seconds: u32,
}

pub struct DHCPOptGeneric {
    pub data: Vec<u8>,
}

pub enum DHCPOptionWrapper {
    ClientId(DHCPOptClientId),
    TimeValue(DHCPOptTimeValue),
    Generic(DHCPOptGeneric),
    End,
}

pub struct DHCPOption {
    pub code: u8,
    pub data: Option<Vec<u8>>,
    pub option: DHCPOptionWrapper,
}

pub fn parse_header(i: &[u8]) -> IResult<&[u8], DHCPHeader> {
    let (i, opcode) = be_u8(i)?;
    let (i, htype) = be_u8(i)?;
    let (i, hlen) = be_u8(i)?;
    let (i, hops) = be_u8(i)?;
    let (i, txid) = be_u32(i)?;
    let (i, seconds) = be_u16(i)?;
    let (i, flags) = be_u16(i)?;
    let (i, clientip) = take(4_usize).parse(i)?;
    let (i, yourip) = take(4_usize).parse(i)?;
    let (i, serverip) = take(4_usize).parse(i)?;
    let (i, giaddr) = take(4_usize).parse(i)?;
    let (i, clienthw) = take(16_usize).parse(i)?;
    let (i, servername) = take(64_usize).parse(i)?;
    let (i, bootfilename) = take(128_usize).parse(i)?;
    let (i, magic) = take(4_usize).parse(i)?;
    Ok((
        i,
        DHCPHeader {
            opcode,
            htype,
            hlen,
            hops,
            txid,
            seconds,
            flags,
            clientip: clientip.to_vec(),
            yourip: yourip.to_vec(),
            serverip: serverip.to_vec(),
            giaddr: giaddr.to_vec(),
            clienthw: clienthw[0..min(hlen as usize, 16)].to_vec(),
            servername: servername.to_vec(),
            bootfilename: bootfilename.to_vec(),
            magic: magic.to_vec(),
        },
    ))
}

pub fn parse_clientid_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i, code) = be_u8(i)?;
    let (i, len) = verify(be_u8, |&v| v > 1).parse(i)?;
    let (i, _htype) = be_u8(i)?;
    let (i, data) = take(len - 1).parse(i)?;
    Ok((
        i,
        DHCPOption {
            code,
            data: None,
            option: DHCPOptionWrapper::ClientId(DHCPOptClientId {
                htype: 1,
                data: data.to_vec(),
            }),
        },
    ))
}

pub fn parse_address_time_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i, code) = be_u8(i)?;
    let (i, _len) = be_u8(i)?;
    let (i, seconds) = be_u32(i)?;
    Ok((
        i,
        DHCPOption {
            code,
            data: None,
            option: DHCPOptionWrapper::TimeValue(DHCPOptTimeValue { seconds }),
        },
    ))
}

pub fn parse_generic_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i, code) = be_u8(i)?;
    let (i, len) = be_u8(i)?;
    let (i, data) = take(len).parse(i)?;
    Ok((
        i,
        DHCPOption {
            code,
            data: None,
            option: DHCPOptionWrapper::Generic(DHCPOptGeneric {
                data: data.to_vec(),
            }),
        },
    ))
}

// Parse a single DHCP option. When option 255 (END) is parsed, the remaining
// data will be consumed.
pub fn parse_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (_, opt) = be_u8(i)?;
    match opt {
        DHCP_OPT_END => {
            // End of options case. We consume the rest of the data
            // so the parser is not called again. But is there a
            // better way to "break"?
            let (data, code) = be_u8(i)?;
            Ok((
                &[],
                DHCPOption {
                    code,
                    data: Some(data.to_vec()),
                    option: DHCPOptionWrapper::End,
                },
            ))
        }
        DHCP_OPT_CLIENT_ID => parse_clientid_option(i),
        DHCP_OPT_ADDRESS_TIME => parse_address_time_option(i),
        DHCP_OPT_RENEWAL_TIME => parse_address_time_option(i),
        DHCP_OPT_REBINDING_TIME => parse_address_time_option(i),
        _ => parse_generic_option(i),
    }
}

fn find_overload_value(options: &[DHCPOption]) -> u8 {
    for opt in options {
        if opt.code == DHCP_OPT_OVERLOAD {
            if let DHCPOptionWrapper::Generic(ref g) = opt.option {
                if !g.data.is_empty() {
                    return g.data[0];
                }
            }
        }
    }
    0
}

fn parse_overloaded_field(field: &[u8], options: &mut Vec<DHCPOption>) {
    let mut next = field;
    while !next.is_empty() {
        match parse_option(next) {
            Ok((rem, option)) => {
                let done = option.code == DHCP_OPT_END;
                options.push(option);
                next = rem;
                if done {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

pub fn parse_dhcp(input: &[u8]) -> IResult<&[u8], DHCPMessage> {
    match parse_header(input) {
        Ok((rem, header)) => {
            let mut options = Vec::new();
            let mut next = rem;
            let malformed_options = false;
            let mut truncated_options = false;
            loop {
                match parse_option(next) {
                    Ok((rem, option)) => {
                        let done = option.code == DHCP_OPT_END;
                        options.push(option);
                        next = rem;
                        if done {
                            break;
                        }
                    }
                    Err(_) => {
                        truncated_options = true;
                        break;
                    }
                }
            }
            let overload = find_overload_value(&options);
            if overload & 0x01 != 0 {
                parse_overloaded_field(&header.bootfilename, &mut options);
            }
            if overload & 0x02 != 0 {
                parse_overloaded_field(&header.servername, &mut options);
            }

            let message = DHCPMessage {
                header,
                options,
                malformed_options,
                truncated_options,
            };
            return Ok((next, message));
        }
        Err(err) => {
            return Err(err);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::dhcp::dhcp::*;
    use crate::dhcp::parser::*;

    #[test]
    fn test_parse_discover() {
        let pcap = include_bytes!("discover.pcap");
        let payload = &pcap[24 + 16 + 42..];

        let (_rem, message) = parse_dhcp(payload).unwrap();
        let header = message.header;
        assert_eq!(header.opcode, BOOTP_REQUEST);
        assert_eq!(header.htype, 1);
        assert_eq!(header.hlen, 6);
        assert_eq!(header.hops, 0);
        assert_eq!(header.txid, 0x00003d1d);
        assert_eq!(header.seconds, 0);
        assert_eq!(header.flags, 0);
        assert_eq!(header.clientip, &[0, 0, 0, 0]);
        assert_eq!(header.yourip, &[0, 0, 0, 0]);
        assert_eq!(header.serverip, &[0, 0, 0, 0]);
        assert_eq!(header.giaddr, &[0, 0, 0, 0]);
        assert_eq!(
            &header.clienthw[..(header.hlen as usize)],
            &[0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42]
        );
        assert!(header.servername.iter().all(|&x| x == 0));
        assert!(header.bootfilename.iter().all(|&x| x == 0));
        assert_eq!(header.magic, &[0x63, 0x82, 0x53, 0x63]);

        assert!(!message.malformed_options);
        assert!(!message.truncated_options);

        assert_eq!(message.options.len(), 5);
        assert_eq!(message.options[0].code, DHCP_OPT_TYPE);
        assert_eq!(message.options[1].code, DHCP_OPT_CLIENT_ID);
        assert_eq!(message.options[2].code, DHCP_OPT_REQUESTED_IP);
        assert_eq!(message.options[3].code, DHCP_OPT_PARAMETER_LIST);
        assert_eq!(message.options[4].code, DHCP_OPT_END);
    }

    #[test]
    fn test_parse_sname_overload() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&[BOOTP_REPLY, 1, 6, 0]);
        buf.extend_from_slice(&[0x24, 0x59, 0x3b, 0x3e, 0, 0, 0, 0]);
        buf.extend_from_slice(&[0; 16]);
        buf.extend_from_slice(&[0; 16]);
        let mut sname = vec![
            0x06, 0x04, 10, 100, 0, 2, 0x03, 0x04, 10, 100, 0, 2, 0x0f, 0x09, b'e', b'v', b'i',
            b'l', b'.', b'c', b'o', b'r', b'p', 0xff,
        ];
        sname.resize(64, 0);
        buf.extend_from_slice(&sname);
        buf.extend_from_slice(&[0; 128]);
        buf.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        buf.extend_from_slice(&[0x35, 0x01, DHCP_TYPE_ACK, 0x34, 0x01, 0x02, 0xff]);

        let (_rem, message) = parse_dhcp(&buf).unwrap();
        assert!(!message.malformed_options);
        assert!(!message.truncated_options);

        let codes: Vec<u8> = message.options.iter().map(|o| o.code).collect();
        assert!(codes.contains(&DHCP_OPT_OVERLOAD));
        assert!(codes.contains(&DHCP_OPT_DNS_SERVER));
        assert!(codes.contains(&DHCP_OPT_ROUTERS));
        assert!(codes.contains(&15));

        let dns = message
            .options
            .iter()
            .find(|o| o.code == DHCP_OPT_DNS_SERVER)
            .expect("DNS option missing");
        if let DHCPOptionWrapper::Generic(ref g) = dns.option {
            assert_eq!(g.data, vec![10, 100, 0, 2]);
        } else {
            panic!("DNS option had wrong wrapper variant");
        }
    }

    #[test]
    fn test_parse_no_overload_leaves_sname_alone() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&[BOOTP_REPLY, 1, 6, 0]);
        buf.extend_from_slice(&[0; 8]);
        buf.extend_from_slice(&[0; 16]);
        buf.extend_from_slice(&[0; 16]);
        let mut sname = vec![0x06, 0x04, 10, 100, 0, 2, 0xff];
        sname.resize(64, 0);
        buf.extend_from_slice(&sname);
        buf.extend_from_slice(&[0; 128]);
        buf.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        buf.extend_from_slice(&[0x35, 0x01, DHCP_TYPE_ACK, 0xff]);

        let (_rem, message) = parse_dhcp(&buf).unwrap();
        let codes: Vec<u8> = message.options.iter().map(|o| o.code).collect();
        assert!(!codes.contains(&DHCP_OPT_DNS_SERVER));
    }

    #[test]
    fn test_parse_file_overload() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&[BOOTP_REPLY, 1, 6, 0]);
        buf.extend_from_slice(&[0; 8]);
        buf.extend_from_slice(&[0; 16]);
        buf.extend_from_slice(&[0; 16]);
        let mut sname = b"tftp.example.com\0".to_vec();
        sname.resize(64, 0);
        buf.extend_from_slice(&sname);
        let mut file = vec![12, 0x05, b'h', b'o', b's', b't', b'1', 0xff];
        file.resize(128, 0);
        buf.extend_from_slice(&file);
        buf.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        buf.extend_from_slice(&[0x35, 0x01, DHCP_TYPE_ACK, 0x34, 0x01, 0x01, 0xff]);

        let (_rem, message) = parse_dhcp(&buf).unwrap();
        let codes: Vec<u8> = message.options.iter().map(|o| o.code).collect();
        assert!(codes.contains(&DHCP_OPT_HOSTNAME));
        assert!(!codes.contains(&DHCP_OPT_DNS_SERVER));
        assert!(!codes.contains(&DHCP_OPT_ROUTERS));
    }

    #[test]
    fn test_parse_overload_both() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&[BOOTP_REPLY, 1, 6, 0]);
        buf.extend_from_slice(&[0; 8]);
        buf.extend_from_slice(&[0; 16]);
        buf.extend_from_slice(&[0; 16]);
        let mut sname = vec![0x06, 0x04, 9, 9, 9, 9, 0xff];
        sname.resize(64, 0);
        buf.extend_from_slice(&sname);
        let mut file = vec![0x03, 0x04, 8, 8, 8, 8, 0xff];
        file.resize(128, 0);
        buf.extend_from_slice(&file);
        buf.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        buf.extend_from_slice(&[0x35, 0x01, DHCP_TYPE_ACK, 0x34, 0x01, 0x03, 0xff]);

        let (_rem, message) = parse_dhcp(&buf).unwrap();
        let dns = message
            .options
            .iter()
            .find(|o| o.code == DHCP_OPT_DNS_SERVER)
            .unwrap();
        let router = message
            .options
            .iter()
            .find(|o| o.code == DHCP_OPT_ROUTERS)
            .unwrap();
        if let DHCPOptionWrapper::Generic(ref g) = dns.option {
            assert_eq!(g.data, vec![9, 9, 9, 9]);
        } else {
            panic!()
        }
        if let DHCPOptionWrapper::Generic(ref g) = router.option {
            assert_eq!(g.data, vec![8, 8, 8, 8]);
        } else {
            panic!()
        }
    }

    #[test]
    fn test_parse_overload_garbage_field_is_safe() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&[BOOTP_REPLY, 1, 6, 0]);
        buf.extend_from_slice(&[0; 8]);
        buf.extend_from_slice(&[0; 16]);
        buf.extend_from_slice(&[0; 16]);
        let mut sname = vec![0x06, 0xfe, 0xaa, 0xbb];
        sname.resize(64, 0);
        buf.extend_from_slice(&sname);
        buf.extend_from_slice(&[0; 128]);
        buf.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        buf.extend_from_slice(&[0x35, 0x01, DHCP_TYPE_ACK, 0x34, 0x01, 0x02, 0xff]);

        let result = parse_dhcp(&buf);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_client_id_too_short() {
        // Length field of 0.
        let buf: &[u8] = &[
            0x01, 0x00, // Length of 0.
            0x01, 0x01, // Junk data start here.
            0x02, 0x03,
        ];
        let r = parse_clientid_option(buf);
        assert!(r.is_err());

        // Length field of 1.
        let buf: &[u8] = &[
            0x01, 0x01, // Length of 1.
            0x01, 0x41,
        ];
        let r = parse_clientid_option(buf);
        assert!(r.is_err());

        // Length field of 2 -- OK.
        let buf: &[u8] = &[
            0x01, 0x02, // Length of 2.
            0x01, 0x41,
        ];
        let r = parse_clientid_option(buf);
        match r {
            Ok((rem, _)) => {
                assert_eq!(rem.len(), 0);
            }
            _ => {
                panic!("failed");
            }
        }
    }
}
