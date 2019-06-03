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

use std::cmp::min;

use dhcp::dhcp::*;
use nom::*;

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

named!(pub parse_header<DHCPHeader>,
       do_parse!(
           opcode: be_u8
           >> htype: be_u8
           >> hlen: be_u8
           >> hops: be_u8
           >> txid: be_u32
           >> seconds: be_u16
           >> flags: be_u16
           >> clientip: take!(4)
           >> yourip: take!(4)
           >> serverip: take!(4)
           >> giaddr: take!(4)
           >> clienthw: take!(16)
           >> servername: take!(64)
           >> bootfilename: take!(128)
           >> magic: take!(4)
           >> (
                   DHCPHeader{
                       opcode: opcode,
                       htype: htype,
                       hlen: hlen,
                       hops: hops,
                       txid: txid,
                       seconds: seconds,
                       flags: flags,
                       clientip: clientip.to_vec(),
                       yourip: yourip.to_vec(),
                       serverip: serverip.to_vec(),
                       giaddr: giaddr.to_vec(),
                       clienthw: clienthw[0..min(hlen as usize, 16)].to_vec(),
                       servername: servername.to_vec(),
                       bootfilename: bootfilename.to_vec(),
                       magic: magic.to_vec(),
                   }
               )
       )
);

named!(pub parse_clientid_option<DHCPOption>,
       do_parse!(
           code:   be_u8 >>
           len: verify!(be_u8, |v| v > 1) >>
           _htype: be_u8 >>
           data:   take!(len - 1) >>
               (
                   DHCPOption{
                       code: code,
                       data: None,
                       option: DHCPOptionWrapper::ClientId(DHCPOptClientId{
                           htype: 1,
                           data: data.to_vec(),
                       }),
                   }
               )
       )
);

named!(pub parse_address_time_option<DHCPOption>,
       do_parse!(
           code:    be_u8 >>
           _len:    be_u8 >>
           seconds: be_u32 >>
               (
                   DHCPOption{
                       code: code,
                       data: None,
                       option: DHCPOptionWrapper::TimeValue(DHCPOptTimeValue{
                           seconds: seconds,
                       }),
                   }
               )
       )
);

named!(pub parse_generic_option<DHCPOption>,
       do_parse!(
           code: be_u8 >>
           len: be_u8 >>
           data: take!(len) >> (
               DHCPOption{
                   code: code,
                   data: None,
                   option: DHCPOptionWrapper::Generic(DHCPOptGeneric{
                       data: data.to_vec(),
                   }),
               }
           ))
);

// Parse a single DHCP option. When option 255 (END) is parsed, the remaining
// data will be consumed.
named!(pub parse_option<DHCPOption>,
       switch!(peek!(be_u8),
               // End of options case. We consume the rest of the data
               // so the parse is not called again. But is there a
               // better way to "break"?
               DHCP_OPT_END => do_parse!(
                   code: be_u8 >>
                   data: rest >> (DHCPOption{
                       code: code,
                       data: Some(data.to_vec()),
                       option: DHCPOptionWrapper::End,
                   })) |
               DHCP_OPT_CLIENT_ID => call!(parse_clientid_option) |
               DHCP_OPT_ADDRESS_TIME => call!(parse_address_time_option) |
               DHCP_OPT_RENEWAL_TIME => call!(parse_address_time_option) |
               DHCP_OPT_REBINDING_TIME => call!(parse_address_time_option) |
               _ => call!(parse_generic_option)
       ));

// Parse and return all the options. Upon the end of option indicator
// all the data will be consumed.
named!(pub parse_all_options<Vec<DHCPOption>>, many0!(complete!(call!(parse_option))));

pub fn dhcp_parse(input: &[u8]) -> IResult<&[u8], DHCPMessage> {
    match parse_header(input) {
        Ok((rem, header)) => {
            let mut options = Vec::new();
            let mut next = rem;
            let mut malformed_options = false;
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
            let message = DHCPMessage {
                header: header,
                options: options,
                malformed_options: malformed_options,
                truncated_options: truncated_options,
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
    use dhcp::dhcp::*;
    use dhcp::parser::*;

    #[test]
    fn test_parse_discover() {
        let pcap = include_bytes!("discover.pcap");
        let payload = &pcap[24 + 16 + 42..];

        match dhcp_parse(payload) {
            Ok((_rem, message)) => {
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
                assert_eq!(&header.clienthw[..(header.hlen as usize)],
                           &[0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42]);
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
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_parse_client_id_too_short() {
        // Length field of 0.
        let buf: &[u8] = &[
            0x01,
            0x00, // Length of 0.
            0x01,
            0x01, // Junk data start here.
            0x02,
            0x03,
        ];
        let r = parse_clientid_option(buf);
        assert!(r.is_err());

        // Length field of 1.
        let buf: &[u8] = &[
            0x01,
            0x01, // Length of 1.
            0x01,
            0x41,
        ];
        let r = parse_clientid_option(buf);
        assert!(r.is_err());

        // Length field of 2 -- OK.
        let buf: &[u8] = &[
            0x01,
            0x02, // Length of 2.
            0x01,
            0x41,
        ];
        let r = parse_clientid_option(buf);
        match r {
            Ok((rem, _)) => { assert_eq!(rem.len(), 0); },
            _ => { panic!("failed"); }
        }
    }
}
