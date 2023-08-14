/* Copyright (C) 2023 Open Information Security Foundation
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
    number::streaming::{be_u8, be_u16},
    IResult,
};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub struct BacNetPacket {
    pub bvlc_type: u8,
    pub bvlc_func: u8,
    pub length: u16,
    pub bvlc_data: Option<BVLCData>,
    pub npdu_data: Option<NPDU>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BVLCData {
    pub ip_addr: [u8; 4],
    pub port: u16,
}


#[derive(Debug, PartialEq, Eq)]
pub struct NPDU {
    pub version: u8,
    pub control: u8,
    pub network_priority: u8,
    pub hop_count: u8,
    pub data_expecting_reply: bool,
    pub dnet: Option<u16>,
    pub dlen: Option<u8>,
    pub dadr: Option<Vec<u8>>,
    pub snet: Option<u16>,
    pub slen: Option<u8>,
    pub sadr: Option<Vec<u8>>,
    pub message_type: Option<u8>,
    pub vendor_id: Option<u16>,
    pub apdu_data: Option<Vec<u8>>,
}

impl fmt::Display for BVLCData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BVLCData {{ ip_addr: {:?}, port: {} }}", self.ip_addr, self.port)
    }
}

impl fmt::Display for NPDU {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NPDU {{ version: {}, control: {}, network_priority: {}, hop_count: {}, data_expecting_reply: {}, dnet: {:?}, dlen: {:?}, dadr: {:?}, snet: {:?}, slen: {:?}, sadr: {:?}, message_type: {:?}, vendor_id: {:?}, apdu_data: {:?} }}",
            self.version,
            self.control,
            self.network_priority,
            self.hop_count,
            self.data_expecting_reply,
            self.dnet,
            self.dlen,
            self.dadr,
            self.snet,
            self.slen,
            self.sadr,
            self.message_type,
            self.vendor_id,
            self.apdu_data
        )
    }
}

impl fmt::Display for BacNetPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BacNetPacket {{ bvlc_type: {}, bvlc_func: {}, length: {}, bvlc_data: {:?}, npdu_data: {:?} }}",
            self.bvlc_type,
            self.bvlc_func,
            self.length,
            self.bvlc_data,
            self.npdu_data
        )
    }
}

fn parse_ipv4_addr(i: &[u8]) -> IResult<&[u8], [u8; 4]> {
    let (i, ip_addr) = take(4u8)(i)?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(ip_addr);
    Ok((i, arr))
}

fn parse_vec_u8(i: &[u8], len: usize) -> IResult<&[u8], Vec<u8>> {
    let (i, data) = take(len)(i)?;
    Ok((i, data.to_vec()))
}

fn parse_bvlc_data(i: &[u8], func: u8) -> IResult<&[u8], Option<BVLCData>> {
    if func == 0x01 || func == 0x04 {
        let (i, ip_addr) = parse_ipv4_addr(i)?;
        let (i, port) = be_u16(i)?;
        Ok((i, Some(BVLCData { ip_addr, port })))
    } else {
        Ok((i, None))
    }
}

fn parse_apdu(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (i, apdu_data) = parse_vec_u8(i, i.len())?;
    Ok((i, apdu_data))
}

fn parse_npdu(i: &[u8], func: u8) -> IResult<&[u8], Option<NPDU>> {
    if func == 0x01 || func == 0x04 || func == 0x0A || func == 0x0B  || func == 0x09 {
        let (i, version) = be_u8(i)?;
        let (i, control) = be_u8(i)?;

        let message_type_exists = (control >> 7) & 1 == 1;
        let vendor_id_exists = message_type_exists;
        let dnet_exists = (control >> 5) & 1 == 1;
        let snet_exists = (control >> 3) & 1 == 1;
        let data_expecting_reply = (control >> 2) & 1 == 1;
        let network_priority = control & 0b11;

        let (i, dnet) = if dnet_exists { be_u16(i)? } else { (i, 0) };
        let (i, dlen) = if dnet_exists { be_u8(i)? } else { (i, 0) };
        let (i, dadr) = if dlen > 0 { parse_vec_u8(i, dlen as usize)? } else { (i, vec![]) };
        let (i, snet) = if snet_exists { be_u16(i)? } else { (i, 0) };
        let (i, slen) = if snet_exists { be_u8(i)? } else { (i, 0) };
        let (i, sadr) = if slen > 0 { parse_vec_u8(i, slen as usize)? } else { (i, vec![]) };
        let (i, hop_count) = be_u8(i)?;
        let (i, message_type) = if message_type_exists { be_u8(i)? } else { (i, 0) };
        let (i, vendor_id) = if vendor_id_exists { be_u16(i)? } else { (i, 0) };
        let (i, apdu_data) = if !message_type_exists { parse_apdu(i)? } else { (i, vec![]) };

        let npdu = NPDU {
            version,
            control,
            dnet: if dnet_exists { Some(dnet) } else { None },
            dlen: if dnet_exists { Some(dlen) } else { None },
            dadr: if dlen > 0 { Some(dadr) } else { None },
            snet: if snet_exists { Some(snet) } else { None },
            slen: if snet_exists { Some(slen) } else { None },
            sadr: if slen > 0 { Some(sadr) } else { None },
            hop_count,
            message_type: if message_type_exists { Some(message_type) } else { None },
            vendor_id: if vendor_id_exists { Some(vendor_id) } else { None },
            data_expecting_reply,
            network_priority,
            apdu_data: if !message_type_exists { Some(apdu_data) } else { None },
        };

        Ok((i, Some(npdu)))
    } else {
        Ok((i, None))
    }
}

pub fn parse_bacnet_packet(i: &[u8]) -> IResult<&[u8], BacNetPacket> {
    let (i, bvlc_type) = be_u8(i)?;
    let (i, bvlc_func) = be_u8(i)?;
    let (i, length) = be_u16(i)?;

    let (i, bvlc_data) = parse_bvlc_data(i, bvlc_func)?;
    let (i, npdu_data) = parse_npdu(i, bvlc_func)?;

    let packet = BacNetPacket {
        bvlc_type,
        bvlc_func,
        length,
        bvlc_data,
        npdu_data,
    };

    Ok((i, packet))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom7::Err;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_valid() {
        let buf: &[u8] = &[
             0x81, 0x04, 0x00, 0x12, 0xc0, 0xa8, 0x00, 0x86, 0xba, 0xc0, 0x01, 0x20, 0xff, 0xff, 0x00, 0x0e, 0xff
        ];

        let bvlc_expected_packet = BacNetPacket {
            bvlc_type: 129,
            bvlc_func: 4,
            length: 18,
            bvlc_data: Some(
                BVLCData {
                    ip_addr: [
                        192,
                        168,
                        0,
                        134,
                    ],
                    port: 47808,
                },
            ),
            npdu_data: Some(
                NPDU {
                    version: 1,
                    control: 32,
                    network_priority: 0,
                    hop_count: 14,
                    data_expecting_reply: false,
                    dnet: Some(
                        65535,
                    ),
                    dlen: Some(
                        0,
                    ),
                    dadr: None,
                    snet: None,
                    slen: None,
                    sadr: None,
                    message_type: None,
                    vendor_id: None,
                    apdu_data: Some(vec![0xff]),
                },
            ),
        };

        let result = parse_bacnet_packet(buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, bvlc_expected_packet);

                // And we should have 6 bytes left.
                assert_eq!(remainder.len(), 0);
            }
            Err(e) => {
                panic!("Parsing failed: {:?}", e);
            }
        }
    }
}
