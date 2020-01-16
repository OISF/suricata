/* Copyright (C) 2017 Open Information Security Foundation
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

use crate::dcerpc::dcerpc::{DCERPCHdrUdp, Uuid};
use nom::{be_u8, Endianness};

named!(pub parse_uuid<Uuid>,
    do_parse!(
        time_low: take!(4) >>
        time_mid: take!(2) >>
        time_hi_and_version: take!(2) >>
        clock_seq_hi_and_reserved: be_u8 >>
        clock_seq_low: be_u8 >>
        node: take!(6) >>
        (
            Uuid {
                time_low: time_low.to_vec(),
                time_mid: time_mid.to_vec(),
                time_hi_and_version: time_hi_and_version.to_vec(),
                clock_seq_hi_and_reserved: clock_seq_hi_and_reserved,
                clock_seq_low: clock_seq_low,
                node: node.to_vec(),
            }
            )
        )
    );

fn assemble_uuid(uuid: Uuid) -> Vec<u8> {
    let mut uuidtmp = uuid;
    let mut vect: Vec<u8> = Vec::new();
    uuidtmp.time_low.reverse();
    uuidtmp.time_mid.reverse();
    uuidtmp.time_hi_and_version.reverse();
    vect.append(&mut uuidtmp.time_low);
    vect.append(&mut uuidtmp.time_mid);
    vect.append(&mut uuidtmp.time_hi_and_version);
    vect.push(uuidtmp.clock_seq_hi_and_reserved);
    vect.push(uuidtmp.clock_seq_low);
    vect.append(&mut uuidtmp.node);

    vect
}

named!(pub dcerpc_parse_header<DCERPCHdrUdp>,
       do_parse!(
           rpc_vers: be_u8 >>
           pkt_type: be_u8 >>
           flags1: be_u8 >>
           flags2: be_u8 >>
           drep: take!(3) >>
           endianness: value!(if drep[0] == 0 { Endianness::Big } else { Endianness::Little }) >>
           serial_hi: be_u8 >>
           objectuuid: take!(16) >>
           interfaceuuid: take!(16) >>
           activityuuid: take!(16) >>
           server_boot: u32!(endianness) >>
           if_vers: u32!(endianness) >>
           seqnum: u32!(endianness) >>
           opnum: u16!(endianness) >>
           ihint: u16!(endianness) >>
           ahint: u16!(endianness) >>
           fraglen: u16!(endianness) >>
           fragnum: u16!(endianness) >>
           auth_proto: be_u8 >>
           serial_lo: be_u8 >>
           (
               DCERPCHdrUdp {
                   rpc_vers: rpc_vers,
                   pkt_type: pkt_type,
                   flags1: flags1,
                   flags2: flags2,
                   drep: drep.to_vec(),
                   serial_hi: serial_hi,
                   objectuuid: match parse_uuid(objectuuid) {
                       Ok((_, vect)) => assemble_uuid(vect),
                       Err(e) => {
                           println!("{}", e);
                           vec![0]
                       },
                   },
                   interfaceuuid: match parse_uuid(interfaceuuid) {
                       Ok((_, vect)) => assemble_uuid(vect),
                       Err(e) => {
                           println!("{}", e);
                           vec![0]
                       },
                   },
                   activityuuid: match parse_uuid(activityuuid){
                       Ok((_, vect)) => assemble_uuid(vect),
                       Err(e) => {
                           println!("{}", e);
                           vec![0]
                       },
                   },
                   server_boot: server_boot,
                   if_vers: if_vers,
                   seqnum: seqnum,
                   opnum: opnum,
                   ihint: ihint,
                   ahint: ahint,
                   fraglen: fraglen,
                   fragnum: fragnum,
                   auth_proto: auth_proto,
                   serial_lo: serial_lo,
               }
               )
           )
   );

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uuid() {
        let uuid: &[u8] = &[
            0xb8, 0x4a, 0x9f, 0x4d, 0x1c, 0x7d, 0xcf, 0x11, 0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e,
            0x7c, 0x57,
        ];
        let expected_uuid = Uuid {
            time_low: vec![0xb8, 0x4a, 0x9f, 0x4d],
            time_mid: vec![0x1c, 0x7d],
            time_hi_and_version: vec![0xcf, 0x11],
            clock_seq_hi_and_reserved: 0x86,
            clock_seq_low: 0x1e,
            node: vec![0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57],
        };
        let (_remainder, parsed_uuid) = parse_uuid(uuid).unwrap();
        assert_eq!(expected_uuid, parsed_uuid);
    }

    #[test]
    fn test_assemble_uuid() {
        let uuid = Uuid {
            time_low: vec![0xb8, 0x4a, 0x9f, 0x4d],
            time_mid: vec![0x1c, 0x7d],
            time_hi_and_version: vec![0xcf, 0x11],
            clock_seq_hi_and_reserved: 0x86,
            clock_seq_low: 0x1e,
            node: vec![0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57],
        };
        let expected_val = vec![
            0x4d, 0x9f, 0x4a, 0xb8, 0x7d, 0x1c, 0x11, 0xcf, 0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e,
            0x7c, 0x57,
        ];
        assert_eq!(expected_val, assemble_uuid(uuid));
    }

    #[test]
    fn test_dcerpc_parse_header() {
        let dcerpcheader: &[u8] = &[
            0x04, 0x00, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x4a, 0x9f, 0x4d,
            0x1c, 0x7d, 0xcf, 0x11, 0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57, 0x86, 0xc2,
            0x37, 0x67, 0xf7, 0x1e, 0xd1, 0x11, 0xbc, 0xd9, 0x00, 0x60, 0x97, 0x92, 0xd2, 0x6c,
            0x79, 0xbe, 0x01, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0x68, 0x00, 0x00, 0x00, 0x0a, 0x00,
        ];
        let (_remainder, header) = dcerpc_parse_header(dcerpcheader).unwrap();
        let expected_activityuuid = vec![
            0x67, 0x37, 0xc2, 0x86, 0x1e, 0xf7, 0x11, 0xd1, 0xbc, 0xd9, 0x00, 0x60, 0x97, 0x92,
            0xd2, 0x6c,
        ];
        assert_eq!(0x04, header.rpc_vers);
        assert_eq!(0x00, header.pkt_type);
        assert_eq!(0x08, header.flags1);
        assert_eq!(0x00, header.flags2);
        assert_eq!(vec!(0x10, 0x00, 0x00), header.drep);
        assert_eq!(0x00, header.serial_hi);
        assert_eq!(expected_activityuuid, header.activityuuid);
        assert_eq!(0x3401be79, header.server_boot);
        assert_eq!(0x00000000, header.seqnum);
        assert_eq!(0xffff, header.ihint);
        assert_eq!(0x0068, header.fraglen);
        assert_eq!(0x0a, header.auth_proto);
    }
}
