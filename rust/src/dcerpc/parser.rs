/* Copyright (C) 2020 Open Information Security Foundation
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
use crate::dcerpc::dcerpc::{
    BindCtxItem, DCERPCBind, DCERPCBindAck, DCERPCBindAckResult, DCERPCHdr, DCERPCRequest, Uuid,
};
use crate::dcerpc::dcerpc_udp::DCERPCHdrUdp;
use nom::number::complete::{le_u16, le_u32, le_u8};
use nom::number::Endianness;

fn uuid_to_vec(uuid: Uuid) -> Vec<u8> {
    let mut uuidtmp = uuid;
    let mut vect: Vec<u8> = Vec::new();
    vect.append(&mut uuidtmp.time_low);
    vect.append(&mut uuidtmp.time_mid);
    vect.append(&mut uuidtmp.time_hi_and_version);
    vect.push(uuidtmp.clock_seq_hi_and_reserved);
    vect.push(uuidtmp.clock_seq_low);
    vect.append(&mut uuidtmp.node);
    vect
}

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

named!(pub parse_uuid<Uuid>,
    do_parse!(
        time_low: take!(4)
        >> time_mid: take!(2)
        >> time_hi_and_version: take!(2)
        >> clock_seq_hi_and_reserved: le_u8
        >> clock_seq_low: le_u8
        >> node: take!(6)
        >> (
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

named!(pub parse_dcerpc_udp_header<DCERPCHdrUdp>,
    do_parse!(
        rpc_vers: le_u8
        >> pkt_type: le_u8
        >> flags1: le_u8
        >> flags2: le_u8
        >> drep: take!(3)
        >> endianness: value!(if drep[0] == 0 { Endianness::Big } else { Endianness::Little })
        >> serial_hi: le_u8
        >> objectuuid: take!(16)
        >> interfaceuuid: take!(16)
        >> activityuuid: take!(16)
        >> server_boot: u32!(endianness)
        >> if_vers: u32!(endianness)
        >> seqnum: u32!(endianness)
        >> opnum: u16!(endianness)
        >> ihint: u16!(endianness)
        >> ahint: u16!(endianness)
        >> fraglen: u16!(endianness)
        >> fragnum: u16!(endianness)
        >> auth_proto: le_u8
        >> serial_lo: le_u8
        >> (
             DCERPCHdrUdp {
                rpc_vers: rpc_vers,
                pkt_type: pkt_type,
                flags1: flags1,
                flags2: flags2,
                drep: drep.to_vec(),
                serial_hi: serial_hi,
                objectuuid: match parse_uuid(objectuuid) {
                    Ok((_, vect)) => assemble_uuid(vect),
                    Err(_e) => {
                        SCLogDebug!("{}", _e);
                        vec![0]
                    },
                },
                interfaceuuid: match parse_uuid(interfaceuuid) {
                    Ok((_, vect)) => assemble_uuid(vect),
                    Err(_e) => {
                        SCLogDebug!("{}", _e);
                        vec![0]
                    },
                },
                activityuuid: match parse_uuid(activityuuid){
                    Ok((_, vect)) => assemble_uuid(vect),
                    Err(_e) => {
                        SCLogDebug!("{}", _e);
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

named!(pub parse_dcerpc_bindack_result<DCERPCBindAckResult>,
    do_parse!(
        ack_result: le_u16
        >>  ack_reason: le_u16
        >>  transfer_syntax: take!(16)
        >>  syntax_version: le_u32
        >> (
             DCERPCBindAckResult {
                ack_result:ack_result,
                ack_reason:ack_reason,
                transfer_syntax:transfer_syntax.to_vec(),
                syntax_version:syntax_version,
            }
        )
    )
);

named!(pub parse_dcerpc_bindack<DCERPCBindAck>,
    do_parse!(
        _max_xmit_frag: le_u16
        >> _max_recv_frag: le_u16
        >> _assoc_group: take!(4)
        >> sec_addr_len: le_u16
        >> take!(sec_addr_len)
        >> cond!((sec_addr_len.wrapping_add(2)) % 4 != 0, take!(4 - (sec_addr_len.wrapping_add(2)) % 4))
        >> numctxitems: le_u8
        >> take!(3) // Padding
        >> ctxitems: count!(parse_dcerpc_bindack_result, numctxitems as usize)
        >> (
             DCERPCBindAck {
                accepted_uuid_list: Vec::new(),
                sec_addr_len: sec_addr_len,
                numctxitems: numctxitems,
                ctxitems: ctxitems,
            }
        )
    )
);

named_args!(pub parse_bindctx_item(endianness: Endianness) <BindCtxItem>,
    do_parse!(
        ctxid: u16!(endianness)
        >> _num_trans_items: le_u8
        >> take!(1) // Reservid bit
        >> uuid: take!(16)
        >> version: u16!(endianness)
        >> versionminor: u16!(endianness)
        >> take!(20)
        >> (
             BindCtxItem {
                ctxid: ctxid,
                // UUID parsing for TCP seems to change as per endianness
                uuid: match parse_uuid(uuid) {
                    Ok((_, vect)) => match endianness {
                        Endianness::Little => assemble_uuid(vect),
                        _ => uuid_to_vec(vect),
                    },
                    // Shouldn't happen
                    Err(_e) => {vec![0]},
                },
                version: version,
                versionminor: versionminor,
            }
        )
    )
);

named!(pub parse_dcerpc_bind<DCERPCBind>,
    do_parse!(
        _max_xmit_frag: le_u16
        >> _max_recv_frag: le_u16
        >> _assoc_group_id: le_u32
        >> numctxitems: le_u8
        >> take!(3)
        >> (
             DCERPCBind {
                numctxitems: numctxitems,
                uuid_list: Vec::new(),
            }
        )
    )
);

named!(pub parse_dcerpc_header<DCERPCHdr>,
    do_parse!(
        rpc_vers: le_u8
        >> rpc_vers_minor: le_u8
        >> hdrtype: le_u8
        >> pfc_flags: le_u8
        >> packed_drep: take!(4)
        >> endianness: value!(if packed_drep[0] & 0x10 == 0 { Endianness::Big } else { Endianness::Little })
        >> frag_length: u16!(endianness)
        >> auth_length: u16!(endianness)
        >> call_id: u32!(endianness)
        >> (
             DCERPCHdr {
                rpc_vers: rpc_vers,
                rpc_vers_minor: rpc_vers_minor,
                hdrtype: hdrtype,
                pfc_flags: pfc_flags,
                packed_drep: packed_drep.to_vec(),
                frag_length: frag_length,
                auth_length: auth_length,
                call_id: call_id,
            }
        )
    )
);

named_args!(pub parse_dcerpc_request(endianness: Endianness) <DCERPCRequest>,
    do_parse!(
        _pad: take!(4)
        >> ctxid: u16!(endianness)
        >> opnum: u16!(endianness)
        >> (
             DCERPCRequest {
                ctxid: ctxid,
                opnum: opnum,
                first_request_seen: 1,
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
    fn test_parse_dcerpc_udp_header() {
        let dcerpcheader: &[u8] = &[
            0x04, 0x00, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x4a, 0x9f, 0x4d,
            0x1c, 0x7d, 0xcf, 0x11, 0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57, 0x86, 0xc2,
            0x37, 0x67, 0xf7, 0x1e, 0xd1, 0x11, 0xbc, 0xd9, 0x00, 0x60, 0x97, 0x92, 0xd2, 0x6c,
            0x79, 0xbe, 0x01, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0x68, 0x00, 0x00, 0x00, 0x0a, 0x00,
        ];
        let (_remainder, header) = parse_dcerpc_udp_header(dcerpcheader).unwrap();
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

    #[test]
    fn test_parse_dcerpc_header() {
        let dcerpcheader: &[u8] = &[
            0x05, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let (_remainder, header) = parse_dcerpc_header(dcerpcheader).unwrap();
        assert_eq!(5, header.rpc_vers);
        assert_eq!(0, header.rpc_vers_minor);
        assert_eq!(0, header.hdrtype);
        assert_eq!(1024, header.frag_length);
    }

    #[test]
    fn test_parse_dcerpc_bind() {
        let dcerpcbind: &[u8] = &[
            0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
        ];
        let (_remainder, bind) = parse_dcerpc_bind(dcerpcbind).unwrap();
        assert_eq!(24, bind.numctxitems);
    }

    #[test]
    fn test_parse_bindctx_item() {
        let dcerpcbind: &[u8] = &[
            0x00, 0x00, 0x01, 0x00, 0x2c, 0xd0, 0x28, 0xda, 0x76, 0x91, 0xf6, 0x6e, 0xcb, 0x0f,
            0xbf, 0x85, 0xcd, 0x9b, 0xf6, 0x39, 0x01, 0x00, 0x03, 0x00, 0x04, 0x5d, 0x88, 0x8a,
            0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
            0x00, 0x00,
        ];
        let (_remainder, ctxitem) = parse_bindctx_item(dcerpcbind, Endianness::Little).unwrap();
        assert_eq!(0, ctxitem.ctxid);
        assert_eq!(1, ctxitem.version);
        assert_eq!(3, ctxitem.versionminor);
    }
}
