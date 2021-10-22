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

// written by Victor Julien

use crate::smb::smb::*;
use crate::smb::smb2::*;
use crate::smb::dcerpc_records::*;
use crate::smb::events::*;

pub const DCERPC_TYPE_REQUEST:              u8 = 0;
pub const DCERPC_TYPE_PING:                 u8 = 1;
pub const DCERPC_TYPE_RESPONSE:             u8 = 2;
pub const DCERPC_TYPE_FAULT:                u8 = 3;
pub const DCERPC_TYPE_WORKING:              u8 = 4;
pub const DCERPC_TYPE_NOCALL:               u8 = 5;
pub const DCERPC_TYPE_REJECT:               u8 = 6;
pub const DCERPC_TYPE_ACK:                  u8 = 7;
pub const DCERPC_TYPE_CL_CANCEL:            u8 = 8;
pub const DCERPC_TYPE_FACK:                 u8 = 9;
pub const DCERPC_TYPE_CANCEL_ACK:           u8 = 10;
pub const DCERPC_TYPE_BIND:                 u8 = 11;
pub const DCERPC_TYPE_BINDACK:              u8 = 12;
pub const DCERPC_TYPE_BINDNAK:              u8 = 13;
pub const DCERPC_TYPE_ALTER_CONTEXT:        u8 = 14;
pub const DCERPC_TYPE_ALTER_CONTEXT_RESP:   u8 = 15;
pub const DCERPC_TYPE_AUTH3:                u8 = 16;
pub const DCERPC_TYPE_SHUTDOWN:             u8 = 17;
pub const DCERPC_TYPE_CO_CANCEL:            u8 = 18;
pub const DCERPC_TYPE_ORPHANED:             u8 = 19;
pub const DCERPC_TYPE_RTS:                  u8 = 20;

pub fn dcerpc_type_string(t: u8) -> String {
    match t {
        DCERPC_TYPE_REQUEST             => "REQUEST",
        DCERPC_TYPE_PING                => "PING",
        DCERPC_TYPE_RESPONSE            => "RESPONSE",
        DCERPC_TYPE_FAULT               => "FAULT",
        DCERPC_TYPE_WORKING             => "WORKING",
        DCERPC_TYPE_NOCALL              => "NOCALL",
        DCERPC_TYPE_REJECT              => "REJECT",
        DCERPC_TYPE_ACK                 => "ACK",
        DCERPC_TYPE_CL_CANCEL           => "CL_CANCEL",
        DCERPC_TYPE_FACK                => "FACK",
        DCERPC_TYPE_CANCEL_ACK          => "CANCEL_ACK",
        DCERPC_TYPE_BIND                => "BIND",
        DCERPC_TYPE_BINDACK             => "BINDACK",
        DCERPC_TYPE_BINDNAK             => "BINDNAK",
        DCERPC_TYPE_ALTER_CONTEXT       => "ALTER_CONTEXT",
        DCERPC_TYPE_ALTER_CONTEXT_RESP  => "ALTER_CONTEXT_RESP",
        DCERPC_TYPE_AUTH3               => "AUTH3",
        DCERPC_TYPE_SHUTDOWN            => "SHUTDOWN",
        DCERPC_TYPE_CO_CANCEL           => "CO_CANCEL",
        DCERPC_TYPE_ORPHANED            => "ORPHANED",
        DCERPC_TYPE_RTS                 => "RTS",
        _ => { return (t).to_string(); },
    }.to_string()
}

impl SMBCommonHdr {
    /// helper for DCERPC tx tracking. Check if we need
    /// to use the msg_id/multiplex_id in TX tracking.
    ///
    pub fn to_dcerpc(&self, vercmd: &SMBVerCmdStat) -> SMBCommonHdr {
        // only use the msg id for IOCTL, not for READ/WRITE
        // as there request/response are different transactions
        let mut use_msg_id = self.msg_id;
        match vercmd.get_version() {
            2 => {
                let (_, cmd2) = vercmd.get_smb2_cmd();
                let x = match cmd2 as u16 {
                    SMB2_COMMAND_READ => { 0 },
                    SMB2_COMMAND_WRITE => { 0 },
                    SMB2_COMMAND_IOCTL => { self.msg_id },
                    _ => { self.msg_id },
                };
                use_msg_id = x;
            },
            1 => {
                SCLogDebug!("FIXME TODO");
                //let (_, cmd1) = vercmd.get_smb1_cmd();
                //if cmd1 != SMB1_COMMAND_IOCTL {
                use_msg_id = 0;
                //}
            },
            _ => { },
        }
        SMBCommonHdr {
            ssn_id: self.ssn_id,
            tree_id: self.tree_id,
            msg_id: use_msg_id,
            rec_type: SMBHDR_TYPE_DCERPCTX,
        }
    }
}

#[derive(Debug)]
pub struct DCERPCIface {
    pub uuid: Vec<u8>,
    pub ver: u16,
    pub ver_min: u16,
    pub ack_result: u16,
    pub ack_reason: u16,
    pub acked: bool,
}

impl DCERPCIface {
    pub fn new(uuid: Vec<u8>, ver: u16, ver_min: u16) -> DCERPCIface {
        DCERPCIface {
            uuid: uuid,
            ver:ver,
            ver_min:ver_min,
            ack_result:0,
            ack_reason:0,
            acked:false,
        }
    }
}

pub fn dcerpc_uuid_to_string(i: &DCERPCIface) -> String {
    let output = format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            i.uuid[0],  i.uuid[1],  i.uuid[2],  i.uuid[3],
            i.uuid[4],  i.uuid[5],  i.uuid[6],  i.uuid[7],
            i.uuid[8],  i.uuid[9],  i.uuid[10], i.uuid[11],
            i.uuid[12], i.uuid[13], i.uuid[14], i.uuid[15]);
    return output;
}


#[derive(Debug)]
pub struct SMBTransactionDCERPC {
    pub opnum: u16,
    pub req_cmd: u8,
    pub req_set: bool,
    pub res_cmd: u8,
    pub res_set: bool,
    pub call_id: u32,
    pub frag_cnt_ts: u16,
    pub frag_cnt_tc: u16,
    pub stub_data_ts: Vec<u8>,
    pub stub_data_tc: Vec<u8>,
}

impl SMBTransactionDCERPC {
    fn new_request(req: u8, call_id: u32) -> SMBTransactionDCERPC {
        return SMBTransactionDCERPC {
            opnum: 0,
            req_cmd: req,
            req_set: true,
            res_cmd: 0,
            res_set: false,
            call_id: call_id,
            frag_cnt_ts: 0,
            frag_cnt_tc: 0,
            stub_data_ts:Vec::new(),
            stub_data_tc:Vec::new(),
        }
    }
    fn new_response(call_id: u32) -> SMBTransactionDCERPC {
        return SMBTransactionDCERPC {
            opnum: 0,
            req_cmd: 0,
            req_set: false,
            res_cmd: 0,
            res_set: false,
            call_id: call_id,
            frag_cnt_ts: 0,
            frag_cnt_tc: 0,
            stub_data_ts:Vec::new(),
            stub_data_tc:Vec::new(),
        }
    }
    pub fn set_result(&mut self, res: u8) {
        self.res_set = true;
        self.res_cmd = res;
    }
}

impl SMBState {
    fn new_dcerpc_tx(&mut self, hdr: SMBCommonHdr, vercmd: SMBVerCmdStat, cmd: u8, call_id: u32)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();
        tx.hdr = hdr;
        tx.vercmd = vercmd;
        tx.type_data = Some(SMBTransactionTypeData::DCERPC(
                    SMBTransactionDCERPC::new_request(cmd, call_id)));

        SCLogDebug!("SMB: TX DCERPC created: ID {} hdr {:?}", tx.id, tx.hdr);
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    fn new_dcerpc_tx_for_response(&mut self, hdr: SMBCommonHdr, vercmd: SMBVerCmdStat, call_id: u32)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();
        tx.hdr = hdr;
        tx.vercmd = vercmd;
        tx.type_data = Some(SMBTransactionTypeData::DCERPC(
                    SMBTransactionDCERPC::new_response(call_id)));

        SCLogDebug!("SMB: TX DCERPC created: ID {} hdr {:?}", tx.id, tx.hdr);
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    fn get_dcerpc_tx(&mut self, hdr: &SMBCommonHdr, vercmd: &SMBVerCmdStat, call_id: u32)
        -> Option<&mut SMBTransaction>
    {
        let dce_hdr = hdr.to_dcerpc(vercmd);

        SCLogDebug!("looking for {:?}", dce_hdr);
        for tx in &mut self.transactions {
            let found = dce_hdr.compare(&tx.hdr.to_dcerpc(vercmd)) &&
                match tx.type_data {
                Some(SMBTransactionTypeData::DCERPC(ref x)) => {
                    x.call_id == call_id
                },
                _ => { false },
            };
            if found {
                return Some(tx);
            }
        }
        return None;
    }
}

/// Handle DCERPC request data from a WRITE, IOCTL or TRANS record.
/// return bool indicating whether an tx has been created/updated.
///
pub fn smb_write_dcerpc_record<'b>(state: &mut SMBState,
        vercmd: SMBVerCmdStat,
        hdr: SMBCommonHdr,
        data: &'b [u8]) -> bool
{
    let mut bind_ifaces : Option<Vec<DCERPCIface>> = None;
    let mut is_bind = false;

    SCLogDebug!("called for {} bytes of data", data.len());
    match parse_dcerpc_record(data) {
        Ok((_, dcer)) => {
            SCLogDebug!("DCERPC: version {}.{} write data {} => {:?}",
                    dcer.version_major, dcer.version_minor, dcer.data.len(), dcer);

            /* if this isn't the first frag, simply update the existing
             * tx with the additional stub data */
            if dcer.packet_type == DCERPC_TYPE_REQUEST && dcer.first_frag == false {
                SCLogDebug!("NOT the first frag. Need to find an existing TX");
                match parse_dcerpc_request_record(dcer.data, dcer.frag_len, dcer.little_endian) {
                    Ok((_, recr)) => {
                        let found = match state.get_dcerpc_tx(&hdr, &vercmd, dcer.call_id) {
                            Some(tx) => {
                                SCLogDebug!("previous CMD {} found at tx {} => {:?}",
                                        dcer.packet_type, tx.id, tx);
                                if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                                    SCLogDebug!("additional frag of size {}", recr.data.len());
                                    tdn.stub_data_ts.extend_from_slice(&recr.data);
                                    tdn.frag_cnt_ts += 1;
                                    SCLogDebug!("stub_data now {}", tdn.stub_data_ts.len());
                                }
                                if dcer.last_frag {
                                    SCLogDebug!("last frag set, so request side of DCERPC closed");
                                    tx.request_done = true;
                                } else {
                                    SCLogDebug!("NOT last frag, so request side of DCERPC remains open");
                                }
                                true
                            },
                            None => {
                                SCLogDebug!("NO previous CMD {} found", dcer.packet_type);
                                false
                            },
                        };
                        return found;
                    },
                    _ => {
                        state.set_event(SMBEvent::MalformedData);
                        return false;
                    },
                }
            }

            let tx = state.new_dcerpc_tx(hdr, vercmd, dcer.packet_type, dcer.call_id);
            match dcer.packet_type {
                DCERPC_TYPE_REQUEST => {
                    match parse_dcerpc_request_record(dcer.data, dcer.frag_len, dcer.little_endian) {
                        Ok((_, recr)) => {
                            SCLogDebug!("DCERPC: REQUEST {:?}", recr);
                            if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                                SCLogDebug!("first frag size {}", recr.data.len());
                                tdn.stub_data_ts.extend_from_slice(&recr.data);
                                tdn.opnum = recr.opnum;
                                tdn.frag_cnt_ts += 1;
                                SCLogDebug!("DCERPC: REQUEST opnum {} stub data len {}",
                                        tdn.opnum, tdn.stub_data_ts.len());
                            }
                            if dcer.last_frag {
                                tx.request_done = true;
                            } else {
                                SCLogDebug!("NOT last frag, so request side of DCERPC remains open");
                            }
                        },
                        _ => {
                            tx.set_event(SMBEvent::MalformedData);
                            tx.request_done = true;
                        },
                    }
                },
                DCERPC_TYPE_BIND => {
                    let brec = if dcer.little_endian == true {
                        parse_dcerpc_bind_record(dcer.data)
                    } else {
                        parse_dcerpc_bind_record_big(dcer.data)
                    };
                    match brec {
                        Ok((_, bindr)) => {
                            is_bind = true;
                            SCLogDebug!("SMB DCERPC {:?} BIND {:?}", dcer, bindr);

                            if bindr.ifaces.len() > 0 {
                                let mut ifaces: Vec<DCERPCIface> = Vec::new();
                                for i in bindr.ifaces {
                                    let x = if dcer.little_endian == true {
                                        vec![i.iface[3],  i.iface[2],  i.iface[1],  i.iface[0],
                                             i.iface[5],  i.iface[4],  i.iface[7],  i.iface[6],
                                             i.iface[8],  i.iface[9],  i.iface[10], i.iface[11],
                                             i.iface[12], i.iface[13], i.iface[14], i.iface[15]]
                                    } else {
                                        i.iface.to_vec()
                                    };
                                    let d = DCERPCIface::new(x,i.ver,i.ver_min);
                                    SCLogDebug!("UUID {} version {}/{} bytes {:?}",
                                            dcerpc_uuid_to_string(&d),
                                            i.ver, i.ver_min,i.iface);
                                    ifaces.push(d);
                                }
                                bind_ifaces = Some(ifaces);
                            }
                        },
                        _ => {
                            tx.set_event(SMBEvent::MalformedData);
                        },
                    }
                    tx.request_done = true;
                }
                21..=255 => {
                    tx.set_event(SMBEvent::MalformedData);
                    tx.request_done = true;
                },
                _ => {
                    // valid type w/o special processing
                    tx.request_done = true;
                },
            }
        },
        _ => {
            state.set_event(SMBEvent::MalformedData);
        },
    }

    if is_bind {
        // We have to write here the interfaces
        // rather than in the BIND block
        // due to borrow issues with the tx mutable reference
        // that is part of the state
        state.dcerpc_ifaces = bind_ifaces; // TODO store per ssn
    }
    return true;
}

/// Update TX for bind ack. Needs to update both tx and state.
///
fn smb_dcerpc_response_bindack(
        state: &mut SMBState,
        vercmd: SMBVerCmdStat,
        hdr: SMBCommonHdr,
        dcer: &DceRpcRecord,
        ntstatus: u32)
{
    match parse_dcerpc_bindack_record(dcer.data) {
        Ok((_, bindackr)) => {
            SCLogDebug!("SMB READ BINDACK {:?}", bindackr);

            let found = match state.get_dcerpc_tx(&hdr, &vercmd, dcer.call_id) {
                Some(tx) => {
                    if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                        tdn.set_result(DCERPC_TYPE_BINDACK);
                    }
                    tx.vercmd.set_ntstatus(ntstatus);
                    tx.response_done = true;
                    true
                },
                None => false,
            };
            if found {
                match state.dcerpc_ifaces {
                    Some(ref mut ifaces) => {
                        let mut i = 0;
                        for r in bindackr.results {
                            if i >= ifaces.len() {
                                // TODO set event: more acks that requests
                                break;
                            }
                            ifaces[i].ack_result = r.ack_result;
                            ifaces[i].acked = true;
                            i = i + 1;
                        }
                    },
                    _ => {},
                }
            }
        },
        _ => {
            state.set_event(SMBEvent::MalformedData);
        },
    }
}

fn smb_read_dcerpc_record_error(state: &mut SMBState,
        hdr: SMBCommonHdr, vercmd: SMBVerCmdStat, ntstatus: u32)
    -> bool
{
    let ver = vercmd.get_version();
    let cmd = if ver == 2 {
        let (_, c) = vercmd.get_smb2_cmd();
        c
    } else {
        let (_, c) = vercmd.get_smb1_cmd();
        c as u16
    };

    let found = match state.get_generic_tx(ver, cmd, &hdr) {
        Some(tx) => {
            SCLogDebug!("found");
            tx.set_status(ntstatus, false);
            tx.response_done = true;
            true
        },
        None => {
            SCLogDebug!("NOT found");
            false
        },
    };
    return found;
}

fn dcerpc_response_handle<'b>(tx: &mut SMBTransaction,
        vercmd: SMBVerCmdStat,
        dcer: &DceRpcRecord)
{
    let (_, ntstatus) = vercmd.get_ntstatus();
    match dcer.packet_type {
        DCERPC_TYPE_RESPONSE => {
            match parse_dcerpc_response_record(dcer.data, dcer.frag_len) {
                Ok((_, respr)) => {
                    SCLogDebug!("SMBv1 READ RESPONSE {:?}", respr);
                    if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                        SCLogDebug!("CMD 11 found at tx {}", tx.id);
                        tdn.set_result(DCERPC_TYPE_RESPONSE);
                        tdn.stub_data_tc.extend_from_slice(&respr.data);
                        tdn.frag_cnt_tc += 1;
                    }
                    tx.vercmd.set_ntstatus(ntstatus);
                    tx.response_done = dcer.last_frag;
                },
                _ => {
                    tx.set_event(SMBEvent::MalformedData);
                },
            }
        },
        DCERPC_TYPE_BINDACK => {
            // handled elsewhere
        },
        21..=255 => {
            if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                tdn.set_result(dcer.packet_type);
            }
            tx.vercmd.set_ntstatus(ntstatus);
            tx.response_done = true;
            tx.set_event(SMBEvent::MalformedData);
        }
        _ => { // valid type w/o special processing
            if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                tdn.set_result(dcer.packet_type);
            }
            tx.vercmd.set_ntstatus(ntstatus);
            tx.response_done = true;
        },
    }
}

/// Handle DCERPC reply record. Called for READ, TRANS, IOCTL
///
pub fn smb_read_dcerpc_record<'b>(state: &mut SMBState,
        vercmd: SMBVerCmdStat,
        hdr: SMBCommonHdr,
        guid: &[u8],
        indata: &'b [u8]) -> bool
{
    let (_, ntstatus) = vercmd.get_ntstatus();

    if ntstatus != SMB_NTSTATUS_SUCCESS && ntstatus != SMB_NTSTATUS_BUFFER_OVERFLOW {
        return smb_read_dcerpc_record_error(state, hdr, vercmd, ntstatus);
    }

    SCLogDebug!("lets first see if we have prior data");
    // msg_id 0 as this data crosses cmd/reply pairs
    let ehdr = SMBHashKeyHdrGuid::new(SMBCommonHdr::new(SMBHDR_TYPE_TRANS_FRAG,
            hdr.ssn_id as u64, hdr.tree_id as u32, 0 as u64), guid.to_vec());
    let mut prevdata = match state.ssnguid2vec_map.remove(&ehdr) {
        Some(s) => s,
        None => Vec::new(),
    };
    SCLogDebug!("indata {} prevdata {}", indata.len(), prevdata.len());
    prevdata.extend_from_slice(&indata);
    let data = prevdata;

    let mut malformed = false;

    if data.len() == 0 {
        SCLogDebug!("weird: no DCERPC data"); // TODO
        // TODO set event?
        return false;

    } else {
        match parse_dcerpc_record(&data) {
            Ok((_, dcer)) => {
                SCLogDebug!("DCERPC: version {}.{} read data {} => {:?}",
                        dcer.version_major, dcer.version_minor, dcer.data.len(), dcer);

                if ntstatus == SMB_NTSTATUS_BUFFER_OVERFLOW && data.len() < dcer.frag_len as usize {
                    SCLogDebug!("short record {} < {}: storing partial data in state",
                            data.len(), dcer.frag_len);
                    state.ssnguid2vec_map.insert(ehdr, data.to_vec());
                    return true; // TODO review
                }

                if dcer.packet_type == DCERPC_TYPE_BINDACK {
                    smb_dcerpc_response_bindack(state, vercmd, hdr, &dcer, ntstatus);
                    return true;
                }

                let found = match state.get_dcerpc_tx(&hdr, &vercmd, dcer.call_id) {
                    Some(tx) => {
                        dcerpc_response_handle(tx, vercmd.clone(), &dcer);
                        true
                    },
                    None => {
                        SCLogDebug!("no tx");
                        false
                    },
                };
                if !found {
                    // pick up DCERPC tx even if we missed the request
                    let tx = state.new_dcerpc_tx_for_response(hdr, vercmd.clone(), dcer.call_id);
                    dcerpc_response_handle(tx, vercmd, &dcer);
                }
            },
            _ => {
                malformed = true;
            },
        }
    }

    if malformed {
        state.set_event(SMBEvent::MalformedData);
    }

    return true;
}

/// Try to find out if the input data looks like DCERPC
pub fn smb_dcerpc_probe<'b>(data: &[u8]) -> bool
{
    if let Ok((_, recr)) = parse_dcerpc_record(data) {
        SCLogDebug!("SMB: could be DCERPC {:?}", recr);
        if recr.version_major == 5 && recr.version_minor < 3 &&
            recr.frag_len > 0 && recr.packet_type <= 20
            {
                SCLogDebug!("SMB: looks like we have dcerpc");
                return true;
            }
    }
    return false;
}
