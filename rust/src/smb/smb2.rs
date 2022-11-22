/* Copyright (C) 2017-2022 Open Information Security Foundation
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

use nom7::Err;

use crate::core::*;

use crate::smb::smb::*;
use crate::smb::smb2_records::*;
use crate::smb::smb2_session::*;
use crate::smb::smb2_ioctl::*;
use crate::smb::dcerpc::*;
use crate::smb::events::*;
use crate::smb::files::*;
use crate::smb::smb_status::*;

pub const SMB2_COMMAND_NEGOTIATE_PROTOCOL:      u16 = 0;
pub const SMB2_COMMAND_SESSION_SETUP:           u16 = 1;
pub const SMB2_COMMAND_SESSION_LOGOFF:          u16 = 2;
pub const SMB2_COMMAND_TREE_CONNECT:            u16 = 3;
pub const SMB2_COMMAND_TREE_DISCONNECT:         u16 = 4;
pub const SMB2_COMMAND_CREATE:                  u16 = 5;
pub const SMB2_COMMAND_CLOSE:                   u16 = 6;
pub const SMB2_COMMAND_FLUSH:                   u16 = 7;
pub const SMB2_COMMAND_READ:                    u16 = 8;
pub const SMB2_COMMAND_WRITE:                   u16 = 9;
pub const SMB2_COMMAND_LOCK:                    u16 = 10;
pub const SMB2_COMMAND_IOCTL:                   u16 = 11;
pub const SMB2_COMMAND_CANCEL:                  u16 = 12;
pub const SMB2_COMMAND_KEEPALIVE:               u16 = 13;
pub const SMB2_COMMAND_FIND:                    u16 = 14;
pub const SMB2_COMMAND_CHANGE_NOTIFY:           u16 = 15;
pub const SMB2_COMMAND_GET_INFO:                u16 = 16;
pub const SMB2_COMMAND_SET_INFO:                u16 = 17;
pub const SMB2_COMMAND_OPLOCK_BREAK:            u16 = 18;

pub fn smb2_command_string(c: u16) -> String {
    match c {
        SMB2_COMMAND_NEGOTIATE_PROTOCOL     => "SMB2_COMMAND_NEGOTIATE_PROTOCOL",
        SMB2_COMMAND_SESSION_SETUP          => "SMB2_COMMAND_SESSION_SETUP",
        SMB2_COMMAND_SESSION_LOGOFF         => "SMB2_COMMAND_SESSION_LOGOFF",
        SMB2_COMMAND_TREE_CONNECT           => "SMB2_COMMAND_TREE_CONNECT",
        SMB2_COMMAND_TREE_DISCONNECT        => "SMB2_COMMAND_TREE_DISCONNECT",
        SMB2_COMMAND_CREATE                 => "SMB2_COMMAND_CREATE",
        SMB2_COMMAND_CLOSE                  => "SMB2_COMMAND_CLOSE",
        SMB2_COMMAND_READ                   => "SMB2_COMMAND_READ",
        SMB2_COMMAND_FLUSH                  => "SMB2_COMMAND_FLUSH",
        SMB2_COMMAND_WRITE                  => "SMB2_COMMAND_WRITE",
        SMB2_COMMAND_LOCK                   => "SMB2_COMMAND_LOCK",
        SMB2_COMMAND_IOCTL                  => "SMB2_COMMAND_IOCTL",
        SMB2_COMMAND_CANCEL                 => "SMB2_COMMAND_CANCEL",
        SMB2_COMMAND_KEEPALIVE              => "SMB2_COMMAND_KEEPALIVE",
        SMB2_COMMAND_FIND                   => "SMB2_COMMAND_FIND",
        SMB2_COMMAND_CHANGE_NOTIFY          => "SMB2_COMMAND_CHANGE_NOTIFY",
        SMB2_COMMAND_GET_INFO               => "SMB2_COMMAND_GET_INFO",
        SMB2_COMMAND_SET_INFO               => "SMB2_COMMAND_SET_INFO",
        SMB2_COMMAND_OPLOCK_BREAK           => "SMB2_COMMAND_OPLOCK_BREAK",
        _ => { return (c).to_string(); },
    }.to_string()

}

pub fn smb2_dialect_string(d: u16) -> String {
    match d {
        0x0202 => "2.02",
        0x0210 => "2.10",
        0x0222 => "2.22",
        0x0224 => "2.24",
        0x02ff => "2.??",
        0x0300 => "3.00",
        0x0302 => "3.02",
        0x0310 => "3.10",
        0x0311 => "3.11",
        _ => { return (d).to_string(); },
    }.to_string()
}

// later we'll use this to determine if we need to
// track a ssn per type
fn smb2_create_new_tx(cmd: u16) -> bool {
    match cmd {
        SMB2_COMMAND_READ |
        SMB2_COMMAND_WRITE |
        SMB2_COMMAND_GET_INFO |
        SMB2_COMMAND_SET_INFO => { false },
        _ => { true },
    }
}

fn smb2_read_response_record_generic<'b>(state: &mut SMBState, r: &Smb2Record<'b>)
{
    if smb2_create_new_tx(r.command) {
        let tx_hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_GENERICTX);
        let tx = state.get_generic_tx(2, r.command, &tx_hdr);
        if let Some(tx) = tx {
            tx.set_status(r.nt_status, false);
            tx.response_done = true;
        }
    }
}

pub fn smb2_read_response_record<'b>(state: &mut SMBState, r: &Smb2Record<'b>)
{
    let max_queue_size = unsafe { SMB_CFG_MAX_READ_QUEUE_SIZE };
    let max_queue_cnt = unsafe { SMB_CFG_MAX_READ_QUEUE_CNT };

    smb2_read_response_record_generic(state, r);

    match parse_smb2_response_read(r.data) {
        Ok((_, rd)) => {
            if r.nt_status == SMB_NTSTATUS_BUFFER_OVERFLOW {
                SCLogDebug!("SMBv2/READ: incomplete record, expecting a follow up");
                // fall through

            } else if r.nt_status != SMB_NTSTATUS_SUCCESS {
                SCLogDebug!("SMBv2: read response error code received: skip record");
                state.set_skip(Direction::ToClient, rd.len, rd.data.len() as u32);
                return;
            }

            if (state.max_read_size != 0 && rd.len > state.max_read_size) ||
               (unsafe { SMB_CFG_MAX_READ_SIZE != 0 && SMB_CFG_MAX_READ_SIZE < rd.len })
            {
                state.set_event(SMBEvent::ReadResponseTooLarge);
                state.set_skip(Direction::ToClient, rd.len, rd.data.len() as u32);
                return;
            }

            SCLogDebug!("SMBv2: read response => {:?}", rd);

            // get the request info. If we don't have it, there is nothing
            // we can do except skip this record.
            let guid_key = SMBCommonHdr::from2_notree(r, SMBHDR_TYPE_OFFSET);
            let (offset, file_guid) = match state.ssn2vecoffset_map.remove(&guid_key) {
                Some(o) => (o.offset, o.guid),
                None => {
                    SCLogDebug!("SMBv2 READ response: reply to unknown request {:?}",rd);
                    state.set_skip(Direction::ToClient, rd.len, rd.data.len() as u32);
                    return;
                },
            };
            SCLogDebug!("SMBv2 READ: GUID {:?} offset {}", file_guid, offset);

            let mut set_event_fileoverlap = false;
            // look up existing tracker and if we have it update it
            let found = match state.get_file_tx_by_fuid(&file_guid, Direction::ToClient) {
                Some(tx) => {
                    if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                        let file_id : u32 = tx.id as u32;
                        if offset < tdf.file_tracker.tracked {
                            set_event_fileoverlap = true;
                        }
                        if max_queue_size != 0 && tdf.file_tracker.get_inflight_size() + rd.len as u64 > max_queue_size.into() {
                            state.set_event(SMBEvent::ReadQueueSizeExceeded);
                            state.set_skip(Direction::ToClient, rd.len, rd.data.len() as u32);
                        } else if max_queue_cnt != 0 && tdf.file_tracker.get_inflight_cnt() >= max_queue_cnt as usize {
                            state.set_event(SMBEvent::ReadQueueCntExceeded);
                            state.set_skip(Direction::ToClient, rd.len, rd.data.len() as u32);
                        } else {
                            let (files, flags) = tdf.files.get(Direction::ToClient);
                            filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                                    &tdf.file_name, rd.data, offset,
                                    rd.len, false, &file_id);
                        }
                    }
                    true
                },
                None => { false },
            };
            SCLogDebug!("existing file tx? {}", found);
            if !found {
                let tree_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_SHARE);
                let (share_name, mut is_pipe) = match state.ssn2tree_map.get(&tree_key) {
                    Some(n) => (n.name.to_vec(), n.is_pipe),
                    _ => { (Vec::new(), false) },
                };
                let mut is_dcerpc = if is_pipe || (share_name.is_empty() && !is_pipe) {
                    state.get_service_for_guid(&file_guid).1
                } else {
                    false
                };
                SCLogDebug!("SMBv2/READ: share_name {:?} is_pipe {} is_dcerpc {}",
                        share_name, is_pipe, is_dcerpc);

                if share_name.is_empty() && !is_pipe {
                    SCLogDebug!("SMBv2/READ: no tree connect seen, we don't know if we are a pipe");

                    if smb_dcerpc_probe(rd.data) {
                        SCLogDebug!("SMBv2/READ: looks like dcerpc");
                        // insert fake tree to assist in follow up lookups
                        let tree = SMBTree::new(b"suricata::dcerpc".to_vec(), true);
                        state.ssn2tree_map.insert(tree_key, tree);
                        if !is_dcerpc {
                            state.guid2name_map.insert(file_guid.to_vec(), b"suricata::dcerpc".to_vec());
                        }
                        is_pipe = true;
                        is_dcerpc = true;
                    } else {
                        SCLogDebug!("SMBv2/READ: not DCERPC");
                    }
                }

                if is_pipe && is_dcerpc {
                    SCLogDebug!("SMBv2 DCERPC read");
                    let hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_HEADER);
                    let vercmd = SMBVerCmdStat::new2_with_ntstatus(SMB2_COMMAND_READ, r.nt_status);
                    smb_read_dcerpc_record(state, vercmd, hdr, &file_guid, rd.data);
                } else if is_pipe {
                    SCLogDebug!("non-DCERPC pipe");
                    state.set_skip(Direction::ToClient, rd.len, rd.data.len() as u32);
                } else {
                    let file_name = match state.guid2name_map.get(&file_guid) {
                        Some(n) => { n.to_vec() }
                        None => { b"<unknown>".to_vec() }
                    };

                    let tx = state.new_file_tx(&file_guid, &file_name, Direction::ToClient);
                    tx.vercmd.set_smb2_cmd(SMB2_COMMAND_READ);
                    tx.hdr = SMBCommonHdr::new(SMBHDR_TYPE_HEADER,
                            r.session_id, r.tree_id, 0); // TODO move into new_file_tx
                    if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                        tdf.share_name = share_name;
                        let file_id : u32 = tx.id as u32;
                        if offset < tdf.file_tracker.tracked {
                            set_event_fileoverlap = true;
                        }
                        if max_queue_size != 0 && tdf.file_tracker.get_inflight_size() + rd.len as u64 > max_queue_size.into() {
                            state.set_event(SMBEvent::ReadQueueSizeExceeded);
                            state.set_skip(Direction::ToClient, rd.len, rd.data.len() as u32);
                        } else if max_queue_cnt != 0 && tdf.file_tracker.get_inflight_cnt() >= max_queue_cnt as usize {
                            state.set_event(SMBEvent::ReadQueueCntExceeded);
                            state.set_skip(Direction::ToClient, rd.len, rd.data.len() as u32);
                        } else {
                            let (files, flags) = tdf.files.get(Direction::ToClient);
                            filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                                    &file_name, rd.data, offset,
                                    rd.len, false, &file_id);
                        }
                    }
                }
            }

            if set_event_fileoverlap {
                state.set_event(SMBEvent::FileOverlap);
            }
            state.set_file_left(Direction::ToClient, rd.len, rd.data.len() as u32, file_guid.to_vec());
        }
        _ => {
            SCLogDebug!("SMBv2: failed to parse read response");
            state.set_event(SMBEvent::MalformedData);
        }
    }
}

pub fn smb2_write_request_record<'b>(state: &mut SMBState, r: &Smb2Record<'b>)
{
    let max_queue_size = unsafe { SMB_CFG_MAX_WRITE_QUEUE_SIZE };
    let max_queue_cnt = unsafe { SMB_CFG_MAX_WRITE_QUEUE_CNT };

    SCLogDebug!("SMBv2/WRITE: request record");
    if smb2_create_new_tx(r.command) {
        let tx_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_GENERICTX);
        let tx = state.new_generic_tx(2, r.command, tx_key);
        tx.request_done = true;
    }
    match parse_smb2_request_write(r.data) {
        Ok((_, wr)) => {
            if (state.max_write_size != 0 && wr.wr_len > state.max_write_size) ||
               (unsafe { SMB_CFG_MAX_WRITE_SIZE != 0 && SMB_CFG_MAX_WRITE_SIZE < wr.wr_len }) {
                state.set_event(SMBEvent::WriteRequestTooLarge);
                state.set_skip(Direction::ToServer, wr.wr_len, wr.data.len() as u32);
                return;
            }

            /* update key-guid map */
            let guid_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_GUID);
            state.ssn2vec_map.insert(guid_key, wr.guid.to_vec());

            let file_guid = wr.guid.to_vec();
            let file_name = match state.guid2name_map.get(&file_guid) {
                Some(n) => n.to_vec(),
                None => Vec::new(),
            };

            let mut set_event_fileoverlap = false;
            let found = match state.get_file_tx_by_fuid(&file_guid, Direction::ToServer) {
                Some(tx) => {
                    if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                        let file_id : u32 = tx.id as u32;
                        if wr.wr_offset < tdf.file_tracker.tracked {
                            set_event_fileoverlap = true;
                        }
                        if max_queue_size != 0 && tdf.file_tracker.get_inflight_size() + wr.wr_len as u64 > max_queue_size.into() {
                            state.set_event(SMBEvent::WriteQueueSizeExceeded);
                            state.set_skip(Direction::ToServer, wr.wr_len, wr.data.len() as u32);
                        } else if max_queue_cnt != 0 && tdf.file_tracker.get_inflight_cnt() >= max_queue_cnt as usize {
                            state.set_event(SMBEvent::WriteQueueCntExceeded);
                            state.set_skip(Direction::ToServer, wr.wr_len, wr.data.len() as u32);
                        } else {
                            let (files, flags) = tdf.files.get(Direction::ToServer);
                            filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                                    &file_name, wr.data, wr.wr_offset,
                                    wr.wr_len, false, &file_id);
                        }
                    }
                    true
                },
                None => { false },
            };
            if !found {
                let tree_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_SHARE);
                let (share_name, mut is_pipe) = match state.ssn2tree_map.get(&tree_key) {
                    Some(n) => { (n.name.to_vec(), n.is_pipe) },
                    _ => { (Vec::new(), false) },
                };
                let mut is_dcerpc = if is_pipe || (share_name.is_empty() && !is_pipe) {
                    state.get_service_for_guid(wr.guid).1
                } else {
                    false
                };
                SCLogDebug!("SMBv2/WRITE: share_name {:?} is_pipe {} is_dcerpc {}",
                        share_name, is_pipe, is_dcerpc);

                // if we missed the TREE connect we can't be sure if 'is_dcerpc' is correct
                if share_name.is_empty() && !is_pipe {
                    SCLogDebug!("SMBv2/WRITE: no tree connect seen, we don't know if we are a pipe");

                    if smb_dcerpc_probe(wr.data) {
                        SCLogDebug!("SMBv2/WRITE: looks like we have dcerpc");

                        let tree = SMBTree::new(b"suricata::dcerpc".to_vec(), true);
                        state.ssn2tree_map.insert(tree_key, tree);
                        if !is_dcerpc {
                            state.guid2name_map.insert(file_guid.to_vec(),
                                    b"suricata::dcerpc".to_vec());
                        }
                        is_pipe = true;
                        is_dcerpc = true;
                    } else {
                        SCLogDebug!("SMBv2/WRITE: not DCERPC");
                    }
                }
                if is_pipe && is_dcerpc {
                    SCLogDebug!("SMBv2 DCERPC write");
                    let hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_HEADER);
                    let vercmd = SMBVerCmdStat::new2(SMB2_COMMAND_WRITE);
                    smb_write_dcerpc_record(state, vercmd, hdr, wr.data);
                } else if is_pipe {
                    SCLogDebug!("non-DCERPC pipe: skip rest of the record");
                    state.set_skip(Direction::ToServer, wr.wr_len, wr.data.len() as u32);
                } else {
                    let tx = state.new_file_tx(&file_guid, &file_name, Direction::ToServer);
                    tx.vercmd.set_smb2_cmd(SMB2_COMMAND_WRITE);
                    tx.hdr = SMBCommonHdr::new(SMBHDR_TYPE_HEADER,
                            r.session_id, r.tree_id, 0); // TODO move into new_file_tx
                    if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                        let file_id : u32 = tx.id as u32;
                        if wr.wr_offset < tdf.file_tracker.tracked {
                            set_event_fileoverlap = true;
                        }

                        if max_queue_size != 0 && tdf.file_tracker.get_inflight_size() + wr.wr_len as u64 > max_queue_size.into() {
                            state.set_event(SMBEvent::WriteQueueSizeExceeded);
                            state.set_skip(Direction::ToServer, wr.wr_len, wr.data.len() as u32);
                        } else if max_queue_cnt != 0 && tdf.file_tracker.get_inflight_cnt() >= max_queue_cnt as usize {
                            state.set_event(SMBEvent::WriteQueueCntExceeded);
                            state.set_skip(Direction::ToServer, wr.wr_len, wr.data.len() as u32);
                        } else {
                            let (files, flags) = tdf.files.get(Direction::ToServer);
                            filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                                    &file_name, wr.data, wr.wr_offset,
                                    wr.wr_len, false, &file_id);
                        }
                    }
                }
            }

            if set_event_fileoverlap {
                state.set_event(SMBEvent::FileOverlap);
            }
            state.set_file_left(Direction::ToServer, wr.wr_len, wr.data.len() as u32, file_guid.to_vec());
        },
        _ => {
            state.set_event(SMBEvent::MalformedData);
        },
    }
}

pub fn smb2_request_record<'b>(state: &mut SMBState, r: &Smb2Record<'b>)
{
    SCLogDebug!("SMBv2 request record, command {} tree {} session {}",
            &smb2_command_string(r.command), r.tree_id, r.session_id);

    let mut events : Vec<SMBEvent> = Vec::new();

    let have_tx = match r.command {
        SMB2_COMMAND_SET_INFO => {
            SCLogDebug!("SMB2_COMMAND_SET_INFO: {:?}", r);
            let have_si_tx = match parse_smb2_request_setinfo(r.data) {
                Ok((_, rd)) => {
                    SCLogDebug!("SMB2_COMMAND_SET_INFO: {:?}", rd);

                    match rd.data {
                        Smb2SetInfoRequestData::RENAME(ref ren) => {
                            let tx_hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_GENERICTX);
                            let mut newname = ren.name.to_vec();
                            newname.retain(|&i|i != 0x00);
                            let oldname = match state.guid2name_map.get(rd.guid) {
                                Some(n) => { n.to_vec() },
                                None => { b"<unknown>".to_vec() },
                            };
                            let tx = state.new_rename_tx(rd.guid.to_vec(), oldname, newname);
                            tx.hdr = tx_hdr;
                            tx.request_done = true;
                            tx.vercmd.set_smb2_cmd(SMB2_COMMAND_SET_INFO);
                            true
                        }
                        Smb2SetInfoRequestData::DISPOSITION(ref dis) => {
                            let tx_hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_GENERICTX);
                            let fname = match state.guid2name_map.get(rd.guid) {
                                Some(n) => { n.to_vec() },
                                None => {
                                    // try to find latest created file in case of chained commands
                                    let mut guid_key = SMBCommonHdr::from2_notree(r, SMBHDR_TYPE_FILENAME);
                                    if guid_key.msg_id == 0 {
                                        b"<unknown>".to_vec()
                                    } else {
                                        guid_key.msg_id -= 1;
                                        match state.ssn2vec_map.get(&guid_key) {
                                            Some(n) => { n.to_vec() },
                                            None => { b"<unknown>".to_vec()},
                                        }
                                    }
                                },
                            };
                            let tx = state.new_setfileinfo_tx(fname, rd.guid.to_vec(), rd.class as u16, rd.infolvl as u16, dis.delete);
                            tx.hdr = tx_hdr;
                            tx.request_done = true;
                            tx.vercmd.set_smb2_cmd(SMB2_COMMAND_SET_INFO);
                            true
                        }
                        _ => false,
                    }
                },
                Err(Err::Incomplete(_n)) => {
                    SCLogDebug!("SMB2_COMMAND_SET_INFO: {:?}", _n);
                    events.push(SMBEvent::MalformedData);
                    false
                },
                Err(Err::Error(_e)) |
                Err(Err::Failure(_e)) => {
                    SCLogDebug!("SMB2_COMMAND_SET_INFO: {:?}", _e);
                    events.push(SMBEvent::MalformedData);
                    false
                },
            };
            have_si_tx
        },
        SMB2_COMMAND_IOCTL => {
            smb2_ioctl_request_record(state, r);
            true
        },
        SMB2_COMMAND_TREE_DISCONNECT => {
            let tree_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_SHARE);
            state.ssn2tree_map.remove(&tree_key);
            false
        }
        SMB2_COMMAND_NEGOTIATE_PROTOCOL => {
            match parse_smb2_request_negotiate_protocol(r.data) {
                Ok((_, rd)) => {
                    let mut dialects : Vec<Vec<u8>> = Vec::new();
                    for d in rd.dialects_vec {
                        SCLogDebug!("dialect {:x} => {}", d, &smb2_dialect_string(d));
                        let dvec = smb2_dialect_string(d).as_bytes().to_vec();
                        dialects.push(dvec);
                    }

                    let found = match state.get_negotiate_tx(2) {
                        Some(_) => {
                            SCLogDebug!("WEIRD, should not have NEGOTIATE tx!");
                            true
                        },
                        None => { false },
                    };
                    if !found {
                        let tx = state.new_negotiate_tx(2);
                        if let Some(SMBTransactionTypeData::NEGOTIATE(ref mut tdn)) = tx.type_data {
                            tdn.dialects2 = dialects;
                            tdn.client_guid = Some(rd.client_guid.to_vec());
                        }
                        tx.request_done = true;
                    }
                    true
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                    false
                },
            }
        },
        SMB2_COMMAND_SESSION_SETUP => {
            smb2_session_setup_request(state, r);
            true
        },
        SMB2_COMMAND_TREE_CONNECT => {
            match parse_smb2_request_tree_connect(r.data) {
                Ok((_, tr)) => {
                    let name_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_TREE);
                    let mut name_val = tr.share_name.to_vec();
                    name_val.retain(|&i|i != 0x00);
                    if name_val.len() > 1 {
                        name_val = name_val[1..].to_vec();
                    }

                    let tx = state.new_treeconnect_tx(name_key, name_val);
                    tx.request_done = true;
                    tx.vercmd.set_smb2_cmd(SMB2_COMMAND_TREE_CONNECT);
                    true
                }
                _ => {
                    events.push(SMBEvent::MalformedData);
                    false
                },
            }
        },
        SMB2_COMMAND_READ => {
            match parse_smb2_request_read(r.data) {
                Ok((_, rd)) => {
                    if (state.max_read_size != 0 && rd.rd_len > state.max_read_size) ||
                        (unsafe { SMB_CFG_MAX_READ_SIZE != 0 && SMB_CFG_MAX_READ_SIZE < rd.rd_len }) {
                        events.push(SMBEvent::ReadRequestTooLarge);
                    } else {
                        SCLogDebug!("SMBv2 READ: GUID {:?} requesting {} bytes at offset {}",
                                rd.guid, rd.rd_len, rd.rd_offset);

                        // store read guid,offset in map
                        let guid_key = SMBCommonHdr::from2_notree(r, SMBHDR_TYPE_OFFSET);
                        let guidoff = SMBFileGUIDOffset::new(rd.guid.to_vec(), rd.rd_offset);
                        state.ssn2vecoffset_map.insert(guid_key, guidoff);
                    }
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                },
            }
            false
        },
        SMB2_COMMAND_CREATE => {
            match parse_smb2_request_create(r.data) {
                Ok((_, cr)) => {
                    let del = cr.create_options & 0x0000_1000 != 0;
                    let dir = cr.create_options & 0x0000_0001 != 0;

                    SCLogDebug!("create_options {:08x}", cr.create_options);

                    let name_key = SMBCommonHdr::from2_notree(r, SMBHDR_TYPE_FILENAME);
                    state.ssn2vec_map.insert(name_key, cr.data.to_vec());

                    let tx_hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_GENERICTX);
                    let tx = state.new_create_tx(cr.data,
                            cr.disposition, del, dir, tx_hdr);
                    tx.vercmd.set_smb2_cmd(r.command);
                    SCLogDebug!("TS CREATE TX {} created", tx.id);
                    true
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                    false
                },
            }
        },
        SMB2_COMMAND_WRITE => {
            smb2_write_request_record(state, r);
            true // write handling creates both file tx and generic tx
        },
        SMB2_COMMAND_CLOSE => {
            match parse_smb2_request_close(r.data) {
                Ok((_, cd)) => {
                    let found_ts = match state.get_file_tx_by_fuid(cd.guid, Direction::ToServer) {
                        Some(tx) => {
                            if !tx.request_done {
                                if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                                    let (files, flags) = tdf.files.get(Direction::ToServer);
                                    tdf.file_tracker.close(files, flags);
                                }
                            }
                            tx.request_done = true;
                            tx.response_done = true;
                            tx.set_status(SMB_NTSTATUS_SUCCESS, false);
                            true
                        },
                        None => { false },
                    };
                    let found_tc = match state.get_file_tx_by_fuid(cd.guid, Direction::ToClient) {
                        Some(tx) => {
                            if !tx.request_done {
                                if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                                    let (files, flags) = tdf.files.get(Direction::ToClient);
                                    tdf.file_tracker.close(files, flags);
                                }
                            }
                            tx.request_done = true;
                            tx.response_done = true;
                            tx.set_status(SMB_NTSTATUS_SUCCESS, false);
                            true
                        },
                        None => { false },
                    };
                    if !found_ts && !found_tc {
                        SCLogDebug!("SMBv2: CLOSE(TS): no TX at GUID {:?}", cd.guid);
                    }
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                },
            }
            false
        },
        _ => {
            false
        },
    };
    /* if we don't have a tx, create it here (maybe) */
    if !have_tx && smb2_create_new_tx(r.command) {
        let tx_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_GENERICTX);
        let tx = state.new_generic_tx(2, r.command, tx_key);
        SCLogDebug!("TS TX {} command {} created with session_id {} tree_id {} message_id {}",
                tx.id, r.command, r.session_id, r.tree_id, r.message_id);
        tx.set_events(events);
    }
}

pub fn smb2_response_record<'b>(state: &mut SMBState, r: &Smb2Record<'b>)
{
    SCLogDebug!("SMBv2 response record, command {} status {} tree {} session {} message {}",
            &smb2_command_string(r.command), r.nt_status,
            r.tree_id, r.session_id, r.message_id);

    let mut events : Vec<SMBEvent> = Vec::new();

    let have_tx = match r.command {
        SMB2_COMMAND_IOCTL => {
            smb2_ioctl_response_record(state, r);
            true
        },
        SMB2_COMMAND_SESSION_SETUP => {
            smb2_session_setup_response(state, r);
            true
        },
        SMB2_COMMAND_WRITE => {
            if r.nt_status == SMB_NTSTATUS_SUCCESS {
                match parse_smb2_response_write(r.data)
                {
                    Ok((_, _wr)) => {
                        SCLogDebug!("SMBv2: Write response => {:?}", _wr);

                        /* search key-guid map */
                        let guid_key = SMBCommonHdr::new(SMBHDR_TYPE_GUID,
                                r.session_id, r.tree_id, r.message_id);
                        let _guid_vec = match state.ssn2vec_map.remove(&guid_key) {
                            Some(p) => p,
                            None => {
                                SCLogDebug!("SMBv2 response: GUID NOT FOUND");
                                Vec::new()
                            },
                        };
                        SCLogDebug!("SMBv2 write response for GUID {:?}", _guid_vec);
                    }
                    _ => {
                        events.push(SMBEvent::MalformedData);
                    },
                }
            }
            false // the request may have created a generic tx, so handle that here
        },
        SMB2_COMMAND_READ => {
            if r.nt_status == SMB_NTSTATUS_SUCCESS ||
               r.nt_status == SMB_NTSTATUS_BUFFER_OVERFLOW {
                smb2_read_response_record(state, r);
                false

            } else if r.nt_status == SMB_NTSTATUS_END_OF_FILE {
                SCLogDebug!("SMBv2: read response => EOF");

                let guid_key = SMBCommonHdr::from2_notree(r, SMBHDR_TYPE_OFFSET);
                let file_guid = match state.ssn2vecoffset_map.remove(&guid_key) {
                    Some(o) => o.guid,
                    _ => {
                        SCLogDebug!("SMBv2 READ response: reply to unknown request");
                        Vec::new()
                    },
                };
                let found = match state.get_file_tx_by_fuid(&file_guid, Direction::ToClient) {
                    Some(tx) => {
                        if !tx.request_done {
                            if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                                let (files, flags) = tdf.files.get(Direction::ToClient);
                                tdf.file_tracker.close(files, flags);
                            }
                        }
                        tx.set_status(r.nt_status, false);
                        tx.request_done = true;
                        false
                    },
                    None => { false },
                };
                if !found {
                    SCLogDebug!("SMBv2 READ: no TX at GUID {:?}", file_guid);
                }
                false
            } else {
                SCLogDebug!("SMBv2 READ: status {}", r.nt_status);
                false
            }
        },
        SMB2_COMMAND_CREATE => {
            if r.nt_status == SMB_NTSTATUS_SUCCESS {
                match parse_smb2_response_create(r.data) {
                    Ok((_, cr)) => {
                        SCLogDebug!("SMBv2: Create response => {:?}", cr);

                        let guid_key = SMBCommonHdr::from2_notree(r, SMBHDR_TYPE_FILENAME);
                        if let Some(mut p) = state.ssn2vec_map.remove(&guid_key) {
                            p.retain(|&i|i != 0x00);
                            state.guid2name_map.insert(cr.guid.to_vec(), p);
                        } else {
                            SCLogDebug!("SMBv2 response: GUID NOT FOUND");
                        }

                        let tx_hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_GENERICTX);
                        if let Some(tx) = state.get_generic_tx(2, r.command, &tx_hdr) {
                            SCLogDebug!("tx {} with {}/{} marked as done",
                                    tx.id, r.command, &smb2_command_string(r.command));
                            tx.set_status(r.nt_status, false);
                            tx.response_done = true;

                            if let Some(SMBTransactionTypeData::CREATE(ref mut tdn)) = tx.type_data {
                                tdn.create_ts = cr.create_ts.as_unix();
                                tdn.last_access_ts = cr.last_access_ts.as_unix();
                                tdn.last_write_ts = cr.last_write_ts.as_unix();
                                tdn.last_change_ts = cr.last_change_ts.as_unix();
                                tdn.size = cr.size;
                                tdn.guid = cr.guid.to_vec();
                            }
                        }
                    }
                    _ => {
                        events.push(SMBEvent::MalformedData);
                    },
                }
                true
            } else {
                false
            }
        },
        SMB2_COMMAND_TREE_DISCONNECT => {
            // normally removed when processing request,
            // but in case we missed that try again here
            let tree_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_SHARE);
            state.ssn2tree_map.remove(&tree_key);
            false
        }
        SMB2_COMMAND_TREE_CONNECT => {
            if r.nt_status == SMB_NTSTATUS_SUCCESS {
                match parse_smb2_response_tree_connect(r.data) {
                    Ok((_, tr)) => {
                        let name_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_TREE);
                        let mut share_name = Vec::new();
                        let is_pipe = tr.share_type == 2;
                        let found = match state.get_treeconnect_tx(name_key) {
                            Some(tx) => {
                                if let Some(SMBTransactionTypeData::TREECONNECT(ref mut tdn)) = tx.type_data {
                                    tdn.share_type = tr.share_type;
                                    tdn.is_pipe = is_pipe;
                                    tdn.tree_id = r.tree_id;
                                    share_name = tdn.share_name.to_vec();
                                }
                                // update hdr now that we have a tree_id
                                tx.hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_HEADER);
                                tx.response_done = true;
                                tx.set_status(r.nt_status, false);
                                true
                            },
                            None => { false },
                        };
                        if found {
                            let tree = SMBTree::new(share_name.to_vec(), is_pipe);
                            let tree_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_SHARE);
                            state.ssn2tree_map.insert(tree_key, tree);
                        }
                        true
                    }
                    _ => {
                        events.push(SMBEvent::MalformedData);
                        false
                    },
                }
            } else {
                let name_key = SMBCommonHdr::from2(r, SMBHDR_TYPE_TREE);
                let found = match state.get_treeconnect_tx(name_key) {
                    Some(tx) => {
                        tx.response_done = true;
                        tx.set_status(r.nt_status, false);
                        true
                    },
                    None => { false },
                };
                found
            }
        },
        SMB2_COMMAND_NEGOTIATE_PROTOCOL => {
            let res = if r.nt_status == SMB_NTSTATUS_SUCCESS {
                parse_smb2_response_negotiate_protocol(r.data)
            } else {
                parse_smb2_response_negotiate_protocol_error(r.data)
            };
            match res {
                Ok((_, rd)) => {
                    SCLogDebug!("SERVER dialect => {}", &smb2_dialect_string(rd.dialect));

                    let smb_cfg_max_read_size = unsafe { SMB_CFG_MAX_READ_SIZE };
                    if smb_cfg_max_read_size != 0 && rd.max_read_size > smb_cfg_max_read_size {
                        state.set_event(SMBEvent::NegotiateMaxReadSizeTooLarge);
                    }
                    let smb_cfg_max_write_size = unsafe { SMB_CFG_MAX_WRITE_SIZE };
                    if smb_cfg_max_write_size != 0 && rd.max_write_size > smb_cfg_max_write_size {
                        state.set_event(SMBEvent::NegotiateMaxWriteSizeTooLarge);
                    }

                    state.dialect = rd.dialect;
                    state.max_read_size = rd.max_read_size;
                    state.max_write_size = rd.max_write_size;

                    let found2 = match state.get_negotiate_tx(2) {
                        Some(tx) => {
                            if let Some(SMBTransactionTypeData::NEGOTIATE(ref mut tdn)) = tx.type_data {
                                tdn.server_guid = rd.server_guid.to_vec();
                            }
                            tx.set_status(r.nt_status, false);
                            tx.response_done = true;
                            true
                        },
                        None => { false },
                    };
                    // SMB2 response to SMB1 request?
                    let found1 = !found2 && match state.get_negotiate_tx(1) {
                        Some(tx) => {
                            if let Some(SMBTransactionTypeData::NEGOTIATE(ref mut tdn)) = tx.type_data {
                                tdn.server_guid = rd.server_guid.to_vec();
                            }
                            tx.set_status(r.nt_status, false);
                            tx.response_done = true;
                            true
                        },
                        None => { false },
                    };
                    found1 || found2
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                    false
                }
            }
        },
        _ => {
            SCLogDebug!("default case: no TX");
            false
        },
    };
    if !have_tx {
        let tx_hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_GENERICTX);
        SCLogDebug!("looking for TX {} with session_id {} tree_id {} message_id {}",
                &smb2_command_string(r.command),
                r.session_id, r.tree_id, r.message_id);
        let _found = match state.get_generic_tx(2, r.command, &tx_hdr) {
            Some(tx) => {
                SCLogDebug!("tx {} with {}/{} marked as done",
                        tx.id, r.command, &smb2_command_string(r.command));
                if r.nt_status != SMB_NTSTATUS_PENDING {
                    tx.response_done = true;
                }
                tx.set_status(r.nt_status, false);
                tx.set_events(events);
                true
            },
            _ => {
                SCLogDebug!("no tx found for {:?}", r);
                false
            },
        };
    }
}
