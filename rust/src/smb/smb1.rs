/* Copyright (C) 2018-2022 Open Information Security Foundation
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

/* TODO
 * - check all parsers for calls on non-SUCCESS status
 */

use crate::core::*;

use crate::smb::smb::*;
use crate::smb::dcerpc::*;
use crate::smb::events::*;
use crate::smb::files::*;

use crate::smb::smb1_records::*;
use crate::smb::smb1_session::*;

use crate::smb::smb_status::*;

use nom7::Err;

// https://msdn.microsoft.com/en-us/library/ee441741.aspx
pub const SMB1_COMMAND_CREATE_DIRECTORY:        u8 = 0x00;
pub const SMB1_COMMAND_DELETE_DIRECTORY:        u8 = 0x01;
pub const SMB1_COMMAND_OPEN:                    u8 = 0x02;
pub const SMB1_COMMAND_CREATE:                  u8 = 0x03;
pub const SMB1_COMMAND_CLOSE:                   u8 = 0x04;
pub const SMB1_COMMAND_FLUSH:                   u8 = 0x05;
pub const SMB1_COMMAND_DELETE:                  u8 = 0x06;
pub const SMB1_COMMAND_RENAME:                  u8 = 0x07;
pub const SMB1_COMMAND_QUERY_INFORMATION:       u8 = 0x08;
pub const SMB1_COMMAND_SET_INFORMATION:         u8 = 0x09;
pub const SMB1_COMMAND_READ:                    u8 = 0x0a;
pub const SMB1_COMMAND_WRITE:                   u8 = 0x0b;
pub const SMB1_COMMAND_LOCK_BYTE_RANGE:         u8 = 0x0c;
pub const SMB1_COMMAND_UNLOCK_BYTE_RANGE:       u8 = 0x0d;
pub const SMB1_COMMAND_CREATE_TEMPORARY:        u8 = 0x0e;
pub const SMB1_COMMAND_CREATE_NEW:              u8 = 0x0f;
pub const SMB1_COMMAND_CHECK_DIRECTORY:         u8 = 0x10;
pub const SMB1_COMMAND_PROCESS_EXIT:            u8 = 0x11;
pub const SMB1_COMMAND_SEEK:                    u8 = 0x12;
pub const SMB1_COMMAND_LOCK_AND_READ:           u8 = 0x13;
pub const SMB1_COMMAND_WRITE_AND_UNLOCK:        u8 = 0x14;
pub const SMB1_COMMAND_LOCKING_ANDX:            u8 = 0x24;
pub const SMB1_COMMAND_TRANS:                   u8 = 0x25;
pub const SMB1_COMMAND_ECHO:                    u8 = 0x2b;
pub const SMB1_COMMAND_WRITE_AND_CLOSE:         u8 = 0x2c;
pub const SMB1_COMMAND_OPEN_ANDX:               u8 = 0x2d;
pub const SMB1_COMMAND_READ_ANDX:               u8 = 0x2e;
pub const SMB1_COMMAND_WRITE_ANDX:              u8 = 0x2f;
pub const SMB1_COMMAND_TRANS2:                  u8 = 0x32;
pub const SMB1_COMMAND_TRANS2_SECONDARY:        u8 = 0x33;
pub const SMB1_COMMAND_FIND_CLOSE2:             u8 = 0x34;
pub const SMB1_COMMAND_TREE_DISCONNECT:         u8 = 0x71;
pub const SMB1_COMMAND_NEGOTIATE_PROTOCOL:      u8 = 0x72;
pub const SMB1_COMMAND_SESSION_SETUP_ANDX:      u8 = 0x73;
pub const SMB1_COMMAND_LOGOFF_ANDX:             u8 = 0x74;
pub const SMB1_COMMAND_TREE_CONNECT_ANDX:       u8 = 0x75;
pub const SMB1_COMMAND_QUERY_INFO_DISK:         u8 = 0x80;
pub const SMB1_COMMAND_NT_TRANS:                u8 = 0xa0;
pub const SMB1_COMMAND_NT_TRANS_SECONDARY:      u8 = 0xa1;
pub const SMB1_COMMAND_NT_CREATE_ANDX:          u8 = 0xa2;
pub const SMB1_COMMAND_NT_CANCEL:               u8 = 0xa4;
pub const SMB1_COMMAND_NONE:                    u8 = 0xff;

pub fn smb1_command_string(c: u8) -> String {
    match c {
        SMB1_COMMAND_CREATE_DIRECTORY   => "SMB1_COMMAND_CREATE_DIRECTORY",
        SMB1_COMMAND_DELETE_DIRECTORY   => "SMB1_COMMAND_DELETE_DIRECTORY",
        SMB1_COMMAND_OPEN               => "SMB1_COMMAND_OPEN",
        SMB1_COMMAND_CREATE             => "SMB1_COMMAND_CREATE",
        SMB1_COMMAND_CLOSE              => "SMB1_COMMAND_CLOSE",
        SMB1_COMMAND_FLUSH              => "SMB1_COMMAND_FLUSH",
        SMB1_COMMAND_DELETE             => "SMB1_COMMAND_DELETE",
        SMB1_COMMAND_RENAME             => "SMB1_COMMAND_RENAME",
        SMB1_COMMAND_QUERY_INFORMATION  => "SMB1_COMMAND_QUERY_INFORMATION",
        SMB1_COMMAND_SET_INFORMATION    => "SMB1_COMMAND_SET_INFORMATION",
        SMB1_COMMAND_READ               => "SMB1_COMMAND_READ",
        SMB1_COMMAND_WRITE              => "SMB1_COMMAND_WRITE",
        SMB1_COMMAND_LOCK_BYTE_RANGE    => "SMB1_COMMAND_LOCK_BYTE_RANGE",
        SMB1_COMMAND_UNLOCK_BYTE_RANGE  => "SMB1_COMMAND_UNLOCK_BYTE_RANGE",
        SMB1_COMMAND_CREATE_TEMPORARY   => "SMB1_COMMAND_CREATE_TEMPORARY",
        SMB1_COMMAND_CREATE_NEW         => "SMB1_COMMAND_CREATE_NEW",
        SMB1_COMMAND_CHECK_DIRECTORY    => "SMB1_COMMAND_CHECK_DIRECTORY",
        SMB1_COMMAND_PROCESS_EXIT       => "SMB1_COMMAND_PROCESS_EXIT",
        SMB1_COMMAND_SEEK               => "SMB1_COMMAND_SEEK",
        SMB1_COMMAND_LOCK_AND_READ      => "SMB1_COMMAND_LOCK_AND_READ",
        SMB1_COMMAND_WRITE_AND_UNLOCK   => "SMB1_COMMAND_WRITE_AND_UNLOCK",
        SMB1_COMMAND_LOCKING_ANDX       => "SMB1_COMMAND_LOCKING_ANDX",
        SMB1_COMMAND_ECHO               => "SMB1_COMMAND_ECHO",
        SMB1_COMMAND_WRITE_AND_CLOSE    => "SMB1_COMMAND_WRITE_AND_CLOSE",
        SMB1_COMMAND_OPEN_ANDX          => "SMB1_COMMAND_OPEN_ANDX",
        SMB1_COMMAND_READ_ANDX          => "SMB1_COMMAND_READ_ANDX",
        SMB1_COMMAND_WRITE_ANDX         => "SMB1_COMMAND_WRITE_ANDX",
        SMB1_COMMAND_TRANS              => "SMB1_COMMAND_TRANS",
        SMB1_COMMAND_TRANS2             => "SMB1_COMMAND_TRANS2",
        SMB1_COMMAND_TRANS2_SECONDARY   => "SMB1_COMMAND_TRANS2_SECONDARY",
        SMB1_COMMAND_FIND_CLOSE2        => "SMB1_COMMAND_FIND_CLOSE2",
        SMB1_COMMAND_TREE_DISCONNECT    => "SMB1_COMMAND_TREE_DISCONNECT",
        SMB1_COMMAND_NEGOTIATE_PROTOCOL => "SMB1_COMMAND_NEGOTIATE_PROTOCOL",
        SMB1_COMMAND_SESSION_SETUP_ANDX => "SMB1_COMMAND_SESSION_SETUP_ANDX",
        SMB1_COMMAND_LOGOFF_ANDX        => "SMB1_COMMAND_LOGOFF_ANDX",
        SMB1_COMMAND_TREE_CONNECT_ANDX  => "SMB1_COMMAND_TREE_CONNECT_ANDX",
        SMB1_COMMAND_QUERY_INFO_DISK    => "SMB1_COMMAND_QUERY_INFO_DISK",
        SMB1_COMMAND_NT_TRANS           => "SMB1_COMMAND_NT_TRANS",
        SMB1_COMMAND_NT_TRANS_SECONDARY => "SMB1_COMMAND_NT_TRANS_SECONDARY",
        SMB1_COMMAND_NT_CREATE_ANDX     => "SMB1_COMMAND_NT_CREATE_ANDX",
        SMB1_COMMAND_NT_CANCEL          => "SMB1_COMMAND_NT_CANCEL",
        _ => { return (c).to_string(); },
    }.to_string()
}

// later we'll use this to determine if we need to
// track a ssn per type
pub fn smb1_create_new_tx(cmd: u8) -> bool {
    match cmd {
        SMB1_COMMAND_READ_ANDX |
        SMB1_COMMAND_WRITE_ANDX |
        SMB1_COMMAND_TRANS |
        SMB1_COMMAND_TRANS2 => { false },
        _ => { true },
    }
}

// see if we're going to do a lookup for a TX.
// related to smb1_create_new_tx(), however it
// excludes the 'maybe' commands like TRANS2
pub fn smb1_check_tx(cmd: u8) -> bool {
    match cmd {
        SMB1_COMMAND_READ_ANDX |
        SMB1_COMMAND_WRITE_ANDX |
        SMB1_COMMAND_TRANS => { false },
        _ => { true },
    }
}

fn smb1_close_file(state: &mut SMBState, fid: &Vec<u8>, direction: Direction)
{
    if let Some((tx, files, flags)) = state.get_file_tx_by_fuid(fid, direction) {
        SCLogDebug!("found tx {}", tx.id);
        if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
            if !tx.request_done {
                SCLogDebug!("closing file tx {} FID {:?}", tx.id, fid);
                tdf.file_tracker.close(files, flags);
                tx.request_done = true;
                tx.response_done = true;
                SCLogDebug!("tx {} is done", tx.id);
            }
        }
    }
}

fn smb1_command_is_andx(c: u8) -> bool {
    match c {
        SMB1_COMMAND_LOCKING_ANDX |
        SMB1_COMMAND_OPEN_ANDX |
        SMB1_COMMAND_READ_ANDX |
        SMB1_COMMAND_SESSION_SETUP_ANDX |
        SMB1_COMMAND_LOGOFF_ANDX |
        SMB1_COMMAND_TREE_CONNECT_ANDX |
        SMB1_COMMAND_NT_CREATE_ANDX |
        SMB1_COMMAND_WRITE_ANDX  => {
            return true;
        }
        _ => {
            return false;
        }
    }
}

fn smb1_request_record_one<'b>(state: &mut SMBState, r: &SmbRecord<'b>, command: u8, andx_offset: &mut usize) {
    let mut events : Vec<SMBEvent> = Vec::new();
    let mut no_response_expected = false;

    let have_tx = match command {
        SMB1_COMMAND_RENAME => {
            match parse_smb_rename_request_record(r.data) {
                Ok((_, rd)) => {
                    SCLogDebug!("RENAME {:?}", rd);

                    let tx_hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_GENERICTX);
                    let mut newname = rd.newname;
                    newname.retain(|&i|i != 0x00);
                    let mut oldname = rd.oldname;
                    oldname.retain(|&i|i != 0x00);

                    let tx = state.new_rename_tx(Vec::new(), oldname, newname);
                    tx.hdr = tx_hdr;
                    tx.request_done = true;
                    tx.vercmd.set_smb1_cmd(SMB1_COMMAND_RENAME);
                    true
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                    false
                },
            }
        },
        SMB1_COMMAND_TRANS2 => {
            match parse_smb_trans2_request_record(r.data) {
                Ok((_, rd)) => {
                    SCLogDebug!("TRANS2 DONE {:?}", rd);

                    if rd.subcmd == 6 {
                        SCLogDebug!("SET_PATH_INFO");
                        match parse_trans2_request_params_set_path_info(rd.setup_blob) {
                            Ok((_, pd)) => {
                                SCLogDebug!("TRANS2 SET_PATH_INFO PARAMS DONE {:?}", pd);

                                if pd.loi == 1013 { // set disposition info
                                    match parse_trans2_request_data_set_file_info_disposition(rd.data_blob) {
                                        Ok((_, disp)) => {
                                            SCLogDebug!("TRANS2 SET_FILE_INFO DATA DISPOSITION DONE {:?}", disp);
                                            let tx_hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_GENERICTX);

                                            let tx = state.new_setpathinfo_tx(pd.oldname,
                                                    rd.subcmd, pd.loi, disp.delete);
                                            tx.hdr = tx_hdr;
                                            tx.request_done = true;
                                            tx.vercmd.set_smb1_cmd(SMB1_COMMAND_TRANS2);
                                            true

                                        },
                                        Err(Err::Incomplete(_n)) => {
                                            SCLogDebug!("TRANS2 SET_FILE_INFO DATA DISPOSITION INCOMPLETE {:?}", _n);
                                            events.push(SMBEvent::MalformedData);
                                            false
                                        },
                                        Err(Err::Error(_e)) |
                                        Err(Err::Failure(_e)) => {
                                            SCLogDebug!("TRANS2 SET_FILE_INFO DATA DISPOSITION ERROR {:?}", _e);
                                            events.push(SMBEvent::MalformedData);
                                            false
                                        },
                                    }
                                } else if pd.loi == 1010 {
                                    match parse_trans2_request_data_set_path_info_rename(rd.data_blob) {
                                        Ok((_, ren)) => {
                                            SCLogDebug!("TRANS2 SET_PATH_INFO DATA RENAME DONE {:?}", ren);
                                            let tx_hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_GENERICTX);
                                            let mut newname = ren.newname.to_vec();
                                            newname.retain(|&i|i != 0x00);

                                            let fid : Vec<u8> = Vec::new();

                                            let tx = state.new_rename_tx(fid, pd.oldname, newname);
                                            tx.hdr = tx_hdr;
                                            tx.request_done = true;
                                            tx.vercmd.set_smb1_cmd(SMB1_COMMAND_TRANS2);
                                            true
                                        },
                                        Err(Err::Incomplete(_n)) => {
                                            SCLogDebug!("TRANS2 SET_PATH_INFO DATA RENAME INCOMPLETE {:?}", _n);
                                            events.push(SMBEvent::MalformedData);
                                            false
                                        },
                                        Err(Err::Error(_e)) |
                                        Err(Err::Failure(_e)) => {
                                            SCLogDebug!("TRANS2 SET_PATH_INFO DATA RENAME ERROR {:?}", _e);
                                            events.push(SMBEvent::MalformedData);
                                            false
                                        },
                                    }
                                } else {
                                    false
                                }
                            },
                            Err(Err::Incomplete(_n)) => {
                                SCLogDebug!("TRANS2 SET_PATH_INFO PARAMS INCOMPLETE {:?}", _n);
                                events.push(SMBEvent::MalformedData);
                                false
                            },
                            Err(Err::Error(_e)) |
                            Err(Err::Failure(_e)) => {
                                SCLogDebug!("TRANS2 SET_PATH_INFO PARAMS ERROR {:?}", _e);
                                events.push(SMBEvent::MalformedData);
                                false
                            },
                        }
                    } else if rd.subcmd == 8 {
                        SCLogDebug!("SET_FILE_INFO");
                        match parse_trans2_request_params_set_file_info(rd.setup_blob) {
                            Ok((_, pd)) => {
                                SCLogDebug!("TRANS2 SET_FILE_INFO PARAMS DONE {:?}", pd);

                                if pd.loi == 1013 { // set disposition info
                                    match parse_trans2_request_data_set_file_info_disposition(rd.data_blob) {
                                        Ok((_, disp)) => {
                                            SCLogDebug!("TRANS2 SET_FILE_INFO DATA DISPOSITION DONE {:?}", disp);
                                            let tx_hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_GENERICTX);

                                            let mut frankenfid = pd.fid.to_vec();
                                            frankenfid.extend_from_slice(&u32_as_bytes(r.ssn_id));

                                            let filename = match state.guid2name_map.get(&frankenfid) {
                                                Some(n) => n.to_vec(),
                                                None => b"<unknown>".to_vec(),
                                            };
                                            let tx = state.new_setfileinfo_tx(filename, pd.fid.to_vec(),
                                                    rd.subcmd, pd.loi, disp.delete);
                                            tx.hdr = tx_hdr;
                                            tx.request_done = true;
                                            tx.vercmd.set_smb1_cmd(SMB1_COMMAND_TRANS2);
                                            true

                                        },
                                        Err(Err::Incomplete(_n)) => {
                                            SCLogDebug!("TRANS2 SET_FILE_INFO DATA DISPOSITION INCOMPLETE {:?}", _n);
                                            events.push(SMBEvent::MalformedData);
                                            false
                                        },
                                        Err(Err::Error(_e)) |
                                        Err(Err::Failure(_e)) => {
                                            SCLogDebug!("TRANS2 SET_FILE_INFO DATA DISPOSITION ERROR {:?}", _e);
                                            events.push(SMBEvent::MalformedData);
                                            false
                                        },
                                    }
                                } else if pd.loi == 1010 {
                                    match parse_trans2_request_data_set_file_info_rename(rd.data_blob) {
                                        Ok((_, ren)) => {
                                            SCLogDebug!("TRANS2 SET_FILE_INFO DATA RENAME DONE {:?}", ren);
                                            let tx_hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_GENERICTX);
                                            let mut newname = ren.newname.to_vec();
                                            newname.retain(|&i|i != 0x00);

                                            let mut frankenfid = pd.fid.to_vec();
                                            frankenfid.extend_from_slice(&u32_as_bytes(r.ssn_id));

                                            let oldname = match state.guid2name_map.get(&frankenfid) {
                                                Some(n) => n.to_vec(),
                                                None => b"<unknown>".to_vec(),
                                            };
                                            let tx = state.new_rename_tx(pd.fid.to_vec(), oldname, newname);
                                            tx.hdr = tx_hdr;
                                            tx.request_done = true;
                                            tx.vercmd.set_smb1_cmd(SMB1_COMMAND_TRANS2);
                                            true
                                        },
                                        Err(Err::Incomplete(_n)) => {
                                            SCLogDebug!("TRANS2 SET_FILE_INFO DATA RENAME INCOMPLETE {:?}", _n);
                                            events.push(SMBEvent::MalformedData);
                                            false
                                        },
                                        Err(Err::Error(_e)) |
                                        Err(Err::Failure(_e)) => {
                                            SCLogDebug!("TRANS2 SET_FILE_INFO DATA RENAME ERROR {:?}", _e);
                                            events.push(SMBEvent::MalformedData);
                                            false
                                        },
                                    }
                                } else {
                                    false
                                }
                            },
                            Err(Err::Incomplete(_n)) => {
                                SCLogDebug!("TRANS2 SET_FILE_INFO PARAMS INCOMPLETE {:?}", _n);
                                events.push(SMBEvent::MalformedData);
                                false
                            },
                            Err(Err::Error(_e)) |
                            Err(Err::Failure(_e)) => {
                                SCLogDebug!("TRANS2 SET_FILE_INFO PARAMS ERROR {:?}", _e);
                                events.push(SMBEvent::MalformedData);
                                false
                            },
                        }
                    } else {
                        false
                    }
                },
                Err(Err::Incomplete(_n)) => {
                    SCLogDebug!("TRANS2 INCOMPLETE {:?}", _n);
                    events.push(SMBEvent::MalformedData);
                    false
                },
                Err(Err::Error(_e)) |
                Err(Err::Failure(_e)) => {
                    SCLogDebug!("TRANS2 ERROR {:?}", _e);
                    events.push(SMBEvent::MalformedData);
                    false
                },
            }
        },
        SMB1_COMMAND_READ_ANDX => {
            match parse_smb_read_andx_request_record(&r.data[*andx_offset-SMB1_HEADER_SIZE..]) {
                Ok((_, rr)) => {
                    SCLogDebug!("rr {:?}", rr);

                    // store read fid,offset in map
                    let fid_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_OFFSET);
                    let mut fid = rr.fid.to_vec();
                    fid.extend_from_slice(&u32_as_bytes(r.ssn_id));
                    let fidoff = SMBFileGUIDOffset::new(fid, rr.offset);
                    state.ssn2vecoffset_map.insert(fid_key, fidoff);
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                },
            }
            false
        },
        SMB1_COMMAND_WRITE_ANDX |
        SMB1_COMMAND_WRITE |
        SMB1_COMMAND_WRITE_AND_CLOSE => {
            smb1_write_request_record(state, r, *andx_offset, command);
            true // tx handling in func
        },
        SMB1_COMMAND_TRANS => {
            smb1_trans_request_record(state, r);
            true
        },
        SMB1_COMMAND_NEGOTIATE_PROTOCOL => {
            match parse_smb1_negotiate_protocol_record(r.data) {
                Ok((_, pr)) => {
                    SCLogDebug!("SMB_COMMAND_NEGOTIATE_PROTOCOL {:?}", pr);

                    let mut bad_dialects = false;
                    let mut dialects : Vec<Vec<u8>> = Vec::new();
                    for d in &pr.dialects {
                        if d.len() == 0 {
                            bad_dialects = true;
                            continue;
                        } else if d.len() == 1 {
                            bad_dialects = true;
                        }
                        let x = &d[1..d.len()];
                        let dvec = x.to_vec();
                        dialects.push(dvec);
                    }

                    let found = match state.get_negotiate_tx(1) {
                        Some(tx) => {
                            SCLogDebug!("WEIRD, should not have NEGOTIATE tx!");
                            tx.set_event(SMBEvent::DuplicateNegotiate);
                            true
                        },
                        None => { false },
                    };
                    if !found {
                        let tx = state.new_negotiate_tx(1);
                        if let Some(SMBTransactionTypeData::NEGOTIATE(ref mut tdn)) = tx.type_data {
                            tdn.dialects = dialects;
                        }
                        tx.request_done = true;
                        if bad_dialects {
                            tx.set_event(SMBEvent::NegotiateMalformedDialects);
                        }
                    }
                    true
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                    false
                },
            }
        },
        SMB1_COMMAND_NT_CREATE_ANDX => {
            match parse_smb_create_andx_request_record(&r.data[*andx_offset-SMB1_HEADER_SIZE..], r) {
                Ok((_, cr)) => {
                    SCLogDebug!("Create AndX {:?}", cr);
                    let del = cr.create_options & 0x0000_1000 != 0;
                    let dir = cr.create_options & 0x0000_0001 != 0;
                    SCLogDebug!("del {} dir {} options {:08x}", del, dir, cr.create_options);

                    let name_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_FILENAME);
                    let name_val = cr.file_name.to_vec();
                    state.ssn2vec_map.insert(name_key, name_val);

                    let tx_hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_GENERICTX);
                    let tx = state.new_create_tx(&cr.file_name.to_vec(),
                            cr.disposition, del, dir, tx_hdr);
                    tx.vercmd.set_smb1_cmd(command);
                    SCLogDebug!("TS CREATE TX {} created", tx.id);
                    true
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                    false
                },
            }
        },
        SMB1_COMMAND_SESSION_SETUP_ANDX => {
            SCLogDebug!("SMB1_COMMAND_SESSION_SETUP_ANDX user_id {}", r.user_id);
            smb1_session_setup_request(state, r, *andx_offset);
            true
        },
        SMB1_COMMAND_TREE_CONNECT_ANDX => {
            SCLogDebug!("SMB1_COMMAND_TREE_CONNECT_ANDX");
            match parse_smb_connect_tree_andx_record(&r.data[*andx_offset-SMB1_HEADER_SIZE..], r) {
                Ok((_, tr)) => {
                    let name_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_TREE);
                    let mut name_val = tr.path;
                    if name_val.len() > 1 {
                        name_val = name_val[1..].to_vec();
                    }

                    // store hdr as SMBHDR_TYPE_TREE, so with tree id 0
                    // when the response finds this we update it
                    let tx = state.new_treeconnect_tx(name_key, name_val);
                    if let Some(SMBTransactionTypeData::TREECONNECT(ref mut tdn)) = tx.type_data {
                        tdn.req_service = Some(tr.service.to_vec());
                    }
                    tx.request_done = true;
                    tx.vercmd.set_smb1_cmd(SMB1_COMMAND_TREE_CONNECT_ANDX);
                    true
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                    false
                },
            }
        },
        SMB1_COMMAND_TREE_DISCONNECT => {
            let tree_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_SHARE);
            state.ssn2tree_map.remove(&tree_key);
            false
        },
        SMB1_COMMAND_CLOSE => {
            match parse_smb1_close_request_record(r.data) {
                Ok((_, cd)) => {
                    let mut fid = cd.fid.to_vec();
                    fid.extend_from_slice(&u32_as_bytes(r.ssn_id));
                    state.ssn2vec_map.insert(SMBCommonHdr::from1(r, SMBHDR_TYPE_GUID), fid.to_vec());

                    SCLogDebug!("closing FID {:?}/{:?}", cd.fid, fid);
                    smb1_close_file(state, &fid, Direction::ToServer);
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                },
            }
            false
        },
        SMB1_COMMAND_NT_CANCEL |
        SMB1_COMMAND_TRANS2_SECONDARY |
        SMB1_COMMAND_LOCKING_ANDX => {
            no_response_expected = true;
            false
        },
        _ => {
            if command == SMB1_COMMAND_LOGOFF_ANDX ||
               command == SMB1_COMMAND_TREE_DISCONNECT ||
               command == SMB1_COMMAND_NT_TRANS ||
               command == SMB1_COMMAND_NT_TRANS_SECONDARY ||
               command == SMB1_COMMAND_NT_CANCEL ||
               command == SMB1_COMMAND_RENAME ||
               command == SMB1_COMMAND_CHECK_DIRECTORY ||
               command == SMB1_COMMAND_ECHO ||
               command == SMB1_COMMAND_TRANS
            { } else {
                 SCLogDebug!("unsupported command {}/{}",
                         command, &smb1_command_string(command));
            }
            false
        },
    };
    if !have_tx {
        if smb1_create_new_tx(command) {
            let tx_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_GENERICTX);
            let tx = state.new_generic_tx(1, command as u16, tx_key);
            SCLogDebug!("tx {} created for {}/{}", tx.id, command, &smb1_command_string(command));
            tx.set_events(events);
            if no_response_expected {
                tx.response_done = true;
            }
        }
    }
}

pub fn smb1_request_record<'b>(state: &mut SMBState, r: &SmbRecord<'b>) -> u32 {
    SCLogDebug!("record: command {}: record {:?}", r.command, r);

    let mut andx_offset = SMB1_HEADER_SIZE;
    let mut command = r.command;
    loop {
        smb1_request_record_one(state, r, command, &mut andx_offset);

        // continue for next andx command if any
        if smb1_command_is_andx(command) {
            if let Ok((_, andx_hdr)) = smb1_parse_andx_header(&r.data[andx_offset-SMB1_HEADER_SIZE..]) {
                if (andx_hdr.andx_offset as usize) > andx_offset &&
                   andx_hdr.andx_command != SMB1_COMMAND_NONE &&
                   (andx_hdr.andx_offset as usize) - SMB1_HEADER_SIZE < r.data.len() {
                    andx_offset = andx_hdr.andx_offset as usize;
                    command = andx_hdr.andx_command;
                    continue;
                }
            }
        }
        break;
    }

    0
}

fn smb1_response_record_one<'b>(state: &mut SMBState, r: &SmbRecord<'b>, command: u8, andx_offset: &mut usize) {
    SCLogDebug!("record: command {} status {} -> {:?}", r.command, r.nt_status, r);

    let key_ssn_id = r.ssn_id;
    let key_tree_id = r.tree_id;
    let key_multiplex_id = r.multiplex_id;
    let mut tx_sync = false;
    let mut events : Vec<SMBEvent> = Vec::new();

    let have_tx = match command {
        SMB1_COMMAND_READ_ANDX => {
            smb1_read_response_record(state, r, *andx_offset);
            true // tx handling in func
        },
        SMB1_COMMAND_NEGOTIATE_PROTOCOL => {
            SCLogDebug!("SMB1_COMMAND_NEGOTIATE_PROTOCOL response");
            match parse_smb1_negotiate_protocol_response_record(r.data) {
                Ok((_, pr)) => {
                    let (have_ntx, dialect) = match state.get_negotiate_tx(1) {
                        Some(tx) => {
                            tx.set_status(r.nt_status, r.is_dos_error);
                            tx.response_done = true;
                            SCLogDebug!("tx {} is done", tx.id);
                            let d = match tx.type_data {
                                Some(SMBTransactionTypeData::NEGOTIATE(ref mut x)) => {
                                    x.server_guid = pr.server_guid.to_vec();

                                    let dialect_idx = pr.dialect_idx as usize;
                                    if x.dialects.len() <= dialect_idx {
                                        None
                                    } else {
                                        let d = x.dialects[dialect_idx].to_vec();
                                        Some(d)
                                    }
                                },
                                _ => { None },
                            };
                            if d == None {
                                tx.set_event(SMBEvent::NegotiateMalformedDialects);
                            }
                            (true, d)
                        },
                        None => { (false, None) },
                    };
                    if let Some(d) = dialect {
                        SCLogDebug!("dialect {:?}", d);
                        state.dialect_vec = Some(d);
                    }
                    have_ntx
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                    false
                },
            }
        },
        SMB1_COMMAND_TREE_CONNECT_ANDX => {
            if r.nt_status != SMB_NTSTATUS_SUCCESS {
                let name_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_TREE);
                match state.get_treeconnect_tx(name_key) {
                    Some(tx) => {
                        if let Some(SMBTransactionTypeData::TREECONNECT(ref mut tdn)) = tx.type_data {
                            tdn.tree_id = r.tree_id as u32;
                        }
                        tx.set_status(r.nt_status, r.is_dos_error);
                        tx.response_done = true;
                        SCLogDebug!("tx {} is done", tx.id);
                    },
                    None => { },
                }
                return;
            }

            match parse_smb_connect_tree_andx_response_record(&r.data[*andx_offset-SMB1_HEADER_SIZE..]) {
                Ok((_, tr)) => {
                    let name_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_TREE);
                    let is_pipe = tr.service == "IPC".as_bytes();
                    let mut share_name = Vec::new();
                    let found = match state.get_treeconnect_tx(name_key) {
                        Some(tx) => {
                            if let Some(SMBTransactionTypeData::TREECONNECT(ref mut tdn)) = tx.type_data {
                                tdn.is_pipe = is_pipe;
                                tdn.tree_id = r.tree_id as u32;
                                share_name = tdn.share_name.to_vec();
                                tdn.res_service = Some(tr.service.to_vec());
                            }
                            tx.hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_HEADER);
                            tx.set_status(r.nt_status, r.is_dos_error);
                            tx.response_done = true;
                            SCLogDebug!("tx {} is done", tx.id);
                            true
                        },
                        None => { false },
                    };
                    if found {
                        let tree = SMBTree::new(share_name.to_vec(), is_pipe);
                        let tree_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_SHARE);
                        state.ssn2tree_map.insert(tree_key, tree);
                    }
                    found
                },
                _ => {
                    events.push(SMBEvent::MalformedData);
                    false
                },
            }
        },
        SMB1_COMMAND_TREE_DISCONNECT => {
            // normally removed when processing request,
            // but in case we missed that try again here
            let tree_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_SHARE);
            state.ssn2tree_map.remove(&tree_key);
            false
        },
        SMB1_COMMAND_NT_CREATE_ANDX => {
            SCLogDebug!("SMB1_COMMAND_NT_CREATE_ANDX response {:08x}", r.nt_status);
            if r.nt_status == SMB_NTSTATUS_SUCCESS {
                match parse_smb_create_andx_response_record(&r.data[*andx_offset-SMB1_HEADER_SIZE..]) {
                    Ok((_, cr)) => {
                        SCLogDebug!("Create AndX {:?}", cr);

                        let guid_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_FILENAME);
                        match state.ssn2vec_map.remove(&guid_key) {
                            Some(mut p) => {
                                p.retain(|&i|i != 0x00);

                                let mut fid = cr.fid.to_vec();
                                fid.extend_from_slice(&u32_as_bytes(r.ssn_id));
                                SCLogDebug!("SMB1_COMMAND_NT_CREATE_ANDX fid {:?}", fid);
                                SCLogDebug!("fid {:?} name {:?}", fid, p);
                                state.guid2name_map.insert(fid, p);
                            },
                            _ => {
                                SCLogDebug!("SMBv1 response: GUID NOT FOUND");
                            },
                        }

                        let tx_hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_GENERICTX);
                        if let Some(tx) = state.get_generic_tx(1, command as u16, &tx_hdr) {
                            SCLogDebug!("tx {} with {}/{} marked as done",
                                    tx.id, command, &smb1_command_string(command));
                            tx.set_status(r.nt_status, false);
                            tx.response_done = true;

                            if let Some(SMBTransactionTypeData::CREATE(ref mut tdn)) = tx.type_data {
                                tdn.create_ts = cr.create_ts.as_unix();
                                tdn.last_access_ts = cr.last_access_ts.as_unix();
                                tdn.last_write_ts = cr.last_write_ts.as_unix();
                                tdn.last_change_ts = cr.last_change_ts.as_unix();
                                tdn.size = cr.file_size;
                                tdn.guid = cr.fid.to_vec();
                            }
                        }
                        true
                    },
                    _ => {
                        events.push(SMBEvent::MalformedData);
                        false
                    },
                }
            } else {
                false
            }
        },
        SMB1_COMMAND_CLOSE => {
            let fid = state.ssn2vec_map.remove(&SMBCommonHdr::from1(r, SMBHDR_TYPE_GUID));
            if let Some(fid) = fid {
                SCLogDebug!("closing FID {:?}", fid);
                smb1_close_file(state, &fid, Direction::ToClient);
            }
            false
        },
        SMB1_COMMAND_TRANS => {
            smb1_trans_response_record(state, r);
            true
        },
        SMB1_COMMAND_SESSION_SETUP_ANDX => {
            smb1_session_setup_response(state, r, *andx_offset);
            true
        },
        SMB1_COMMAND_LOGOFF_ANDX => {
            tx_sync = true;
            false
        },
        _ => {
            false
        },
    };

    if !have_tx && tx_sync {
        match state.get_last_tx(1, command as u16) {
            Some(tx) => {
                SCLogDebug!("last TX {} is CMD {}", tx.id, &smb1_command_string(command));
                tx.response_done = true;
                SCLogDebug!("tx {} cmd {} is done", tx.id, command);
                tx.set_status(r.nt_status, r.is_dos_error);
                tx.set_events(events);
            },
            _ => {},
        }
    } else if !have_tx && smb1_check_tx(command) {
        let tx_key = SMBCommonHdr::new(SMBHDR_TYPE_GENERICTX,
                key_ssn_id as u64, key_tree_id as u32, key_multiplex_id as u64);
        let _have_tx2 = match state.get_generic_tx(1, command as u16, &tx_key) {
            Some(tx) => {
                tx.request_done = true;
                tx.response_done = true;
                SCLogDebug!("tx {} cmd {} is done", tx.id, command);
                tx.set_status(r.nt_status, r.is_dos_error);
                tx.set_events(events);
                true
            },
            _ => {
                SCLogDebug!("no TX found for key {:?}", tx_key);
                false
            },
        };
    } else {
        SCLogDebug!("have tx for cmd {}", command);
    }
}

pub fn smb1_response_record<'b>(state: &mut SMBState, r: &SmbRecord<'b>) -> u32 {
    let mut andx_offset = SMB1_HEADER_SIZE;
    let mut command = r.command;
    loop {
        smb1_response_record_one(state, r, command, &mut andx_offset);

        // continue for next andx command if any
        if smb1_command_is_andx(command) {
            if let Ok((_, andx_hdr)) = smb1_parse_andx_header(&r.data[andx_offset-SMB1_HEADER_SIZE..]) {
                if (andx_hdr.andx_offset as usize) > andx_offset &&
                    andx_hdr.andx_command != SMB1_COMMAND_NONE &&
                    (andx_hdr.andx_offset as usize) - SMB1_HEADER_SIZE < r.data.len() {
                    andx_offset = andx_hdr.andx_offset as usize;
                    command = andx_hdr.andx_command;
                    continue;
                }
            }
        }
        break;
    }

    0
}

pub fn smb1_trans_request_record<'b>(state: &mut SMBState, r: &SmbRecord<'b>)
{
    let mut events : Vec<SMBEvent> = Vec::new();

    match parse_smb_trans_request_record(r.data, r) {
        Ok((_, rd)) => {
            SCLogDebug!("TRANS request {:?}", rd);

            /* if we have a fid, store it so the response can pick it up */
            let mut pipe_dcerpc = false;
            if rd.pipe != None {
                let pipe = rd.pipe.unwrap();
                state.ssn2vec_map.insert(SMBCommonHdr::from1(r, SMBHDR_TYPE_GUID),
                        pipe.fid.to_vec());

                let mut frankenfid = pipe.fid.to_vec();
                frankenfid.extend_from_slice(&u32_as_bytes(r.ssn_id));

                let (_filename, is_dcerpc) = state.get_service_for_guid(&frankenfid);

                SCLogDebug!("smb1_trans_request_record: name {} is_dcerpc {}",
                        _filename, is_dcerpc);
                pipe_dcerpc = is_dcerpc;
            }

            if pipe_dcerpc {
                SCLogDebug!("SMBv1 TRANS TO PIPE");
                let hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_HEADER);
                let vercmd = SMBVerCmdStat::new1(r.command);
                smb_write_dcerpc_record(state, vercmd, hdr, rd.data.data);
            }
        },
        _ => {
            events.push(SMBEvent::MalformedData);
        },
    }
    smb1_request_record_generic(state, r, events);
}

pub fn smb1_trans_response_record<'b>(state: &mut SMBState, r: &SmbRecord<'b>)
{
    let mut events : Vec<SMBEvent> = Vec::new();

    match parse_smb_trans_response_record(r.data) {
        Ok((_, rd)) => {
            SCLogDebug!("TRANS response {:?}", rd);

            // see if we have a stored fid
            let fid = match state.ssn2vec_map.remove(
                    &SMBCommonHdr::from1(r, SMBHDR_TYPE_GUID)) {
                Some(f) => f,
                None => Vec::new(),
            };
            SCLogDebug!("FID {:?}", fid);

            let mut frankenfid = fid.to_vec();
            frankenfid.extend_from_slice(&u32_as_bytes(r.ssn_id));

            let (_filename, is_dcerpc) = state.get_service_for_guid(&frankenfid);

            SCLogDebug!("smb1_trans_response_record: name {} is_dcerpc {}",
                    _filename, is_dcerpc);

            // if we get status 'BUFFER_OVERFLOW' this is only a part of
            // the data. Store it in the ssn/tree for later use.
            if r.nt_status == SMB_NTSTATUS_BUFFER_OVERFLOW {
                let key = SMBHashKeyHdrGuid::new(SMBCommonHdr::from1(r, SMBHDR_TYPE_TRANS_FRAG), fid);
                SCLogDebug!("SMBv1/TRANS: queueing data for len {} key {:?}", rd.data.len(), key);
                state.ssnguid2vec_map.insert(key, rd.data.to_vec());
            } else if is_dcerpc {
                SCLogDebug!("SMBv1 TRANS TO PIPE");
                let hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_HEADER);
                let vercmd = SMBVerCmdStat::new1_with_ntstatus(r.command, r.nt_status);
                smb_read_dcerpc_record(state, vercmd, hdr, &fid, rd.data);
            }
        },
        _ => {
            events.push(SMBEvent::MalformedData);
        },
    }

    // generic tx as well. Set events if needed.
    smb1_response_record_generic(state, r, events);
}

/// Handle WRITE, WRITE_ANDX, WRITE_AND_CLOSE request records
pub fn smb1_write_request_record<'b>(state: &mut SMBState, r: &SmbRecord<'b>, andx_offset: usize, command: u8)
{
    let mut events : Vec<SMBEvent> = Vec::new();

    let result = if command == SMB1_COMMAND_WRITE_ANDX {
        parse_smb1_write_andx_request_record(&r.data[andx_offset-SMB1_HEADER_SIZE..], andx_offset)
    } else if command == SMB1_COMMAND_WRITE {
        parse_smb1_write_request_record(r.data)
    } else {
        parse_smb1_write_and_close_request_record(r.data)
    };
    match result {
        Ok((_, rd)) => {
            SCLogDebug!("SMBv1: write andx => {:?}", rd);

            let mut file_fid = rd.fid.to_vec();
            file_fid.extend_from_slice(&u32_as_bytes(r.ssn_id));
            SCLogDebug!("SMBv1 WRITE: FID {:?} offset {}",
                    file_fid, rd.offset);

            let file_name = match state.guid2name_map.get(&file_fid) {
                Some(n) => n.to_vec(),
                None => b"<unknown>".to_vec(),
            };
            let mut set_event_fileoverlap = false;
            let found = match state.get_file_tx_by_fuid(&file_fid, Direction::ToServer) {
                Some((tx, files, flags)) => {
                    let file_id : u32 = tx.id as u32;
                    if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                        if rd.offset < tdf.file_tracker.tracked {
                            set_event_fileoverlap = true;
                        }
                        filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                                &file_name, rd.data, rd.offset,
                                rd.len, false, &file_id);
                        SCLogDebug!("FID {:?} found at tx {}", file_fid, tx.id);
                    }
                    true
                },
                None => { false },
            };
            if !found {
                let tree_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_SHARE);
                let (share_name, is_pipe) = match state.ssn2tree_map.get(&tree_key) {
                    Some(n) => (n.name.to_vec(), n.is_pipe),
                    None => (Vec::new(), false),
                };
                if is_pipe {
                    SCLogDebug!("SMBv1 WRITE TO PIPE");
                    let hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_HEADER);
                    let vercmd = SMBVerCmdStat::new1_with_ntstatus(command, r.nt_status);
                    smb_write_dcerpc_record(state, vercmd, hdr, rd.data);
                } else {
                    let (tx, files, flags) = state.new_file_tx(&file_fid, &file_name, Direction::ToServer);
                    if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                        let file_id : u32 = tx.id as u32;
                        SCLogDebug!("FID {:?} found at tx {}", file_fid, tx.id);
                        if rd.offset < tdf.file_tracker.tracked {
                            set_event_fileoverlap = true;
                        }
                        filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                                &file_name, rd.data, rd.offset,
                                rd.len, false, &file_id);
                        tdf.share_name = share_name;
                    }
                    tx.vercmd.set_smb1_cmd(SMB1_COMMAND_WRITE_ANDX);
                }
            }
            if set_event_fileoverlap {
                state.set_event(SMBEvent::FileOverlap);
            }

            state.set_file_left(Direction::ToServer, rd.len, rd.data.len() as u32, file_fid.to_vec());

            if command == SMB1_COMMAND_WRITE_AND_CLOSE {
                SCLogDebug!("closing FID {:?}", file_fid);
                smb1_close_file(state, &file_fid, Direction::ToServer);
            }
        },
        _ => {
            events.push(SMBEvent::MalformedData);
        },
    }
    smb1_request_record_generic(state, r, events);
}

pub fn smb1_read_response_record<'b>(state: &mut SMBState, r: &SmbRecord<'b>, andx_offset: usize)
{
    let mut events : Vec<SMBEvent> = Vec::new();

    if r.nt_status == SMB_NTSTATUS_SUCCESS {
        match parse_smb_read_andx_response_record(&r.data[andx_offset-SMB1_HEADER_SIZE..]) {
            Ok((_, rd)) => {
                SCLogDebug!("SMBv1: read response => {:?}", rd);

                let fid_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_OFFSET);
                let (offset, file_fid) = match state.ssn2vecoffset_map.remove(&fid_key) {
                    Some(o) => (o.offset, o.guid),
                    None => {
                        SCLogDebug!("SMBv1 READ response: reply to unknown request: left {} {:?}",
                                rd.len - rd.data.len() as u32, rd);
                        state.set_skip(Direction::ToClient, rd.len, rd.data.len() as u32);
                        return;
                    },
                };
                SCLogDebug!("SMBv1 READ: FID {:?} offset {}", file_fid, offset);

                let tree_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_SHARE);
                let (is_pipe, share_name) = match state.ssn2tree_map.get(&tree_key) {
                    Some(n) => (n.is_pipe, n.name.to_vec()),
                    _ => { (false, Vec::new()) },
                };
                if !is_pipe {
                    let file_name = match state.guid2name_map.get(&file_fid) {
                        Some(n) => n.to_vec(),
                        None => Vec::new(),
                    };
                    let mut set_event_fileoverlap = false;
                    let found = match state.get_file_tx_by_fuid(&file_fid, Direction::ToClient) {
                        Some((tx, files, flags)) => {
                            if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                                let file_id : u32 = tx.id as u32;
                                SCLogDebug!("FID {:?} found at tx {}", file_fid, tx.id);
                                if offset < tdf.file_tracker.tracked {
                                    set_event_fileoverlap = true;
                                }
                                filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                                        &file_name, rd.data, offset,
                                        rd.len, false, &file_id);
                            }
                            true
                        },
                        None => { false },
                    };
                    if !found {
                        let (tx, files, flags) = state.new_file_tx(&file_fid, &file_name, Direction::ToClient);
                        if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                            let file_id : u32 = tx.id as u32;
                            SCLogDebug!("FID {:?} found at tx {}", file_fid, tx.id);
                            if offset < tdf.file_tracker.tracked {
                                set_event_fileoverlap = true;
                            }
                            filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                                    &file_name, rd.data, offset,
                                    rd.len, false, &file_id);
                            tdf.share_name = share_name;
                        }
                        tx.vercmd.set_smb1_cmd(SMB1_COMMAND_READ_ANDX);
                    }
                    if set_event_fileoverlap {
                        state.set_event(SMBEvent::FileOverlap);
                    }
                } else {
                    SCLogDebug!("SMBv1 READ response from PIPE");
                    let hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_HEADER);
                    let vercmd = SMBVerCmdStat::new1(SMB1_COMMAND_READ_ANDX);

                    // hack: we store fid with ssn id mixed in, but here we want the
                    // real thing instead.
                    let pure_fid = if file_fid.len() > 2 { &file_fid[0..2] } else { &[] };
                    smb_read_dcerpc_record(state, vercmd, hdr, pure_fid, rd.data);
                }

                state.set_file_left(Direction::ToClient, rd.len, rd.data.len() as u32, file_fid.to_vec());
            }
            _ => {
                events.push(SMBEvent::MalformedData);
            },
        }
    }

    // generic tx as well. Set events if needed.
    smb1_response_record_generic(state, r, events);
}

/// create a tx for a command / response pair if we're
/// configured to do so, or if this is a tx especially
/// for setting an event.
fn smb1_request_record_generic<'b>(state: &mut SMBState, r: &SmbRecord<'b>, events: Vec<SMBEvent>) {
    if smb1_create_new_tx(r.command) || events.len() > 0 {
        let tx_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_GENERICTX);
        let tx = state.new_generic_tx(1, r.command as u16, tx_key);
        tx.set_events(events);
    }
}

/// update or create a tx for a command / reponse pair based
/// on the response. We only create a tx for the response side
/// if we didn't already update a tx, and we have to set events
fn smb1_response_record_generic<'b>(state: &mut SMBState, r: &SmbRecord<'b>, events: Vec<SMBEvent>) {
    let tx_key = SMBCommonHdr::from1(r, SMBHDR_TYPE_GENERICTX);
    match state.get_generic_tx(1, r.command as u16, &tx_key) {
        Some(tx) => {
            tx.request_done = true;
            tx.response_done = true;
            SCLogDebug!("tx {} cmd {} is done", tx.id, r.command);
            tx.set_status(r.nt_status, r.is_dos_error);
            tx.set_events(events);
            return;
        },
        None => {},
    }
    if events.len() > 0 {
        let tx = state.new_generic_tx(1, r.command as u16, tx_key);
        tx.request_done = true;
        tx.response_done = true;
        SCLogDebug!("tx {} cmd {} is done", tx.id, r.command);
        tx.set_status(r.nt_status, r.is_dos_error);
        tx.set_events(events);
    }
}
