/* Copyright (C) 2018-2020 Open Information Security Foundation
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

use nom7::bytes::streaming::take;
use nom7::number::streaming::be_u32;
use nom7::{Err, IResult};

use crate::core::*;
use crate::nfs::nfs::*;
use crate::nfs::nfs4_records::*;
use crate::nfs::nfs_records::*;
use crate::nfs::rpc_records::*;
use crate::nfs::types::*;

use crate::kerberos::{parse_kerberos5_request, Kerberos5Ticket, SecBlobError};

fn parse_req_gssapi(i: &[u8]) -> IResult<&[u8], Kerberos5Ticket, SecBlobError> {
    let (i, len) = be_u32(i)?;
    let (i, buf) = take(len as usize)(i)?;
    let (_, ap) = parse_kerberos5_request(buf)?;
    Ok((i, ap))
}

impl NFSState {
    /* normal write: PUTFH (file handle), WRITE (write opts/data). File handle
     * is not part of the write record itself so we pass it in here. */
    fn write_v4<'b>(&mut self, r: &RpcPacket<'b>, w: &Nfs4RequestWrite<'b>, fh: &'b [u8]) {
        // for now assume that stable FILE_SYNC flags means a single chunk
        let is_last = w.stable == 2;
        SCLogDebug!("is_last {}", is_last);

        let mut fill_bytes = 0;
        let pad = w.write_len % 4;
        if pad != 0 {
            fill_bytes = 4 - pad;
        }

        // linux defines a max of 1mb. Allow several multiples.
        if w.write_len == 0 || w.write_len > 16777216 {
            return;
        }

        let file_handle = fh.to_vec();
        let file_name = if let Some(name) = self.namemap.get(fh) {
            SCLogDebug!("WRITE name {:?}", name);
            name.to_vec()
        } else {
            SCLogDebug!("WRITE object {:?} not found", w.stateid.data);
            Vec::new()
        };

        let found = match self.get_file_tx_by_handle(&file_handle, Direction::ToServer) {
            Some(tx) => {
                if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    let (files, flags) = tdf.files.get(Direction::ToServer);
                    filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                            &file_name, w.data, w.offset,
                            w.write_len, fill_bytes as u8, is_last, &r.hdr.xid);
                    tdf.chunk_count += 1;
                    if is_last {
                        tdf.file_last_xid = r.hdr.xid;
                        tx.is_last = true;
                        tx.response_done = true;
                    }
                }
                true
            }
            None => false,
        };
        if !found {
            let tx = self.new_file_tx(&file_handle, &file_name, Direction::ToServer);
            if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                let (files, flags) = tdf.files.get(Direction::ToServer);
                filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                        &file_name, w.data, w.offset,
                        w.write_len, fill_bytes as u8, is_last, &r.hdr.xid);
                tx.procedure = NFSPROC4_WRITE;
                tx.xid = r.hdr.xid;
                tx.is_first = true;
                tx.nfs_version = r.progver as u16;
                if is_last {
                    tdf.file_last_xid = r.hdr.xid;
                    tx.is_last = true;
                    tx.request_done = true;
                    tx.is_file_closed = true;
                }
            }
        }
        self.ts_chunk_xid = r.hdr.xid;
        debug_validate_bug_on!(w.data.len() as u32 > w.write_len);
        self.ts_chunk_left = w.write_len - w.data.len()  as u32;
    }

    fn close_v4<'b>(&mut self, r: &RpcPacket<'b>, fh: &'b [u8]) {
        self.commit_v4(r, fh)
    }

    fn commit_v4<'b>(&mut self, r: &RpcPacket<'b>, fh: &'b [u8]) {
        SCLogDebug!("COMMIT, closing shop");

        let file_handle = fh.to_vec();
        if let Some(tx) = self.get_file_tx_by_handle(&file_handle, Direction::ToServer) {
            if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                let (files, flags) = tdf.files.get(Direction::ToServer);
                tdf.file_tracker.close(files, flags);
                tdf.file_last_xid = r.hdr.xid;
                tx.is_last = true;
                tx.request_done = true;
                tx.is_file_closed = true;
            }
        }
    }

    fn new_tx_v4<'b>(
        &mut self, r: &RpcPacket<'b>, xidmap: &NFSRequestXidMap, procedure: u32,
        _aux_opcodes: &[u32],
    ) {
        let mut tx = self.new_tx();
        tx.xid = r.hdr.xid;
        tx.procedure = procedure;
        tx.request_done = true;
        tx.file_name = xidmap.file_name.to_vec();
        tx.nfs_version = r.progver as u16;
        tx.file_handle = xidmap.file_handle.to_vec();

        tx.auth_type = r.creds_flavor;
        #[allow(clippy::single_match)]
        match r.creds {
            RpcRequestCreds::Unix(ref u) => {
                tx.request_machine_name = u.machine_name_buf.to_vec();
                tx.request_uid = u.uid;
                tx.request_gid = u.gid;
            }
            _ => {}
        }
        SCLogDebug!(
            "NFSv4: TX created: ID {} XID {} PROCEDURE {}",
            tx.id,
            tx.xid,
            tx.procedure
        );
        self.transactions.push(tx);
    }

    /* A normal READ request looks like: PUTFH (file handle) READ (read opts).
     * We need the file handle for the READ.
     */
    fn compound_request<'b>(
        &mut self, r: &RpcPacket<'b>, cr: &Nfs4RequestCompoundRecord<'b>,
        xidmap: &mut NFSRequestXidMap,
    ) {
        let mut last_putfh: Option<&'b [u8]> = None;
        let mut main_opcode: u32 = 0;
        let mut aux_opcodes: Vec<u32> = Vec::new();

        for c in &cr.commands {
            SCLogDebug!("c {:?}", c);
            match *c {
                Nfs4RequestContent::PutFH(ref rd) => {
                    last_putfh = Some(rd.value);
                    aux_opcodes.push(NFSPROC4_PUTFH);
                }
                Nfs4RequestContent::Read(ref rd) => {
                    SCLogDebug!("READv4: {:?}", rd);
                    if let Some(fh) = last_putfh {
                        xidmap.chunk_offset = rd.offset;
                        xidmap.file_handle = fh.to_vec();
                        self.xidmap_handle2name(xidmap);
                    }
                }
                Nfs4RequestContent::Open(ref rd) => {
                    SCLogDebug!("OPENv4: {}", String::from_utf8_lossy(rd.filename));
                    xidmap.file_name = rd.filename.to_vec();
                }
                Nfs4RequestContent::Lookup(ref rd) => {
                    SCLogDebug!("LOOKUPv4: {}", String::from_utf8_lossy(rd.filename));
                    xidmap.file_name = rd.filename.to_vec();
                }
                Nfs4RequestContent::Write(ref rd) => {
                    SCLogDebug!("WRITEv4: {:?}", rd);
                    if let Some(fh) = last_putfh {
                        self.write_v4(r, rd, fh);
                    }
                }
                Nfs4RequestContent::Commit => {
                    SCLogDebug!("COMMITv4");
                    if let Some(fh) = last_putfh {
                        self.commit_v4(r, fh);
                    }
                }
                Nfs4RequestContent::Close(ref _rd) => {
                    SCLogDebug!("CLOSEv4: {:?}", _rd);
                    if let Some(fh) = last_putfh {
                        self.close_v4(r, fh);
                    }
                }
                Nfs4RequestContent::Create(ref rd) => {
                    SCLogDebug!("CREATEv4: {:?}", rd);
                    if let Some(fh) = last_putfh {
                        xidmap.file_handle = fh.to_vec();
                    }
                    xidmap.file_name = rd.filename.to_vec();
                    main_opcode = NFSPROC4_CREATE;
                }
                Nfs4RequestContent::Remove(rd) => {
                    SCLogDebug!("REMOVEv4: {:?}", rd);
                    xidmap.file_name = rd.to_vec();
                    main_opcode = NFSPROC4_REMOVE;
                }
                Nfs4RequestContent::SetClientId(ref _rd) => {
                    SCLogDebug!(
                        "SETCLIENTIDv4: client id {} r_netid {} r_addr {}",
                        String::from_utf8_lossy(_rd.client_id),
                        String::from_utf8_lossy(_rd.r_netid),
                        String::from_utf8_lossy(_rd.r_addr)
                    );
                }
                _ => {}
            }
        }

        if main_opcode != 0 {
            self.new_tx_v4(r, xidmap, main_opcode, &aux_opcodes);
        }
    }

    /// complete request record
    pub fn process_request_record_v4<'b>(&mut self, r: &RpcPacket<'b>) {
        SCLogDebug!(
            "NFSv4 REQUEST {} procedure {} ({}) blob size {}",
            r.hdr.xid,
            r.procedure,
            self.requestmap.len(),
            r.prog_data.len()
        );

        let mut xidmap = NFSRequestXidMap::new(r.progver, r.procedure, 0);

        if r.procedure == NFSPROC4_NULL {
            if let RpcRequestCreds::GssApi(ref creds) = r.creds {
                if creds.procedure == 1 {
                    let _x = parse_req_gssapi(r.prog_data);
                    SCLogDebug!("RPCSEC_GSS_INIT {:?}", _x);
                }
            }
        } else if r.procedure == NFSPROC4_COMPOUND {
            let mut data = r.prog_data;

            if let RpcRequestCreds::GssApi(ref creds) = r.creds {
                if creds.procedure == 0 && creds.service == 2 {
                    SCLogDebug!("GSS INTEGRITIY: {:?}", creds);
                    match parse_rpc_gssapi_integrity(r.prog_data) {
                        Ok((_rem, rec)) => {
                            SCLogDebug!("GSS INTEGRITIY wrapper: {:?}", rec);
                            data = rec.data;
                            // store proc and serv for the reply
                            xidmap.gssapi_proc = creds.procedure;
                            xidmap.gssapi_service = creds.service;
                        }
                        Err(Err::Incomplete(_n)) => {
                            SCLogDebug!("NFSPROC4_COMPOUND/GSS INTEGRITIY: INCOMPLETE {:?}", _n);
                            self.set_event(NFSEvent::MalformedData);
                            return;
                        }
                        Err(Err::Error(_e)) | Err(Err::Failure(_e)) => {
                            SCLogDebug!(
                                "NFSPROC4_COMPOUND/GSS INTEGRITIY: Parsing failed: {:?}",
                                _e
                            );
                            self.set_event(NFSEvent::MalformedData);
                            return;
                        }
                    }
                }
            }

            match parse_nfs4_request_compound(data) {
                Ok((_, rd)) => {
                    SCLogDebug!("NFSPROC4_COMPOUND: {:?}", rd);
                    self.compound_request(r, &rd, &mut xidmap);
                }
                Err(Err::Incomplete(_n)) => {
                    SCLogDebug!("NFSPROC4_COMPOUND: INCOMPLETE {:?}", _n);
                    self.set_event(NFSEvent::MalformedData);
                }
                Err(Err::Error(_e)) | Err(Err::Failure(_e)) => {
                    SCLogDebug!("NFSPROC4_COMPOUND: Parsing failed: {:?}", _e);
                    self.set_event(NFSEvent::MalformedData);
                }
            };
        }

        self.requestmap.insert(r.hdr.xid, xidmap);
    }

    fn compound_response<'b>(
        &mut self, r: &RpcReplyPacket<'b>, cr: &Nfs4ResponseCompoundRecord<'b>,
        xidmap: &mut NFSRequestXidMap,
    ) {
        let mut insert_filename_with_getfh = false;
        let mut main_opcode_status: u32 = 0;
        let mut main_opcode_status_set: bool = false;

        for c in &cr.commands {
            SCLogDebug!("c {:?}", c);
            match *c {
                Nfs4ResponseContent::ReadDir(_s, Some(ref rd)) => {
                    SCLogDebug!("READDIRv4: status {} eof {}", _s, rd.eof);
                    
                    for d in &rd.listing {
                        if let &Some(ref _d) = d {
                            SCLogDebug!("READDIRv4: dir {}", String::from_utf8_lossy(_d.name));
                        }
                    }
                }
                Nfs4ResponseContent::Remove(s) => {
                    SCLogDebug!("REMOVE4: status {}", s);
                    main_opcode_status = s;
                    main_opcode_status_set = true;
                }
                Nfs4ResponseContent::Create(s) => {
                    SCLogDebug!("CREATE4: status {}", s);
                    main_opcode_status = s;
                    main_opcode_status_set = true;
                }
                Nfs4ResponseContent::Read(s, Some(ref rd)) => {
                    SCLogDebug!(
                        "READ4: xidmap {:?} status {} data {}",
                        xidmap,
                        s,
                        rd.data.len()
                    );
                    // convert record to generic read reply
                    let reply = NfsReplyRead {
                        status: s,
                        attr_follows: 0,
                        attr_blob: &[],
                        count: rd.count,
                        eof: rd.eof,
                        data_len: rd.data.len() as u32,
                        data: rd.data,
                    };
                    self.process_read_record(r, &reply, Some(xidmap));
                }
                Nfs4ResponseContent::Open(_s, Some(ref _rd)) => {
                    SCLogDebug!("OPENv4: status {} opendata {:?}", _s, _rd);
                    insert_filename_with_getfh = true;
                }
                Nfs4ResponseContent::GetFH(_s, Some(ref rd)) => {
                    if insert_filename_with_getfh {
                        self.namemap
                            .insert(rd.value.to_vec(), xidmap.file_name.to_vec());
                    }
                }
                Nfs4ResponseContent::PutRootFH(s) => {
                    if s == NFS4_OK && xidmap.file_name.is_empty() {
                        xidmap.file_name = b"<mount_root>".to_vec();
                        SCLogDebug!("filename {:?}", xidmap.file_name);
                    }
                }
                _ => {}
            }
        }

        if main_opcode_status_set {
            let resp_handle = Vec::new();
            self.mark_response_tx_done(r.hdr.xid, r.reply_state, main_opcode_status, &resp_handle);
        }
    }

    pub fn process_reply_record_v4<'b>(
        &mut self, r: &RpcReplyPacket<'b>, xidmap: &mut NFSRequestXidMap,
    ) {
        if xidmap.procedure == NFSPROC4_COMPOUND {
            let mut data = r.prog_data;

            if xidmap.gssapi_proc == 0 && xidmap.gssapi_service == 2 {
                SCLogDebug!("GSS INTEGRITIY as set by call: {:?}", xidmap);
                match parse_rpc_gssapi_integrity(r.prog_data) {
                    Ok((_rem, rec)) => {
                        SCLogDebug!("GSS INTEGRITIY wrapper: {:?}", rec);
                        data = rec.data;
                    }
                    Err(Err::Incomplete(_n)) => {
                        SCLogDebug!("NFSPROC4_COMPOUND/GSS INTEGRITIY: INCOMPLETE {:?}", _n);
                        self.set_event(NFSEvent::MalformedData);
                        return;
                    }
                    Err(Err::Error(_e)) | Err(Err::Failure(_e)) => {
                        SCLogDebug!("NFSPROC4_COMPOUND/GSS INTEGRITIY: Parsing failed: {:?}", _e);
                        self.set_event(NFSEvent::MalformedData);
                        return;
                    }
                }
            }
            match parse_nfs4_response_compound(data) {
                Ok((_, rd)) => {
                    SCLogDebug!("COMPOUNDv4: {:?}", rd);
                    self.compound_response(r, &rd, xidmap);
                }
                Err(Err::Incomplete(_)) => {
                    self.set_event(NFSEvent::MalformedData);
                }
                Err(Err::Error(_e)) | Err(Err::Failure(_e)) => {
                    SCLogDebug!("Parsing failed: {:?}", _e);
                    self.set_event(NFSEvent::MalformedData);
                }
            };
        }
    }
}
