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

// written by Victor Julien

extern crate libc;

use nom::{IResult, be_u32};

use core::*;
use log::*;

use nfs::nfs::*;
use nfs::types::*;
use nfs::rpc_records::*;
use nfs::nfs_records::*;
use nfs::nfs4_records::*;

use kerberos;

named!(parse_req_gssapi<kerberos::Kerberos5Ticket>,
   do_parse!(
        len: be_u32
    >>  ap: flat_map!(take!(len), call!(kerberos::parse_kerberos5_request))
    >> ( ap )
));

impl NFSState {
    /* normal write: PUTFH (file handle), WRITE (write opts/data). File handle
     * is not part of the write record itself so we pass it in here. */
    fn write_v4<'b>(&mut self, r: &RpcPacket<'b>, w: &Nfs4RequestWrite<'b>, fh: &'b[u8])
    {
        // for now assume that stable FILE_SYNC flags means a single chunk
        let is_last = if w.stable == 2 { true } else { false };
        SCLogDebug!("is_last {}", is_last);

        let mut fill_bytes = 0;
        let pad = w.write_len % 4;
        if pad != 0 {
            fill_bytes = 4 - pad;
        }

        let file_handle = fh.to_vec();
        let file_name = match self.namemap.get(fh) {
            Some(n) => {
                SCLogDebug!("WRITE name {:?}", n);
                n.to_vec()
            },
            None => {
                SCLogDebug!("WRITE object {:?} not found", w.stateid.data);
                Vec::new()
            },
        };

        let found = match self.get_file_tx_by_handle(&file_handle, STREAM_TOSERVER) {
            Some((tx, files, flags)) => {
                if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
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
            },
            None => { false },
        };
        if !found {
            let (tx, files, flags) = self.new_file_tx(&file_handle, &file_name, STREAM_TOSERVER);
            if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
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
                }
            }
        }
        self.ts_chunk_xid = r.hdr.xid;
        let file_data_len = w.data.len() as u32 - fill_bytes as u32;
        self.ts_chunk_left = w.write_len as u32 - file_data_len as u32;
    }

    fn commit_v4<'b>(&mut self, r: &RpcPacket<'b>, fh: &'b[u8])
    {
        SCLogDebug!("COMMIT, closing shop");

        let file_handle = fh.to_vec();
        match self.get_file_tx_by_handle(&file_handle, STREAM_TOSERVER) {
            Some((tx, files, flags)) => {
                if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    tdf.file_tracker.close(files, flags);
                    tdf.file_last_xid = r.hdr.xid;
                    tx.is_last = true;
                    tx.request_done = true;
                }
            }
            None => {},
        }
    }

    /* A normal READ request looks like: PUTFH (file handle) READ (read opts).
     * We need the file handle for the READ.
     */
    fn compound_request<'b>(&mut self, r: &RpcPacket<'b>,
            cr: &Nfs4RequestCompoundRecord<'b>,
            xidmap: &mut NFSRequestXidMap)
    {
        let mut last_putfh : Option<&'b[u8]> = None;

        for c in &cr.commands {
            SCLogDebug!("c {:?}", c);
            match c {
                &Nfs4RequestContent::PutFH(ref rd) => {
                    last_putfh = Some(rd.value);
                }
                &Nfs4RequestContent::Read(ref rd) => {
                    SCLogDebug!("READv4: {:?}", rd);
                    if let Some(fh) = last_putfh {
                        xidmap.chunk_offset = rd.offset;
                        xidmap.file_handle = fh.to_vec();
                        self.xidmap_handle2name(xidmap);
                    }
                }
                &Nfs4RequestContent::Open(ref rd) => {
                    SCLogDebug!("OPENv4: {}", String::from_utf8_lossy(&rd.filename));
                    xidmap.file_name = rd.filename.to_vec();
                }
                &Nfs4RequestContent::Lookup(ref rd) => {
                    SCLogDebug!("LOOKUPv4: {}", String::from_utf8_lossy(&rd.filename));
                    xidmap.file_name = rd.filename.to_vec();
                }
                &Nfs4RequestContent::Write(ref rd) => {
                    SCLogDebug!("WRITEv4: {:?}", rd);
                    if let Some(fh) = last_putfh {
                        self.write_v4(r, rd, fh);
                    }
                }
                &Nfs4RequestContent::Commit => {
                    SCLogDebug!("COMMITv4");
                    if let Some(fh) = last_putfh {
                        self.commit_v4(r, fh);
                    }
                }
                &Nfs4RequestContent::Close(ref rd) => {
                    SCLogDebug!("CLOSEv4: {:?}", rd);
                }
                &Nfs4RequestContent::SetClientId(ref rd) => {
                    SCLogDebug!("SETCLIENTIDv4: client id {} r_netid {} r_addr {}",
                            String::from_utf8_lossy(&rd.client_id),
                            String::from_utf8_lossy(&rd.r_netid),
                            String::from_utf8_lossy(&rd.r_addr));
                }
                &_ => { },
            }
        }
    }

    /// complete request record
    pub fn process_request_record_v4<'b>(&mut self, r: &RpcPacket<'b>) -> u32 {
        SCLogDebug!("NFSv4 REQUEST {} procedure {} ({}) blob size {}",
                r.hdr.xid, r.procedure, self.requestmap.len(), r.prog_data.len());

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
                if creds.procedure == 0  && creds.service == 2 {
                    SCLogDebug!("GSS INTEGRITIY: {:?}", creds);
                    match parse_rpc_gssapi_integrity(r.prog_data) {
                        IResult::Done(_rem, rec) => {
                            SCLogDebug!("GSS INTEGRITIY wrapper: {:?}", rec);
                            data = rec.data;
                            // store proc and serv for the reply
                            xidmap.gssapi_proc = creds.procedure;
                            xidmap.gssapi_service = creds.service;
                        },
                        IResult::Incomplete(_n) => {
                            SCLogDebug!("NFSPROC4_COMPOUND/GSS INTEGRITIY: INCOMPLETE {:?}", _n);
                            self.set_event(NFSEvent::MalformedData);
                            return 0;
                        },
                        IResult::Error(_e) => {
                            SCLogDebug!("NFSPROC4_COMPOUND/GSS INTEGRITIY: Parsing failed: {:?}", _e);
                            self.set_event(NFSEvent::MalformedData);
                            return 0;
                        },
                    }
                }
            }

            match parse_nfs4_request_compound(data) {
                IResult::Done(_, rd) => {
                    SCLogDebug!("NFSPROC4_COMPOUND: {:?}", rd);
                    self.compound_request(&r, &rd, &mut xidmap);
                },
                IResult::Incomplete(_n) => {
                    SCLogDebug!("NFSPROC4_COMPOUND: INCOMPLETE {:?}", _n);
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(_e) => {
                    SCLogDebug!("NFSPROC4_COMPOUND: Parsing failed: {:?}", _e);
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        }

        self.requestmap.insert(r.hdr.xid, xidmap);
        0
    }

    fn compound_response<'b>(&mut self, r: &RpcReplyPacket<'b>,
            cr: &Nfs4ResponseCompoundRecord<'b>,
            xidmap: &mut NFSRequestXidMap)
    {
        let mut insert_filename_with_getfh = false;

        for c in &cr.commands {
            SCLogDebug!("c {:?}", c);
            match c {
                &Nfs4ResponseContent::ReadDir(s, ref rd) => {
                    if let &Some(ref rd) = rd {
                        SCLogDebug!("READDIRv4: status {} eof {}", s, rd.eof);

                        for d in &rd.listing {
                            if let &Some(ref d) = d {
                                SCLogDebug!("READDIRv4: dir {}", String::from_utf8_lossy(&d.name));
                            }
                        }

                    }
                }
                &Nfs4ResponseContent::Remove(s) => {
                    SCLogDebug!("REMOVE4: status {}", s);
                },
                &Nfs4ResponseContent::Read(s, ref rd) => {
                    if let &Some(ref rd) = rd {
                        SCLogDebug!("READ4: xidmap {:?} status {} data {}", xidmap, s, rd.data.len());
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
                        self.process_read_record(r, &reply, Some(&xidmap));
                    }
                },
                &Nfs4ResponseContent::Open(s, ref rd) => {
                    if let &Some(ref rd) = rd {
                        SCLogDebug!("OPENv4: status {} opendata {:?}", s, rd);
                        insert_filename_with_getfh = true;
                    }
                },
                &Nfs4ResponseContent::GetFH(_s, ref rd) => {
                    if let &Some(ref rd) = rd {
                        if insert_filename_with_getfh {
                            self.namemap.insert(rd.value.to_vec(),
                                    xidmap.file_name.to_vec());
                        }
                    }
                },
                &Nfs4ResponseContent::PutRootFH(s) => {
                    if s == NFS4_OK && xidmap.file_name.len() == 0 {
                        xidmap.file_name = b"<mount_root>".to_vec();
                        SCLogDebug!("filename {:?}", xidmap.file_name);
                    }
                },
                &_ => { },
            }
        }
    }

    pub fn process_reply_record_v4<'b>(&mut self, r: &RpcReplyPacket<'b>,
            xidmap: &mut NFSRequestXidMap) -> u32 {
        if xidmap.procedure == NFSPROC4_COMPOUND {
            let mut data = r.prog_data;

            if xidmap.gssapi_proc == 0 && xidmap.gssapi_service == 2 {

                SCLogDebug!("GSS INTEGRITIY as set by call: {:?}", xidmap);
                match parse_rpc_gssapi_integrity(r.prog_data) {
                    IResult::Done(_rem, rec) => {
                        SCLogDebug!("GSS INTEGRITIY wrapper: {:?}", rec);
                        data = rec.data;
                    },
                    IResult::Incomplete(_n) => {
                        SCLogDebug!("NFSPROC4_COMPOUND/GSS INTEGRITIY: INCOMPLETE {:?}", _n);
                        self.set_event(NFSEvent::MalformedData);
                        return 0;
                    },
                    IResult::Error(_e) => {
                        SCLogDebug!("NFSPROC4_COMPOUND/GSS INTEGRITIY: Parsing failed: {:?}", _e);
                        self.set_event(NFSEvent::MalformedData);
                        return 0;
                    },
                }
            }
            match parse_nfs4_response_compound(data) {
                IResult::Done(_, rd) => {
                    SCLogDebug!("COMPOUNDv4: {:?}", rd);
                    self.compound_response(&r, &rd, xidmap);
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(_e) => {
                    SCLogDebug!("Parsing failed: {:?}", _e);
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        }
        0
    }
}
