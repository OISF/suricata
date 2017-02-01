// written by Victor Julien
// partly written by Pierre Chifflier
extern crate libc;
use std;
use std::ptr;
use std::mem;
use std::str;
use libc::c_char;
//use std::ffi::CStr;

use nom::{rest, be_u32, be_u64};
use nom::IResult;
use rparser::*;
use common::*;

use std::collections::HashMap;

use filetracker::*;
use filecontainer::*;

//use std::io::Write;
//use std::fmt::Write;

macro_rules! println_debug(
    ($($arg:tt)*) => { {
        //println!($($arg)*);
    } }
);

#[derive(Debug,PartialEq)]
pub struct RpcRequestCredsUnix<'a> {
    pub stamp: u32,
    pub machine_name_len: u32,
    pub machine_name_buf: &'a[u8],
    pub uid: u32,
    pub gid: u32,
    pub aux_gids: Option<Vec<u32>>,
    // list of gids
}

//named!(parse_rpc_creds_unix_aux_gids<Vec<u32>>,
//    many0!(be_u32)
//);

named!(pub parse_rfc_request_creds_unix<RpcRequestCredsUnix>,
    do_parse!(
           stamp: be_u32
        >> machine_name_len: be_u32
        >> machine_name_buf: take!(machine_name_len)
        >> uid: be_u32
        >> gid: be_u32
        //>> aux_gids: parse_rpc_creds_unix_aux_gids

        >> (
            RpcRequestCredsUnix {
                stamp:stamp,
                machine_name_len:machine_name_len,
                machine_name_buf:machine_name_buf,
                uid:uid,
                gid:gid,
                aux_gids:None,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ReplyObject<'a> {
    pub status: u32,
    pub value: &'a[u8],
}

named!(pub parse_nfs3_reply_object<Nfs3ReplyObject>,
    do_parse!(
           status: be_u32
        >> data: rest
        >> (
            Nfs3ReplyObject{
                status:status,
                value:data,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3Handle<'a> {
    pub len: u32,
    pub value: &'a[u8],
}

named!(pub parse_nfs3_response_handle<Nfs3Handle>,
    do_parse!(
        obj_len: be_u32
        >> obj: take!(obj_len)
        >> (
            Nfs3Handle {
                len:obj_len,
                value:obj,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ReplyCreate<'a> {
    pub handle: Option<Nfs3Handle<'a>>,
}

named!(pub parse_nfs3_response_create<Nfs3ReplyCreate>,
    do_parse!(
        status: be_u32
        >> handle_has_value: be_u32
        >> handle: cond!(handle_has_value == 1, parse_nfs3_response_handle)
        >> (
            Nfs3ReplyCreate {
               handle:handle, 
            }
        ))
);     

#[derive(Debug,PartialEq)]
pub struct Nfs3ReplyLookup<'a> {
    pub handle: Nfs3Handle<'a>,
}

named!(pub parse_nfs3_response_lookup<Nfs3ReplyLookup>,
    do_parse!(
        status: be_u32
        >> handle: parse_nfs3_response_handle
        >> (
            Nfs3ReplyLookup {
               handle:handle, 
            }
        ))
);     


#[derive(Debug,PartialEq)]
pub struct Nfs3RequestObject<'a> {
    pub len: u32,
    pub value: &'a[u8],
}

named!(pub parse_nfs3_request_object<Nfs3RequestObject>,
    do_parse!(
           len: be_u32
        >> data: take!(len)
        >> (
            Nfs3RequestObject{
                len:len,
                value:data,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestCreate<'a> {
    pub object: Nfs3RequestObject<'a>,
    pub name_len: u32,
//    pub name_contents: &'a[u8],
    pub create_mode: u32,
    pub verifier: &'a[u8],
    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_create<Nfs3RequestCreate>,
    do_parse!(
            obj: parse_nfs3_request_object
        >>  name_len: be_u32
        >>  name: take!(name_len)
        >>  create_mode: be_u32
        >>  verifier: rest
        >> (
            Nfs3RequestCreate {
                object:obj,
                name_len:name_len,
//                name_contents:name,
                create_mode:create_mode,
                verifier:verifier,
                name_vec:name.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestAccess<'a> {
    pub object: Nfs3RequestObject<'a>,
    pub check_access: u32,
}

named!(pub parse_nfs3_request_access<Nfs3RequestAccess>,
    do_parse!(
            obj: parse_nfs3_request_object
        >>  check_access: be_u32
        >> (
            Nfs3RequestAccess {
                object:obj,
                check_access:check_access,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestRead<'a> {
    pub object: Nfs3RequestObject<'a>,
    pub offset: u64,
}

named!(pub parse_nfs3_request_read<Nfs3RequestRead>,
    do_parse!(
            obj: parse_nfs3_request_object
        >>  offset: be_u64
        >>  count: be_u32
        >> (
            Nfs3RequestRead {
                object:obj,
                offset:offset,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestLookup<'a> {
    pub dir_object: Nfs3RequestObject<'a>,

    //pub name_len: u32,
    //pub name_contents: &'a[u8],
    //pub name_padding: &'a[u8],
    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_lookup<Nfs3RequestLookup>,
    do_parse!(
            obj: parse_nfs3_request_object
        >>  name_len: be_u32
        >>  name_contents: take!(name_len)
        >>  name_padding: rest
        >> (
            Nfs3RequestLookup {
                dir_object:obj,
                //name_len:name_len,
                //name_contents:name_contents,
                //name_padding:name_padding
                name_vec:name_contents.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestReaddirplus<'a> {
    pub dir_object: Nfs3RequestObject<'a>,

    pub cookie: u32,
    pub verifier: &'a[u8],
    pub dircount: u32,
    pub maxcount: u32,
}

named!(pub parse_nfs3_request_readdirplus<Nfs3RequestReaddirplus>,
    do_parse!(
            obj: parse_nfs3_request_object
        >>  cookie: be_u32
        >>  verifier: take!(8)
        >>  dircount: be_u32
        >>  maxcount: be_u32
        >> (
            Nfs3RequestReaddirplus {
                dir_object:obj,
                cookie:cookie,
                verifier:verifier,
                dircount:dircount,
                maxcount:maxcount,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestWrite<'a> {
    pub object: Nfs3RequestObject<'a>,

    pub offset: u64,
    pub count: u32,
    pub stable: u32,
    pub file_len: u32,
    pub file_data: &'a[u8],
}

named!(pub parse_nfs3_request_write<Nfs3RequestWrite>,
    do_parse!(
            obj: parse_nfs3_request_object
        >>  offset: be_u64
        >>  count: be_u32
        >>  stable: be_u32
        >>  file_len: be_u32
        >>  file_data: rest // likely partial
        >> (
            Nfs3RequestWrite {
                object:obj,
                offset:offset,
                count:count,
                stable:stable,
                file_len:file_len,
                file_data:file_data,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ReplyRead<'a> {
    pub status: u32,
    pub attr_follows: u32,
    pub attr_blob: &'a[u8],    
    pub count: u32,
    pub eof: bool,
    pub data_len: u32,
    pub data: &'a[u8], // likely partial
}

named!(pub parse_nfs3_reply_read<Nfs3ReplyRead>,
    do_parse!(
            status: be_u32
        >>  attr_follows: be_u32
        >>  attr_blob: take!(84) // fixed size?
        >>  count: be_u32
        >>  eof: be_u32
        >>  data_len: be_u32
        >>  data_contents: rest
        >> (
            Nfs3ReplyRead {
                status:status,
                attr_follows:attr_follows,
                attr_blob:attr_blob,
                count:count,
                eof:eof != 0,
                data_len:data_len,
                data:data_contents,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct RpcPacketHeader<> {
    pub frag_is_last: bool,
    pub frag_len: u32,
    pub xid: u32,
    pub msgtype: u32,
}

named!(pub parse_rpc_packet_header<RpcPacketHeader>,
    do_parse!(
        fraghdr: bits!(tuple!(
                take_bits!(u8, 1),       // is_last
                take_bits!(u32, 31)))    // len

        >> xid: be_u32
        >> msgtype: be_u32
        >> (
            RpcPacketHeader {
                frag_is_last:fraghdr.0 == 1,
                frag_len:fraghdr.1,
                xid:xid,
                msgtype:msgtype,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct RpcReplyPacket<'a> {
    pub hdr: RpcPacketHeader<>,

    pub verifier_flavor: u32,
    pub verifier_len: u32,
    pub verifier: Option<&'a[u8]>,

    pub reply_state: u32,
    pub accept_state: u32,

    pub prog_data: &'a[u8],
}

// top of request packet, just to get to procedure
#[derive(Debug)]
pub struct RpcRequestPacketPartial {
    pub hdr: RpcPacketHeader,

    pub rpcver: u32,
    pub program: u32,
    pub progver: u32,
    pub procedure: u32,
}

named!(pub parse_rpc_request_partial<RpcRequestPacketPartial>,
   do_parse!(
       hdr: parse_rpc_packet_header
       >> rpcver: be_u32
       >> program: be_u32
       >> progver: be_u32
       >> procedure: be_u32
       >> (
            RpcRequestPacketPartial {
                hdr:hdr,
                rpcver:rpcver,
                program:program,
                progver:progver,
                procedure:procedure,
            }
          ))
);

#[derive(Debug,PartialEq)]
pub struct RpcPacket<'a> {
    pub hdr: RpcPacketHeader<>,

    pub rpcver: u32,
    pub program: u32,
    pub progver: u32,
    pub procedure: u32,

    pub creds_flavor: u32,
    pub creds_len: u32,
    pub creds: Option<&'a[u8]>,
    pub creds_unix:Option<RpcRequestCredsUnix<'a>>,

    pub verifier_flavor: u32,
    pub verifier_len: u32,
    pub verifier: Option<&'a[u8]>,

//    pub nfs3_request_obj: Option<Vec<Nfs3RequestObject<'a>>>,
//    pub nfs3_request_access: Option<Nfs3RequestAccess<'a>>,
//    pub nfs3_request_lookup: Option<Nfs3RequestLookup<'a>>,
//    pub nfs3_request_readdirplus: Option<Nfs3RequestReaddirplus<'a>>,

    pub prog_data: &'a[u8],
}

// nom bug leads to this wrappers being necessary
named!(many0_nfs3_request_objects<Vec<Nfs3RequestObject<'a>>>, many0!(parse_nfs3_request_object));
named!(many0_nfs3_reply_objects<Vec<Nfs3ReplyObject<'a>>>, many0!(parse_nfs3_reply_object));

named!(pub parse_rpc<RpcPacket>,
   do_parse!(
       hdr: parse_rpc_packet_header

       >> rpcver: be_u32
       >> program: be_u32
       >> progver: be_u32
       >> procedure: be_u32

       >> creds_flavor: be_u32
       >> creds_len: be_u32
       >> creds: cond!(creds_flavor != 1 && creds_len > 0, take!(creds_len as usize))
       >> creds_unix: cond!(creds_len > 0 && creds_flavor == 1, flat_map!(take!((creds_len) as usize),parse_rfc_request_creds_unix))

       >> verifier_flavor: be_u32
       >> verifier_len: be_u32
       >> verifier: cond!(verifier_len > 0, take!(verifier_len as usize))

//       >> nfs3_request_obj:    cond!(program == 100003 && progver == 3 && procedure == 1, many0_nfs3_request_objects)
//       >> nfs3_request_access: cond!(program == 100003 && progver == 3 && procedure == 4, parse_nfs3_request_access)
//       >> nfs3_request_lookup: cond!(program == 100003 && progver == 3 && procedure == 3, parse_nfs3_request_lookup)
//       >> nfs3_request_readdirplus: cond!(program == 100003 && progver == 3 && procedure == 17, parse_nfs3_request_readdirplus)

       >> pl: rest

       >> (
           RpcPacket {
                hdr:hdr,

                rpcver:rpcver,
                program:program,
                progver:progver,
                procedure:procedure,

                creds_flavor:creds_flavor,
                creds_len:creds_len,
                creds:creds,
                creds_unix:creds_unix,

                verifier_flavor:verifier_flavor,
                verifier_len:verifier_len,
                verifier:verifier,

//                nfs3_request_obj:nfs3_request_obj,
//                nfs3_request_access:nfs3_request_access,
//                nfs3_request_lookup:nfs3_request_lookup,
//                nfs3_request_readdirplus:nfs3_request_readdirplus,

                prog_data:pl,
           }
   ))
);

// to be called with data <= hdr.frag_len + 4. Sending more data is undefined.
named!(pub parse_rpc_reply<RpcReplyPacket>,
   do_parse!(
       hdr: parse_rpc_packet_header

       >> verifier_flavor: be_u32
       >> verifier_len: be_u32
       >> verifier: cond!(verifier_len > 0, take!(verifier_len as usize))

       >> reply_state: be_u32
       >> accept_state: be_u32

       >> pl: rest

       >> (
           RpcReplyPacket {
                hdr:hdr,

                verifier_flavor:verifier_flavor,
                verifier_len:verifier_len,
                verifier:verifier,

                reply_state:reply_state,
                accept_state:accept_state,

                prog_data:pl, //&[], // empty until we've done the full packet
           }
   ))
);

pub struct NfsRequestXidMap {
    //xid: u32,
    procedure: u32,
    chunk_offset: u64,
    file_name:Vec<u8>,
}

impl NfsRequestXidMap {
    pub fn new(xid: u32, procedure: u32, chunk_offset: u64) -> NfsRequestXidMap {
        NfsRequestXidMap {
            //xid:xid,
            procedure:procedure, chunk_offset:chunk_offset,
            file_name:Vec::new(),
        }
    }
}

pub struct NfsTcpParser {
    /// map xid to procedure so replies can lookup the procedure
    pub requestmap: HashMap<u32, NfsRequestXidMap>,

    /// map file handle (1) to name (2)
    pub namemap: HashMap<Vec<u8>, Vec<u8>>,

    /// TCP segments defragmentation buffer
    pub tcp_buffer_ts: Vec<u8>,
    pub tcp_buffer_tc: Vec<u8>,

    pub file_name: Vec<u8>,
    pub file_ts: FileTransferTracker,
    pub file_tc: FileTransferTracker,
}

impl NfsTcpParser {
    /// Allocation function for a new TLS parser instance
    pub fn new() -> NfsTcpParser {
        NfsTcpParser {
            requestmap:HashMap::new(),
            namemap:HashMap::new(),
            // capacity is the amount of space allocated, which means elements can be added
            // without reallocating the vector
            tcp_buffer_ts:Vec::with_capacity(8192),
            tcp_buffer_tc:Vec::with_capacity(8192),
            file_name:Vec::with_capacity(64),
            file_ts:FileTransferTracker::new(),
            file_tc:FileTransferTracker::new(),
        }
    }

    fn process_request_record_lookup<'b>(&mut self, r: &RpcPacket<'b>, xidmap: &mut NfsRequestXidMap) {
        match parse_nfs3_request_lookup(r.prog_data) {
            IResult::Done(_, lookup) => {
                println_debug!("LOOKUP {:?}", lookup);

                xidmap.file_name = lookup.name_vec;
            },
            IResult::Incomplete(_) => { panic!("WEIRD"); },
            IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
        };
    }

    fn process_request_record<'b>(&mut self, r: &RpcPacket<'b>) -> u32 {
        let mut xidmap = NfsRequestXidMap::new(r.hdr.xid, r.procedure, 0);

        //println_debug!("REQUEST {} procedure {} ({}) blob size {}", r.hdr.xid, r.procedure, self.requestmap.len(), r.prog_data.len());

        if r.procedure == 3 { // LOOKUP
            self.process_request_record_lookup(r, &mut xidmap);
        } else if r.procedure == 6 { // READ
            match parse_nfs3_request_read(r.prog_data) {
                IResult::Done(_, nfs3_read_record) => {
                    xidmap.chunk_offset = nfs3_read_record.offset;

                    match self.namemap.get(nfs3_read_record.object.value) {
                        Some(n) => {
                            println_debug!("READ name {:?}", n);
                            xidmap.file_name = n.to_vec();
                        },
                        _ => {
                            println_debug!("READ object {:?} not found", nfs3_read_record.object.value);
                        },
                    }
                },
                IResult::Incomplete(_) => { panic!("WEIRD"); },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if r.procedure == 7 { // WRITE
            match parse_nfs3_request_write(r.prog_data) {
                IResult::Done(_, w) => {
                    let v = w.file_data;
                    let mut fill_bytes = 0;
                    let pad = w.file_len % 4;
                    if pad != 0 {
                        fill_bytes = 4 - pad;
                    } 

                    let mut name;
                    match self.namemap.get(w.object.value) {
                        Some(n) => {
                            println_debug!("WRITE name {:?}", n);
                            name = n.to_vec();
                        },
                        _ => {
                            println_debug!("WRITE object {:?} not found", w.object.value);
                            name = Vec::new();
                        },
                    }

                    // for now assume that stable FILE_SYNC flags means a single chunk
                    let mut is_last = false;
                    if w.stable == 2 {
                        is_last = true;
                    }

                    self.file_ts.new_chunk(&name, v, w.offset, w.file_len, fill_bytes as u8, is_last);
                },
                IResult::Incomplete(_) => { panic!("WEIRD"); },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            }
        } else if r.procedure == 8 { // CREATE
            match parse_nfs3_request_create(r.prog_data) {
                IResult::Done(_, nfs3_create_record) => {
                    //println_debug!("nfs3_create_record: {:?}", nfs3_create_record);

                    //let vstr = vec!(nfs3_create_record.name_contents);
                    //println_debug!("vstr {:?}", vstr);
                    self.file_name = nfs3_create_record.name_vec;

                    //println!("CREATE object {:?} stored", nfs3_create_record.object.value);
                    //self.namemap.insert(nfs3_create_record.object.value.to_vec(), self.file_name.to_vec());

                    let file_name = match str::from_utf8(&self.file_name) {
                        Ok(v) => v,
                        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                    };
                    println!("NFSv3: created file {}", file_name);

                    xidmap.file_name = self.file_name.to_vec();

                    self.file_ts.create(&self.file_name, 0);
                },
                IResult::Incomplete(_) => { panic!("WEIRD"); },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if r.procedure == 21 {
            println_debug!("COMMIT, closing shop");
            self.file_ts.close();
        }

        self.requestmap.insert(r.hdr.xid, xidmap);

        0
    }

    fn process_partial_write_request_record<'b>(&mut self, r: &RpcPacket<'b>, w: &Nfs3RequestWrite<'b>) -> u32 {
        println_debug!("REQUEST {} procedure {} blob size {}", r.hdr.xid, r.procedure, r.prog_data.len());

        let xidmap = NfsRequestXidMap::new(r.hdr.xid, r.procedure, 0);
        self.requestmap.insert(r.hdr.xid, xidmap);

        if r.procedure != 7 { // WRITE
            panic!("call me for procedure WRITE *only*");
        }

        let v = w.file_data;
        let mut fill_bytes = 0;
        let pad = w.file_len % 4;
        if pad != 0 {
            fill_bytes = 4 - pad;
        } 

        let mut name;
        match self.namemap.get(w.object.value) {
            Some(n) => {
                println_debug!("WRITE name {:?}", n);
                name = n.to_vec();
            },
            _ => {
                println_debug!("WRITE object {:?} not found", w.object.value);
                name = Vec::new();
            },
        }

        // for now assume that stable FILE_SYNC flags means a single chunk
        let mut is_last = false;
        if w.stable == 2 {
            is_last = true;
        }

        self.file_ts.new_chunk(&name, v, w.offset, w.file_len, fill_bytes as u8, is_last);

        0
    }

    fn process_reply_record<'b>(&mut self, r: &RpcReplyPacket<'b>) -> u32 {
        let xidmap;
        match self.requestmap.remove(&r.hdr.xid) {
            Some(p) => { xidmap = p; },
            _ => { panic!("REPLY: xid {} NOT FOUND", r.hdr.xid); return 1; },
        }

        if xidmap.procedure == 3 { // LOOKUP
            match parse_nfs3_response_lookup(r.prog_data) {
                IResult::Done(_, lookup) => {
                    println_debug!("LOOKUP: {:?}", lookup);
                    println_debug!("RESPONSE LOOKUP file_name {:?}", xidmap.file_name);

                    println_debug!("LOOKUP handle {:?}", lookup.handle);
                    self.namemap.insert(lookup.handle.value.to_vec(), xidmap.file_name);
                },
                IResult::Incomplete(_) => { panic!("WEIRD"); },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if xidmap.procedure == 8 { // CREATE
            match parse_nfs3_response_create(r.prog_data) {
                IResult::Done(_, nfs3_create_record) => {
                    println_debug!("nfs3_create_record: {:?}", nfs3_create_record);

                    println_debug!("RESPONSE CREATE file_name {:?}", xidmap.file_name);

                    match nfs3_create_record.handle {
                        Some(h) => {
                            println_debug!("handle {:?}", h);
                            self.namemap.insert(h.value.to_vec(), xidmap.file_name);
                        },
                        _ => { },
                    }

                },
                IResult::Incomplete(_) => { panic!("WEIRD"); },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if xidmap.procedure == 6 {
            match parse_nfs3_reply_read(r.prog_data) {
                IResult::Done(_, ref reply) => {
                    let mut fill_bytes = 0;
                    let pad = reply.count % 4;
                    if pad != 0 {
                        fill_bytes = 4 - pad;
                    } 

                    println_debug!("NEW CHUNK in process_partial_read_reply_record EOF {} OFFSET {}", reply.eof, xidmap.chunk_offset);
                    self.file_tc.new_chunk(&xidmap.file_name, reply.data, xidmap.chunk_offset,
                        reply.count, fill_bytes as u8, reply.eof);
                },
                IResult::Incomplete(_) => { panic!("Incomplete!"); },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
            }
        }

        //println_debug!("REPLY {} to procedure {} blob size {}", r.hdr.xid, xidmap.procedure, r.prog_data.len());

        0
    }

    fn process_partial_read_reply_record<'b>(&mut self, r: &RpcReplyPacket<'b>, reply: &Nfs3ReplyRead<'b>, procedure: u32) -> u32 {
        println_debug!("REPLY {} to procedure {} blob size {}", r.hdr.xid, procedure, r.prog_data.len());

        let xidmap;
        match self.requestmap.get(&r.hdr.xid) {
            Some(p) => { xidmap = p; },
            _ => { panic!("REPLY: xid {} NOT FOUND", r.hdr.xid); return 1; },
        }
        if procedure != 6 { // READ
            panic!("call me for procedure READ *only*");
        }

        let mut fill_bytes = 0;
        let pad = reply.count % 4;
        if pad != 0 {
            fill_bytes = 4 - pad;
        } 

        println_debug!("NEW CHUNK in process_partial_read_reply_record EOF {} OFFSET {}", reply.eof, xidmap.chunk_offset);
        self.file_tc.new_chunk(&xidmap.file_name, reply.data, xidmap.chunk_offset,
                reply.count, fill_bytes as u8, reply.eof);

        //println_debug!("file data left after this record: {}", (r.hdr.frag_len + 4) - sz);

        0
    }

    fn peek_reply_record(&mut self, r: &RpcPacketHeader) -> u32 {
        let xidmap;
        match self.requestmap.get(&r.xid) {
            Some(p) => { xidmap = p; },
            _ => { panic!("REPLY: xid {} NOT FOUND", r.xid); return 1; },
        }

        if xidmap.procedure == 6 {
            1
        } else {
            0
        }
    }

    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_data_ts<'b>(&mut self, i: &'b[u8]) -> u32 {
        let mut v : Vec<u8>;
        let mut status = 0;
        //println_debug!("parse_tcp_data_ts ({})",i.len());
        //println_debug!("{:?}",i);
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer_ts.len() {
            0 => i, 
            _ => {
                v = self.tcp_buffer_ts.split_off(0);
                // sanity check vector length to avoid memory exhaustion
                // maximum length may be 2^24 (handshake message)
                if self.tcp_buffer_ts.len() + i.len() > 100000 {
                    //self.events.push(TlsParserEvents::RecordOverflow as u32);
                    panic!("TS buffer exploded"); //return 1;
                };
                v.extend_from_slice(i);
                v.as_slice()
            },
        }; 
        //println_debug!("tcp_buffer ({})",tcp_buffer.len());
        let mut cur_i = tcp_buffer;
        if cur_i.len() > 100000 {
            panic!("BUG buffer exploded");
        }
        let consumed = self.file_ts.update(cur_i);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 { panic!("BUG consumed more than we gave it"); }
            cur_i = &cur_i[consumed as usize..];
        }
        while cur_i.len() > 0 { // min record size
            match parse_rpc_request_partial(cur_i) {
                IResult::Done(_, ref rpc_phdr) => {
                    let rec_size = (rpc_phdr.hdr.frag_len + 4) as usize;
                    //println_debug!("rec_size {}/{}", rec_size, cur_i.len());
                    //println_debug!("cur_i {:?}", cur_i);

                    if rec_size > 40000 { panic!("invalid rec_size"); }
                    if rec_size > cur_i.len() {
                        // special case: avoid buffering file write blobs
                        // as these can be large.
                        if rec_size >= 512 && cur_i.len() >= 44 {
                            // large record, likely file xfer
                            //println_debug!("large record {}, likely file xfer", rec_size);

                            // quick peek, are in WRITE mode?
                            if rpc_phdr.procedure == 7 {
                                //println_debug!("CONFIRMED WRITE: large record {}, file xfer", rec_size);

                                // lets try to parse the RPC record. Might fail with Incomplete.
                                match parse_rpc(cur_i) {
                                    IResult::Done(rem2, ref rpc_record) => {
                                        match parse_nfs3_request_write(rpc_record.prog_data) {
                                            IResult::Done(_, ref nfs_request_write) => {
                                                // deal with the partial nfs write data                                        
                                                status |= self.process_partial_write_request_record(rpc_record, nfs_request_write);
                                                cur_i = rem2; // progress input past parsed record
                                            },
                                            IResult::Incomplete(_) => {
                                                //println_debug!("TS WRITE record incomplete");
                                            },
                                            IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
                                        }
                                    },
                                    IResult::Incomplete(_) => {
                                        // we just size checked for the minimal record size above,
                                        // so if options are used (creds/verifier), we can still
                                        // have Incomplete data. Fall through to the buffer code
                                        // and try again on our next iteration.
                                        //println_debug!("TS data incomplete");
                                    },
                                    IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
                                }
                            }
                        }
                        self.tcp_buffer_ts.extend_from_slice(cur_i);
                        break;
                    }

                    // we have the full records size worth of data,
                    // let's parse it
                    match parse_rpc(&cur_i[..rec_size]) {
                        IResult::Done(_, ref rpc_record) => {
                            cur_i = &cur_i[rec_size..];
                            status |= self.process_request_record(rpc_record);
                        },
                        IResult::Incomplete(x) => {
                            // should be unreachable unless our rec_size calc is off
                            panic!("TS data incomplete while we checked for rec_size? BUG {:?}", x);
                            self.tcp_buffer_ts.extend_from_slice(cur_i);
                            break;
                        },
                        IResult::Error(e) => { panic!("Parsing failed: {:?}",e); break },
                    }
                },
                IResult::Incomplete(_) => {
                    //println_debug!("Fragmentation required (TCP level) 2");
                    self.tcp_buffer_ts.extend_from_slice(cur_i);
                    break;
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e); break },
            }
        };
        status
    }

    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_data_tc<'b>(&mut self, i: &'b[u8]) -> u32 {
        let mut v : Vec<u8>;
        let mut status = 0;
        //println_debug!("parse_tcp_data_tc ({})",i.len());
        //println_debug!("{:?}",i);
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer_tc.len() {
            0 => i, 
            _ => {
                v = self.tcp_buffer_tc.split_off(0);
                // sanity check vector length to avoid memory exhaustion
                // maximum length may be 2^24 (handshake message)
                if self.tcp_buffer_tc.len() + i.len() > 100000 {
                    //self.events.push(TlsParserEvents::RecordOverflow as u32);
                    println_debug!("TC buffer exploded");
                    return 1;
                };
                v.extend_from_slice(i);
                v.as_slice()
            },
        }; 

        //println_debug!("tcp_buffer ({})",tcp_buffer.len());

        let mut cur_i = tcp_buffer;
        if cur_i.len() > 100000 {
            panic!("BUG buffer exploded");
        }
        let consumed = self.file_tc.update(cur_i);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 { panic!("BUG consumed more than we gave it"); }
            cur_i = &cur_i[consumed as usize..];
        }
        while cur_i.len() > 0 {
            match parse_rpc_packet_header(cur_i) {
                IResult::Done(_, ref rpc_hdr) => {
                    let rec_size = (rpc_hdr.frag_len + 4) as usize;
                    // see if we have all data available
                    if rec_size > cur_i.len() {
                        // special case: avoid buffering file read blobs
                        // as these can be large.
                        if rec_size >= 512 && cur_i.len() >= 128 {//36 {
                            // large record, likely file xfer
                            println_debug!("large record {}, likely file xfer", rec_size);

                            // quick peek, are in READ mode?
                            if self.peek_reply_record(&rpc_hdr) == 1 {
                                println_debug!("CONFIRMED large record {}, likely file xfer", rec_size);

                                // we should have enough data to parse the RPC record
                                match parse_rpc_reply(cur_i) {
                                    IResult::Done(rem2, ref rpc_record) => {
                                        match parse_nfs3_reply_read(rpc_record.prog_data) {
                                            IResult::Done(_, ref nfs_reply_read) => {
                                                // deal with the partial nfs read data                                        
                                                status |= self.process_partial_read_reply_record(rpc_record, nfs_reply_read, 6);
                                                cur_i = rem2; // progress input past parsed record
                                            },
                                            IResult::Incomplete(_) => {
                                                //println_debug!("TS WRITE record incomplete");
                                            },
                                            IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
                                        }
                                    },
                                    IResult::Incomplete(_) => {
                                        // size check was done for MINIMAL record size,
                                        // so Incomplete is normal.
                                        println_debug!("TC data incomplete");
                                    },
                                    IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
                                }
                            }
                        }
                        self.tcp_buffer_tc.extend_from_slice(cur_i);
                        break;
                    }

                    // we have the full data of the record, lets parse
                    match parse_rpc_reply(&cur_i[..rec_size]) {
                        IResult::Done(_, ref rpc_record) => {
                            cur_i = &cur_i[rec_size..]; // progress input past parsed record
                            status |= self.process_reply_record(rpc_record);
                        },
                        IResult::Incomplete(_) => {
                            // we shouldn't get incomplete as we have the full data
                            panic!("TC data incomplete, BUG!");
                            self.tcp_buffer_tc.extend_from_slice(cur_i);
                            break;
                        },
                        IResult::Error(e) => { panic!("Parsing failed: {:?}",e); break },
                    }
                },
                IResult::Incomplete(_) => {
                    println_debug!("REPLY: insufficient data for HDR");
                    self.tcp_buffer_tc.extend_from_slice(cur_i);
                    break;
                },
                IResult::Error(e) => { println_debug!("Parsing failed: {:?}",e); break },
            }
        };
        status
    }
}



r_declare_state_new!(r_nfstcp_state_new,NfsTcpParser);
r_declare_state_free!(r_nfstcp_state_free,NfsTcpParser,{});

impl RParser for NfsTcpParser {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        if i.len() == 0 {
            // Connection closed ?
            return 0;
        };
        //println_debug!("calling parse_tcp_data()");
        let status;
        if direction == 0 {
            status = self.parse_tcp_data_ts(i);
        } else {
            status = self.parse_tcp_data_tc(i);
        };
        //println_debug!("parser for {} returned {}", direction, status);
        status
    }
    fn getfiles(&mut self, direction: u8) -> * mut SuricataFileContainer {
        //println_debug!("direction: {}", direction);
        if direction == 8 {
            &mut self.file_tc.files as *mut SuricataFileContainer
        } else {
            &mut self.file_ts.files as *mut SuricataFileContainer
        }
    }
    fn setfileflags(&mut self, direction: u8, flags: u16) {
        println_debug!("direction: {}, flags: {}", direction, flags);
        if direction == 1 {
            self.file_tc.set_flags(flags);
        } else {
            self.file_ts.set_flags(flags);
        }
    }
}

fn nfstcp_probe(i: &[u8]) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn r_nfstcp_getfiles(direction: u8, ptr: *mut NfsTcpParser) -> * mut SuricataFileContainer {
    if ptr.is_null() { panic!("NULL ptr"); };
    let parser = unsafe { &mut *ptr };
    parser.getfiles(direction)//.as_ptr()
}

r_implement_probe!(r_nfstcp_probe,nfstcp_probe);
r_implement_parse!(r_nfstcp_parse,NfsTcpParser);
//r_implement_getfiles!(r_nfstcp_getfiles,NfsTcpParser);

#[no_mangle]
pub extern "C" fn r_nfstcp_setfileflags(direction: u8, ptr: *mut NfsTcpParser, flags: u16) {
    if ptr.is_null() { panic!("NULL ptr"); };
    let parser = unsafe { &mut *ptr };
    println_debug!("direction {} flags {}", direction, flags);
    parser.setfileflags(direction, flags)
}

#[cfg(test)]
mod tests {
    use nfs3::*;
    use nom::IResult;
    use nom::Needed;

static RPC_REQ1: &'static [u8] = &[
    0x80, 0x00, 0x00, 0x60, 0x74, 0x07, 0xf0, 0x77, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
    0x00, 0x01, 0x86, 0xa3, 0x00, 0x00, 0x00, 0x03, 
    0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x18, 0x01, 0x09, 0x15, 0xe9, 
    0x00, 0x00, 0x00, 0x04, 0x7a, 0x34, 0x34, 0x30, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
    0x01, 0x00, 0x07, 0x00, 0x01, 0x00, 0x76, 0x0b, 
    0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66, 
    0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00
];

#[test]
fn test_rpc_packet_req1() {
    let empty = &b""[..];
    let bytes = RPC_REQ1;
    let nfs3_req_object = Nfs3RequestObject { len: 28, value:
        &[0x01, 0x00, 0x07, 0x00, 0x01, 0x00, 0x76, 0x0b,
          0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66,
          0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00] };
    let nfs3_req_objects = vec![nfs3_req_object];
    let creds_unix = RpcRequestCredsUnix { stamp:0x010915e9,
        machine_name_len:4, machine_name_buf:&[0x7a, 0x34, 0x34, 0x30],
        uid:0, gid:0, aux_gids:None, };
    let hdr = RpcPacketHeader {
        frag_is_last:true,
        frag_len:96,
        xid:1946677367,
        msgtype:0,
    };
    let expected = IResult::Done(empty,RpcPacket{
        hdr:hdr,

        rpcver:2,
        program:100003,
        progver:3,
        procedure:19,

        creds_flavor:1,
        creds_len:24,
        creds:None,
        creds_unix:Some(creds_unix),

        verifier_flavor:0,
        verifier_len:0,
        verifier:None,

        nfs3_request_obj:Some(nfs3_req_objects),

        prog_data:&[],
    });
    let res = parse_rpc(&bytes);
    //println!("{:?}",res);
    assert_eq!(res, expected);
}

// as RPC_REQ1, but last byte missing
static RPC_REQ2: &'static [u8] = &[
    0x80, 0x00, 0x00, 0x60, 0x74, 0x07, 0xf0, 0x77, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
    0x00, 0x01, 0x86, 0xa3, 0x00, 0x00, 0x00, 0x03, 
    0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x18, 0x01, 0x09, 0x15, 0xe9, 
    0x00, 0x00, 0x00, 0x04, 0x7a, 0x34, 0x34, 0x30, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
    0x01, 0x00, 0x07, 0x00, 0x01, 0x00, 0x76, 0x0b, 
    0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66, 
    0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00
];

#[test]
fn test_rpc_packet_req2() {
    let bytes = RPC_REQ2;
    let expected = IResult::Incomplete(Needed::Size(100));
    let res = parse_rpc(&bytes);
    //println!("{:?}",res);
    assert_eq!(res, expected);
}

// as REQ1, with extra byte appended
static RPC_REQ3: &'static [u8] = &[
    0x80, 0x00, 0x00, 0x60, 0x74, 0x07, 0xf0, 0x77, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
    0x00, 0x01, 0x86, 0xa3, 0x00, 0x00, 0x00, 0x03, 
    0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x18, 0x01, 0x09, 0x15, 0xe9, 
    0x00, 0x00, 0x00, 0x04, 0x7a, 0x34, 0x34, 0x30, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
    0x01, 0x00, 0x07, 0x00, 0x01, 0x00, 0x76, 0x0b, 
    0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66, 
    0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0xff
];

#[test]
fn test_rpc_packet_req3() {
    let bytes = RPC_REQ3;
    let expected = IResult::Incomplete(Needed::Size(104));
    let res = parse_rpc(&bytes);
    assert_eq!(res, expected);
}

static RPC_REP1: &'static [u8] = &[
    0x80, 0x00, 0x00, 0x50, 0x74, 0x07, 0xf0, 0x77, 
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 
    0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x10, 0x00, 
    0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 
    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 
    0x00, 0x00, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x1b
];

#[test]
fn test_rpc_packet_rep1() {
    let empty = &b""[..];
    let bytes = RPC_REP1;

    let hdr = RpcPacketHeader {
        frag_is_last:true,
        frag_len:80,
        xid:1946677367,
        msgtype:1,
    };
        
    let nfs3_rep_object = Nfs3ReplyObject { status: 0, value:
        &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
            0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x1b          
        ] };
    let nfs3_rep_objects = vec![nfs3_rep_object];

    let expected = IResult::Done(empty,RpcReplyPacket{
        hdr: hdr,

        verifier_flavor:0,
        verifier_len:0,
        verifier:None,

        reply_state:0,
        accept_state:0,

        nfs3_reply_obj:Some(nfs3_rep_objects),

        prog_data:&[],
    });
    let res = parse_rpc_reply(&bytes);
    //println!("{:?}",res);
    assert_eq!(res, expected);
}

static RPC_REQ1A: &'static [u8] = &[
    0x80, 0x00, 0x00, 0x60, 0x74, 0x07, 0xf0, 0x77, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
    0x00, 0x01, 0x86, 0xa3, 0x00, 0x00, 0x00, 0x03, 
    0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x01, 
];
static RPC_REQ1B: &'static [u8] = &[
    0x00, 0x00, 0x00, 0x18, 0x01, 0x09, 0x15, 0xe9, 
    0x00, 0x00, 0x00, 0x04, 0x7a, 0x34, 0x34, 0x30, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
    0x01, 0x00, 0x07, 0x00, 0x01, 0x00, 0x76, 0x0b, 
    0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66, 
    0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00
];
#[test]
fn test_rpc_stream_req1() {
    let bytes_a = RPC_REQ1A;
    let bytes_b = RPC_REQ1B;
    let mut p = NfsTcpParser::new();
    let mut res = NfsTcpParser::parse_tcp_data_ts(&mut p, &bytes_a);
    assert_eq!(res, 0);
    res = NfsTcpParser::parse_tcp_data_ts(&mut p, &bytes_b);
    assert_eq!(res, 0);
    let expected = 0x7407f077;
    let actual_xid = p.last_xid;
    assert_eq!(actual_xid, expected);
}

static RPC_REQ2A: &'static [u8] = &[
    0x80, 0x00, 0x00, 0x60, 0x74, 0x07, 0xf0, 0x77, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
    0x00, 0x01, 0x86, 0xa3, 0x00, 0x00, 0x00, 0x03, 
    0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x01, 
];
static RPC_REQ2B: &'static [u8] = &[
    0x00, 0x00, 0x00, 0x18, 0x01, 0x09, 0x15, 0xe9, 
    0x00, 0x00, 0x00, 0x04, 0x7a, 0x34, 0x34, 0x30, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
    0x01, 0x00, 0x07, 0x00, 0x01, 0x00, 0x76, 0x0b, 
    0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66, 
    0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, // end of first record

    0x80, 0x00, 0x00, 0x60, 0x75, 0x07, 0xf0, 0x77, 
];
static RPC_REQ2C: &'static [u8] = &[
    0x80, 0x00, 0x00, 0x60, 0x75, 0x07, 0xf0, 0x77, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
    0x00, 0x01, 0x86, 0xa3, 0x00, 0x00, 0x00, 0x03, 
    0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x18, 0x01, 0x09, 0x15, 0xe9, 
    0x00, 0x00, 0x00, 0x04, 0x7a, 0x34, 0x34, 0x30, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
    0x01, 0x00, 0x07, 0x00, 0x01, 0x00, 0x76, 0x0b, 
    0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66, 
    0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00
];
#[test]
fn test_rpc_stream_req2() {
    let bytes_a = RPC_REQ2A;
    let bytes_b = RPC_REQ2B;
    let bytes_c = RPC_REQ2C;
    let mut p = NfsTcpParser::new();
    let mut res = NfsTcpParser::parse_tcp_data_ts(&mut p, &bytes_a);
    assert_eq!(res, 0);
    res = NfsTcpParser::parse_tcp_data_ts(&mut p, &bytes_b);
    assert_eq!(res, 0);
    let mut expected = 0x7407f077;
    let mut actual_xid = p.last_xid;
    assert_eq!(actual_xid, expected);
    res = NfsTcpParser::parse_tcp_data_ts(&mut p, &bytes_c);
    assert_eq!(res, 0);
    expected = 0x7507f077;
    actual_xid = p.last_xid;
    assert_eq!(actual_xid, expected);
}
}
