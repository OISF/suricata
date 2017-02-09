// written by Victor Julien
// partly written by Pierre Chifflier
extern crate libc;
use std;
use std::mem;
use std::str;
use libc::c_char;

use nom::{rest, le_u8, le_u16, be_u16, be_u8, be_u32};
use nom::IResult;
use rparser::*;

use std::collections::HashMap;

#[derive(Debug,PartialEq)]
pub struct SmbPipeProtocolRecord<'a> {
    pub function: u16,
    pub fid: u16,

    pub data: &'a[u8],
}
/*
named!(pub parse_smb_connect_tree_andx_record<SmbRecordTreeConnectAndX>,
    dbg_dmp!(do_parse!(
       skip1: take!(7)
       >> pwlen: le_u16
       >> bcc: le_u16
       >> pw: take!(pwlen)
       >> share: take!(bcc - (6 + pwlen))
       >> service: take!(6)
       >> (SmbRecordTreeConnectAndX {
                share:share,
           }))
));
*/
#[derive(Debug,PartialEq)]
pub struct SmbRecordTreeConnectAndX<'a> {
    pub share: &'a[u8],
}

named!(pub parse_smb_connect_tree_andx_record<SmbRecordTreeConnectAndX>,
    dbg_dmp!(do_parse!(
       skip1: take!(7)
       >> pwlen: le_u16
       >> bcc: le_u16
       >> pw: take!(pwlen)
       >> share: take!(bcc - (6 + pwlen))
       >> service: take!(6)
       >> (SmbRecordTreeConnectAndX {
                share:share,
           }))
));

#[derive(Debug,PartialEq)]
pub struct SmbRecordTransRequest<'a> {
    pub data: &'a[u8],
}

named!(pub parse_smb_trans_request_record<SmbRecordTransRequest>,
    dbg_dmp!(do_parse!(
       skip1: take!(29)
       >> bcc: le_u16
       >> data: take!(bcc)
       >> (SmbRecordAndX {
                data:data,
           }))
));

#[derive(Debug,PartialEq)]
pub struct SmbRecordAndX<'a> {
    pub file_name: &'a[u8],
}

named!(pub parse_smb_andx_record<SmbRecordAndX>,
    dbg_dmp!(do_parse!(
       skip1: take!(6)
       >> file_name_len: le_u16
       >> skip2: take!(44)
       >> file_name: take!(file_name_len)
       >> skip3: rest
       >> (SmbRecordAndX {
                file_name:file_name,
           }))
));

#[derive(Debug,PartialEq)]
pub struct NbssRecord<'a> {
    pub message_type: u8,
    pub length: u32,
    pub data: &'a[u8],
}

#[derive(Debug,PartialEq)]
pub struct SmbRecord<'a> {
    //pub nbss_hdr: NbssRecord<'a>,
    pub greeter: &'a[u8],

    pub command: u8,
    pub nt_status: u32,
    pub flags: u8,
    pub flags2: u16,

    pub data: &'a[u8],
}

named!(pub parse_nbss_record<NbssRecord>,
   do_parse!(
       type_and_len: bits!(tuple!(
               take_bits!(u8, 8),
               take_bits!(u32, 24)))
       >> data: take!(type_and_len.1 as usize)
       >> (NbssRecord {
            message_type:type_and_len.0,
            length:type_and_len.1,
            data:data,
        })
));

named!(pub parse_smb_record<SmbRecord>,
    do_parse!(
            server_component:take!(4) // ff SMB
        >>  command:le_u8
        >>  nt_status:be_u32
        >>  flags:be_u8
        >>  flags2:be_u16
        >>  process_id_high:be_u16
        >>  signature:take!(8)
        >>  reserved:take!(2)
        >>  tree_id:be_u16
        >>  process_id:be_u16
        >>  user_id:be_u16
        >>  multiplex_id:be_u16
        >>  data: rest

        >>  (SmbRecord {
                greeter:server_component,
                command:command,
                nt_status:nt_status,
                flags:flags,
                flags2:flags2,
                data:data,
            })
));

pub struct SmbParser<> {
    /// map xid to procedure so replies can lookup the procedure
    pub requestmap: HashMap<u32, u32>,

    /// TCP segments defragmentation buffer
    pub tcp_buffer_ts: Vec<u8>,
    pub tcp_buffer_tc: Vec<u8>,

    /// helper for file data parser
    pub file_xfer_left_ts: u32,
    pub file_xfer_left_tc: u32,
}

impl SmbParser {
    /// Allocation function for a new TLS parser instance
    pub fn new() -> SmbParser {
        SmbParser {
            requestmap:HashMap::new(),
            // capacity is the amount of space allocated, which means elements can be added
            // without reallocating the vector
            tcp_buffer_ts:Vec::with_capacity(8192),
            tcp_buffer_tc:Vec::with_capacity(8192),
            file_xfer_left_ts:0,
            file_xfer_left_tc:0,
        }
    }

    fn process_request_record<'b>(&mut self, r: &SmbRecord<'b>) -> u32 {
        //println!("record: {:?} command {}", r.greeter, r.command);

        if r.command == 0xa2 {
            //println!("command CreateAndX");
            match parse_smb_andx_record(r.data) {
                IResult::Done(rem, create_record) => {
                    //println!("Create AndX {:?}", create_record);

                    let file_name = match str::from_utf8(create_record.file_name) {
                        Ok(v) => v,
                        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                    };
                    //println!("SMB: file {}", file_name);
                },
                IResult::Incomplete(_) => {
                    panic!("WEIRD: r.data.len() {} data {:?}", r.data.len(), r.data);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
            }
        } else if r.command == 0x75 {
            match parse_smb_connect_tree_andx_record(r.data) {
                IResult::Done(rem, create_record) => {
                    //println!("Create AndX {:?}", create_record);

                    let file_name = match str::from_utf8(create_record.share) {
                        Ok(v) => v,
                        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                    };
                    //println!("SMB: share {}", file_name);
                },
                IResult::Incomplete(_) => {
                    panic!("WEIRD: r.data.len() {} data {:?}", r.data.len(), r.data);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
            }
        } else if r.command == 0x25 {

        } else {
            //println!("command {:X}", r.command);
        }

        0
    }


    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_data_ts<'b>(&mut self, i: &'b[u8]) -> u32 {
        let mut status = 0;

        let mut v : Vec<u8>;
        //println!("parse_tcp_data_ts ({})",i.len());
        //println!("{:?}",i);
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer_ts.len() {
            0 => i, 
            _ => {
                v = self.tcp_buffer_ts.split_off(0);
                // sanity check vector length to avoid memory exhaustion
                // maximum length may be 2^24 (handshake message)
                if self.tcp_buffer_ts.len() + i.len() > 100000 {
                    //self.events.push(TlsParserEvents::RecordOverflow as u32);
                    panic!("TS buffer exploded");
                    return 1;
                };
                v.extend_from_slice(i);
                v.as_slice()
            },
        }; 
        //println!("tcp_buffer ({})",tcp_buffer.len());
        let mut cur_i = tcp_buffer;
        if cur_i.len() > 100000 {
            panic!("BUG buffer exploded");
        }
        while cur_i.len() > 0 { // min record size
            match parse_nbss_record(cur_i) {
                IResult::Done(rem, ref nbss_hdr) => {
                    //cur_i = rem;
                    let rec_size = nbss_hdr.length as usize;
                    //println!("rec_size {}/{}", rec_size, cur_i.len());
                    //println!("cur_i {:?}", cur_i);

                    if rec_size > 40000 { panic!("invalid rec_size"); }
                    if rec_size > cur_i.len() {
                        //panic!("NOT IMPLEMENTED: partial record");
                        self.tcp_buffer_ts.extend_from_slice(cur_i);
                        break;
                    }

                    // we have the full records size worth of data,
                    // let's parse it
                    match parse_smb_record(&nbss_hdr.data) {
                        IResult::Done(rem, ref smb_record) => {
                            cur_i = rem;
                            status |= self.process_request_record(smb_record);
                        },
                        IResult::Incomplete(_) => {
                            // should be unreachable unless our rec_size calc is off
                            panic!("TS data incomplete while we checked for rec_size? BUG");
                            self.tcp_buffer_ts.extend_from_slice(cur_i);
                            break;
                        },
                        IResult::Error(e) => { panic!("Parsing failed: {:?}",e); break },
                    }
                },
                IResult::Incomplete(_) => {
                    //println!("Fragmentation required (TCP level) 2");
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
        let mut status = 0;
        status
    }
}



r_declare_state_new!(r_smb_state_new,SmbParser);
r_declare_state_free!(r_smb_state_free,SmbParser,{});

impl<'a> RParser for SmbParser {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        if i.len() == 0 {
            // Connection closed ?
            return 0;
        };
        //println!("calling parse_tcp_data()");
        let status;
        if direction == 0 {
            status = self.parse_tcp_data_ts(i);
        } else {
            status = self.parse_tcp_data_tc(i);
        };
        //println!("parser for {} returned {}", direction, status);
        status
    }
}

fn smb_probe(i: &[u8]) -> bool {
    true
}

r_implement_probe!(r_smb_probe,smb_probe);
r_implement_parse!(r_smb_parse,SmbParser);
