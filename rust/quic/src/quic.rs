// written by Victor Julien
// partly written by Pierre Chifflier
extern crate libc;
use std;
use std::mem;
use libc::c_char;
//use std::ffi::CStr;

use nom::{rest};
use nom::IResult;
use rparser::*;

use std::io::Write;

pub fn bytes_to_u64(s: &[u8]) -> Result<u64, &'static str> {
    let mut u = 0;

    for &c in s {
        u *= 256;
        u += c as u64;
    }

    Ok(u)
}

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

pub struct QuicParserState<'a> {
    pub o: Option<&'a[u8]>,
    events: Vec<u32>,
    counter: u64,
}

impl<'a> QuicParserState<'a> {
    pub fn new(i: &'a[u8]) -> QuicParserState<'a> {
        QuicParserState {
            o:Some(i),
            events:Vec::new(),
            counter:0,
        }
    }
}

r_declare_state_new!(r_quic_state_new,QuicParserState,b"blah");
r_declare_state_free!(r_quic_state_free,QuicParserState,{});

#[derive(Debug,PartialEq)]
pub struct QuicPacket<'a> {
    pub flags_has_version: bool,
    pub flags_has_reset: bool,
    pub conn_fld_len: u8,
    pub connection_id: Option<&'a[u8]>,
    pub version: Option<&'a[u8]>,
    pub seq_fld_len: u8,
    pub seq_id: &'a[u8],
    pub payload: &'a[u8],
}

named!(pub parse_quic<QuicPacket>,
   do_parse!(
       flags: bits!(tuple!(
               take_bits!(u8, 2),   // reserved
               take_bits!(u8, 2),   // seq
               take_bits!(u8, 2),   // conn,
               take_bits!(u8, 1),   // reset
               take_bits!(u8, 1)))  // has ver

       // get connection field length and take it
       >> conn_len: value!(match flags.2 { 0x00 => 0, 0x01 => 1, 0x02 => 4, /* 0x03 */_ => 8, })
       >> connid: cond!(flags.2 > 0, take!(conn_len))

       // if version is present it's always 4 bytes
       >> ver : cond!(flags.4 == 1, take!(4))

       // sequence is 1, 2, 4 or 6 bytes
       >> seq_len: value!(match flags.1 { 0x00 => 1, 0x10 => 2, 0x20 => 4, /* 0x30 */_ => 6, })
       >> seqid: take!(seq_len)

       >> pl: rest

       >> (
           QuicPacket {
               flags_has_version:flags.4 == 1,
               flags_has_reset:flags.3 == 1,
               conn_fld_len:conn_len,
               version:ver,
               seq_fld_len:seq_len,
               connection_id:connid,
               seq_id:seqid,
               payload: pl,
           }
   ))
);

struct QuicParser;

impl<'a> RParser<QuicParserState<'a>> for QuicParser {
    fn new_state() -> QuicParserState<'a> {
        QuicParserState::new(b"blah")
    }

    fn probe(i: &[u8]) -> bool {
        match parse_quic(i) {
            IResult::Done(_, quic_packet) => {
//                println!("rust::quic.rs::probe: match!");
                true
            }
            IResult::Incomplete(_) => {
                println!("rust: incomplete");
                false
            }
            IResult::Error(_) => {
                println!("rust: error");
                false
            }
        }
    }

    fn parse(this: &mut QuicParserState, i: &[u8], direction: u8) -> u32 {
        match parse_quic(i) {
            IResult::Done(_, quic_packet) => {
                //println!("quic.rs: {:?}", quic_packet);

                let my_int = bytes_to_u64(quic_packet.seq_id); 
                this.counter = this.counter + 1;
//                println!("quic.rs: SEQ {:?} raw {:?}, msg {}", my_int, quic_packet.seq_id, this.counter);
            }
            IResult::Incomplete(_) => {
                println!("rust: incomplete");
            }
            IResult::Error(_) => {
                println!("rust: error");
            }
        }

        //let d = parse_quic(i);
        //println!("d {:?}", d);
        let status = R_STATUS_OK;
//        println_stderr!("status: {:x}",status);
        status
    }
}

r_implement_probe!(r_quic_probe,QuicParser);
r_implement_parse!(r_quic_parse,QuicParser);

#[cfg(test)]
mod tests {
    use quic::*;
    use nom::IResult;

static QUIC_REQ1: &'static [u8] = &[
    0x00, 0x02, 0xb3, 0xb1, 0x7f, 0xa8, 0x89, 0x5c, 
    0x77, 0xeb, 0xcb, 0x8d, 0x90, 0xe5, 0x51, 0xc9, 
    0xcd, 0x13, 0xdb, 0xbf, 0x45, 0x65, 0x11, 0xf6, 
    0xfc, 0xf9, 0xbf, 0x32, 0x6a, 0xb8
];

#[test]
fn test_quic_packet1() {
    let empty = &b""[..];
    let bytes = QUIC_REQ1;
    let session_id = [0x02];
    let expected = IResult::Done(empty,QuicPacket{
        flags_has_version:false,
        flags_has_reset:false,
        conn_fld_len:0,
        version:None,
        seq_fld_len:1,
        connection_id:None,
        seq_id:&session_id,
        payload:&bytes[2..],
    });
    let res = parse_quic(&bytes);
    println!("{:?}",res);
    assert_eq!(res, expected);
}

static QUIC_REQ2: &'static [u8] = &[
    0x0c, 0xe3, 0x67, 0x86, 0xee, 0x6e, 0xc8, 0x56, 
    0x62, 0x07, 0xc0, 0xcf, 0x74, 0x6e, 0xef, 0xe1, 
    0xd1, 0x64, 0x76, 0xa4, 0xfd, 0xec, 0x0b, 0x74, 
    0x3b, 0xa0, 0x13, 0xef, 0xd9, 0x98, 0xc7, 0xbf, 
    0x04, 0xda, 0x47, 0x35, 0xf3, 0x7e
];

#[test]
fn test_quic_packet2() {
    let empty = &b""[..];
    let bytes = QUIC_REQ2;
    let session_id = [0x07];
    let expected = IResult::Done(empty,QuicPacket{
        flags_has_version:false,
        flags_has_reset:false,
        conn_fld_len:8,
        version:None,
        seq_fld_len:1,
        connection_id:Some(&bytes[1..9]),
        seq_id:&session_id,
        payload:&bytes[10..],
    });
    let res = parse_quic(&bytes);
    assert_eq!(res, expected);
}

static QUIC_REQ3: &'static [u8] = &[
    0x04, 0x5e, 0x78
];

#[test]
fn test_quic_packet3() {
    let empty = &b""[..];
    let bytes = QUIC_REQ3;
    let session_id = [0x78];
    let expected = IResult::Done(empty,QuicPacket{
        flags_has_version:false,
        flags_has_reset:false,
        conn_fld_len:1,
        version:None,
        seq_fld_len:1,
        connection_id:Some(&bytes[1..2]),
        seq_id:&session_id,
        payload:&[],
    });
    let res = parse_quic(&bytes);
    println!("{:?}",res);
    assert_eq!(res, expected);
}

static QUIC_REQ4: &'static [u8] = &[
    0x0d, 0xe3, 0x67, 0x86, 0xee, 0x6e, 0xc8, 0x56, 
    0x62, 0x51, 0x30, 0x33, 0x35, 0x01, 0x19, 0xad, 
    0x47, 0x62, 0x6b, 0xf0, 0x9a, 0x19, 0x45, 0xc2, 
    0x58, 0xa8, 0xa0, 0x01, // truncated the payload
];

#[test]
fn test_quic_packet4() {
    let empty = &b""[..];
    let bytes = QUIC_REQ4;
    let session_id = [0x01];
    let version = [0x51, 0x30, 0x33, 0x35]; // Q035
    let expected = IResult::Done(empty,QuicPacket{
        flags_has_version:true,
        flags_has_reset:false,
        conn_fld_len:8,
        version:Some(&version),
        seq_fld_len:1,
        connection_id:Some(&bytes[1..9]),
        seq_id:&session_id,
        payload:&bytes[14..],
    });
    let res = parse_quic(&bytes);
    println!("{:?}",res);
    assert_eq!(res, expected);
}

}
