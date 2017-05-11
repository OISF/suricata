extern crate libc;

use std;
use std::mem;
use libc::c_char;

use suricata_interface::rparser::*;

use ntp_parser::*;

use nom::IResult;

pub struct NtpParser<'a> {
    _name: Option<&'a[u8]>,
}

impl<'a> RParser for NtpParser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match parse_ntp(i) {
            IResult::Done(rem,ref res) => {
                debug!("parse_ntp: {:?}",res);
            },
            e @ _ => warn!("parse_ntp: {:?}",e),
        };
        R_STATUS_OK
    }
}

impl<'a> NtpParser<'a> {
    pub fn new(name: &'a[u8]) -> NtpParser<'a> {
        NtpParser{
            _name: Some(name),
        }
    }
}

fn ntp_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    true
}

r_declare_state_new!(r_ntp_state_new,NtpParser,b"Ntp state");
r_declare_state_free!(r_ntp_state_free,NtpParser,{ () });

r_implement_probe!(r_ntp_probe,ntp_probe);
r_implement_parse!(r_ntp_parse,NtpParser);

