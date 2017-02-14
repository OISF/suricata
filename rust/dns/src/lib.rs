#[macro_use]
extern crate nom;
extern crate libc;

use std::slice;
use nom::{be_u16};

#[repr(C, packed)]
pub struct DNSHeader<> {
    tx_id: u16,
    flags: u16,
    questions: u16,
    answer_rr: u16,
    authority_rr: u16,
    additional_rr: u16,
}

// DNS header parser.
named!(parse_dns_header<DNSHeader>,
       do_parse!(
           tx_id: be_u16
               >> flags: be_u16
               >> questions: be_u16
               >> answer_rr: be_u16
               >> authority_rr: be_u16
               >> additional_rr: be_u16
               >> (
                   DNSHeader{
                       tx_id: tx_id,
                       flags: flags,
                       questions: questions,
                       answer_rr: answer_rr,
                       authority_rr: authority_rr,
                       additional_rr: additional_rr,
                   }
               )
       )
);

#[no_mangle]
pub extern fn dns_header_parse(input: *const libc::uint8_t, len: libc::size_t,
    header: *mut DNSHeader)
{
    // println!("rust: parsing DNS header");
    let slice : &[u8] = unsafe {
        slice::from_raw_parts(input as *mut u8, len)
    };
    match parse_dns_header(&slice) {
        nom::IResult::Done(_, dns_header) => {
            // println!("rust: done");
            // println!("rust: tx_id: {}", dns_header.tx_id);
            unsafe {
                (*header).tx_id = dns_header.tx_id;
                (*header).flags = dns_header.flags;
                (*header).questions = dns_header.questions;
                (*header).answer_rr = dns_header.answer_rr;
                (*header).authority_rr = dns_header.authority_rr;
                (*header).additional_rr = dns_header.additional_rr;
            }
        },
        nom::IResult::Incomplete(_) => {
            // println!("rust: incomplete")
        },
        nom::IResult::Error(_) => {
            // println!("rust: error")
        }
    }
    // println!("rust: done parsing");
}

#[no_mangle]
pub extern fn hello_world() {
    println!("Hello Suricata from Rust.");
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
