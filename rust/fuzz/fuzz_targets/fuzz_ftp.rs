#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate suricata;

fuzz_target!(|data: &[u8]| {
    suricata::ftp::rs_ftp_pasv_response(data.as_ptr(), data.len() as u32);
});
