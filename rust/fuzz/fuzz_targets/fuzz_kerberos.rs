#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate suricata;

fuzz_target!(|data: &[u8]| {
    suricata::kerberos::parse_kerberos5_request(data);
});
