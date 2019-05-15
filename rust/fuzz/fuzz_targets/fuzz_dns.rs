#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate suricata;

fuzz_target!(|data: &[u8]| {
    {
        let mut state = suricata::dns::dns::DNSState::new();
        state.parse_request_tcp(data);
    }
    {
        let mut state = suricata::dns::dns::DNSState::new();
        state.parse_response_tcp(data);
    }
});
