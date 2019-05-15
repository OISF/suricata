#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate suricata;

fuzz_target!(|data: &[u8]| {
    let mut state = suricata::dhcp::dhcp::DHCPState::new();
    state.parse(data);
});
