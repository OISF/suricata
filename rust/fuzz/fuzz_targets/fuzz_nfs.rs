#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate suricata;

fuzz_target!(|data: &[u8]| {
    let mut state = suricata::nfs::nfs::NFSState::new();
    state.parse_tcp_data_ts(data);
    state.parse_tcp_data_tc(data);
    state.parse_udp_ts(data);
    state.parse_udp_tc(data);
});
