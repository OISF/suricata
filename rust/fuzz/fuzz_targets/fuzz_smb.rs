#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate suricata;

fuzz_target!(|data: &[u8]| {
    {
        let mut state = suricata::smb::smb::SMBState::new();
        state.parse_tcp_data_ts(data);
        state.ts_gap = true;
        state.parse_tcp_data_ts(data);
    }

    {
        let mut state = suricata::smb::smb::SMBState::new();
        state.parse_tcp_data_tc(data);
        state.tc_gap = true;
        state.parse_tcp_data_tc(data);
    }

    suricata::smb::smb::rs_smb_probe_tcp(data.as_ptr(), data.len() as u32);
});
