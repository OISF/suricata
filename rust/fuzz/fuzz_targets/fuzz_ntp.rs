#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate suricata;

fuzz_target!(|data: &[u8]| {
    {
        let state = suricata::ntp::ntp::rs_ntp_state_new();
        suricata::ntp::ntp::rs_ntp_parse_request(
            std::ptr::null(),
            state,
            state,
            data.as_ptr(),
            data.len() as u32,
            std::ptr::null(),
            0
        );
        suricata::ntp::ntp::rs_ntp_state_free(state);
    }
    {
        let state = suricata::ntp::ntp::rs_ntp_state_new();
        suricata::ntp::ntp::rs_ntp_parse_response(
            std::ptr::null(),
            state,
            state,
            data.as_ptr(),
            data.len() as u32,
            std::ptr::null(),
            0
        );
        suricata::ntp::ntp::rs_ntp_state_free(state);
    }
});
