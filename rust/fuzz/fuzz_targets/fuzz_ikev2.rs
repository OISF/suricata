#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate suricata;

fuzz_target!(|data: &[u8]| {
    let state = suricata::ikev2::ikev2::rs_ikev2_state_new();
    suricata::ikev2::ikev2::rs_ikev2_parse_request(
        std::ptr::null(),
        state,
        state,
        data.as_ptr(),
        data.len() as u32,
        std::ptr::null(),
        0
    );
    suricata::ikev2::ikev2::rs_ikev2_state_free(state);
});
