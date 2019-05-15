#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate suricata;

fuzz_target!(|data: &[u8]| {
    {
        let state = suricata::krb::krb5::rs_krb5_state_new();
        suricata::krb::krb5::rs_krb5_parse_request(
            std::ptr::null(),
            state,
            state,
            data.as_ptr(),
            data.len() as u32,
            std::ptr::null(),
            0
        );
        suricata::krb::krb5::rs_krb5_state_free(state);
    }
    {
        let state = suricata::krb::krb5::rs_krb5_state_new();
        suricata::krb::krb5::rs_krb5_parse_response(
            std::ptr::null(),
            state,
            state,
            data.as_ptr(),
            data.len() as u32,
            std::ptr::null(),
            0
        );
        suricata::krb::krb5::rs_krb5_state_free(state);
    }
});
