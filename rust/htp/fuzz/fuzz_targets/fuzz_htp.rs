#![allow(non_snake_case)]
#![no_main]
#[macro_use] extern crate libfuzzer_sys;

extern crate htp;

use htp::test::{Test, TestConfig};
use std::env;


fuzz_target!(|data: &[u8]| {
    let mut t = Test::new(TestConfig());
    t.run_slice(data);
});
