#![allow(non_snake_case)]
use crate::{
    bstr::*,
    config::{Config, HtpServerPersonality},
    connection_parser::{ConnectionParser, ParserData},
    decompressors::{Decompressor, HtpContentEncoding},
    transaction::Transaction,
    HtpStatus,
};
use std::{env, path::PathBuf};

#[derive(Debug)]
struct Test {
    connp: ConnectionParser,
    expected: Bstr,
    decompressor: Decompressor,
}

enum TestError {
    Io(()),
    Htp(()),
}

fn GUnzip_decompressor_callback(tx: &mut Transaction, d: &ParserData) -> HtpStatus {
    tx.set_user_data(Box::new(Bstr::from(d.as_slice())));
    HtpStatus::OK
}

impl Test {
    fn new() -> Self {
        let mut cfg = Config::default();
        cfg.set_server_personality(HtpServerPersonality::APACHE_2)
            .unwrap();
        // The default bomb limit may be slow in some development environments causing tests to fail.
        cfg.compression_options.set_time_limit(u32::MAX);
        let cfg = Box::leak(Box::new(cfg));
        let mut connp = ConnectionParser::new(cfg);

        let expected = Bstr::from("The five boxing wizards jump quickly.");
        let tx = connp.request_mut().unwrap() as *mut Transaction;
        Test {
            connp,
            expected,
            decompressor: Decompressor::new_with_callback(
                HtpContentEncoding::Gzip,
                Box::new(move |data: Option<&[u8]>| {
                    let data = ParserData::from(data);
                    GUnzip_decompressor_callback(unsafe { &mut *tx }, &data);
                    Ok(data.len())
                }),
                Default::default(),
            )
            .unwrap(),
        }
    }

    fn run(&mut self, filename: &str) -> Result<(), TestError> {
        let mut filepath = if let Ok(dir) = std::env::var("srcdir") {
            PathBuf::from(dir)
        } else {
            let mut base = PathBuf::from(
                env::var("CARGO_MANIFEST_DIR").expect("Could not determine test file directory"),
            );
            base.push("src");
            base.push("test");
            base.push("files");
            base
        };
        filepath.push(filename);

        let data = std::fs::read(filepath).map_err(|_| TestError::Io(()))?;
        self.decompressor
            .decompress(&data)
            .map(|_| ())
            .map_err(|_| TestError::Htp(()))
    }
}

#[test]
fn GUnzip_Minimal() {
    let mut t = Test::new();
    assert!(t.run("gztest-01-minimal.gz").is_ok());
    let request_tx = t.connp.request().unwrap();
    let output = request_tx.user_data::<Bstr>().unwrap();
    assert_eq!(*output, t.expected);
}

#[test]
fn GUnzip_FNAME() {
    let mut t = Test::new();
    assert!(t.run("gztest-02-fname.gz").is_ok());
    let request_tx = t.connp.request().unwrap();
    let output = request_tx.user_data::<Bstr>().unwrap();
    assert_eq!(*output, t.expected);
}

#[test]
fn GUnzip_FEXTRA() {
    let mut t = Test::new();
    assert!(t.run("gztest-05-fextra.gz").is_ok());
    let request_tx = t.connp.request().unwrap();
    let output = request_tx.user_data::<Bstr>().unwrap();
    assert_eq!(*output, t.expected);
}

#[test]
fn GUnzip_FTEXT() {
    let mut t = Test::new();
    assert!(t.run("gztest-06-ftext.gz").is_ok());
    let request_tx = t.connp.request().unwrap();
    let output = request_tx.user_data::<Bstr>().unwrap();
    assert_eq!(*output, t.expected);
}

#[test]
fn GUnzip_Multipart() {
    let mut t = Test::new();
    assert!(t.run("gztest-10-multipart.gz").is_ok());
    let request_tx = t.connp.request().unwrap();
    let output = request_tx.user_data::<Bstr>().unwrap();
    assert_eq!(*output, t.expected);
}

#[test]
fn GUnzip_InvalidExtraFlags() {
    let mut t = Test::new();
    assert!(t.run("gztest-14-invalid-xfl.gz").is_ok());
    let request_tx = t.connp.request().unwrap();
    let output = request_tx.user_data::<Bstr>().unwrap();
    assert_eq!(*output, t.expected);
}

#[test]
fn GUnzip_InvalidHeaderCrc() {
    let mut t = Test::new();
    assert!(t.run("gztest-15-invalid-fhcrc.gz").is_ok());
    let request_tx = t.connp.request().unwrap();
    let output = request_tx.user_data::<Bstr>().unwrap();
    assert_eq!(*output, t.expected);
}

/*
// These tests were disabled in libhtp
#[test]
fn GUnzip_FCOMMENT() {
    let mut t = Test::new();
    assert!(t.run("gztest-03-fcomment.gz").is_ok());
    assert_eq!(t.output, t.expected);
}

#[test]
fn GUnzip_FHCRC() {
    let mut t = Test::new();
    assert!(t.run("gztest-04-fhcrc.gz").is_ok());
    assert_eq!(t.output, t.expected);
}

#[test]
fn GUnzip_FRESERVED1() {
    let mut t = Test::new();
    assert!(t.run("gztest-07-freserved1.gz").is_ok());
    assert_eq!(t.output, t.expected);
}

#[test]
fn GUnzip_FRESERVED2() {
    let mut t = Test::new();
    assert!(t.run("gztest-08-freserved2.gz").is_ok());
    assert_eq!(t.output, t.expected);
}

#[test]
fn GUnzip_FRESERVED3() {
    let mut t = Test::new();
    assert!(t.run("gztest-09-freserved3.gz").is_ok());
    assert_eq!(t.output, t.expected);
}

#[test]
fn GUnzip_InvalidMethod() {
    let mut t = Test::new();
    assert!(t.run("gztest-11-invalid-method.gz.gz").is_ok());
    assert_eq!(t.output, t.expected);
}

#[test]
fn GUnzip_InvalidCrc() {
    let mut t = Test::new();
    assert!(t.run("gztest-12-invalid-crc32.gz").is_ok());
    assert_eq!(t.output, t.expected);
}

#[test]
fn GUnzip_InvalidInputSize() {
    let mut t = Test::new();
    assert!(t.run("gztest-13-invalid-isize.gz").is_ok());
    assert_eq!(t.output, t.expected);
}
*/
