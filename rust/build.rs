extern crate cbindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let cfg = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml")).unwrap();
    cbindgen::Builder::new()
        .with_config(cfg)
        .with_crate(crate_dir.clone())
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(crate_dir.join("gen").join("rust-bindings.h"));;
}
