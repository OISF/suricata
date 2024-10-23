// builds.rs for Suricata
//
// Currently this build.rs only uses bindgen to build some Rust
// bindings to the Suricata C code.
//
// For more info on Rust and the build.rs file, see:
//    https://doc.rust-lang.org/cargo/reference/build-scripts.html
fn main() {
    // Pull in a simple header that presents no issues with bindgen at
    // this time. Multiple headers can be specified.
    let bindings = bindgen::Builder::default()
        .header("../src/app-layer-ext.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_item("SC.*")
        .allowlist_item("AppLayer.*")
        .rustified_enum("AppLayerEventType")
        .generate()
        .unwrap();

    // Write out the bindings. *Rules* say we should only write into
    // the target directory (idiomatically the OUT_DIR env var), so
    // we'll pull them into our namespace using an include!() macro
    // (current in sys.rs).
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();
}
