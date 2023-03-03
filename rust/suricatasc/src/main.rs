#[cfg(not(target_os = "windows"))]
mod unix;

#[cfg(not(target_os = "windows"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    crate::unix::main::main()
}

#[cfg(target_os = "windows")]
fn main() {
    println!("suricatasc is not supported on Windows");
}
