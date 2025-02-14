// SPDX-FileCopyrightText: Copyright 2023 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

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
