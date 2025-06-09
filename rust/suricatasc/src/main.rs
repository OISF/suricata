// SPDX-FileCopyrightText: Copyright 2023 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

// Allow these patterns as its a style we like.
#![allow(clippy::needless_return)]
#![allow(clippy::let_and_return)]
#![allow(clippy::uninlined_format_args)]

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
