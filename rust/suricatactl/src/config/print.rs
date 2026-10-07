// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use std::io::ErrorKind;
use std::io::Write;
use std::path::Path;

use crate::ConfigFormat;
use crate::ConfigPrintArgs;

/// Load a configuration like Suricata does, and print it.
pub(crate) fn print(args: ConfigPrintArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = args.config;
    let mut config = suricata_config::load_file(&path)?;

    // Like Suricata, relative paths of additional configuration files are
    // resolved from the directory of the configuration file.
    let include_dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    for include in &args.include {
        suricata_config::merge_file(&mut config, include, include_dir)?;
    }

    let output = match args.format {
        ConfigFormat::Yaml => suricata_config::print_yaml(&config)?,
        ConfigFormat::Flat => suricata_config::print_flat_config(&config),
    };
    match std::io::stdout().lock().write_all(output.as_bytes()) {
        // The reader went away, for example when piped into head.
        Err(err) if err.kind() == ErrorKind::BrokenPipe => Ok(()),
        result => Ok(result?),
    }
}
