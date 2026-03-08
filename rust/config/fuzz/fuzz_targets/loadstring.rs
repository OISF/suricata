// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(config) = suricata_config::load_string(input) {
        let _ = suricata_config::print_yaml(&config);
        let _ = suricata_config::print_flat_config(&config);
    }

    if let Ok(config) = suricata_config::parse_yaml(input) {
        let _ = suricata_config::print_yaml(&config);
        let _ = suricata_config::print_flat_config(&config);
    }
});
