// SPDX-FileCopyrightText: Copyright 2023 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use std::path::{Path, PathBuf};
use tracing::{debug, error, info};

use crate::FilestorePruneArgs;

pub(crate) fn prune(args: FilestorePruneArgs) -> Result<(), Box<dyn std::error::Error>> {
    let age = parse_age(&args.age)?;
    info!("Pruning files older than {} seconds", age);

    let mut total_bytes = 0;
    let mut file_count = 0;

    let mut stack = vec![PathBuf::from(&args.directory)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                match FileInfo::from_path(&path) {
                    Ok(info) => {
                        if info.age > age {
                            debug!("Deleting {:?}", path);
                            file_count += 1;
                            total_bytes += info.size;
                            if !args.dry_run {
                                if let Err(err) = std::fs::remove_file(&path) {
                                    error!("Failed to delete {}: {}", path.display(), err);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        error!(
                            "Failed to get last modified time of file {}: {}",
                            path.display(),
                            err
                        );
                    }
                }
            }
        }
    }

    info!("Removed {} files; {} bytes", file_count, total_bytes);

    Ok(())
}

struct FileInfo {
    age: u64,
    size: u64,
}

impl FileInfo {
    fn from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let metadata = path.metadata()?;
        let age = metadata.modified()?.elapsed()?.as_secs();
        Ok(Self {
            age,
            size: metadata.len(),
        })
    }
}

/// Given input like "1s", "1m", "1h" or "1d" return the number of
/// seconds
fn parse_age(age: &str) -> Result<u64, String> {
    // Use a regex to separate the value from the unit.
    let re = regex::Regex::new(r"^(\d+)([smhd])$").unwrap();
    let caps = re.captures(age).ok_or_else(|| {
        format!(
            "Invalid age: {}. Must be a number followed by one of s, m, h, d",
            age
        )
    })?;
    let value = caps
        .get(1)
        .unwrap()
        .as_str()
        .parse::<u64>()
        .map_err(|e| format!("Invalid age: {}: {}", age, e))?;
    let unit = caps.get(2).unwrap().as_str();

    match unit {
        "s" => Ok(value),
        "m" => Ok(value * 60),
        "h" => Ok(value * 60 * 60),
        "d" => Ok(value * 60 * 60 * 24),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_age() {
        assert!(parse_age("1").is_err());
        assert!(parse_age("s").is_err());
        assert!(parse_age("1a").is_err());

        // Valid tests
        assert_eq!(parse_age("1s").unwrap(), 1);
        assert_eq!(parse_age("3s").unwrap(), 3);
        assert_eq!(parse_age("1m").unwrap(), 60);
        assert_eq!(parse_age("3m").unwrap(), 180);
        assert_eq!(parse_age("3h").unwrap(), 10800);
        assert_eq!(parse_age("1d").unwrap(), 86400);
        assert_eq!(parse_age("3d").unwrap(), 86400 * 3);
    }
}
