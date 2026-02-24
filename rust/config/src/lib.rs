// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

pub mod loader;

pub use loader::{load_file, load_string, LoadError};

use saphyr::LoadableYamlNode;
use saphyr::MappingOwned;
use saphyr::Yaml;
use saphyr::YamlEmitter;
use saphyr::YamlOwned;
use thiserror::Error;

/// Parsed Suricata configuration document.
pub type Config = YamlOwned;

/// Errors returned while parsing a configuration document.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to parse yaml: {0}")]
    Parse(#[from] saphyr::ScanError),
    #[error("expected one yaml document, got {0}")]
    MultipleDocuments(usize),
}

/// Parse a Suricata YAML configuration document.
///
/// Empty input (or an empty/null document) is treated as an empty
/// configuration mapping.
pub fn parse_yaml(input: &str) -> Result<Config, ParseError> {
    let mut docs = YamlOwned::load_from_str(input)?;

    match docs.len() {
        0 => Ok(YamlOwned::Mapping(MappingOwned::new())),
        1 => {
            let Some(document) = docs.pop() else {
                return Ok(YamlOwned::Mapping(MappingOwned::new()));
            };

            if document.is_null() {
                Ok(YamlOwned::Mapping(MappingOwned::new()))
            } else {
                Ok(document)
            }
        }
        count => Err(ParseError::MultipleDocuments(count)),
    }
}

/// Print a parsed configuration document as YAML.
pub fn print_yaml(config: &Config) -> Result<String, saphyr::EmitError> {
    let mut output = String::new();
    let mut emitter = YamlEmitter::new(&mut output);
    let borrowed = Yaml::from(config);
    emitter.dump(&borrowed)?;
    Ok(output)
}

/// Print a parsed configuration document in the format used by
/// `suricata --dump-config`.
pub fn print_flat_config(config: &Config) -> String {
    let mut output = String::new();
    print_root_entries(config, &mut output);
    output
}

// Print all top-level mapping or sequence entries.
fn print_root_entries(node: &YamlOwned, output: &mut String) {
    let node = untagged_node(node);

    match node {
        YamlOwned::Mapping(mapping) => {
            for (key, value) in mapping {
                let path = scalar_to_string(key);
                print_path_value(&path, value, output);
            }
        }
        YamlOwned::Sequence(sequence) => {
            for (index, value) in sequence.iter().enumerate() {
                let path = index.to_string();
                print_path_value(&path, value, output);
            }
        }
        _ => {}
    }
}

// Print one node and recurse into children using dotted key paths.
fn print_path_value(path: &str, node: &YamlOwned, output: &mut String) {
    let node = untagged_node(node);

    match node {
        YamlOwned::Mapping(mapping) => {
            print_line(output, path, "(mapping)");
            for (key, value) in mapping {
                let child_key = scalar_to_string(key);
                let child_path = format!("{path}.{child_key}");
                print_path_value(&child_path, value, output);
            }
        }
        YamlOwned::Sequence(sequence) => {
            print_line(output, path, "(sequence)");
            for (index, value) in sequence.iter().enumerate() {
                print_sequence_entry(path, index, value, output);
            }
        }
        _ => print_line(output, path, &scalar_to_string(node)),
    }
}

// Print a sequence entry in Suricata's flattened output style.
fn print_sequence_entry(path: &str, index: usize, node: &YamlOwned, output: &mut String) {
    let node = untagged_node(node);
    let index_path = format!("{path}.{index}");

    if let YamlOwned::Mapping(mapping) = node {
        if let Some((first_key, _)) = mapping.iter().next() {
            let entry_name = scalar_to_string(first_key);
            print_line(output, &index_path, &entry_name);

            for (key, value) in mapping {
                let child_key = scalar_to_string(key);
                let child_path = format!("{index_path}.{child_key}");
                print_path_value(&child_path, value, output);
            }
            return;
        }
    }

    print_path_value(&index_path, node, output);
}

// Append one flattened key-value line to the output buffer.
fn print_line(output: &mut String, path: &str, value: &str) {
    output.push_str(path);
    output.push_str(" = ");
    output.push_str(value);
    output.push('\n');
}

// Convert a scalar YAML node into the display string used by flat output.
fn scalar_to_string(node: &YamlOwned) -> String {
    let node = untagged_node(node);

    if node.is_null() {
        return "(null)".into();
    }

    if let Some(value) = node.as_str() {
        return value.to_string();
    }

    if let Some(value) = node.as_integer() {
        return value.to_string();
    }

    if let Some(value) = node.as_floating_point() {
        return value.to_string();
    }

    if let Some(value) = node.as_bool() {
        return value.to_string();
    }

    match node {
        YamlOwned::Representation(value, _, _) => value.to_string(),
        YamlOwned::Alias(anchor) => format!("*{anchor}"),
        YamlOwned::BadValue => "(bad value)".into(),
        _ => "(null)".into(),
    }
}

// Follow tagged YAML wrappers and return the underlying node.
// This keeps printing/formatting logic independent of YAML tags.
fn untagged_node(mut node: &YamlOwned) -> &YamlOwned {
    while let Some(inner) = node.get_tagged_node() {
        node = inner;
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_matching_lines(output: &str, expected: &str) -> usize {
        output.lines().filter(|line| *line == expected).count()
    }

    fn contains_tagged_nodes(node: &YamlOwned) -> bool {
        match node {
            YamlOwned::Tagged(_, _) => true,
            YamlOwned::Mapping(mapping) => mapping
                .iter()
                .any(|(key, value)| contains_tagged_nodes(key) || contains_tagged_nodes(value)),
            YamlOwned::Sequence(sequence) => sequence.iter().any(contains_tagged_nodes),
            _ => false,
        }
    }

    #[test]
    fn test_parse_config() {
        let config = parse_yaml(include_str!("../tests/parse.yaml")).expect("config should parse");

        assert_eq!(
            config["vars"]["address-groups"]["HOME_NET"].as_str(),
            Some("[192.168.0.0/16]")
        );
        assert_eq!(config["stats"]["enabled"].as_str(), Some("yes"));
    }

    #[test]
    fn test_parse_config_empty_input() {
        let config = parse_yaml("").expect("empty input should parse");
        assert!(matches!(&config, YamlOwned::Mapping(mapping) if mapping.is_empty()));
    }

    #[test]
    fn test_parse_config_empty_document() {
        let config = parse_yaml("---\n").expect("empty document should parse");
        assert!(matches!(&config, YamlOwned::Mapping(mapping) if mapping.is_empty()));
    }

    #[test]
    fn test_parse_config_multiple_documents_error() {
        let error = parse_yaml("---\nfoo: 1\n---\nbar: 2\n")
            .expect_err("multiple documents should return an error");

        assert!(matches!(error, ParseError::MultipleDocuments(2)));
    }

    #[test]
    fn test_load_config_empty_file() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/empty.yaml");

        let config = load_file(&path).expect("empty config file should load");

        assert!(matches!(&config, YamlOwned::Mapping(mapping) if mapping.is_empty()));
        assert_eq!(print_flat_config(&config), "");
    }

    #[test]
    fn test_load_config_without_yaml_directive() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/no-yaml-directive.yaml");

        let config = load_file(&path).expect("config should load without %YAML directive");

        assert_eq!(config["stats"]["enabled"].as_str(), Some("yes"));
    }

    #[test]
    fn test_load_config_without_yaml_directive_or_doc_start() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/no-yaml-directive-no-doc-start.yaml");

        let config = load_file(&path).expect("config should load without %YAML or ---");

        assert_eq!(config["stats"]["enabled"].as_str(), Some("yes"));
    }

    #[test]
    fn test_load_config_includes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/include.yaml");

        let config = load_file(&path).expect("config should load with includes");

        assert!(config.as_mapping_get("include").is_none());
        assert_eq!(config["host-mode"].as_str(), Some("pcap"));

        let stats = &config["stats"];
        assert_eq!(stats["interval"].as_integer(), Some(30));
        assert!(stats.as_mapping_get("enabled").is_none());

        let address_groups = &config["vars"]["address-groups"];
        assert_eq!(address_groups["HOME_NET"].as_str(), Some("[10.10.10.0/24]"));
        assert_eq!(address_groups["EXTERNAL_NET"].as_str(), Some("any"));
        assert!(address_groups.as_mapping_get("include").is_none());

        let outputs = config["outputs"]
            .as_sequence()
            .expect("outputs should be a sequence");
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0]["fast"]["enabled"].as_str(), Some("yes"));
        assert_eq!(outputs[0]["fast"]["filename"].as_str(), Some("fast.log"));
    }

    // Duplicate mapping keys (including `include`) are not supported.
    #[test]
    fn test_load_config_multiple_include_key_not_supported() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/multiple-include.yaml");

        let config = load_file(&path).expect("config should load");

        // With duplicate keys, only the last `include:` survives YAML parsing.
        assert!(config.as_mapping_get("include").is_none());
        assert_eq!(config["HOME_NET"].as_str(), Some("[192.168.0.0/16]"));
        assert_eq!(config["EXTERNAL_NET"].as_str(), Some("any"));
        assert!(config.as_mapping_get("stats").is_none());
        assert!(config.as_mapping_get("vars").is_none());
    }

    #[test]
    fn test_load_config_nested_includes() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/include-nested.yaml");

        let config = load_file(&path)
            .expect("nested includes should resolve relative to the including file directory");

        assert!(config.as_mapping_get("include").is_none());
        assert_eq!(config["base"].as_str(), Some("root"));
        assert_eq!(config["from-one"].as_str(), Some("one"));
        assert_eq!(config["from-two"].as_str(), Some("two"));
        assert_eq!(config["from-tag"]["source"].as_str(), Some("nested-tag"));
    }

    #[test]
    fn test_load_config_dotted_overrides() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/flat-includes.yaml");

        let config = load_file(&path).expect("config should load with dotted overrides");

        assert!(config
            .as_mapping_get("vars.address-groups.HOME_NET")
            .is_none());
        assert!(config
            .as_mapping_get("vars.port-groups.FTP_PORTS")
            .is_none());

        assert_eq!(
            config["vars"]["address-groups"]["HOME_NET"].as_str(),
            Some("10.10.10.10/32")
        );
        assert_eq!(
            config["vars"]["address-groups"]["EXTERNAL_NET"].as_str(),
            Some("!$HOME_NET")
        );
        assert_eq!(
            config["vars"]["port-groups"]["HTTP_PORTS"].as_str(),
            Some("80")
        );
        assert_eq!(
            config["vars"]["port-groups"]["FTP_PORTS"].as_str(),
            Some("[21,2121]")
        );
        assert_eq!(
            config["vars"]["port-groups"]["DEV_SERVER_PORTS"].as_str(),
            Some("[3000,4200]")
        );
    }

    #[test]
    fn test_print_flat_config_includes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/include.yaml");

        let config = load_file(&path).expect("config should load with includes");

        let printed = print_flat_config(&config);
        let expected = "stats = (mapping)\n\
stats.interval = 30\n\
host-mode = pcap\n\
outputs = (sequence)\n\
outputs.0 = fast\n\
outputs.0.fast = (mapping)\n\
outputs.0.fast.enabled = yes\n\
outputs.0.fast.filename = fast.log\n\
vars = (mapping)\n\
vars.address-groups = (mapping)\n\
vars.address-groups.HOME_NET = [10.10.10.0/24]\n\
vars.address-groups.EXTERNAL_NET = any\n";

        assert_eq!(printed, expected);
    }

    #[test]
    fn test_print_flat_config_dotted_overrides() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/flat-includes.yaml");

        let config = load_file(&path).expect("config should load with includes");
        let printed = print_flat_config(&config);
        let expected = "vars = (mapping)\n\
vars.address-groups = (mapping)\n\
vars.address-groups.HOME_NET = 10.10.10.10/32\n\
vars.address-groups.EXTERNAL_NET = !$HOME_NET\n\
vars.port-groups = (mapping)\n\
vars.port-groups.HTTP_PORTS = 80\n\
vars.port-groups.FTP_PORTS = [21,2121]\n\
vars.port-groups.DEV_SERVER_PORTS = [3000,4200]\n";

        assert_eq!(printed, expected);
    }

    #[test]
    fn test_print_flat_config_verify_array_includes() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/flat-includes-array.yaml");

        let config = load_file(&path).expect("config should load with includes");
        let printed = print_flat_config(&config);

        assert_eq!(count_matching_lines(&printed, "af-packet.0 = interface"), 1);
        assert_eq!(
            count_matching_lines(&printed, "af-packet.0.interface = enp10s0"),
            1
        );
        assert_eq!(
            count_matching_lines(&printed, "foobar.af-packet.0 = interface"),
            1
        );
        assert_eq!(
            count_matching_lines(&printed, "foobar.af-packet.0.interface = enp10s0"),
            1
        );
    }

    #[test]
    fn test_load_config_unwraps_all_tagged_values() {
        let config = load_string(
            r#"foo: !tag value
list: !seq [!item one]
nested: !outer
  child: !inner value
tagged.path: !leaf final
? !k tagged-key
: !v tagged-value
"#,
        )
        .expect("tagged config should load");

        assert!(!contains_tagged_nodes(&config));
        assert_eq!(config["foo"].as_str(), Some("value"));
        assert_eq!(config["list"][0].as_str(), Some("one"));
        assert_eq!(config["nested"]["child"].as_str(), Some("value"));
        assert_eq!(config["tagged"]["path"].as_str(), Some("final"));
        assert_eq!(config["tagged-key"].as_str(), Some("tagged-value"));
    }

    #[test]
    fn test_null() {
        // Standard YAML null forms.
        let config = load_string("foo: ~").expect("failed to parse");
        assert!(config["foo"].is_null());

        let config = load_string("foo: null").expect("failed to parse");
        assert!(config["foo"].is_null());

        // No value is null.
        let config = load_string("foo:").expect("failed to parse");
        assert!(config["foo"].is_null());

        let config = load_string("foo: NULL").expect("failed to parse");
        assert!(config["foo"].is_null());

        // Non-standard case variations are not null.
        let config = load_string("foo: Null").expect("failed to parse");
        assert!(!config["foo"].is_null());

        let config = load_string("foo: NuLL").expect("failed to parse");
        assert!(!config["foo"].is_null());

        // An empty string is not null.
        let config = load_string("foo: \"\"").expect("failed to parse");
        assert_eq!(config["foo"].as_str(), Some(""));
        assert!(!config["foo"].is_null());
    }
}
