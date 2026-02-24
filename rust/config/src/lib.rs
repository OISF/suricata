// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

pub mod loader;

pub use loader::{load_file, load_file_with_include_dir, load_string, LoadError};

use std::collections::HashMap;

use saphyr::MappingOwned;
use saphyr::Yaml;
use saphyr::YamlEmitter;
use saphyr::YamlLoader;
use saphyr::YamlOwned;
use saphyr_parser::Event;
use saphyr_parser::Parser;
use saphyr_parser::Span;
use saphyr_parser::SpannedEventReceiver;
use thiserror::Error;

/// Parsed Suricata configuration document.
pub type Config = YamlOwned;

/// Maximum nesting depth of a configuration, counting the root mapping
/// or sequence. This is the same limit as the C loader had.
pub const MAX_NESTING_DEPTH: usize = 128;

/// Errors returned while parsing a configuration document.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to parse yaml: {0}")]
    Parse(#[from] saphyr::ScanError),
    #[error("expected one yaml document, got {0}")]
    MultipleDocuments(usize),
    #[error("maximum nesting depth exceeded ({limit}) at line {line}")]
    NestingLimit { limit: usize, line: usize },
}

/// Parse a Suricata YAML configuration document.
///
/// Empty input (or an empty/null document) is treated as an empty
/// configuration mapping.
///
/// Parsing is not recursive, and a document nested deeper than
/// [`MAX_NESTING_DEPTH`] fails to parse.
pub fn parse_yaml(input: &str) -> Result<Config, ParseError> {
    let mut docs = load_documents(input)?;

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

// Parse all YAML documents in the input.
//
// The parser's own load() recurses for each level of nesting, so the
// events are passed to the loader here instead, checking the nesting
// depth on the way.
fn load_documents(input: &str) -> Result<Vec<Config>, ParseError> {
    let mut loader = YamlLoader::<YamlOwned>::default();
    let mut nesting = NestingCheck::default();

    for event in Parser::new_from_str(input) {
        let (event, span) = event?;
        nesting.check(&event, span)?;
        loader.on_event(event, span);
    }

    Ok(loader.into_documents())
}

// Tracks the nesting depth while parsing.
//
// An alias copies its anchored node, so the height of each anchored node
// is recorded, and an alias nests as deep as its anchored node.
#[derive(Default)]
struct NestingCheck {
    // The open mappings and sequences.
    open: Vec<OpenNode>,
    // The height of each anchored node by anchor ID.
    anchors: HashMap<usize, usize>,
}

struct OpenNode {
    anchor: usize,
    // The height of the highest child seen so far.
    height: usize,
}

impl NestingCheck {
    fn check(&mut self, event: &Event, span: Span) -> Result<(), ParseError> {
        match event {
            Event::MappingStart(anchor, _) | Event::SequenceStart(anchor, _) => {
                self.open.push(OpenNode {
                    anchor: *anchor,
                    height: 0,
                });
                self.check_depth(0, span)
            }
            Event::MappingEnd | Event::SequenceEnd => {
                if let Some(node) = self.open.pop() {
                    self.add_node(node.anchor, node.height + 1);
                }
                Ok(())
            }
            Event::Scalar(_, _, anchor, _) => {
                self.add_node(*anchor, 0);
                Ok(())
            }
            Event::Alias(anchor) => {
                let height = self.anchors.get(anchor).copied().unwrap_or(0);
                self.check_depth(height, span)?;
                self.add_node(0, height);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    // Check the depth of a node with the given height below the open
    // nodes.
    fn check_depth(&self, height: usize, span: Span) -> Result<(), ParseError> {
        if self.open.len() + height > MAX_NESTING_DEPTH {
            return Err(ParseError::NestingLimit {
                limit: MAX_NESTING_DEPTH,
                line: span.start.line(),
            });
        }
        Ok(())
    }

    // Record a complete node of the given height in its parent, and its
    // anchor if it has one.
    fn add_node(&mut self, anchor: usize, height: usize) {
        if anchor > 0 {
            self.anchors.insert(anchor, height);
        }
        if let Some(parent) = self.open.last_mut() {
            parent.height = parent.height.max(height);
        }
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

    // Like the C loader, includes in an included file are resolved
    // relative to the top-level config directory, not to the directory
    // of the including file.
    #[test]
    fn test_load_config_nested_includes() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/include-nested.yaml");

        let config = load_file(&path)
            .expect("nested includes should resolve relative to the top-level config directory");

        assert!(config.as_mapping_get("include").is_none());
        assert_eq!(config["base"].as_str(), Some("root"));
        assert_eq!(config["from-one"].as_str(), Some("one"));
        assert_eq!(config["from-two"].as_str(), Some("two"));
        assert_eq!(config["from-tag"]["source"].as_str(), Some("nested-tag"));
    }

    // Includes in a file loaded with an explicit include directory, like
    // an additional config file (--include), are resolved from that
    // directory, not from the directory of the file.
    #[test]
    fn test_load_config_with_include_dir() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let path = dir.join("nested/one.yaml");

        let config = load_file_with_include_dir(&path, &dir)
            .expect("includes should resolve relative to the include directory");

        assert!(config.as_mapping_get("include").is_none());
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

    // A dotted key can index into a sequence without replacing it.
    #[test]
    fn test_load_config_dotted_override_sequence() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dotted-sequence.yaml");

        let config = load_file(&path).expect("config should load");

        let outputs = config["outputs"]
            .as_sequence()
            .expect("outputs should still be a sequence");
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0]["fast"]["enabled"].as_str(), Some("yes"));
        assert_eq!(outputs[1]["eve-log"]["enabled"].as_str(), Some("no"));
        assert_eq!(outputs[1]["eve-log"]["filetype"].as_str(), Some("regular"));
    }

    // A dotted key with a mapping value merges into the existing mapping.
    #[test]
    fn test_load_config_dotted_override_mapping_merge() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dotted-mapping-merge.yaml");

        let config = load_file(&path).expect("config should load");

        let address_groups = &config["vars"]["address-groups"];
        assert_eq!(address_groups["HOME_NET"].as_str(), Some("10.10.10.10/32"));
        assert_eq!(address_groups["EXTERNAL_NET"].as_str(), Some("!$HOME_NET"));
    }

    // An include that comes after a dotted override replaces it.
    #[test]
    fn test_load_config_include_after_dotted_override() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dotted-include-after.yaml");

        let config = load_file(&path).expect("config should load");

        let address_groups = &config["vars"]["address-groups"];
        assert_eq!(address_groups["HOME_NET"].as_str(), Some("3.3.3.3"));
        assert!(address_groups.as_mapping_get("EXTERNAL_NET").is_none());
    }

    // A dotted override from an include is applied in document order,
    // even when the same dotted key was used earlier.
    #[test]
    fn test_load_config_include_dotted_override_order() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dotted-include-order.yaml");

        let config = load_file(&path).expect("config should load");

        assert_eq!(
            config["vars"]["address-groups"]["HOME_NET"].as_str(),
            Some("3.3.3.3")
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

    // Build a config with `depth` levels of nested mappings, counting the
    // root mapping. The value 1 is at "key" followed by depth - 1 times
    // "a".
    fn nested_mappings(depth: usize) -> String {
        format!(
            "key: {}1{}\n",
            "{a: ".repeat(depth - 1),
            "}".repeat(depth - 1)
        )
    }

    fn assert_nesting_limit<T: std::fmt::Debug>(result: Result<T, LoadError>) {
        let err = result.expect_err("config over the nesting limit should fail to load");
        assert!(
            err.to_string().contains("maximum nesting depth"),
            "unexpected error: {err}"
        );
    }

    // Like the C loader, a config may be nested 128 levels deep, counting
    // the root mapping.
    #[test]
    fn test_nesting_limit() {
        let config = load_string(&nested_mappings(128)).expect("128 levels should load");
        let mut node = &config["key"];
        for _ in 1..128 {
            node = &node["a"];
        }
        assert_eq!(node.as_integer(), Some(1));

        assert_nesting_limit(load_string(&nested_mappings(129)));
    }

    // Nesting far beyond the limit fails cleanly instead of overflowing
    // the stack.
    #[test]
    fn test_nesting_limit_deep() {
        let input = format!("key:\n  {}x\n", "- ".repeat(100_000));
        assert_nesting_limit(load_string(&input));
    }

    // Each part of a dotted key is a level of nesting.
    #[test]
    fn test_nesting_limit_dotted_key() {
        let key = |segments: usize| vec!["a"; segments].join(".");

        load_string(&format!("{}: 1\n", key(128))).expect("128 levels should load");
        assert_nesting_limit(load_string(&format!("{}: 1\n", key(129))));
    }

    // Aliases copy the anchored node, so a chain of aliases nests deeper
    // than the document itself.
    #[test]
    fn test_nesting_limit_aliases() {
        let mut input = String::from("a0: &a0 [x]\n");
        for i in 1..200 {
            input.push_str(&format!("a{i}: &a{i} [*a{}]\n", i - 1));
        }
        assert_nesting_limit(load_string(&input));
    }

    // An included file is nested at the depth of the include.
    #[test]
    fn test_nesting_limit_include() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");

        let config = load_file(&dir.join("nesting-include-under.yaml"))
            .expect("include within the nesting limit should load");
        let mut node = &config["key"];
        for _ in 0..59 {
            node = &node["a"];
        }
        node = &node["inner"];
        for _ in 0..49 {
            node = &node["a"];
        }
        assert_eq!(node.as_integer(), Some(1));

        assert_nesting_limit(load_file(&dir.join("nesting-include-over.yaml")));
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
