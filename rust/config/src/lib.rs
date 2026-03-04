// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

pub mod loader;

pub use loader::{load_file, load_string, LoadError};

use saphyr::MappingOwned;
use saphyr::Yaml;
use saphyr::YamlEmitter;
use saphyr::YamlLoader;
use saphyr::YamlOwned;
use saphyr_parser::Event;
use saphyr_parser::Parser;
use saphyr_parser::ScalarStyle;
use saphyr_parser::SpannedEventReceiver;
use serde_json::Map as JsonMap;
use serde_json::Number as JsonNumber;
use serde_json::Value as JsonValue;
use thiserror::Error;

/// Parsed Suricata configuration document.
pub type Config = YamlOwned;

/// Limit for nesting depth. Fuzzing can easily reach this.
const MAX_YAML_NESTING_DEPTH: usize = 255;

/// Errors returned while parsing a configuration document.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to parse yaml: {0}")]
    Parse(#[from] saphyr::ScanError),
    #[error("maximum yaml nesting depth exceeded ({0})")]
    NestingDepthExceeded(usize),
    #[error("expected one yaml document, found multiple")]
    MultipleDocuments,
}

/// Parse a Suricata YAML configuration document.
pub fn parse_yaml(input: &str) -> Result<Config, ParseError> {
    let mut docs = parse_documents(input, MAX_YAML_NESTING_DEPTH)?;

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
        _ => Err(ParseError::MultipleDocuments),
    }
}

// Parse YAML using the event iterator API and enforce structural limits.
fn parse_documents(input: &str, max_nesting_depth: usize) -> Result<Vec<Config>, ParseError> {
    let mut parser = Parser::new_from_str(input);
    let mut loader: YamlLoader<'_, YamlOwned> = YamlLoader::default();
    let mut nesting_depth = 0usize;

    for event in &mut parser {
        let (mut event, span) = event?;
        normalize_legacy_bool_scalars(&mut event);

        match &event {
            Event::MappingStart(..) | Event::SequenceStart(..) => {
                nesting_depth += 1;
                if nesting_depth > max_nesting_depth {
                    return Err(ParseError::NestingDepthExceeded(max_nesting_depth));
                }
            }
            Event::MappingEnd | Event::SequenceEnd => {
                debug_assert!(nesting_depth > 0, "nesting depth underflow");
                nesting_depth = nesting_depth.saturating_sub(1);
            }
            _ => {}
        }

        loader.on_event(event, span);
    }

    Ok(loader.into_documents())
}

// Suricata configs historically treat plain, unquoted yes/no/on/off as booleans.
fn normalize_legacy_bool_scalars(event: &mut Event<'_>) {
    let Event::Scalar(value, style, _, tag) = event else {
        return;
    };

    if *style != ScalarStyle::Plain || tag.is_some() {
        return;
    }

    match value.as_ref() {
        "yes" => *value = "true".into(),
        "no" => *value = "false".into(),
        "on" => *value = "true".into(),
        "off" => *value = "false".into(),
        _ => {}
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

/// Print a parsed configuration document as pretty-printed JSON.
pub fn print_json(config: &Config) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&config_to_json(config))
}

fn config_to_json(node: &YamlOwned) -> JsonValue {
    let node = untagged_node(node);

    if node.is_null() {
        return JsonValue::Null;
    }

    if let Some(value) = node.as_str() {
        return JsonValue::String(value.to_string());
    }

    if let Some(value) = node.as_integer() {
        return JsonValue::Number(value.into());
    }

    if let Some(value) = node.as_floating_point() {
        if let Some(number) = JsonNumber::from_f64(value) {
            return JsonValue::Number(number);
        }
        return JsonValue::String(value.to_string());
    }

    if let Some(value) = node.as_bool() {
        return JsonValue::Bool(value);
    }

    match node {
        YamlOwned::Mapping(mapping) => {
            let mut object = JsonMap::with_capacity(mapping.len());
            for (key, value) in mapping {
                object.insert(scalar_to_string(key), config_to_json(value));
            }
            JsonValue::Object(object)
        }
        YamlOwned::Sequence(sequence) => {
            JsonValue::Array(sequence.iter().map(config_to_json).collect())
        }
        YamlOwned::Representation(value, _, _) => JsonValue::String(value.to_string()),
        YamlOwned::Alias(anchor) => JsonValue::String(format!("*{anchor}")),
        YamlOwned::BadValue => JsonValue::Null,
        YamlOwned::Tagged(_, _) => unreachable!("tagged nodes are unwrapped before conversion"),
        _ => JsonValue::Null,
    }
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
        assert_eq!(config["stats"]["enabled"].as_bool(), Some(true));
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

        assert!(matches!(error, ParseError::MultipleDocuments));
    }

    #[test]
    fn test_parse_nesting_at_limit() {
        let depth = MAX_YAML_NESTING_DEPTH;
        let mut input = String::new();

        for level in 0..depth {
            input.push_str(&" ".repeat(level));
            input.push_str("k:\n");
        }
        input.push_str(&" ".repeat(depth));
        input.push_str("0\n");

        parse_yaml(&input).expect("nesting at exactly the limit should succeed");
    }

    #[test]
    fn test_parse_nesting_exceeds_limit() {
        let depth = MAX_YAML_NESTING_DEPTH + 1;
        let mut input = String::new();

        for level in 0..depth {
            input.push_str(&" ".repeat(level));
            input.push_str("k:\n");
        }
        input.push_str(&" ".repeat(depth));
        input.push_str("0\n");

        let error = parse_yaml(&input).expect_err("excessive nesting should fail");
        assert!(matches!(
            error,
            ParseError::NestingDepthExceeded(MAX_YAML_NESTING_DEPTH)
        ));
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

        assert_eq!(config["stats"]["enabled"].as_bool(), Some(true));
    }

    #[test]
    fn test_load_config_without_yaml_directive_or_doc_start() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/no-yaml-directive-no-doc-start.yaml");

        let config = load_file(&path).expect("config should load without %YAML or ---");

        assert_eq!(config["stats"]["enabled"].as_bool(), Some(true));
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
        assert_eq!(outputs[0]["fast"]["enabled"].as_bool(), Some(true));
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
    fn test_load_config_sequence_entry_include() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/include-sequence-entry.yaml");

        let config =
            load_file(&path).expect("sequence entries with include mappings should resolve");

        let foobar = config["foobar"]
            .as_sequence()
            .expect("foobar should be a sequence");
        assert_eq!(foobar.len(), 2);

        assert!(foobar[0].as_mapping_get("include").is_none());
        assert_eq!(foobar[0]["host-mode"].as_str(), Some("auto"));
        assert_eq!(foobar[0]["stats"]["enabled"].as_bool(), Some(true));
        assert_eq!(foobar[0]["stats"]["interval"].as_integer(), Some(8));

        assert!(foobar[1].as_mapping_get("include").is_none());
        assert_eq!(foobar[1]["host-mode"].as_str(), Some("pcap"));
        assert_eq!(foobar[1]["stats"]["interval"].as_integer(), Some(30));
    }

    #[test]
    fn test_load_config_root_include_tag() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/include-root-tag.yaml");

        let config = load_file(&path).expect("root !include tag should resolve");

        assert_eq!(config["host-mode"].as_str(), Some("auto"));
        assert_eq!(config["stats"]["enabled"].as_bool(), Some(true));
        assert_eq!(config["stats"]["interval"].as_integer(), Some(8));
    }

    #[test]
    fn test_load_config_sequence_entry_include_tag() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/include-sequence-entry-tag.yaml");

        let config = load_file(&path).expect("sequence entries with !include tags should resolve");

        let foobar = config["foobar"]
            .as_sequence()
            .expect("foobar should be a sequence");
        assert_eq!(foobar.len(), 2);

        assert_eq!(foobar[0]["host-mode"].as_str(), Some("auto"));
        assert_eq!(foobar[0]["stats"]["enabled"].as_bool(), Some(true));
        assert_eq!(foobar[0]["stats"]["interval"].as_integer(), Some(8));

        assert_eq!(foobar[1]["host-mode"].as_str(), Some("pcap"));
        assert_eq!(foobar[1]["stats"]["interval"].as_integer(), Some(30));
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
outputs.0.fast.enabled = true\n\
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
    fn test_print_json_preserves_value_types() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/include.yaml");

        let config = load_file(&path).expect("config should load with includes");
        let printed = print_json(&config).expect("json should print");
        let json: JsonValue = serde_json::from_str(&printed).expect("json output should parse");

        assert_eq!(json["stats"]["interval"], JsonValue::from(30));
        assert_eq!(json["host-mode"], JsonValue::from("pcap"));
        assert_eq!(json["outputs"][0]["fast"]["enabled"], JsonValue::from(true));
        assert_eq!(
            json["vars"]["address-groups"]["HOME_NET"],
            JsonValue::from("[10.10.10.0/24]")
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

    #[test]
    fn test_yes_no_on_off_plain_scalars_are_booleans_but_quoted_are_strings() {
        let config = load_string(
            r#"plain_yes: yes
plain_no: no
plain_on: on
plain_off: off
quoted_yes: "yes"
quoted_no: 'no'
quoted_on: "on"
quoted_off: 'off'
"#,
        )
        .expect("failed to parse");

        assert_eq!(config["plain_yes"].as_bool(), Some(true));
        assert_eq!(config["plain_no"].as_bool(), Some(false));
        assert_eq!(config["plain_on"].as_bool(), Some(true));
        assert_eq!(config["plain_off"].as_bool(), Some(false));
        assert_eq!(config["quoted_yes"].as_str(), Some("yes"));
        assert_eq!(config["quoted_no"].as_str(), Some("no"));
        assert_eq!(config["quoted_on"].as_str(), Some("on"));
        assert_eq!(config["quoted_off"].as_str(), Some("off"));
    }
}
