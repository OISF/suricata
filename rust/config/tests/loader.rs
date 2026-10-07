// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;
use std::path::PathBuf;

use suricata_config::load_file;
use suricata_config::load_string;
use suricata_config::load_string_with_include_dir;
use suricata_config::merge_file;
use suricata_config::print_flat_config;
use suricata_config::LoadError;
use suricata_config::Node;

// The configuration files in tests/data.
fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

// Load tests/data/NAME.yaml.
fn load_data(name: &str) -> Result<Node, LoadError> {
    load_file(&data().join(format!("{name}.yaml")))
}

fn flat(config: &Node) -> String {
    print_flat_config(config)
}

fn assert_error<T: std::fmt::Debug>(result: Result<T, LoadError>, message: &str) {
    let err = result.expect_err("should fail to load");
    assert!(err.to_string().contains(message), "unexpected error: {err}");
}

// Build a config with `depth` levels of nested mappings, counting the
// root mapping.
fn nested_mappings(depth: usize) -> String {
    format!(
        "key: {}1{}\n",
        "{a: ".repeat(depth - 1),
        "}".repeat(depth - 1)
    )
}

#[test]
fn test_basic() {
    let config = load_string(
        "%YAML 1.1\n---\nvars:\n  address-groups:\n    HOME_NET: \"[192.168.0.0/16]\"\nlist:\n  - a\n  - b\n",
    )
    .unwrap();
    assert_eq!(
        config["vars"]["address-groups"]["HOME_NET"].as_str(),
        Some("[192.168.0.0/16]")
    );
    assert_eq!(config["list"][1].as_str(), Some("b"));
    assert_eq!(
        config.get_path("vars.address-groups.HOME_NET"),
        Some(&Node::Scalar("[192.168.0.0/16]".into()))
    );
    assert_eq!(config.get_path("list.0").and_then(Node::as_str), Some("a"));
}

#[test]
fn test_empty() {
    for input in ["", "%YAML 1.1\n---\n", "# comment\n", "---\n...\n"] {
        let config = load_string(input).unwrap();
        assert_eq!(config, Node::Mapping(Default::default()), "{input:?}");
    }
}

#[test]
fn test_root_must_be_mapping() {
    assert_error(load_string("- a\n"), "expected a mapping");
    assert_error(load_string("hello\n"), "expected a mapping");
}

// Scalars are kept as written.
#[test]
fn test_scalars() {
    let config = load_string("a: 0x10\nb: 1.0\nc: yes\nd: '010'\ne: !!int 012\n").unwrap();
    assert_eq!(config["a"].as_str(), Some("0x10"));
    assert_eq!(config["b"].as_str(), Some("1.0"));
    assert_eq!(config["c"].as_str(), Some("yes"));
    assert_eq!(config["d"].as_str(), Some("010"));
    assert_eq!(config["e"].as_str(), Some("012"));
}

#[test]
fn test_null() {
    for value in ["~", "null", "Null", "NULL", "", "!!null value"] {
        let config = load_string(&format!("foo: {value}\n")).unwrap();
        assert!(config["foo"].is_null(), "{value:?}");
    }
    for value in ["nUll", "\"null\"", "'~'", "\"\"", "!!str null"] {
        let config = load_string(&format!("foo: {value}\n")).unwrap();
        assert!(!config["foo"].is_null(), "{value:?}");
    }
    // Keys are used as written.
    let config = load_string("~: a\nnull: b\n").unwrap();
    assert_eq!(config["~"].as_str(), Some("a"));
    assert_eq!(config["null"].as_str(), Some("b"));
}

// A duplicate key replaces the value, and keeps its position.
#[test]
fn test_duplicate_keys() {
    let config = load_string("a: 1\nb:\n  x: 1\n  y: 2\nc: 3\nb:\n  z: 3\na: ~\n").unwrap();
    assert_eq!(flat(&config), "a = (null)\nb = (null)\nb.z = 3\nc = 3\n");
}

// Documents of a file are applied one after the other.
#[test]
fn test_multiple_documents() {
    let config = load_string("foo: 1\nshared:\n  a: 1\n---\nbar: 2\nshared:\n  b: 2\n").unwrap();
    assert_eq!(
        flat(&config),
        "foo = 1\nshared = (null)\nshared.b = 2\nbar = 2\n"
    );
}

#[test]
fn test_dotted_keys() {
    let config = load_string(
        r#"
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
outputs:
  - fast:
      enabled: yes
  - eve-log:
      enabled: yes
      filetype: regular
vars.address-groups.HOME_NET: "10.10.10.10/32"
vars.port-groups.HTTP_PORTS: "80"
outputs.1.eve-log.enabled: no
outputs.2:
  stats:
    enabled: yes
"#,
    )
    .unwrap();
    assert_eq!(
        flat(&config),
        "vars = (null)
vars.address-groups = (null)
vars.address-groups.HOME_NET = 10.10.10.10/32
vars.address-groups.EXTERNAL_NET = !$HOME_NET
vars.port-groups = (null)
vars.port-groups.HTTP_PORTS = 80
outputs = (null)
outputs.0 = fast
outputs.0.fast = (null)
outputs.0.fast.enabled = yes
outputs.1 = eve-log
outputs.1.eve-log = (null)
outputs.1.eve-log.enabled = no
outputs.1.eve-log.filetype = regular
outputs.2 = stats
outputs.2.stats = (null)
outputs.2.stats.enabled = yes
"
    );
}

// A dotted key merges a mapping into an existing mapping, a null value
// leaves the existing node as is, anything else replaces it.
#[test]
fn test_dotted_key_merge() {
    let config = load_string(
        r#"
foo:
  map: {x: 1, y: 2, sub: {a: 1}}
  list: [a, b]
  scalar: value
  keep: 1
foo.map:
  x: 9
  z: 3
  sub: {b: 2}
foo.list: [c]
foo.scalar.child: 1
foo.keep: ~
foo.new: ~
"#,
    )
    .unwrap();
    assert_eq!(
        flat(&config),
        "foo = (null)
foo.map = (null)
foo.map.x = 9
foo.map.y = 2
foo.map.sub = (null)
foo.map.sub.b = 2
foo.map.z = 3
foo.list = (null)
foo.list.0 = c
foo.scalar = (null)
foo.scalar.child = 1
foo.keep = 1
foo.new = (null)
"
    );
}

#[test]
fn test_dotted_key_invalid_index() {
    assert_error(
        load_string("l: [a]\nl.2: b\n"),
        "is not a valid index for a sequence of length 1",
    );
    assert_error(load_string("l: [a]\nl.x: b\n"), "is not a valid index");
}

#[test]
fn test_include() {
    let config = load_data("include").unwrap();
    assert_eq!(
        flat(&config),
        "before = 1
vars = (null)
vars.address-groups = (null)
vars.address-groups.HOME_NET = 10.10.10.10/32
vars.address-groups.EXTERNAL_NET = !$HOME_NET
vars.port-groups = (null)
vars.port-groups.FTP_PORTS = [21,2121]
override-me = from-include
nested = (null)
nested.key = value
after = 1
"
    );
}

// Include lists, null entries, and include keys used more than once
// at any level. The last value wins.
#[test]
fn test_include_lists() {
    let config = load_data("include-lists").unwrap();
    assert_eq!(
        flat(&config),
        "from-a = 1
shared = from-b
from-b = 1
outer = (null)
outer.own = 1
outer.from-a = 1
outer.shared = from-a
outer.after-include = 2
list = (null)
list.0 = name
list.0.name = first
list.0.from-b = 1
list.0.shared = from-b
list.1 = from-a
list.1.from-a = 1
list.1.shared = from-a
list.1.own = yes
deeper = (null)
deeper.level = (null)
deeper.level.from-a = 1
deeper.level.shared = from-b
deeper.level.from-b = 1
"
    );
}

// Includes in included files are resolved from the directory of the
// configuration file.
#[test]
fn test_include_nested() {
    let config = load_data("include-nested").unwrap();
    assert_eq!(
        flat(&config),
        "base = root
from-one = one
from-tag = (null)
from-tag.source = nested-tag
from-tag.from-three = three
from-two = two
"
    );
}

// An absolute include path is used as is, not resolved from the include
// directory.
#[test]
fn test_include_absolute_path() {
    let included = data().join("include-absolute.yaml");
    assert!(included.is_absolute());
    let config = load_string_with_include_dir(
        &format!("include: {0}\ntagged: !include {0}\n", included.display()),
        &data().join("nested"),
    )
    .unwrap();
    assert_eq!(
        flat(&config),
        "included = 1\ntagged = (null)\ntagged.included = 1\n"
    );
}

#[test]
fn test_include_tag() {
    let config = load_data("include-tag").unwrap();
    assert_eq!(
        flat(&config),
        "af-packet = (null)
af-packet.0 = interface
af-packet.0.interface = eth0
af-packet.0.threads = 1
af-packet.1 = interface
af-packet.1.interface = eth1
existing = (null)
existing.x = 1
existing.y = (null)
existing.y.0 = 1
existing.y.1 = 2
merged = (null)
merged.x = 1
merged.y = (null)
merged.y.0 = 1
merged.y.1 = 2
dotted = (null)
dotted.merge = (null)
dotted.merge.keep = 1
dotted.merge.x = 1
dotted.merge.y = (null)
dotted.merge.y.0 = 1
dotted.merge.y.1 = 2
scalar = just a scalar
empty = (null)
null-include = (null)
in-list = (null)
in-list.0 = include-tag-scalars.yaml
in-list.1 = plain
"
    );
}

#[test]
fn test_include_same_file_twice() {
    let config = load_data("include-twice").unwrap();
    assert_eq!(
        flat(&config),
        "scalar = 1\nagain = (null)\nagain.scalar = 1\n"
    );
}

#[test]
fn test_include_errors() {
    let dir = data();
    let cases = [
        ("include: nope.yaml\n", "nope.yaml included at"),
        (
            "include: [include-errors-ok.yaml, nope.yaml]\n",
            "nope.yaml included at",
        ),
        ("foo: !include nope.yaml\n", "nope.yaml included at"),
        ("include: .\n", "Is a directory"),
        ("include:\n  a: 1\n", "include fields cannot be a mapping"),
        (
            "include: [[a.yaml]]\n",
            "include list entries must be file names",
        ),
        (
            "include: [{a: 1}]\n",
            "include list entries must be file names",
        ),
        (
            "include: include-errors-seq.yaml\n",
            "expected a mapping at the root",
        ),
        (
            "include: include-errors-scalar.yaml\n",
            "expected a mapping at the root",
        ),
        (
            "foo: !include include-errors-docs.yaml\n",
            "must be one document",
        ),
        ("foo: !include include-errors-bad.yaml\n", "failed to parse"),
    ];
    for (input, message) in cases {
        assert_error(load_string_with_include_dir(input, &dir), message);
    }
}

#[test]
fn test_include_cycle() {
    assert_error(load_data("include-cycle-self"), "includes itself");
    assert_error(
        load_string_with_include_dir("include: include-cycle-a.yaml\n", &data()),
        "includes itself",
    );
    assert_error(
        load_string_with_include_dir("x: !include include-cycle-tag.yaml\n", &data()),
        "includes itself",
    );
}

// Without a cycle, includes may only be nested so deep.
#[test]
fn test_include_limit() {
    assert_error(
        load_file(&data().join("include-limit/0.yaml")),
        "maximum include depth",
    );
}

// Like `suricata --include`.
#[test]
fn test_merge_file() {
    let include_dir = data();
    let path = include_dir.join("merge-file.yaml");
    let mut config = load_file(&path).unwrap();
    merge_file(
        &mut config,
        Path::new("merge-file-extra.yaml"),
        &include_dir,
    )
    .unwrap();
    let expected = "a = 2
map = (null)
map.z = 3
vars = (null)
vars.address-groups = (null)
vars.address-groups.HOME_NET = any
vars.address-groups.EXTERNAL_NET = x
nested = 1
";
    assert_eq!(flat(&config), expected);

    // On error the configuration is not changed.
    assert_error(
        merge_file(&mut config, Path::new("merge-file-bad.yaml"), &include_dir),
        "nope.yaml",
    );
    assert_eq!(flat(&config), expected);
}

// Like the C loader, a config may be nested 128 levels deep, counting
// the root mapping.
#[test]
fn test_nesting_limit() {
    let config = load_string(&nested_mappings(128)).unwrap();
    let mut node = &config["key"];
    for _ in 1..128 {
        node = &node["a"];
    }
    assert_eq!(node.as_str(), Some("1"));

    assert_error(load_string(&nested_mappings(129)), "maximum nesting depth");
}

// A sequence and a mapping in a sequence are each a level.
#[test]
fn test_nesting_limit_sequences() {
    let nested = |depth: usize| {
        format!(
            "key: {}x{}\n",
            "[{a: ".repeat(depth / 2),
            "}]".repeat(depth / 2)
        )
    };
    load_string(&nested(126)).unwrap();
    assert_error(load_string(&nested(128)), "maximum nesting depth");
}

// Nesting far beyond the limit fails cleanly instead of overflowing
// the stack.
#[test]
fn test_nesting_limit_deep() {
    let input = format!("key:\n  {}x\n", "- ".repeat(100_000));
    assert_error(load_string(&input), "maximum nesting depth");
    let input = format!("key: {}\n", "[".repeat(100_000));
    assert!(load_string(&input).is_err());
}

// Each part of a dotted key is a level of nesting.
#[test]
fn test_nesting_limit_dotted_key() {
    let key = |segments: usize| vec!["a"; segments].join(".");

    load_string(&format!("{}: 1\n", key(128))).unwrap();
    assert_error(
        load_string(&format!("{}: 1\n", key(129))),
        "maximum nesting depth",
    );
    load_string(&format!("{}: {{}}\n", key(127))).unwrap();
    assert_error(
        load_string(&format!("{}: {{}}\n", key(128))),
        "maximum nesting depth",
    );
}

// The nesting limit applies across included files.
#[test]
fn test_nesting_limit_include() {
    // 60 levels in the main file, counting the root, and 68 below the
    // root of the ok file, 69 below the root of the over file.
    let outer = |name: &str| {
        format!(
            "key: {}!include {name}{}\n",
            "{a: ".repeat(58),
            "}".repeat(58)
        )
    };

    let config =
        load_string_with_include_dir(&outer("nesting-limit-include-ok.yaml"), &data()).unwrap();
    let mut node = &config["key"];
    for _ in 0..58 {
        node = &node["a"];
    }
    node = &node["inner"]["key"];
    for _ in 0..67 {
        node = &node["a"];
    }
    assert_eq!(node.as_str(), Some("1"));

    assert_error(
        load_string_with_include_dir(&outer("nesting-limit-include-over.yaml"), &data()),
        "maximum nesting depth",
    );
}

#[test]
fn test_anchors_and_aliases() {
    // Anchors are ignored.
    let config = load_string("a: &x 1\nb: &y {c: 2}\nl: [&z x]\n&k key: v\n").unwrap();
    assert_eq!(
        flat(&config),
        "a = 1\nb = (null)\nb.c = 2\nl = (null)\nl.0 = x\nkey = v\n"
    );

    // Aliases are not supported.
    for input in [
        "a: &x 1\nb: *x\n",
        "a: &x 1\n*x : 2\n",
        "a: &x 1\nl: [*x]\n",
    ] {
        assert_error(load_string(input), "aliases are not supported");
    }
}

#[test]
fn test_error_location() {
    let err = load_string_with_include_dir("x: 1\ninclude: error-location-inc.yaml\n", &data())
        .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("error-location-inc.yaml"), "{message}");

    let err = load_data("error-location").unwrap_err();
    assert!(err.to_string().ends_with("error-location.yaml:3"), "{err}");
}

#[test]
fn test_print_flat_config() {
    let config =
        load_string("a: 1\nl:\n  - x\n  - {k: v, o: p}\n  - [1, 2]\n  - {}\n  - ~\nm: {}\n")
            .unwrap();
    assert_eq!(
        flat(&config),
        "a = 1
l = (null)
l.0 = x
l.1 = k
l.1.k = v
l.1.o = p
l.2 = (null)
l.2.0 = 1
l.2.1 = 2
l.3 = (null)
l.4 = (null)
m = (null)
"
    );
}

#[test]
fn test_print_yaml() {
    let input = "a: '1'\nb:\n  - x\n  - k: v\nc: ~\n";
    let config = load_string(input).unwrap();
    let printed = suricata_config::print_yaml(&config).unwrap();
    assert!(printed.ends_with("c: ~\n"), "{printed:?}");
    assert_eq!(load_string(&printed).unwrap(), config);
}

// Underscores in plain keys and dotted path components are replaced
// with dashes, except below `address-groups` and `port-groups`. Values
// are used as written.
#[test]
fn test_key_mangling() {
    let config = load_data("key-mangling").unwrap();
    assert_eq!(
        flat(&config),
        "under-score = (null)
under-score.sub-key = 1
under-score.nested-more = (null)
under-score.nested-more.deeper-key = 2
vars = (null)
vars.address-groups = (null)
vars.address-groups.HOME_NET = [192.168.0.0/16]
vars.address-groups.lower_case = x
vars.address-groups.CLI_NET = y
vars.port-groups = (null)
vars.port-groups.HTTP_PORTS = 80
vars.other-group = (null)
vars.other-group.X-Y = 1
not-vars = (null)
not-vars.address-groups = (null)
not-vars.address-groups.SOME_NET = 1
dotted = (null)
dotted.key-with-underscore = 1
also-dotted = (null)
also-dotted.key-two = 2
seq-of-maps = (null)
seq-of-maps.0 = inter-face
seq-of-maps.0.inter-face = eth0
seq-of-maps.0.cluster-id = 99
seq-of-maps.0.cluster-type = cluster_flow
seq-of-maps.1 = interface
seq-of-maps.1.interface = eth1
--double = 3
trailing-underscore- = 4
k-1 = a
"
    );
}

// Dotted keys follow the same mangling rules as nested mappings,
// including the group-name exceptions at each level of the path.
#[test]
fn test_dotted_key_mangling() {
    let dotted = load_string(
        "\
a_b: foo
foo.bar_foo: foobar
foo.bar-foo: replaced
outer_key.inner_key.leaf_key: value_with_underscores
vars.address_groups.HOME_NET: any
vars.port_groups:
  HTTP_PORTS: 80
  OTHER_PORTS.sub_key: 81
x.address_groups:
  GROUP_NAME.child_key: 1
list_items:
  - old_key: value
list_items.0.new_key: new_value
",
    )
    .unwrap();
    let nested = load_string(
        "\
a-b: foo
foo:
  bar-foo: replaced
outer-key:
  inner-key:
    leaf-key: value_with_underscores
vars:
  address-groups:
    HOME_NET: any
  port-groups:
    HTTP_PORTS: 80
    OTHER_PORTS:
      sub-key: 81
x:
  address-groups:
    GROUP_NAME:
      child-key: 1
list-items:
  - old-key: value
    new-key: new_value
",
    )
    .unwrap();
    assert_eq!(dotted, nested);
    let printed = suricata_config::print_yaml(&dotted).unwrap();
    assert_eq!(load_string(&printed).unwrap(), dotted);
}

// A mangled key and the dashed form are the same key, unlike in C where
// the lookup happened before mangling and both nodes were kept.
#[test]
fn test_key_mangling_collision() {
    let config = load_string("foo_bar: one\nfoo_bar: two\nfoo-bar: three\n").unwrap();
    assert_eq!(flat(&config), "foo-bar = three\n");

    // The exemption applies to the mangled name of the parent, and to
    // a mapping set with a dotted key.
    let config = load_string("address_groups:\n  A_B: 1\nx.port-groups:\n  C_D: 2\n").unwrap();
    assert_eq!(
        flat(&config),
        "address-groups = (null)\naddress-groups.A_B = 1\nx = (null)\nx.port-groups = (null)\nx.port-groups.C_D = 2\n"
    );
}
