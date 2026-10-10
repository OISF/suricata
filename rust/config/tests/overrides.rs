// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

//! Command line overrides (`--set`), applied with `apply_overrides`.
//!
//! One test per `--set` test of the behaviour corpus (`tests/` next to
//! the Suricata work trees, see `DESIGN.md`), with the same input and
//! the same `--set` arguments. The expected output is the corpus
//! `expected.txt` except where `DESIGN.md` lists a deliberate difference
//! under "Breaking changes from 8.0", which each test notes. In short:
//!
//! - Overrides are applied after the load, so a key that exists in the
//!   file keeps its position and a new key is appended. The C loader
//!   created the `--set` nodes before loading, so they were dumped
//!   first.
//! - Only the overridden path wins. The C loader also made every node
//!   created for it final, so a later redefinition of a parent was
//!   merged instead of replacing it.
//! - A node can't have both a value and children: an override replaces
//!   whatever was at its path.
//! - No key mangling, no 1024 byte name limit, and a path with an empty
//!   component is an error.
//!
//! The corpus tests against the frozen full `suricata.yaml`
//! (`sv-set-sequence-index-full-yaml`,
//! `yaml-full-suricata-yaml-with-overrides`) are not repeated here; they
//! run with `run-corpus.py`.

use std::path::Path;
use std::path::PathBuf;

use suricata_config::apply_overrides;
use suricata_config::load_file;
use suricata_config::load_string;
use suricata_config::merge_file;
use suricata_config::parse_set;
use suricata_config::print_flat_config;
use suricata_config::Node;
use suricata_config::Override;
use suricata_config::OverrideError;

// The configuration files in tests/data.
fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn overrides(args: &[&str]) -> Vec<Override> {
    args.iter().map(|arg| parse_set(arg).unwrap()).collect()
}

// Load a configuration, apply the `--set` arguments and dump it.
fn apply(yaml: &str, args: &[&str]) -> String {
    let mut config = load_string(yaml).unwrap();
    apply_overrides(&mut config, &overrides(args)).unwrap();
    print_flat_config(&config)
}

// Load tests/data/NAME.yaml with `--include` files from tests/data,
// apply the `--set` arguments and dump it.
fn apply_with_includes(name: &str, includes: &[&str], args: &[&str]) -> String {
    let dir = data();
    let mut config = load_file(&dir.join(format!("{name}.yaml"))).unwrap();
    for include in includes {
        merge_file(&mut config, Path::new(include), &dir).unwrap();
    }
    apply_overrides(&mut config, &overrides(args)).unwrap();
    print_flat_config(&config)
}

// ut-conf-set: setting `one.two` and then `one.three` creates both
// under `one`.
//
// Differs from C: `one` is appended, `unrelated` from the file comes
// first.
#[test]
fn test_ut_conf_set() {
    assert_eq!(
        apply("unrelated: 1\n", &["one.two=three", "one.three=four"]),
        "\
unrelated = 1
one = (null)
one.two = three
one.three = four
"
    );
}

// ut-conf-set-from-string: whitespace around the '=' is stripped, and
// the last `--set` of a key wins.
#[test]
fn test_ut_conf_set_from_string() {
    assert_eq!(
        apply(
            "stream:\n  midstream: false\n",
            &[
                "stream.midstream=true",
                "stream.a =false",
                "stream.b= true",
                "stream.c = false",
                "stream.d=true",
                "stream.d =false",
            ]
        ),
        "\
stream = (null)
stream.midstream = true
stream.a = false
stream.b = true
stream.c = false
stream.d = false
"
    );
}

// ut-conf-yaml-override-final: a value set on the command line is not
// overridden by the configuration file.
#[test]
fn test_ut_conf_yaml_override_final() {
    assert_eq!(
        apply("default-log-dir: /var/log\n", &["default-log-dir=/tmp"]),
        "default-log-dir = /tmp\n"
    );
}

// ut-conf-node-prune: a mapping with an overridden child is redefined
// in the file.
//
// Differs from C: the redefinition of `node` replaces the earlier
// definition, including the dotted keys below `node.final`, like it
// does without `--set`; the override is then applied to the result. C
// made `node` final with the `--set`, so the redefinition was merged
// and everything survived.
#[test]
fn test_ut_conf_node_prune() {
    assert_eq!(
        apply(
            "\
node:
  notfinal: notfinal
node.final.one: one
node.final.two: two
node:
  after: 1
",
            &["node.final=final"]
        ),
        "\
node = (null)
node.after = 1
node.final = final
"
    );
}

// yaml-set-override: values from the command line win over the file,
// missing keys are created, a later `--set` of the same key wins, the
// value may contain '=' and be empty, and only trailing whitespace of
// the key and leading whitespace of the value are trimmed.
//
// Differs from C: `foo.a` keeps its position in `foo`, and `bar.new`,
// `zzz` and the other new keys are appended in `--set` order.
#[test]
fn test_yaml_set_override() {
    assert_eq!(
        apply(
            "\
foo:
  a: from-file
  b: from-file
bar:
  b: from-file
null-in-file: ~
",
            &[
                "zzz.z=1",
                "bar.new=1",
                "foo.a=from-set",
                "twice=first",
                "twice=second",
                "eq=a=b",
                "spaces=a b c",
                "ws =  padded  ",
                "empty=",
                "null-in-file=set",
                "top=value",
            ]
        ),
        "\
foo = (null)
foo.a = from-set
foo.b = from-file
bar = (null)
bar.b = from-file
bar.new = 1
null-in-file = set
zzz = (null)
zzz.z = 1
twice = second
eq = a=b
spaces = a b c
ws = padded  
empty = 
top = value
"
    );
}

// yaml-set-leading-key-space: leading whitespace of the key and
// trailing whitespace of the value are kept, so ` a` is a key of its
// own.
//
// Differs from C: ` a` is appended after the file's `a`.
#[test]
fn test_yaml_set_leading_key_space() {
    assert_eq!(
        apply("a: file\n", &[" a = value "]),
        "\
a = file
 a = value 
"
    );
}

// yaml-set-mapping-node: overrides on nodes that are mappings or
// scalars in the file.
//
// Differs from C, where a node could have both a value and children:
// `map=scalar` replaces the mapping, and `set-as-scalar=final` replaces
// the mapping from the file, so `map.x`, `map.y` and
// `set-as-scalar.child` are gone. `scalar.child=1` replaces the scalar
// with a mapping, which dumps the same as C. The redefinition of
// `redefined` replaces the first definition (C merged it, as the `--set`
// had made `redefined` final), and `redefined.a` is appended to it.
#[test]
fn test_yaml_set_mapping_node() {
    assert_eq!(
        apply(
            "\
map:
  x: 1
  y: 2
scalar: value
set-as-scalar:
  child: 1
redefined:
  a: 1
redefined:
  b: 2
",
            &[
                "map=scalar",
                "scalar.child=1",
                "set-as-scalar=final",
                "redefined.a=final",
            ]
        ),
        "\
map = scalar
scalar = (null)
scalar.child = 1
set-as-scalar = final
redefined = (null)
redefined.b = 2
redefined.a = final
"
    );
}

// yaml-set-sequence: overrides on sequence items. An index that exists
// is replaced, or for a mapping item the key is set in it; the length
// of the sequence appends an item, so `af-packet.2.interface` appends a
// mapping item and `new-list.1` appends to the one item list.
//
// Differs from C: the items stay in index order (C moved overridden
// items to the end), the keys set in a mapping item stay in the item's
// order with new keys appended, and the appended `af-packet.2` is a
// mapping with its first key as its value rather than a node without a
// value. The `--set list.5=q` of the corpus test is an error, see
// `test_yaml_set_sequence_index_past_end`.
#[test]
fn test_yaml_set_sequence() {
    assert_eq!(
        apply(
            "\
list:
  - a
  - b
  - c
af-packet:
  - interface: eth0
    threads: 1
  - interface: eth1
    threads: 2
new-list:
  - x
",
            &[
                "list.0=z",
                "list.1=y",
                "af-packet.0.interface=eth9",
                "af-packet.0.extra=1",
                "af-packet.1.threads=8",
                "af-packet.2.interface=eth2",
                "new-list.1=added",
            ]
        ),
        "\
list = (null)
list.0 = z
list.1 = y
list.2 = c
af-packet = (null)
af-packet.0 = interface
af-packet.0.interface = eth9
af-packet.0.threads = 1
af-packet.0.extra = 1
af-packet.1 = interface
af-packet.1.interface = eth1
af-packet.1.threads = 8
af-packet.2 = interface
af-packet.2.interface = eth2
new-list = (null)
new-list.0 = x
new-list.1 = added
"
    );

    // A number in the path of a missing parent is a mapping key, like
    // in C.
    assert_eq!(
        apply("other: 1\n", &["new-list.1=added"]),
        "\
other = 1
new-list = (null)
new-list.1 = added
"
    );
}

// yaml-set-sequence, `--set list.5=q` on a list of 3 items.
//
// Differs from C, which appended an item named `5`: an index past the
// end of a sequence is an error, and the configuration is left as it
// was, without the overrides before it.
#[test]
fn test_yaml_set_sequence_index_past_end() {
    let mut config = load_string("list: [a, b, c]\n").unwrap();
    let before = config.clone();
    let err = apply_overrides(&mut config, &overrides(&["list.0=z", "list.5=q"])).unwrap_err();
    assert_eq!(
        err.to_string(),
        "cannot apply --set list.5: \"5\" is not a valid index for a sequence of length 3"
    );
    assert_eq!(config, before);
}

// yaml-set-quirk-dots: a path with an empty component is an error.
//
// Differs from C, which created nodes with empty names.
#[test]
fn test_yaml_set_quirk_dots() {
    for arg in ["foo..x=1", "foo.y.=2", ".z=3"] {
        let err = parse_set(arg).unwrap_err();
        assert!(matches!(err, OverrideError::InvalidPath(_)), "{arg}: {err}");
        assert!(
            err.to_string().starts_with("invalid argument for --set"),
            "{arg}: {err}"
        );
    }
}

// yaml-set-quirk-intermediate-final: an override below a mapping that
// is redefined later in the file.
//
// Differs from C: the redefinition of `outputs` replaces the first one,
// like `plain`, and the override is applied to the result: `outputs`
// has one item, so `outputs.1.eve-log.enabled=no` appends an item. C
// made `outputs` final with the `--set`, so the redefinition was merged
// into the first definition, keeping `outputs.0 = fast` with `syslog`
// added to the item.
#[test]
fn test_yaml_set_quirk_intermediate_final() {
    assert_eq!(
        apply(
            "\
outputs:
  - fast:
      enabled: yes
      filename: fast.log
  - eve-log:
      enabled: yes
outputs:
  - syslog:
      enabled: yes
plain:
  a: 1
plain:
  b: 2
",
            &["outputs.1.eve-log.enabled=no"]
        ),
        "\
outputs = (null)
outputs.0 = syslog
outputs.0.syslog = (null)
outputs.0.syslog.enabled = yes
outputs.1 = eve-log
outputs.1.eve-log = (null)
outputs.1.eve-log.enabled = no
plain = (null)
plain.b = 2
"
    );
}

// yaml-set-error-no-equals: a `--set` argument without '=' is an error,
// reported like C's "invalid argument for --set".
#[test]
fn test_yaml_set_error_no_equals() {
    let err = parse_set("foo").unwrap_err();
    assert_eq!(err, OverrideError::MissingEquals("foo".into()));
    assert!(err.to_string().starts_with("invalid argument for --set"));
}

// yaml-set-name-length-exceeded: a name of 1024 bytes.
//
// Differs from C, which failed with "Configuration name too long": there
// is no limit on the length of a name.
#[test]
fn test_yaml_set_name_length_exceeded() {
    let name = "b".repeat(1024);
    assert_eq!(
        apply("foo: 1\n", &[&format!("a.{name}=ok")]),
        format!("foo = 1\na = (null)\na.{name} = ok\n")
    );
}

// yaml-cli-include: files given with `--include` are merged into the
// configuration in order and override the main file, but not the
// command line.
//
// Differs from C: `final` keeps its position in the main file rather
// than being dumped first.
#[test]
fn test_yaml_cli_include() {
    assert_eq!(
        apply_with_includes(
            "cli-include",
            &["cli-include-a.yaml", "cli-include-b.yaml"],
            &["final=from-set"]
        ),
        "\
from-main = 1
shared = from-b
mapping = (null)
mapping.c = 3
mapping.d = 4
final = from-set
from-a = 1
from-b = 1
"
    );
}

// yaml-include-mixed-precedence: all override mechanisms together. The
// main file, an `include` key, an `include` list, an `!include` tag,
// keys after the includes, then the `--include` files in order, and the
// command line last.
//
// Differs from C: `set-winner` and `section.e` are appended rather than
// dumped first, and `section.a` is gone: `inc-list-2.yaml` redefines
// `section` which replaces it (C merged it, as the `--set section.e` had
// made `section` final).
#[test]
fn test_yaml_include_mixed_precedence() {
    assert_eq!(
        apply_with_includes(
            "mixed-precedence",
            &["mixed-precedence-cli-1.yaml", "mixed-precedence-cli-2.yaml"],
            &["set-winner=set", "section.e=set"]
        ),
        "\
winner = cli-2
from-main = 1
section = (null)
section.c = inc-list-2
section.b = main-dotted
section.d = cli-1
section.e = set
from-inc-key = 1
from-inc-list-1 = 1
from-inc-list-2 = 1
tagged = (null)
tagged.winner = inc-tag
after-includes = 1
from-cli-1 = 1
from-cli-2 = 1
set-winner = set
"
    );
}

// yaml-include-redefines-mapping: a mapping redefined in an included
// file, with an override below it.
//
// Differs from C: `mapping` is replaced by the included file like
// `outputs` is, and `mapping.a` is then applied to the result. C made
// `mapping` final with the `--set`, so the redefinition was merged and
// `mapping.b` survived.
#[test]
fn test_yaml_include_redefines_mapping() {
    assert_eq!(
        apply_with_includes("redefines-mapping", &[], &["mapping.a=final"]),
        "\
outputs = (null)
outputs.0 = fast
outputs.0.fast = (null)
outputs.0.fast.enabled = yes
mapping = (null)
mapping.c = 3
mapping.a = final
"
    );
}

// yaml-key-mangling, the `--set` part: keys given with `--set` are used
// as written, like in C, independently of YAML key mangling.
#[test]
fn test_yaml_key_mangling() {
    assert_eq!(
        apply(
            "\
vars:
  address-groups:
    HOME_NET: \"[192.168.0.0/16]\"
",
            &[
                "cli.set_key=1",
                "vars.address-groups.CLI_NET=x",
                "cli_top.sub_key=y",
            ]
        ),
        "\
vars = (null)
vars.address-groups = (null)
vars.address-groups.HOME_NET = [192.168.0.0/16]
vars.address-groups.CLI_NET = x
cli = (null)
cli.set_key = 1
cli_top = (null)
cli_top.sub_key = y
"
    );
}

// sv-multi-tenant-config: the multi-tenant configuration shape with the
// `--set multi-detect.N.default-rule-path` overrides that create numeric
// keys next to the mappings. Shortened to two tenants and mappings.
//
// Differs from C: the keys set are appended to `multi-detect`.
#[test]
fn test_sv_multi_tenant_config() {
    assert_eq!(
        apply(
            "\
multi-detect:
  enabled: yes
  selector: vlan
  loaders: 4

  tenants:
  - tenant:
    id: 1
    yaml: a.yaml
  - tenant:
    id: 2
    yaml: b.yaml

  mappings:
  - vlan:
    vlan-id: 1000
    tenant-id: 1
  - vlan:
    vlan-id: 2000
    tenant-id: 2

engine-analysis:
  rules-fast-pattern: yes
  rules: yes
",
            &[
                "multi-detect.config-path=/etc/suricata/tenants",
                "multi-detect.1.default-rule-path=/etc/suricata/rules1",
                "multi-detect.2.default-rule-path=/etc/suricata/rules2",
            ]
        ),
        "\
multi-detect = (null)
multi-detect.enabled = yes
multi-detect.selector = vlan
multi-detect.loaders = 4
multi-detect.tenants = (null)
multi-detect.tenants.0 = tenant
multi-detect.tenants.0.tenant = (null)
multi-detect.tenants.0.id = 1
multi-detect.tenants.0.yaml = a.yaml
multi-detect.tenants.1 = tenant
multi-detect.tenants.1.tenant = (null)
multi-detect.tenants.1.id = 2
multi-detect.tenants.1.yaml = b.yaml
multi-detect.mappings = (null)
multi-detect.mappings.0 = vlan
multi-detect.mappings.0.vlan = (null)
multi-detect.mappings.0.vlan-id = 1000
multi-detect.mappings.0.tenant-id = 1
multi-detect.mappings.1 = vlan
multi-detect.mappings.1.vlan = (null)
multi-detect.mappings.1.vlan-id = 2000
multi-detect.mappings.1.tenant-id = 2
multi-detect.config-path = /etc/suricata/tenants
multi-detect.1 = (null)
multi-detect.1.default-rule-path = /etc/suricata/rules1
multi-detect.2 = (null)
multi-detect.2.default-rule-path = /etc/suricata/rules2
engine-analysis = (null)
engine-analysis.rules-fast-pattern = yes
engine-analysis.rules = yes
"
    );
}

// The overrides are applied to the configuration as loaded, so an index
// refers to the sequence after includes and dotted keys.
#[test]
fn test_index_refers_to_resolved_sequence() {
    assert_eq!(
        apply(
            "\
list:
  - a
list.1: b
",
            &["list.2=c"]
        ),
        "\
list = (null)
list.0 = a
list.1 = b
list.2 = c
"
    );
}

// Applying no overrides, or applying to a null (empty) configuration.
#[test]
fn test_apply_nothing_and_to_empty() {
    let mut config = load_string("a: 1\n").unwrap();
    apply_overrides(&mut config, &[]).unwrap();
    assert_eq!(print_flat_config(&config), "a = 1\n");

    let mut config = load_string("").unwrap();
    assert!(matches!(config, Node::Mapping(_)));
    apply_overrides(&mut config, &overrides(&["a.b=1"])).unwrap();
    assert_eq!(print_flat_config(&config), "a = (null)\na.b = 1\n");
}
