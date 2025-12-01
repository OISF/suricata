# Content Inspection Bench tool

## Building In Tree

The Suricata build system has created a Makefile that should allow you
to build this application in-tree on most supported platforms. To
build simply run:

```
make
```

## Running the tests

```
./bench_content_inspect <file prefix>
```

The `file prefix` is used to generate file names for the CSV files that written.

## Tests

Currently 2 sets of rules are evaluated against a set of buffers.

### common

Common is a ruleset with common signature patterns. The idea is to test common constructs
like startswith, endswith, pcre, etc.

### edge

Edge (cases) is meant to find worst case performance combinations of rules and buffers.

## Extending

Rules and buffers are easy to extend. Just add them to the existing arrays.

For rules make sure to use the `msg` field, as this is used for the CSV name in the header.
Each rule should have a unique sid, as it is part of the CSV header as well.
