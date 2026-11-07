# Suricata Threat Model

Suricata is a network IDS/IPS and threat detection engine. It monitors, or sits
inline with, untrusted networks and parses all traffic it sees. Reporting policy
and severity levels are in `SECURITY.md`.

## Attacker

Anyone who can send traffic across a monitored network. Everything is
pre-auth: Suricata authenticates nothing, and the attacker may control both
endpoints, so any protocol state (after login, handshake, etc.) is reachable.
Traffic need not be valid or accepted by an endpoint to reach the parsers, but
an evasion must use traffic that a real endpoint accepts.

## Untrusted

All packet data, live or from PCAP files, and everything derived from it:
defragmented and reassembled data, tunnels, app-layer data, decoded or
decompressed content and extracted files.

## Trusted

- The operator: configuration, command line, environment, plugins, Lua output
  scripts, unix socket clients and data files named in the configuration.
- The capture layer (kernel, NIC, drivers, libpcap, DPDK, etc.), but not the
  packet data it delivers.
- Rules, except where sandboxed. A rule can already disable or degrade
  detection, so bugs triggered only by a rule are ordinary bugs. Escaping the
  Lua rule sandbox (`security.lua`) or dataset file restrictions
  (`datasets.rules`) is in scope, as is traffic that triggers a bug in a rule
  keyword.

## Focus

Most important, all reachable from traffic (the packet path).

Less important: rule parsing, the unix socket, command line utilities.

## In Scope

Untrusted input must not cause:

- Memory corruption or code execution.
- A crash, hang, or unbounded or amplified memory, CPU or log growth.
- Evasion: Suricata interpreting supported protocol data differently from
  real endpoints, hiding it from rules or logs. Inline, this bypasses
  blocking.
- Malformed or forged log output, memory disclosure, or writes to
  attacker-chosen paths.

## Out of Scope

- Inspection stopping at a configured limit (depth, memcap, etc)
- Unsupported protocols or protocol features
- Leaks at exit or on startup failure; UBSan reports with no concrete failure.
- Library API misuse; third-party code not reachable from traffic.
- Tests, fuzz targets, `qa/`, `scripts/`, `examples/`, `doc/`.

## Severity

Use the levels in `SECURITY.md` (MODERATE is medium). Weigh traffic
reachability, whether the feature is enabled by default (`suricata.yaml.in`),
its support tier (`doc/userguide/support-status.rst`), and impact in both IDS
and IPS deployments.

## Exercising and Reporting

- Reproduce with a PCAP, e.g.
  `suricata -c suricata.yaml -k none -r poc.pcap -S poc.rules -l out/`.
  Enable non-default features with `--set`. Unit tests (`--enable-unittests`)
  and fuzz targets (`src/tests/fuzz/`) also exist.
- Confirm memory errors with ASan and impact with a release build.
- Include the PCAP (and generating script), rules, config changes, command,
  sanitizer output and commit. A suricata-verify test
  (https://github.com/OISF/suricata-verify) is ideal.
- State IDS/IPS impact and whether the latest stable release is affected.
- One report per root cause. Patches: minimal, against `main`, no
  reformatting.
