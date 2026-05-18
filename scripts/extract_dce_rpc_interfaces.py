#!/usr/bin/env python3
"""Extract DCE-RPC interface metadata from the Zeek consts documentation and
emit it as NDJSON, one interface (UUID) per line:

    {"uuid": "<uuid>", "service": "<service>", "opcodes": {"<opnum>": "<procedure>", ...}}

The source documents two kinds of entries, both keyed by interface UUID:

    ["<uuid>"] = "<service>",              # interface -> service name
    ["<uuid>", <opnum>] = "<procedure>",   # (interface, opnum) -> procedure name

They are merged here so each UUID appears once, with its service name and the
full opnum -> procedure map nested under "opcodes". Opcodes use the opnum as a
(string) key so the runtime can deserialize straight into a HashMap<u16, String>
keyed by opnum -- the direction lookups actually query.

The final output is saved in rust/src/dcerpc/dcerpc_interfaces.json
"""
import json
import re
import sys

RST_PATH = "doc/scripts/base/protocols/dce-rpc/consts.zeek.rst"

# ["943991a5-...-656ee34b"] = "IWRMMachineGroup",
SERVICE_RE = re.compile(r'\["([0-9a-fA-F-]+)"\]\s*=\s*"([^"]*)"')
# ["367abb81-...-98f038001003", 16] = "OpenServiceW",
PROCEDURE_RE = re.compile(r'\["([0-9a-fA-F-]+)",\s*(\d+)\]\s*=\s*"([^"]*)"')


def main(path=RST_PATH):
    services = {}   # uuid -> service name
    opcodes = {}    # uuid -> {opnum: procedure name}

    with open(path) as f:
        for line in f:
            # A procedure line also contains a '[uuid",' prefix, so try the
            # more specific (uuid, opnum) pattern first.
            m = PROCEDURE_RE.search(line)
            if m:
                uuid, opnum, procedure = m.groups()
                opcodes.setdefault(uuid.lower(), {})[int(opnum)] = procedure
                continue
            m = SERVICE_RE.search(line)
            if m:
                uuid, service = m.groups()
                services[uuid.lower()] = service

    # Every UUID that has opcodes is expected to also have a service name;
    # fail loudly if the source ever violates that so we never emit a record
    # the runtime cannot deserialize.
    orphans = sorted(set(opcodes) - set(services))
    if orphans:
        sys.exit(f"opcodes without a service name: {', '.join(orphans)}")

    for uuid in sorted(services):
        entry = {"uuid": uuid, "service": services[uuid]}
        ops = opcodes.get(uuid)
        if ops:
            # Stringify and sort by opnum for stable, diff-friendly output.
            entry["opcodes"] = {str(n): ops[n] for n in sorted(ops)}
        sys.stdout.write(json.dumps(entry) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
