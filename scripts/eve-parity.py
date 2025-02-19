#! /usr/bin/env python3
#
# Tool for checking parity between the EVE schema and Suricata
# keywords.
#
# Usage: ./scripts/eve-parity.py [missing|having]
#
# ## missing
#
# Display all eve fields that do not have a keyword mapping.
#
# ## having
#
# The "having" command will display all EVE fields that have an
# associated keyword with mapping to the keywords for that EVE field.


import sys
import subprocess
import json
import argparse


def main():
    parser = argparse.ArgumentParser(description="EVE Parity Check Tool")
    parser.add_argument("command", choices=["missing", "having"])
    args = parser.parse_args()

    keywords = load_known_keywords()
    keys = load_schema()

    if args.command == "having":
        having(keywords, keys)
    elif args.command == "missing":
        missing(keywords, keys)


def having(keywords, keys):
    for key in keys.keys():
        if "keywords" in keys[key]:
            for keyword in keys[key]["keywords"]:
                if keyword not in keywords:
                    errprint("ERROR: Unknown keyword: {}".format(keyword))
            print("{} -> [{}]".format(key, ", ".join(keys[key]["keywords"])))


def missing(keywords, keys):
    with_missing = set()

    for key in keys.keys():
        if "keywords" not in keys[key]:
            with_missing.add(key)

    # Print sorted.
    for key in sorted(with_missing):
        print(key)


def load_schema():
    schema = json.load(open("etc/schema.json"))
    stack = [(schema, [])]
    keys = {}

    while stack:
        (current, path) = stack.pop(0)

        for name, props in current["properties"].items():
            if "$ref" in props:
                ref = find_ref(schema, props["$ref"])
                if not ref:
                    raise Exception("$ref not found: {}".format(props["$ref"]))
                props = ref
            if props["type"] in ["string", "integer", "boolean", "number"]:
                # End of the line...
                key = ".".join(path + [name])
                keys[key] = props.get("suricata", {})
            elif props["type"] == "object":
                if "properties" in props:
                    stack.insert(0, (props, path + [name]))
                else:
                    # May want to warn that this object has no properties.
                    key = ".".join(path + [name])
                    keys[key] = {}
            elif props["type"] == "array":
                if "items" in props and "type" in props["items"]:
                    if "properties" in props["items"]:
                        stack.insert(
                            0,
                            (
                                props["items"],
                                path + ["{}".format(name)],
                            ),
                        )
                    else:
                        # May want to warn that this array has no properties.
                        key = ".".join(path + [name])
                        keys[key] = {}
                else:
                    # May want to warn that this array has no items.
                    key = ".".join(path + [name])
                    keys[key] = {}
            else:
                raise Exception("Unsupported type: {}".format(props["type"]))

    return keys


def load_known_keywords():
    keywords = set()
    result = subprocess.check_output(["./src/suricata", "--list-keywords"])
    for line in result.decode().split("\n"):
        if line.startswith("-"):
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                keywords.add(parts[1])
    return keywords


def errprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def find_ref(schema: dict, ref: str) -> dict:
    parts = ref.split("/")

    root = parts.pop(0)
    if root != "#":
        raise Exception("Unsupported reference: {}".format(ref))

    while parts:
        schema = schema[parts.pop(0)]

    return schema


if __name__ == "__main__":
    sys.exit(main())
