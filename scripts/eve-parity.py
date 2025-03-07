#! /usr/bin/env python3
#
# Tool for checking parity between the EVE schema and Suricata
# keywords.
#
# Usage: ./scripts/eve-parity.py [missing|having]
#
# ## unmapped-keywords
#
# Display all known keywords that are not mapped to an EVE field.
#
# ## unmapped-fields
#
# Display all eve fields that do not have a keyword mapping.
#
# ## mapped-fields
#
# Display all EVE fields that have a keyword mapping.


import sys
import subprocess
import json
import argparse


def main():
    parser = argparse.ArgumentParser(description="EVE Parity Check Tool")
    parser.add_argument(
        "command", choices=["mapped-fields", "unmapped-keywords", "unmapped-fields"]
    )
    args = parser.parse_args()

    keywords = load_known_keywords()
    keys = load_schema()

    if args.command == "mapped-fields":
        mapped_fields(keywords, keys)
    elif args.command == "unmapped-keywords":
        unmapped_keywords(keywords, keys)
    elif args.command == "unmapped-fields":
        unmapped_fields(keywords, keys)


def unmapped_keywords(keywords, keys):
    """Report known keywords that are not mapped to an EVE field."""
    schema_keywords = set()
    for key in keys.keys():
        if "keywords" in keys[key] and keys[key]["keywords"]:
            for keyword in keys[key]["keywords"]:
                schema_keywords.add(keyword)
    unmapped = keywords - schema_keywords
    for keyword in sorted(unmapped):
        print(keyword)


def unmapped_fields(keywords, keys):
    with_missing = set()

    for key in keys.keys():
        if "keywords" not in keys[key]:
            with_missing.add(key)

    # Print sorted.
    for key in sorted(with_missing):
        print(key)


def mapped_fields(keywords, keys):
    for key in keys.keys():
        if "keywords" in keys[key] and keys[key]["keywords"]:
            for keyword in keys[key]["keywords"]:
                if keyword not in keywords:
                    errprint("ERROR: Unknown keyword: {}".format(keyword))
            print("{} -> [{}]".format(key, ", ".join(keys[key]["keywords"])))


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
                props = props | ref
            if props["type"] in ["string", "integer", "boolean", "number"]:
                # End of the line...
                key = ".".join(path + [name])
                keys[key] = props.get("suricata", {})
            elif props["type"] == "object":
                #  An object can set "suricata.keywords" to false to
                #  disable descending into it. For examples, "stats".
                keywords = props.get("suricata", {}).get("keywords")
                if keywords is False:
                    # print("Skipping object {}, keywords disabled".format(".".join(path + [name])))
                    continue

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
                        key = ".".join(path + [name])
                        keys[key] = props.get("suricata", {})
                else:
                    # May want to warn that this array has no items.
                    key = ".".join(path + [name])
                    keys[key] = {}
            else:
                raise Exception("Unsupported type: {}".format(props["type"]))

    return keys


def load_known_keywords():
    keywords = set()
    result = subprocess.check_output(["./src/suricata", "--list-keywords=csv"])
    lines = result.decode().split("\n")
    # Skip first line, as its a header line.
    for line in lines[1:]:
        parts = line.split(";")
        if parts:
            # Skip transforms.
            if len(parts) > 3 and parts[3].find("transform") > -1:
                continue

            keywords.add(parts[0])
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
