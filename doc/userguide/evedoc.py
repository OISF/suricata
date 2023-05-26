#! /usr/bin/env python
#
# Generate Sphinx documentation from JSON schema

import argparse
import sys
import json
import re


def find_ref(schema: dict, ref: str) -> dict:
    parts = ref.split("/")

    root = parts.pop(0)
    if root != "#":
        raise Exception("Unsupported reference: {}".format(ref))

    while parts:
        schema = schema[parts.pop(0)]

    return schema


def flatten_schema(schema):
    items = []
    stack = [(schema, [])]

    while stack:
        (current, path) = stack.pop()
        
        for name, props in current["properties"].items():
            if "$ref" in props:
                ref = find_ref(schema, props["$ref"])
                if not ref:
                    raise Exception("Reference not found: {}".format(props["$ref"]))
                props = ref

            description = props.get("description", "")

            prop_type = props["type"]
            if prop_type == "array":
                try:
                    array_type = props["items"]["type"]
                except KeyError:
                    print("Array property without items: {}".format(name), file=sys.stderr)
                    array_type = "unknown"
                prop_type = "{}[]".format(array_type)

            items.append({
                "name": ".".join(path + [name]),
                "description": description,
                "type": prop_type,
            })

            if props["type"] == "object" and "properties" in props:
                stack.append((props, path + [name]))
            elif props["type"] == "array" and "items" in props and "properties" in props["items"]:
                stack.append((props["items"], path + ["{}[]".format(name)]))


    items.sort(key=lambda item: item["name"])
    return items

def main():
    parser = argparse.ArgumentParser(description="Generate documentation from JSON schema")
    parser.add_argument("--object", help="Object name")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("filename", help="JSON schema file")
    args = parser.parse_args()

    schema = json.load(open(args.filename))

    if args.object:
        schema = schema["properties"][args.object]

    flat = flatten_schema(schema)
    name_len = max([len(item["name"]) for item in flat])
    desc_len = max([len(item["description"]) for item in flat] + [len("Description")])
    type_len = max([len(item["type"]) for item in flat])

    if args.output:
        sys.stdout = open(args.output, "w")

    print(".. table:: Fields")
    print("   :width: 100%")
    print("")
    print("   {} {} {}".format("=" * name_len, "=" * type_len, "=" * desc_len))
    print("   {} {} {}".format("Name".ljust(name_len), "Type".ljust(type_len), "Description".ljust(desc_len)))
    print("   {} {} {}".format("=" * name_len, "=" * type_len, "=" * desc_len))
    for item in flat:
        print("   {} {} {}".format(
            item["name"].ljust(name_len),
            item["type"].ljust(type_len),
            item["description"].ljust(desc_len)
        ))
    print("   {} {} {}".format("=" * name_len, "=" * type_len, "=" * desc_len))


if __name__ == "__main__":
    sys.exit(main())
