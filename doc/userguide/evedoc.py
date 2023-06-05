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


def get_type(props: dict, name: str) -> str:
    prop_type = props["type"]
    if prop_type == "array":
        try:
            array_type = props["items"]["type"]
        except KeyError:
            print("Array property without items: {}".format(name), file=sys.stderr)
            array_type = "unknown"
        prop_type = "array of {}s".format(array_type)
    return prop_type
            
def render(schema: dict):
    stack = [(schema, [], "object")]

    while stack:
        (current, path, type) = stack.pop(0)

        items = []
        
        for name, props in current["properties"].items():
            if "$ref" in props:
                ref = find_ref(schema, props["$ref"])
                if not ref:
                    raise Exception("Reference not found: {}".format(props["$ref"]))
                props = ref
            prop_type = get_type(props, name)
            description = props.get("description", "")

            items.append({"name": name, "type": prop_type, "description": description})

            if props["type"] == "object" and "properties" in props:
                stack.insert(0, (props, path + [name], "object"))
            elif props["type"] == "array" and "items" in props and "properties" in props["items"]:
                array_type = props["items"]["type"]
                stack.insert(0, (props["items"], path + ["{}".format(name)], "array of {}s".format(array_type)))

        render_table(items, path, type)
        

def render_table(items: list, path: list, type: str):
    if not path:
        title = "Top Level"
    else:
        title = ".".join(path)
    title = "{} ({})".format(title, type)
    print(title)
    print("^" * len(title))

    name_len = max([len(item["name"]) for item in items] + [len("Name")])
    desc_len = max([len(item["description"]) for item in items] + [len("Description")])
    type_len = max([len(item["type"]) for item in items])

    print(".. table::")
    print("   :width: 100%")
    print("   :widths: 30 25 45")
    print("")

    print("   {} {} {}".format("=" * name_len, "=" * type_len, "=" * desc_len))
    print("   {} {} {}".format("Name".ljust(name_len), "Type".ljust(type_len), "Description".ljust(desc_len)))
    print("   {} {} {}".format("=" * name_len, "=" * type_len, "=" * desc_len))
    for item in items:
        print("   {} {} {}".format(
            item["name"].ljust(name_len),
            item["type"].ljust(type_len),
            item["description"].ljust(desc_len)
        ))
    print("   {} {} {}".format("=" * name_len, "=" * type_len, "=" * desc_len))
    print("")

def main():
    parser = argparse.ArgumentParser(description="Generate documentation from JSON schema")
    parser.add_argument("--object", help="Object name")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("filename", help="JSON schema file")
    args = parser.parse_args()

    root = json.load(open(args.filename))
    schema = root

    if args.object:
        schema = schema["properties"][args.object]

    if args.output:
        sys.stdout = open(args.output, "w")

    render(schema)


if __name__ == "__main__":
    sys.exit(main())
