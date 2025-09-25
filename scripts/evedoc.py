#! /usr/bin/env python3
#
# Generate Sphinx documentation from JSON schema

import argparse
import sys
import json


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


def get_type(props: dict, name: str) -> str:
    prop_type = props["type"]
    if isinstance(prop_type, list):
        prop_type = " or ".join(prop_type)
    elif prop_type == "array":
        try:
            array_type = props["items"]["type"]
            if isinstance(array_type, list):
                array_type = " or ".join(array_type)
        except KeyError:
            errprint("warning: array property without items: {}".format(name))
            array_type = "unknown"
        prop_type = "array of {}s".format(array_type)
    return prop_type


def render_flat(schema: dict):
    stack = [(schema, [])]

    while stack:
        (current, path) = stack.pop(0)

        for name, props in current["properties"].items():
            if "$ref" in props:
                ref = find_ref(schema, props["$ref"])
                if not ref:
                    raise Exception("$ref not found: {}".format(props["$ref"]))
                props = ref
            if isinstance(props["type"], list):
                print("{}: {}".format(".".join(path + [name]), " or ".join(props["type"])))
            elif props["type"] in ["string", "integer", "boolean", "number"]:
                # End of the line...
                print("{}: {}".format(".".join(path + [name]), props["type"]))
            elif props["type"] == "object":
                print("{}: object".format(".".join(path + [name])))
                if "properties" in props:
                    stack.insert(0, (props, path + [name]))
                else:
                    errprint(
                        "warning: object without properties: {}".format(
                            ".".join(path + [name])
                        )
                    )
            elif props["type"] == "array":
                if "items" in props and "type" in props["items"]:
                    item_type = props["items"]["type"]
                    if isinstance(item_type, list):
                        item_type = " or ".join(item_type)
                    print(
                        "{}: {}[]".format(
                            ".".join(path + [name]), item_type
                        )
                    )
                    if "properties" in props["items"]:
                        stack.insert(
                            0,
                            (
                                props["items"],
                                path + ["{}[]".format(name)],
                            ),
                        )
                else:
                    errprint(
                        "warning: undocumented array: {}".format(
                            ".".join(path + [name])
                        )
                    )
                    print("{}: array".format(".".join(path + [name])))
            else:
                raise Exception("Unsupported type: {}".format(props["type"]))


def render_rst(schema: dict):
    stack = [(schema, [], "object")]

    while stack:
        (current, path, type) = stack.pop(0)

        items = []

        for name, props in current["properties"].items():
            if "$ref" in props:
                ref = find_ref(schema, props["$ref"])
                if not ref:
                    raise Exception(
                        "Reference not found: {}".format(props["$ref"])
                    )
                props = ref
            prop_type = get_type(props, name)
            description = props.get("description", "")

            items.append(
                {"name": name, "type": prop_type, "description": description}
            )

            if not isinstance(props["type"], list) and props["type"] == "object" and "properties" in props:
                stack.insert(0, (props, path + [name], "object"))
            elif (
                not isinstance(props["type"], list)
                and props["type"] == "array"
                and "items" in props
                and "properties" in props["items"]
            ):
                array_type = props["items"]["type"]
                if isinstance(array_type, list):
                    array_type = " or ".join(array_type)
                stack.insert(
                    0,
                    (
                        props["items"],
                        path + ["{}".format(name)],
                        "array of {}s".format(array_type),
                    ),
                )

        render_rst_table(items, path, type)


def render_rst_table(items: list, path: list, type: str):
    if not path:
        title = "Top Level"
    else:
        title = ".".join(path)
    title = "{} ({})".format(title, type)
    print(title)
    print("^" * len(title))

    name_len = max([len(item["name"]) for item in items] + [len("Name")])
    desc_len = max(
        [len(item["description"]) for item in items] + [len("Description")]
    )
    type_len = max([len(item["type"]) for item in items])

    print(".. table::")
    print("   :width: 100%")
    print("   :widths: 30 25 45")
    print("")

    print("   {} {} {}".format("=" * name_len, "=" * type_len, "=" * desc_len))
    print(
        "   {} {} {}".format(
            "Name".ljust(name_len),
            "Type".ljust(type_len),
            "Description".ljust(desc_len),
        )
    )
    print("   {} {} {}".format("=" * name_len, "=" * type_len, "=" * desc_len))
    for item in items:
        print(
            "   {} {} {}".format(
                item["name"].ljust(name_len),
                item["type"].ljust(type_len),
                item["description"].ljust(desc_len),
            )
        )
    print("   {} {} {}".format("=" * name_len, "=" * type_len, "=" * desc_len))
    print("")


epilog = """

By default, the EVE schema is rendered as Sphinx documentation. To
create "flat" or "dot" separated output, use the --flat option.

"""


def main():
    parser = argparse.ArgumentParser(
        description="Generate documentation from JSON schema",
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--object", help="Object name")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--flat", help="Flatten output", action="store_true")
    parser.add_argument("filename", help="JSON schema file")

    args = parser.parse_args()

    root = json.load(open(args.filename))
    schema = root

    if args.object:
        schema = schema["properties"][args.object]

    if args.output:
        sys.stdout = open(args.output, "w")

    if args.flat:
        render_flat(schema)
    else:
        render_rst(schema)


if __name__ == "__main__":
    sys.exit(main())
