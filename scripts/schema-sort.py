#!/usr/bin/env python3
#
# Script to sort or just check that properties are in alphabetic order


import json
import sys
import argparse
from collections import OrderedDict


def sort_properties(obj, path=""):
    """Recursively sort 'properties' keys in a JSON schema object."""
    if isinstance(obj, dict):
        new_obj = OrderedDict()

        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else key

            if key == "properties" and isinstance(value, dict):
                sorted_properties = OrderedDict(sorted(value.items()))
                new_obj[key] = sorted_properties
                for prop_key, prop_value in sorted_properties.items():
                    new_obj[key][prop_key] = sort_properties(
                        prop_value, f"{current_path}.{prop_key}"
                    )
            else:
                new_obj[key] = sort_properties(value, current_path)

        return new_obj

    elif isinstance(obj, list):
        return [sort_properties(item, f"{path}[{i}]") for i, item in enumerate(obj)]

    else:
        return obj


def check_properties_sorted(obj, path=""):
    """Check if all 'properties' keys have their contents sorted alphabetically."""
    errors = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else key
            if key == "properties" and isinstance(value, dict):
                keys_list = list(value.keys())
                sorted_keys = sorted(keys_list)

                if keys_list != sorted_keys:
                    errors.append(f"Properties not sorted at path: {current_path}")
                    errors.append(f"  Current order: {keys_list}")
                    errors.append(f"  Should be: {sorted_keys}")

                for prop_key, prop_value in value.items():
                    errors.extend(
                        check_properties_sorted(
                            prop_value, f"{current_path}.{prop_key}"
                        )
                    )
            else:
                errors.extend(check_properties_sorted(value, current_path))

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            errors.extend(check_properties_sorted(item, f"{path}[{i}]"))

    return errors


def main():
    parser = argparse.ArgumentParser(
        description="Sort JSON schema properties alphabetically"
    )
    parser.add_argument("schema_file", help="Path to the JSON schema file")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if properties are sorted (exit 1 if not)",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Sort the file in place (only if not in check mode)",
    )

    args = parser.parse_args()

    try:
        with open(args.schema_file, "r") as f:
            schema = json.load(f, object_pairs_hook=OrderedDict)
    except Exception as e:
        print(f"Error reading schema file: {e}", file=sys.stderr)
        sys.exit(1)

    if args.check:
        errors = check_properties_sorted(schema)

        if errors:
            print("Schema properties are not sorted!", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            sys.exit(1)
        else:
            print("Schema properties are properly sorted.")
            sys.exit(0)
    else:
        sorted_schema = sort_properties(schema)

        if args.in_place:
            try:
                with open(args.schema_file, "w") as f:
                    json.dump(sorted_schema, f, indent=4)
                    f.write("\n")
                print(f"Sorted schema written to {args.schema_file}")
            except Exception as e:
                print(f"Error writing schema file: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print(json.dumps(sorted_schema, indent=4))


if __name__ == "__main__":
    main()
