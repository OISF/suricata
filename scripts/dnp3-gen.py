#! /usr/bin/env python
#
# Copyright (C) 2015 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

# This script generates DNP3 related source code based on definitions
# of DNP3 objects (currently the object structs).

import sys
import re
from cStringIO import StringIO

import jinja2

integer_types = [
    "uint8_t",
    "uint16_t",
    "uint32_t",
]

util_lua_dnp3_objects_c_template = """/* Copyright (C) 2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * DO NOT EDIT. THIS FILE IS AUTO-GENERATED.
 */

#include "suricata-common.h"

#include "app-layer-dnp3.h"
#include "app-layer-dnp3-objects.h"

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-lua.h"

/**
 * \\brief Push an object point item onto the stack.
 */
void DNP3PushPoint(lua_State *luastate, DNP3Object *object,
    DNP3Point *point)
{
    switch (DNP3_OBJECT_CODE(object->group, object->variation)) {
{% for object in objects %}
        case DNP3_OBJECT_CODE({{object["group"]}}, {{object["variation"]}}): {
            DNP3ObjectG{{object["group"]}}V{{object["variation"]}} *data = point->data;
{% for field in object["fields"] %}
{% if f.is_integer_type(field["datatype"]) %}
            lua_pushliteral(luastate, "{{field["name"]}}");
            lua_pushinteger(luastate, data->{{field["name"]}});
            lua_settable(luastate, -3);
{% endif %}
{% if field["datatype"] in ["float"] %}
            lua_pushliteral(luastate, "{{field["name"]}}");
            lua_pushnumber(luastate, data->{{field["name"]}});
            lua_settable(luastate, -3);
{% endif %}
{% if field["datatype"] == "char" %}
            lua_pushliteral(luastate, "{{field["name"]}}");
            LuaPushStringBuffer(luastate, (uint8_t *)data->{{field["name"]}},
                strlen(data->{{field["name"]}}));
            lua_settable(luastate, -3);
{% endif %}
{% endfor %}
            break;
        }
{% endfor %}
        default:
            break;
    }
}

#endif /* HAVE_LUA */

"""

output_json_dnp3_objects_template = """/* Copyright (C) 2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * DO NOT EDIT. THIS FILE IS AUTO-GENERATED.
 */

#include "suricata-common.h"

#include "app-layer-dnp3.h"
#include "app-layer-dnp3-objects.h"

void OutputJsonDNP3SetItem(json_t *js, DNP3Object *object,
    DNP3Point *point)
{

    switch (DNP3_OBJECT_CODE(object->group, object->variation)) {
{% for object in objects %}
        case DNP3_OBJECT_CODE({{object["group"]}}, {{object["variation"]}}): {
            DNP3ObjectG{{object["group"]}}V{{object["variation"]}} *data = point->data;
{% for field in object["fields"] %}
{% if f.is_integer_type(field["datatype"]) %}
            json_object_set_new(js, "{{field["name"]}}",
                json_integer(data->{{field["name"]}}));
{% endif %}
{% if field["datatype"] == "char" %}
            json_object_set_new(js, "{{field["name"]}}",
                json_string(data->{{field["name"]}}));
{% endif %}
{% endfor %}
            break;
        }
{% endfor %}
        default:
            SCLogDebug("Unknown object: %d:%d", object->group,
                object->variation);
            break;
    }

}
"""

def is_integer_type(datatype):
    integer_types = [
        "uint64_t",
        "uint32_t",
        "uint16_t",
        "uint8_t",
        "int64_t",
        "int32_t",
        "int16_t",
        "int8_t",
    ]
    return datatype in integer_types

def generate(template, filename, context):
    print("Generating %s." % (filename))
    env = jinja2.Environment(trim_blocks=True)
    output = env.from_string(template).render(context)
    with open(filename, "w") as fileobj:
        fileobj.write(output)

def parse_name(name):
    m = re.search("G(\d+)V(\d+)", name)
    return (int(m.group(1)), int(m.group(2)))

def parse_objects():
    objects = []
    object_header = open("./src/app-layer-dnp3-objects.h").read()
    for m in re.finditer("typedef struct DNP3Object.*?{(.*?)}(.*?);",
                              object_header, re.M | re.S):
        struct = m.group(1)
        names = [name.strip() for name in m.group(2).split(",")]

        for name in names:
            object = {
                "fields": []
            }
            object["group"], object["variation"] = parse_name(name)

            # Parse out the fields of the struct.
            for field_match in re.finditer("(\w+)\s+(\w+)", struct, re.M):
                object["fields"].append(
                    {"datatype": field_match.group(1),
                     "name": field_match.group(2)})

            objects.append(object)

    return sorted(objects, key=lambda o: o["group"] << 8 | o["variation"])
            
def main():

    objects = parse_objects()

    context = {
        # The object list.
        "objects": objects,

        # Functions to make available in the template.
        "f": {
            "is_integer_type": is_integer_type
        }
    }

    generate(util_lua_dnp3_objects_c_template,
             "src/util-lua-dnp3-objects.c",
             context)
    generate(output_json_dnp3_objects_template,
             "src/output-json-dnp3-objects.c",
             context)

if __name__ == "__main__":
    sys.exit(main())
    
