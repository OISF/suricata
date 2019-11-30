#!/usr/bin/env python
import re
import sys
import os
from string import Template

if len(sys.argv) == 2:
    SRC_DIR = sys.argv[1]
else:
    SRC_DIR = "../../src/"


class Structure:
    def __init__(self, string):
        (self.struct, self.flags, self.values) = string.split(":")

class SetterGetter:
    def __init__(self, string):
        (function, params, self.value) = string.split(":")
        self.function = function.strip("()")
        self.params = [int(a) for a in params.split(",")]


cmd = "grep -h coccinelle ../../src/*[ch] | sed -e 's/.*coccinelle: \(.*\) \*\//\1/'"

struct_list = []
setter_getter_list = []

dirList = os.listdir(SRC_DIR)
for fname in dirList:
    if re.search("\.[ch]$", fname):
        for line in open(os.path.join(SRC_DIR, fname)):
            if "coccinelle:" in line:
                m = re.search("coccinelle: (.*) \*\/", line)
                if "()" not in m.group(1):
                    struct = Structure(m.group(1))
                    struct_list.append(struct)
                else:
                    function = SetterGetter(m.group(1))
                    setter_getter_list.append(function)

header = "@flags@"
body = []

# Handle setter and getter
setter_getter = [x.function for x in setter_getter_list]
if len(setter_getter):
    header += "\nidentifier NotSetterGetter !~ \"^(%s)$\";" % ("|".join(setter_getter))

i = 0
for struct in struct_list:
    header += """
%s *struct%d;
identifier struct_flags%d =~ "^(?!%s).+";""" % (struct.struct, i, i, struct.values)

    body.append("""
struct%d->%s@p1 |= struct_flags%d
|
struct%d->%s@p1 & struct_flags%d
|
struct%d->%s@p1 &= ~struct_flags%d
""" % (i, struct.flags, i, i, struct.flags, i, i, struct.flags, i))

    i += 1

print(header)
print("position p1;")
print("@@")
print("")
print("""
NotSetterGetter(...)
{
    <...
""")
print("")
print("(" + "|".join(body) + ")")
print("")
print("""
...>
}

@script:python@
p1 << flags.p1;
@@

print "Invalid usage of flags field at %s:%s, flags value is incorrect (wrong family)." % (p1[0].file, p1[0].line)
import sys
sys.exit(1)""")

i = 1
setter_template = """
@settergetter${i}@
identifier SetterGetter =~ "${function}";
identifier f_flags =~ "^(?!${value}).+";
identifier ${params_line};
position p1;
@@

SetterGetter@p1(${prefix_param}f_flags${suffix_param})

@script:python@
p1 << settergetter${i}.p1;
@@
print "Invalid usage of ${function} at %s:%s, flags value is incorrect (wrong family)." % (p1[0].file, p1[0].line)
import sys
sys.exit(1)
"""

for sg in setter_getter_list:
    prefix_param = ""
    for index in list(range(1, sg.params[1])):
        prefix_param += "param%d, " % (index)
    if sg.params[1] < sg.params[0]:
        suffix_param = ", " + ", ".join(["param%d" % (index + 1) for index in list(range(sg.params[1], sg.params[0]))])
    else:
        suffix_param = ""
    params_elts = list(range(1, sg.params[1])) + list(range(sg.params[1] + 1, sg.params[0] + 1))
    params_line = ", ".join(["param%d" % (x) for x in params_elts])
    print(Template(setter_template).substitute(i=i, function=sg.function, value=sg.value,
                prefix_param=prefix_param, suffix_param=suffix_param, params_line=params_line))
    i += 1
