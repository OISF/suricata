#!/usr/bin/env python
import re
from os import listdir

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

dirList = listdir(SRC_DIR)
for fname in dirList:
    if re.search("\.[ch]$", fname):
        for line in open(SRC_DIR + fname):
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
