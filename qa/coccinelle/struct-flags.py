#!/usr/bin/env python
import re
from os import listdir

SRC_DIR="../../src/"

class Structure:
    def __init__(self, string):
        (self.struct, self.flags, self.values) = string.split(":")

cmd = "grep -h coccinelle ../../src/*[ch] | sed -e 's/.*coccinelle: \(.*\) \*\//\1/'"

struct_list = []

dirList = listdir(SRC_DIR)
for fname in dirList:
    if re.search("\.[ch]$", fname):
        for line in open(SRC_DIR + fname):
            if "coccinelle:" in line:
                m = re.search("coccinelle: (.*) \*\/", line)
                struct = Structure(m.group(1))
                struct_list.append(struct)

header = "@flags@"
body = []

i = 0
for struct in struct_list:
    header += """
%s *struct%d;
identifier struct_flags%d =~ "^(?!%s).+";""" % ( struct.struct, i, i, struct.values)

    body.append("""
struct%d->%s@p1 |= struct_flags%d
|
struct%d->%s@p1 & struct_flags%d
|
struct%d->%s@p1 &= ~struct_flags%d
""" % (i, struct.flags, i, i, struct.flags, i, i, struct.flags, i))

    i+=1

print header
print "position p1;"
print "@@"
print ""
print "(" + "|".join(body) + ")"
print ""
print """@script:python@
p1 << flags.p1;
@@

print "Invalid usage of flags field at %s:%s, flags value is incorrect (wrong family)." % (p1[0].file, p1[0].line)
import sys
sys.exit(1)"""
