from __future__ import print_function

import os
import re
import sys

from distutils.core import setup

version = None
if os.path.exists("../configure.ac"):
    with open("../configure.ac", "r") as conf:
        for line in conf:
            m = re.search("AC_INIT\(suricata,\s+(\d.+)\)", line)
            if m:
                version = m.group(1)
                break
if version is None:
    print("error: failed to parse Suricata version, will use 0.0.0",
          file=sys.stderr)
    version = "0.0.0"
    
setup(
    name="suricata",
    version=version,
    packages=[
        "suricata",
        "suricata.ctl",
    ],
    scripts=[
        "bin/suricatactl",
    ]
)
