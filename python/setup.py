from __future__ import print_function

import os
import re
import sys
import shutil

from distutils.core import setup
from distutils.command.build_py import build_py

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

class do_build(build_py):
    def run(self):
        build_py.run(self)
        defaults_py_out = os.path.join(
            self.build_lib, "suricata", "config", "defaults.py")
        if not os.path.exists(defaults_py_out):
            # Must be an out of tree build, find defaults.py.
            defaults_py_in = os.path.join(
                self.build_lib, "..", "suricata", "config", "defaults.py")
            if os.path.exists(defaults_py_in):
                shutil.copy(defaults_py_in, defaults_py_out)
            else:
                print("error: failed to find defaults.py")
                sys.exit(1)

setup(
    name="suricata",
    description="Suricata control tools",
    version=version,
    author='OISF Developers, Eric Leblond',
    author_email='oisf-devel@lists.openinfosecfoundation.org, eric@regit.org',
    url='https://www.suricata-ids.org/',
    packages=[
        "suricata",
        "suricata.config",
        "suricata.ctl",
        "suricata.sc",
        "suricatasc",
    ],
    scripts=[
        "bin/suricatactl",
        "bin/suricatasc",
    ],
    provides=['suricatactl', 'suricatasc'],
    requires=['argparse','simplejson'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Topic :: System :: Systems Administration',
    ],
    cmdclass={'build_py': do_build},
)
