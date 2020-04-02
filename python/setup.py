from __future__ import print_function

import os
import re
import sys
import shutil

from distutils.core import setup
from distutils.command.build_py import build_py

# Get the Suricata version from configure.ac.
version = None
overwrite_version = False
if os.path.exists("../configure.ac"):
    with open("../configure.ac", "r") as conf:
        for line in conf:
            if line.find("AC_INIT") > 1:
                m = re.search("AC_INIT\(\[suricata\],\[(\d.+)\]\)", line)
                if m:
                    version = m.group(1)
                    overwrite_version = True
                    break
                else:
                    print("error: failed to parse Suricata version from: %s" % (
                        line.strip()), file=sys.stderr)
                    sys.exit(1)
elif os.path.exists("VERSION"):
    with open("./VERSION") as f:
        version = f.read().strip()
if version is None:
    print("error: failed to find Suricata version", file=sys.stderr)
    sys.exit(1)

# Write the version file so it can be included in the Python sdist
# allowing this Python code to be pip installable. We only do this for
# sdist as it causes issues when doing an out of tree autoconf build.
if "sdist" in sys.argv and overwrite_version:
    with open("./VERSION", "w") as f:
        f.write("{}\n".format(version))

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

# Long description, this is what will show up on PyPI.
long_description = """

This package contains the Python support tools and libraries for
Suricata.

It is important to note that these tools are bundled and installed by
Suricata, so you likely don't need to install this package, unless you
need access to the libraries inside a virtualenv, or have a need to
install them without installing Suricata.

"""

setup(
    name="suricata",
    description="Suricata control tools",
    long_description=long_description,
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
