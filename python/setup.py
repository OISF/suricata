import os

from distutils.core import setup

if os.path.exists("version"):
    version = open("version", "r").read().strip()
else:
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
