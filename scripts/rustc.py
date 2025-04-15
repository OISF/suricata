#!/usr/bin/env python3

import sys
import subprocess

#disable coverage external crates
if len(sys.argv) > 4 and sys.argv[2] == '--crate-name' and not sys.argv[3].startswith("suricata"):
    try:
        sys.argv.remove("-Cinstrument-coverage")
    except:
        pass
result = subprocess.run(sys.argv[1:])
sys.exit(result.returncode)
