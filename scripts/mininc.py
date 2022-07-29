import sys
import shutil
import subprocess
import os

includes = []
cfile = sys.argv[1]
basename = os.path.basename(cfile)[:-2]
f = open(cfile, "r")
needsSuricataH = False
for l in f.readlines():
    if l.startswith('#include "'):
        included = l.split('"')[1]
        if included == "suricata-common.h":
            continue
        if included == basename+".h":
            continue
        if included[-2:] == ".c":
            continue
        includes.append(included)
    if "RunmodeIsUnittests" in l:
        needsSuricataH = True
f.close()

for i in includes:
    if i == "suricata.h" and needsSuricataH:
        continue
    f = open(cfile, "r")
    f2 = open(cfile+".test", "w")
    for l in f.readlines():
        if l.startswith('#include "'):
            if l.split('"')[1] == i:
                continue
        f2.write(l)
    f2.close()
    f.close()
    shutil.copyfile(cfile, cfile+".bak")
    shutil.copyfile(cfile+".test", cfile)
    try:
        os.remove(cfile[:-2]+".o")
    except:
        pass
    cp = subprocess.run(["make", "-C", "src", basename+".o"])
    if cp.returncode != 0:
        shutil.copyfile(cfile+".bak", cfile)
        print("Needs", i)
    else:
        print("Removes", i)
