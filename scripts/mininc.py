import sys
import shutil
import subprocess
import os
import argparse
import time
import threading

parser = argparse.ArgumentParser()
parser.add_argument("--skipdef", action="store_true", default=False,
                        help="Skip the files where everything is defined")
parser.add_argument("--onlydef", action="store_true", default=False,
                        help="Process only the files where everything is defined")
parser.add_argument("--nbthreads", default=1,
                        help="Number of parallel threads")
parser.add_argument('files', help='file or directory to process')
args = parser.parse_args()

# read autoconf.h to get defined from the config : UNITTESTS, DEBUG, HAVE_LUA...
defined = {}
f = open("src/autoconf.h", "r")
for l in f.readlines():
    if l.startswith('#define '):
        defined[l.split()[1]] = True
f.close()

# reads the ifdef in a file, and return either
# True if everything is defined (every line of code is used)
# False if more than 2 different ifdef condition are not met by current configuration
# a string of the undefined condition if there is only one
def ifdef_file(cfile):
    current_ifdefs = []
    total_ifdefs = []
    f = open(cfile, "r")
    ifndef = 0
    current_ifndef = ""
    for l in f.readlines():
        if l.startswith('#ifdef '):
            # this one is not defined by autoconf
            if l.split()[1] == "FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION":
                ifndef = ifndef + 1
                continue
            current_ifdefs.append(l.split()[1])
            current_ifndef = ""
            new_ifdef = current_ifdefs.copy()
            if new_ifdef not in total_ifdefs:
                total_ifdefs.append(new_ifdef)
        if l.startswith('#if '):
            ifndef = ifndef + 1
        elif l.startswith('#ifndef '):
            current_ifndef = l.split()[1]
            ifndef = ifndef + 1
        elif l.startswith('#else'):
            if current_ifndef != "":
                current_ifdefs.append(current_ifndef)
        elif l.startswith('#endif'):
            current_ifndef = ""
            if ifndef > 0:
                ifndef = ifndef - 1
            else:
                current_ifdefs.pop()
    f.close()
    undefined = []
    for ifdef_list in total_ifdefs:
        for i in ifdef_list:
            if not defined.get(i) and i not in undefined:
                undefined.append(i)
    if len(undefined) > 1:
        # There must be something more clever to do
        # like if UNITTESTS is undefined but only used in
        # code with ifdef HAVE_LUA which is also undefined,
        # we should return HAVE_LUA instead of false
        print("Too many undefined, skipping : ", undefined)
        return False
    elif len(undefined) == 1:
        return undefined[0]
    #else:
    return True

# returns the list of included files
def includes_file(cfile):
    includes = []
    basename = os.path.basename(cfile)[:-2]
    f = open(cfile, "r")
    needsSuricataH = False
    current_ifdef = ""
    included_ifdef = ""
    for l in f.readlines():
        if l.startswith('#ifdef '):
            current_ifdef = l.split()[1]
        elif l.startswith('#endif'):
            current_ifdef = ""
        elif l.startswith('#include "'):
            if current_ifdef != "":
                if not defined.get(current_ifdef):
                    continue
                if included_ifdef != "" and included_ifdef != current_ifdef:
                    # do not know how to remove anything
                    return []
                if included_ifdef == "":
                    included_ifdef = current_ifdef
                    # only try to remove includes in ifdef
                    includes = []
            elif included_ifdef != "":
                # only try to remove includes in ifdef
                continue
            included = l.split('"')[1]
            if included == "suricata-common.h":
                continue
            if included == basename+".h":
                continue
            if included[-2:] == ".c":
                continue
            includes.append(included)
        # without unit tests, we do not think we need it, but we do
        if "RunmodeIsUnittests" in l or "EngineModeIsIPS" in l or "g_disable_hashing" in l:
            needsSuricataH = True
    f.close()
    if needsSuricataH and "suricata.h" in includes:
        includes.remove("suricata.h")
    return includes

# removes an include line, except if it is in an undefined section
# In this case, return False
def remove_include_file(fname, i, ifdef):
    f = open(fname, "r")
    f2 = open(fname+".test", "w")
    skipping = False
    for l in f.readlines():
        if not ifdef == True and l.startswith('#ifdef ' + ifdef):
            skipping = True
        elif skipping and l.startswith('#endif'):
            skipping = False
        if l.startswith('#include "'):
            if l.split('"')[1] == i:
                if skipping:
                    f2.close()
                    f.close()
                    return False
                continue
        f2.write(l)
    f2.close()
    f.close()
    return True

def minimize_include(fname):
    ifdef = ifdef_file(fname)
    if ifdef == False:
        print("-- Skipping %s because of ifdefs" % fname)
        return
    else:
        print("-- Ifdef is %s for %s" % (ifdef, fname))

    if ifdef == True and args.skipdef:
        print("Skipping %s as per command line option" % fname)
        return
    if ifdef != True and args.onlydef:
        print("Skipping %s as per command line option" % fname)
        return

    includes = includes_file(fname)

    basename = os.path.basename(fname)[:-2]
    # Let's brute force trying to remove the includes one by one
    first_moved = False
    for i in includes:
        if not remove_include_file(fname, i, ifdef):
            continue
        shutil.copyfile(fname, fname+".bak")
        shutil.copyfile(fname+".test", fname)
        try:
            os.remove(fname[:-2]+".o")
        except:
            pass
        # rerun single file compilation
        cp = subprocess.run(["make", "-C", "src", basename+".o"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if cp.returncode != 0:
            shutil.copyfile(fname+".bak", fname)
            print("Needs %s in %s" % (i, fname))
        else:
            if ifdef == True:
                print("Removes %s from %s" % (i, fname))
            else:
                # we have an undefined section
                # as we do not need this include, maybe this section does
                print("Moves %s in %s" % (i, fname))
                f = open(fname, "r")
                commenting = 0
                commenting_ifdef = 0
                nb_line_insertion = 0
                for l in f.readlines():
                    nb_line_insertion = nb_line_insertion + 1
                    if l.isspace() or l.startswith('#include "'):
                        if commenting_ifdef > 0:
                            commenting_ifdef = commenting_ifdef + 1
                            continue
                        commenting = 0
                        continue
                    if l.startswith('#if'):
                        commenting_ifdef = 1
                        continue
                    if l.startswith('#endif'):
                        commenting_ifdef = 0
                        continue
                    if l.startswith('/*') or l.startswith('//'):
                        commenting = 1
                        continue
                    if l.startswith(' *') and commenting > 0:
                        commenting = commenting + 1
                        continue
                    break
                f.close()
                nb_line_insertion = nb_line_insertion - commenting - commenting_ifdef - 1
                f = open(fname, "r")
                f2 = open(fname+".new", "w")
                done = False
                nb_line = 0
                for l in f.readlines():
                    nb_line = nb_line + 1
                    if not first_moved and nb_line == nb_line_insertion:
                        # create an ifdef in the include part first
                        f2.write(l)
                        f2.write('#ifdef %s\n' % ifdef)
                        f2.write('#include "%s"\n' % i)
                        f2.write('#endif\n')
                        first_moved = True
                        done = True
                        continue
                    f2.write(l)
                    if not done and l.startswith('#ifdef ' + ifdef):
                        # this should be the added include part
                        f2.write('#include "%s"\n' % i)
                        done = True
                f2.close()
                f.close()
                shutil.copyfile(fname+".new", fname)

# Take either a dir or a file as input
if os.path.isdir(args.files):
    filelist1 = os.listdir(args.files)
    filelist1.sort()
    filelist = []
    for fname in filelist1:
        if fname[-2:] != ".c":
            continue
        if not os.path.isfile(os.path.join(args.files, fname)):
            continue
        filelist.append(os.path.join(args.files, fname))
else:
    filelist = [args.files]

# Run for every file in the list

nbthreads = int(args.nbthreads)
threads = [None] * nbthreads
for j in range(len(filelist)):
    fname = filelist[j]
    print("- Processing %s : %d/%d" % (fname, j, len(filelist)))
    t = threading.Thread(
        target=minimize_include, args=(fname,))
    t.start()
    for k in range(nbthreads):
        if threads[k] == None:
            threads[k] = t
    free_thread = False
    while not free_thread:
        for k in range(nbthreads):
            if threads[k] == None:
                free_thread = True
                break
            elif not threads[k].is_alive():
                threads[k].join()
                threads[k] = None
                free_thread = True
                break
        if free_thread:
            break
        time.sleep(1)

for k in range(nbthreads):
    if threads[k] != None:
        threads[k].join()
