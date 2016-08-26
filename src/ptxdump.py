#!/usr/bin/env python
from string import *
import os, getopt, sys, platform

header = '''/* Auto-generated by ptxdump.py DO NOT EDIT
*
* This file contains the ptx code of the Cuda kernels.
* A kernel is identified by its name and the compute capability (e.g. _sm_10).
*/
'''

def FormatCharHex(d):
    s = hex(ord(d))
    if len(s) == 3:
        s = "0x0" + s[2]
    return s

def CleanFileName(f):
    v = f.replace("-","_")
    v = v.replace(".ptx","")
    return v

if not(len(sys.argv[1:]) >= 2):
    print("Usage: ptx2c.py <output> <in.ptx ..> ")
    print("Description: creates a header file containing the ptx files as character array" + os.linesep)
    sys.exit(0)

out_h = sys.argv[1] + ".h"
out = open(out_h, 'w')

out.writelines(header)
out.writelines("#include \"suricata-common.h\"\n")
out.writelines("#ifdef __SC_CUDA_SUPPORT__\n")
out.writelines("#ifndef __ptxdump_h__\n")
out.writelines("#define __ptxdump_h__\n\n")

# write char arrays
for file in sys.argv[2:]:
    in_ptx = open(file, 'r')
    source = in_ptx.read()
    source_len = len(source)

    varname = CleanFileName(file)

    out.writelines("const unsigned char " + varname + "[" + str(source_len+1) + "] = {\n")
    newlinecnt = 0
    for i in range(0, source_len):
        out.write(FormatCharHex(source[i]) + ", ")
        newlinecnt += 1
        if newlinecnt == 16:
            newlinecnt = 0
            out.write("\n")
    out.write("0x00\n};\n\n")

    print(sys.argv[0] + ": CUmodule " + varname + " packed successfully")

# write retrieval function
out.writelines("const unsigned char* SCCudaPtxDumpGetModule(const char* module){\n");
for file in sys.argv[2:]:
    out.writelines('\tif (!strcmp(module, "' + file.replace(".ptx","")+'"))\n')
    out.writelines("\t\treturn " + CleanFileName(file)+";\n")
out.writelines('\tSCLogError(SC_ERR_FATAL, "Error in SCCudaPtxDumpGetModule, module %s not found. Exiting...",module);\n')
out.writelines("\texit(EXIT_FAILURE);\n")
out.writelines("};\n")

out.writelines("#endif /* __ptxdump_h__ */\n")
out.writelines("#endif /* __SC_CUDA_SUPPORT__ */\n")

print(sys.argv[0] + ": " + out_h + " written successfully")

in_ptx.close()
out.close()
