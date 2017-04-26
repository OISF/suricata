#! /usr/bin/env python2

from __future__ import print_function

import sys
import os
import re

types = {
    "u8": "uint8_t",

    "i8": "int8_t",
    "i32" :"int32_t",

    "libc::c_void": "void",

    "libc::uint8_t": "uint8_t",
    "libc::uint16_t": "uint16_t",
    "libc::uint32_t": "uint32_t",
    "libc::uint64_t": "uint64_t",

    "libc::int8_t": "int8_t",
    
    "SuricataContext": "SuricataContext",
    "core::Flow": "Flow",
    "DNSState": "RSDNSState",
    "DNSTransaction": "RSDNSTransaction",
    "JsonT": "json_t",
    "DetectEngineState": "DetectEngineState",
    "core::DetectEngineState": "DetectEngineState",
    "core::AppLayerDecoderEvents": "AppLayerDecoderEvents",
}

def convert_type(rs_type):
    m = re.match("^[^\s]+$", rs_type)
    if m:
        if rs_type in types:
            return types[rs_type]

    m = re.match("^(.*)(\s[^\s]+)$", rs_type)
    if m:
        mod = m.group(1).strip()
        rtype = m.group(2).strip()
        if rtype in types:
            if mod in [
                    "*mut",
                    "*const",
                    "&mut",
                    "&'static mut",
                    ]:
                return "%s *" % (types[rtype])
            elif mod in [
                    "*mut *const"]:
                return "%s **" % (types[rtype])
            else:
                raise Exception("Unknown modifier '%s' in '%s'." % (
                    mod, rs_type))
        else:
            raise Exception("Unknown type: %s" % (rtype))

    raise Exception("Failed to parse Rust type: %s" % (rs_type))

def make_output_filename(filename):
    parts = filename.split(os.path.sep)[2:]
    last = os.path.splitext(parts.pop())[0]
    outpath = "../src/rust-%s-%s.h" % (
        "-".join(parts), last)
    return outpath.replace("--", "-")

def gen_headers(filename):

    buf = open(filename).read()

    output_filename = make_output_filename(filename)
    print(output_filename)
    out = open(output_filename, "w")

    for fn in re.findall(
            r"^pub extern \"C\" fn ([A_Za-z0-9_]+)\(([^{]+)?\)"
            r"(\s+-> ([^{]+))?",
            buf,
            re.M | re.DOTALL):

        args = []

        fnName = fn[0]

        for arg in fn[1].split(","):
            if not arg:
                continue
            arg_name, rs_type = arg.split(":", 1)
            arg_name = arg_name.strip()
            rs_type = rs_type.strip()
            c_type = convert_type(rs_type)

            if arg_name != "_":
                args.append("%s %s" % (c_type, arg_name))
            else:
                args.append(c_type)

        if not args:
            args.append("void")

        retType = fn[3].strip()
        if retType == "":
            returns = "void"
        else:
            returns = convert_type(retType)

        out.write("%s %s(%s);\n" % (returns, fnName, ", ".join(args)))

    if out.tell() == 0:
        os.unlink(output_filename)

def main():

    rust_top = os.path.dirname(sys.argv[0])
    os.chdir(rust_top)

    for dirpath, dirnames, filenames in os.walk("./src"):
        for filename in filenames:
            if filename.endswith(".rs"):
                path = os.path.join(dirpath, filename)
                gen_headers(path)

if __name__ == "__main__":
    sys.exit(main())
    
