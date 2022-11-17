#! /usr/bin/env python3
#
# Script to provision a new application layer parser and/or logger.

import sys
import os
import os.path
import argparse
import io
import re

class SetupError(Exception):
    """Functions in this script can raise this error which will cause the
    application to abort displaying the provided error message, but
    without a stack trace.
    """
    pass

progname = os.path.basename(sys.argv[0])

def fail_if_exists(filename):
    if os.path.exists(filename):
        raise SetupError("%s already exists" % (filename))

def common_copy_templates(proto, pairs, replacements=()):
    upper = proto.upper()
    lower = proto.lower()

    for (src, dst) in pairs:
        fail_if_exists(dst)

    for (src, dst) in pairs:
        dstdir = os.path.dirname(dst)
        if not os.path.exists(dstdir):
            print("Creating directory %s." % (dstdir))
            os.makedirs(dstdir)
        print("Generating %s." % (dst))
        output = open(dst, "w")
        with open(src) as template_in:
            skip = False
            for line in template_in:
                if line.find("TEMPLATE_START_REMOVE") > -1:
                    skip = True
                    continue
                elif line.find("TEMPLATE_END_REMOVE") > -1:
                    skip = False
                    continue
                if skip:
                    continue

                for (old, new) in replacements:
                    line = line.replace(old, new)

                line = re.sub("TEMPLATE(_RUST)?", upper, line)
                line = re.sub("template(-rust)?", lower, line)
                line = re.sub("Template(Rust)?", proto, line)

                output.write(line)
        output.close()

def copy_app_layer_templates(proto):
    lower = proto.lower()
    upper = proto.upper()

    pairs = (
        ("rust/src/applayertemplate/mod.rs",
         "rust/src/applayer%s/mod.rs" % (lower)),
        ("rust/src/applayertemplate/template.rs",
         "rust/src/applayer%s/%s.rs" % (lower, lower)),
        ("rust/src/applayertemplate/parser.rs",
         "rust/src/applayer%s/parser.rs" % (lower)),
    )

    common_copy_templates(proto, pairs)

def patch_rust_lib_rs(protoname):
    filename = "rust/src/lib.rs"
    print("Patching %s." % (filename))
    output = io.StringIO()
    with open(filename) as infile:
        for line in infile:
            if line.startswith("pub mod applayertemplate;"):
                output.write(line.replace("template", protoname.lower()))
            output.write(line)
    open(filename, "w").write(output.getvalue())

def patch_rust_applayer_mod_rs(protoname):
    lower = protoname.lower()
    filename = "rust/src/applayer%s/mod.rs" % (lower)
    print("Patching %s." % (filename))
    output = io.StringIO()
    done = False
    with open(filename) as infile:
        for line in infile:
            if not done and line.find("mod parser") > -1:
                output.write("pub mod logger;\n")
                done = True
            output.write(line)
    open(filename, "w").write(output.getvalue())

def patch_app_layer_protos_h(protoname):
    filename = "src/app-layer-protos.h"
    print("Patching %s." % (filename))
    output = io.StringIO()
    with open(filename) as infile:
        for line in infile:
            if line.find("ALPROTO_TEMPLATE,") > -1:
                output.write(line.replace("TEMPLATE", protoname.upper()))
            output.write(line)
    open(filename, "w").write(output.getvalue())

def patch_app_layer_protos_c(protoname):
    filename = "src/app-layer-protos.c"
    print("Patching %s." % (filename))
    output = io.StringIO()

    # Read in all the lines as we'll be doing some multi-line
    # duplications.
    inlines = open(filename).readlines()
    for i, line in enumerate(inlines):

        if line.find("case ALPROTO_TEMPLATE:") > -1:
            # Duplicate the section starting an this line and
            # including the following 2 lines.
            for j in range(i, i + 3):
                temp = inlines[j]
                temp = temp.replace("TEMPLATE", protoname.upper())
                temp = temp.replace("template", protoname.lower())
                output.write(temp)

        if line.find("return ALPROTO_TEMPLATE;") > -1:
            output.write(
                line.replace("TEMPLATE", protoname.upper()).replace(
                    "template", protoname.lower()))

        output.write(line)
    open(filename, "w").write(output.getvalue())

def patch_app_layer_detect_proto_c(proto):
    filename = "src/app-layer-detect-proto.c"
    print("Patching %s." % (filename))
    output = io.StringIO()
    inlines = open(filename).readlines()
    for i, line in enumerate(inlines):
        if line.find("== ALPROTO_TEMPLATE)") > -1:
            output.write(inlines[i].replace("TEMPLATE", proto.upper()))
            output.write(inlines[i+1].replace("TEMPLATE", proto.upper()))
        output.write(line)
    open(filename, "w").write(output.getvalue())

def patch_app_layer_parser_c(proto):
    filename = "src/app-layer-parser.c"
    print("Patching %s." % (filename))
    output = io.StringIO()
    inlines = open(filename).readlines()
    for line in inlines:
        if line.find("rs_template_register_parser") > -1:
            output.write(line.replace("template", proto.lower()))
        output.write(line)
    open(filename, "w").write(output.getvalue())

def patch_suricata_yaml_in(proto):
    filename = "suricata.yaml.in"
    print("Patching %s." % (filename))
    output = io.StringIO()
    inlines = open(filename).readlines()
    for i, line in enumerate(inlines):

        if line.find("protocols:") > -1:
            if inlines[i-1].find("app-layer:") > -1:
                output.write(line)
                output.write("""    %s:
      enabled: yes
""" % (proto.lower()))
                # Skip writing out the current line, already done.
                continue

        output.write(line)

    open(filename, "w").write(output.getvalue())

def logger_patch_suricata_yaml_in(proto):
    filename = "suricata.yaml.in"
    print("Patching %s." % (filename))
    output = io.StringIO()
    inlines = open(filename).readlines()

    # This is a bit tricky. We want to find the first occurrence of
    # "types:" after "eve-log:".
    n = 0
    for i, line in enumerate(inlines):
        if n == 0 and line.find("eve-log:") > -1:
            n += 1
        if n == 1 and line.find("types:") > -1:
            output.write(line)
            output.write("        - %s\n" % (proto.lower()))
            n += 1
            continue
        output.write(line)

    open(filename, "w").write(output.getvalue())

def logger_patch_suricata_common_h(proto):
    filename = "src/suricata-common.h"
    print("Patching %s." % (filename))
    output = io.StringIO()
    with open(filename) as infile:
        for line in infile:
            if line.find("LOGGER_JSON_TEMPLATE,") > -1:
                output.write(line.replace("TEMPLATE", proto.upper()))
            output.write(line)
    open(filename, "w").write(output.getvalue())

def logger_patch_output_c(proto):
    filename = "src/output.c"
    print("Patching %s." % (filename))
    output = io.StringIO()
    inlines = open(filename).readlines()
    for i, line in enumerate(inlines):
        if line.find("output-json-template.h") > -1:
            output.write(line.replace("template", proto.lower()))
        if line.find("/* Template JSON logger.") > -1:
            output.write(inlines[i].replace("Template", proto))
            output.write(inlines[i+1].replace("Template", proto))
        output.write(line)
    open(filename, "w").write(output.getvalue())

def logger_copy_templates(proto):
    lower = proto.lower()
    
    pairs = (
        ("src/output-json-template-rust.h",
         "src/output-json-%s.h" % (lower)),
        ("src/output-json-template-rust.c",
         "src/output-json-%s.c" % (lower)),
        ("rust/src/applayertemplate/logger.rs",
         "rust/src/applayer%s/logger.rs" % (lower)),
    )

    common_copy_templates(proto, pairs)

def logger_patch_makefile_am(protoname):
    filename = "src/Makefile.am"
    print("Patching %s." % (filename))
    output = io.StringIO()
    with open(filename) as infile:
        for line in infile:
            if line.lstrip().startswith("output-json-template."):
                output.write(line.replace("template", protoname.lower()))
            output.write(line)
    open(filename, "w").write(output.getvalue())

def logger_patch_util_profiling_c(proto):
    filename = "src/util-profiling.c"
    print("Patching %s." % (filename))
    output = io.StringIO()
    with open(filename) as infile:
        for line in infile:
            if line.find("(LOGGER_JSON_TEMPLATE);") > -1:
                output.write(line.replace("TEMPLATE", proto.upper()))
            output.write(line)
    open(filename, "w").write(output.getvalue())

def detect_copy_templates(proto, buffername):
    lower = proto.lower()
    buffername_lower = buffername.lower()

    pairs = (
        ("src/detect-template-rust-buffer.h",
         "src/detect-%s-%s.h" % (lower, buffername_lower)),
        ("src/detect-template-rust-buffer.c",
         "src/detect-%s-%s.c" % (lower, buffername_lower)),
    )
    replacements = (
        ("TEMPLATE_RUST_BUFFER", "%s_%s" % (
            proto.upper(), buffername.upper())),
        ("template-rust-buffer", "%s-%s" % (
            proto.lower(), buffername.lower())),
        ("template_rust_buffer", "%s_%s" % (
            proto.lower(), buffername.lower())),
        ("TemplateRustBuffer", "%s%s" % (proto, buffername)),
    )

    common_copy_templates(proto, pairs, replacements)

def detect_patch_makefile_am(protoname, buffername):
    filename = "src/Makefile.am"
    print("Patching %s." % (filename))
    output = io.StringIO()
    with open(filename) as infile:
        for line in infile:
            if line.lstrip().startswith("detect-template-buffer."):
                new = line.replace("template-buffer", "%s-%s" % (
                    protoname.lower(), buffername.lower()))
                output.write(new)
            output.write(line)
    open(filename, "w").write(output.getvalue())

def detect_patch_detect_engine_register_c(protoname, buffername):
    filename = "src/detect-engine-register.c"
    print("Patching %s." % (filename))
    output = io.StringIO()
    with open(filename) as infile:
        for line in infile:

            if line.find("detect-template-buffer.h") > -1:
                new = line.replace("template-buffer", "%s-%s" % (
                    protoname.lower(), buffername.lower()))
                output.write(new)

            if line.find("DetectTemplateBufferRegister") > -1:
                new = line.replace("TemplateBuffer", "%s%s" % (
                    protoname, buffername))
                output.write(new)

            output.write(line)
    open(filename, "w").write(output.getvalue())

def detect_patch_detect_engine_register_h(protoname, buffername):
    filename = "src/detect-engine-register.h"
    print("Patching %s." % (filename))
    output = io.StringIO()
    with open(filename) as infile:
        for line in infile:

            if line.find("DETECT_AL_TEMPLATE_BUFFER") > -1:
                new = line.replace("TEMPLATE_BUFFER", "%s_%s" % (
                    protoname.upper(), buffername.upper()))
                output.write(new)

            output.write(line)
    open(filename, "w").write(output.getvalue())

def proto_exists(proto):
    upper = proto.upper()
    for line in open("src/app-layer-protos.h"):
        if line.find("ALPROTO_%s," % (upper)) > -1:
            return True
    return False

epilog = """
This script will provision a new app-layer parser for the protocol
name specified on the command line. This is done by copying and
patching src/app-layer-template.[ch] then linking the new files into
the build system.

By default both the parser and logger will be generated. To generate
just one or the other use the --parser or --logger command line flags.

Examples:

    %(progname)s --logger DNP3
    %(progname)s --parser Gopher

This script can also setup a detect buffer. This is a separate
operation that must be done after creating the parser.

Examples:

    %(progname)s --detect Gopher Request
""" % { "progname": progname, }

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog)
    parser.add_argument("--logger", action="store_true", default=False,
                        help="Generate logger.")
    parser.add_argument("--parser", action="store_true", default=False,
                        help="Generate parser.")
    parser.add_argument("--detect", action="store_true", default=False,
                        help="Generate detect module.")
    parser.add_argument("proto", help="Name of protocol")
    parser.add_argument("buffer", help="Name of buffer (for --detect)",
                        nargs="?")
    args = parser.parse_args()

    proto = args.proto

    # The protocol name must start with an upper case letter.
    if proto[0] != proto.upper()[0]:
        raise SetupError("protocol name must begin with an upper case letter")

    # Determine what to generate.
    parser = False
    logger = False
    detect = False

    # If no --parser or no --logger, generate both.
    if not args.parser and not args.logger and not args.detect:
        parser = True
        logger = True
    else:
        parser = args.parser
        logger = args.logger
        detect = args.detect

    if detect:
        if args.buffer is None:
            raise SetupError("--detect requires a buffer name")

    # Make sure we are in the correct directory.
    if os.path.exists("./suricata.c"):
        os.chdir("..")
    elif not os.path.exists("./src/suricata.c"):
        raise SetupError(
            "this does not appear to be a Suricata source directory.")

    if parser:
        if proto_exists(proto):
            raise SetupError("protocol already exists: %s" % (proto))
        copy_app_layer_templates(proto)
        patch_rust_lib_rs(proto)
        patch_app_layer_protos_h(proto)
        patch_app_layer_protos_c(proto)
        patch_app_layer_detect_proto_c(proto)
        patch_app_layer_parser_c(proto)
        patch_suricata_yaml_in(proto)

    if logger:
        if not proto_exists(proto):
            raise SetupError("no app-layer parser exists for %s" % (proto))
        logger_copy_templates(proto)
        patch_rust_applayer_mod_rs(proto)
        logger_patch_makefile_am(proto)
        logger_patch_suricata_common_h(proto)
        logger_patch_output_c(proto)
        logger_patch_suricata_yaml_in(proto)
        logger_patch_util_profiling_c(proto)

    if detect:
        if not proto_exists(proto):
            raise SetupError("no app-layer parser exists for %s" % (proto))
        detect_copy_templates(proto, args.buffer)
        detect_patch_makefile_am(proto, args.buffer)
        detect_patch_detect_engine_register_c(proto, args.buffer)
        detect_patch_detect_engine_register_h(proto, args.buffer)

    if parser:
        print("""
An application detector and parser for the protocol %(proto)s have
now been setup in the files:

    rust/src/applayer%(proto_lower)s/mod.rs
    rust/src/applayer%(proto_lower)s/parser.rs""" % {
            "proto": proto,
            "proto_lower": proto.lower(),
        })

    if logger:
        print("""
A JSON application layer transaction logger for the protocol
%(proto)s has now been set in the file:

    rust/src/applayer%(proto_lower)s/logger.rs""" % {
            "proto": proto,
            "proto_lower": proto.lower(),
        })

    if detect:
        print("""
The following files have been created and linked into the build:

    detect-%(protoname_lower)s-%(buffername_lower)s.h
    detect-%(protoname_lower)s-%(buffername_lower)s.c
""" % {
    "protoname_lower": proto.lower(),
    "buffername_lower": args.buffer.lower(),
})

    if parser or logger:
        print("""
Suricata should now build cleanly. Try running "./configure" and "make".
""")

if __name__ == "__main__":
    try:
        sys.exit(main())
    except SetupError as err:
        print("error: %s" % (err))
        sys.exit(1)
