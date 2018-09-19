#! /usr/bin/env bash
#
# Script to provision a new application layer detector and parser.

set -e

# Fail if "ed" is not available.
if ! which ed > /dev/null 2>&1; then
    echo "error: the program \"ed\" is required for this script"
    exit 1
fi

function usage() {
    cat <<EOF

usage: $0 <protocol name> <buffer name>

This script will provision content inspection for app-layer decoded
buffers.

Examples:

    $0 Gopher Buffer
    $0 DNP3 Buffer
    $0 Http Etag

EOF
}

# Make sure we are running from the correct directory.
set_dir() {
    if [ -e ./suricata.c ]; then
	cd ..
    elif [ -e ./src/suricata.c ]; then
	# Do nothing.
	true
    else
	echo "error: this does not appear to be a suricata source directory."
	exit 1
    fi
}

fail_if_exists() {
    path="$1"
    if test -e "${path}"; then
	echo "error: ${path} already exists."
	exit 1
    fi
}

function copy_template_file() {
    src="$1"
    dst="$2"

    echo "Creating ${dst}."

    sed -e '/TEMPLATE_START_REMOVE/,/TEMPLATE_END_REMOVE/d' \
	-e "s/TEMPLATE_BUFFER/${protoname_upper}_${buffername_upper}/g" \
	-e "s/TEMPLATE/${protoname_upper}/g" \
	-e "s/template-buffer/${protoname_lower}-${buffername_lower}/g" \
	-e "s/template/${protoname_lower}/g" \
	-e "s/TemplateBuffer/${protoname}${buffername}/g" \
	-e "s/Template/${protoname}/g" \
	> ${dst} < ${src}
}

function copy_templates() {
    detect_h_dst="src/detect-${protoname_lower}-${buffername_lower}.h"
    detect_c_dst="src/detect-${protoname_lower}-${buffername_lower}.c"
    tests_detect_c_dst="src/tests/detect-${protoname_lower}-${buffername_lower}.c"

    fail_if_exists ${detect_h_dst}
    fail_if_exists ${detect_c_dst}
    fail_if_exists ${tests_detect_c_dst}

    copy_template_file "src/detect-template-buffer.h" ${detect_h_dst}
    copy_template_file "src/detect-template-buffer.c" ${detect_c_dst}
    copy_template_file "src/tests/detect-template-buffer.c" ${tests_detect_c_dst}
}

function patch() {
    filename="src/Makefile.am"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/^detect-template-buffer.c
t-
s/template-buffer/${protoname_lower}-${buffername_lower}/g
w
EOF

    filename="src/detect-engine-register.c"
    echo "Patching ${filename}."

    ed -s ${filename} > /dev/null <<EOF
/#include "detect-template-buffer.h"
t-
s/template-buffer/${protoname_lower}-${buffername_lower}/
w
EOF

    ed -s ${filename} > /dev/null <<EOF
/DetectTemplateBufferRegister
t-
s/TemplateBuffer/${protoname}${buffername}/
w
EOF

    filename="src/detect-engine-register.h"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/DETECT_AL_TEMPLATE_BUFFER
t-
s/TEMPLATE_BUFFER/${protoname_upper}_${buffername_upper}/
w
EOF
}

set_dir

protoname="$1"
buffername="$2"

if [ "${protoname}" = "" ] || [ "${buffername}" = "" ]; then
    usage
    exit 1
fi

# Make sure the protocol name looks like a proper name (starts with a
# capital letter).
case "${protoname}" in

    [[:upper:]]*)
	# OK.
	;;

    "")
	usage
	exit 1
	;;

    *)
	echo "error: protocol name must beging with an upper case letter"
	exit 1
	;;

esac

protoname_lower=$(printf ${protoname} | tr '[:upper:]' '[:lower:]')
protoname_upper=$(printf ${protoname} | tr '[:lower:]' '[:upper:]')
buffername_lower=$(printf ${buffername} | tr '[:upper:]' '[:lower:]')
buffername_upper=$(printf ${buffername} | tr '[:lower:]' '[:upper:]')

copy_templates
patch

cat <<EOF

The following files have been created and linked into the build:

    detect-${protoname_lower}-${buffername_lower}.h detect-${protoname_lower}-${buffername_lower}.c

        The setup for the content inspection sticky buffer keyword.

Please fix in src/detect.h the values for:
    SIG_MASK_REQUIRE_${protoname_upper}_STATE
    SIG_MASK_REQUIRE_TEMPLATE_STATE

EOF
