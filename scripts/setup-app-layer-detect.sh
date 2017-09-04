#! /usr/bin/env bash
#
# Script to provision a new application layer detector and parser.

set -e

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

    fail_if_exists ${detect_h_dst}
    fail_if_exists ${detect_c_dst}

    copy_template_file "src/detect-template-buffer.h" ${detect_h_dst}
    copy_template_file "src/detect-template-buffer.c" ${detect_c_dst}
}

function patch_makefile_am() {
    filename="src/Makefile.am"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/^detect-template-buffer.c
t-
s/template-buffer/${protoname_lower}-${buffername_lower}/g
w
EOF
}

function patch_detect_c() {
    filename="src/detect.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/#include "detect-template-buffer.h"
t-
s/template-buffer/${protoname_lower}-${buffername_lower}/
/case ALPROTO_TEMPLATE
.,+3t-
-3
s/ALPROTO_TEMPLATE/ALPROTO_${protoname_upper}/g
+
s/template/${protoname_lower}/g
+
s/TEMPLATE/${protoname_upper}/g
+2
/ALPROTO_TEMPLATE
.,+3t-
-3
.,+s/TEMPLATE/${protoname_upper}/g
+
s/template/${protoname_lower}/g
+3
/SIG_MASK_REQUIRE_TEMPLATE_STATE
.t-
s/TEMPLATE/${protoname_upper}/g
/DetectTemplateBufferRegister
t-
s/TemplateBuffer/${protoname}${buffername}/
w
EOF
}

function patch_detect_h() {
    filename="src/detect.h"
    echo "Patching ${filename}."
    if [ $(grep -c SIG_MASK_REQUIRE_${protoname_upper}_STATE ${filename}) -eq 0 ]; then
        ed -s ${filename} > /dev/null <<EOF
/SIG_MASK_REQUIRE_TEMPLATE_STATE
t-
s/TEMPLATE/${protoname_upper}/
w
EOF
    fi
    ed -s ${filename} > /dev/null <<EOF
/DETECT_AL_TEMPLATE_BUFFER
t-
s/TEMPLATE_BUFFER/${protoname_upper}_${buffername_upper}/
w
EOF
}

protoname="$1"
buffername="$2"

if [ "${protoname}" = "" ] || [ "${buffername}" = "" ]; then
    usage
    exit 1
fi

protoname_lower=$(printf ${protoname} | tr '[:upper:]' '[:lower:]')
protoname_upper=$(printf ${protoname} | tr '[:lower:]' '[:upper:]')
buffername_lower=$(printf ${buffername} | tr '[:upper:]' '[:lower:]')
buffername_upper=$(printf ${buffername} | tr '[:lower:]' '[:upper:]')

copy_templates
patch_makefile_am
patch_detect_c
patch_detect_h

cat <<EOF

The following files have been created and linked into the build:

    detect-${protoname_lower}-${buffername_lower}.h detect-${protoname_lower}-${buffername_lower}.c

        The setup for the content inspection sticky buffer keyword.

Please fix in src/detect.h the values for:
    SIG_MASK_REQUIRE_${protoname_upper}_STATE
    SIG_MASK_REQUIRE_TEMPLATE_STATE

EOF
