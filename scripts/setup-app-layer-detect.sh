#! /usr/bin/env bash
#
# Script to provision a new application layer detector and parser.

set -e

function usage() {
    cat <<EOF

usage: $0 <protocol name>

This script will provision content inspection for app-layer decoded
buffers.

Examples:

    $0 DNP3
    $0 Gopher

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
	-e "s/TEMPLATE/${protoname_upper}/g" \
	-e "s/template/${protoname_lower}/g" \
	-e "s/Template/${protoname}/g" \
	> ${dst} < ${src}
}

function copy_templates() {
    detect_h_dst="src/detect-${protoname_lower}-buffer.h"
    detect_c_dst="src/detect-${protoname_lower}-buffer.c"
    detect_engine_h_dst="src/detect-engine-${protoname_lower}.h"
    detect_engine_c_dst="src/detect-engine-${protoname_lower}.c"

    fail_if_exists ${detect_h_dst}
    fail_if_exists ${detect_c_dst}
    fail_if_exists ${detect_engine_h_dst}
    fail_if_exists ${detect_engine_c_dst}

    copy_template_file "src/detect-template-buffer.h" ${detect_h_dst}
    copy_template_file "src/detect-template-buffer.c" ${detect_c_dst}
    copy_template_file "src/detect-engine-template.h" ${detect_engine_h_dst}
    copy_template_file "src/detect-engine-template.c" ${detect_engine_c_dst}
}

function patch_makefile_am() {
    filename="src/Makefile.am"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/^detect-engine-template.c
t-
s/template/${protoname_lower}/g
/^detect-template-buffer.c
t-
s/template/${protoname_lower}/g
w
EOF
}

function patch_detect_engine_content_inspection_h() {
    filename="src/detect-engine-content-inspection.h"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/DETECT_ENGINE_CONTENT_INSPECTION_MODE_TEMPLATE_BUFFER
t-
s/TEMPLATE/${protoname_upper}/
w
EOF
}

function patch_detect_engine_state_h() {
    filename="src/detect-engine-state.h"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/#define DE_STATE_FLAG_TEMPLATE_BUFFER_INSPECT
t-
s/TEMPLATE/${protoname_upper}/
w
EOF
}

function patch_detect_engine_c() {
    filename="src/detect-engine.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/#include "detect-engine-template.h"
t-
s/template/${protoname_lower}/
w
/ALPROTO_TEMPLATE
-2
.,+6t-
-6
.,+6s/Template/${protoname}/g
-6
.,+6s/TEMPLATE/${protoname_upper}/g
+6
/ALPROTO_TEMPLATE
-2
.,+6t-
-6
.,+6s/Template/${protoname}/g
-6
.,+6s/TEMPLATE/${protoname_upper}/g
w
EOF

    ed -s ${filename} > /dev/null <<EOF
/case DETECT_SM_LIST_TEMPLATE_BUFFER_MATCH
.,+1t-
-
s/TEMPLATE/${protoname_upper}/g
+
s/template/${protoname_lower}/g
w
EOF
}

function patch_detect_parse_c() {
    filename="src/detect-parse.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/\/\* Template\. \*\/
.,+4t-
-4s/Template/${protoname}/g
+1s/TEMPLATE/${protoname_upper}/g
w
EOF
}

function patch_detect_c() {
    filename="src/detect.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/#include "detect-template-buffer.h"
t-
s/template/${protoname_lower}/
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
s/Template/${protoname}/
w
EOF
}

function patch_detect_h() {
    filename="src/detect.h"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/DETECT_SM_LIST_TEMPLATE_BUFFER_MATCH
t-
s/TEMPLATE/${protoname_upper}/
/SIG_MASK_REQUIRE_TEMPLATE_STATE
t-
s/TEMPLATE/${protoname_upper}/
/DETECT_AL_TEMPLATE_BUFFER
t-
s/TEMPLATE/${protoname_upper}/
w
EOF
}

protoname="$1"

if [ "${protoname}" = "" ]; then
    usage
    exit 1
fi

protoname_lower=$(printf ${protoname} | tr '[:upper:]' '[:lower:]')
protoname_upper=$(printf ${protoname} | tr '[:lower:]' '[:upper:]')

copy_templates
patch_makefile_am
patch_detect_engine_content_inspection_h
patch_detect_engine_state_h
patch_detect_engine_c
patch_detect_parse_c
patch_detect_c
patch_detect_h

cat <<EOF

The following files have been created and linked into the build:

    detect-${protoname_lower}-buffer.h detect-${protoname_lower}-buffer.c

        The setup for the content inspection modifier keyword.

    detect-engine-${protoname_lower}.h detect-engine-${protoname_lower}.c

        The content inspection engine.

Please fix in src/detect-engine-state.h the values for:
    DE_STATE_FLAG_${protoname_upper}_BUFFER_INSPECT
    DE_STATE_FLAG_TEMPLATE_BUFFER_INSPECT

Please fix in src/detect.h the values for:
    SIG_MASK_REQUIRE_${protoname_upper}_STATE
    SIG_MASK_REQUIRE_TEMPLATE_STATE

EOF
