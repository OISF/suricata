#! /bin/sh
#
# Script to provision a new application layer detector and parser.

set -e
#set -x

function usage() {
    cat <<EOF

usage: $0 <protocol name>

This script will provision a new app-layer parser for the protocol
name specified on the command line. This is done by copying and
patching src/app-layer-template.[ch] then linking the new files into
the build system.

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

function copy_app_layer_templates {
    src_h="src/app-layer-template.h"
    dst_h="src/app-layer-${protoname_lower}.h"
    src_c="src/app-layer-template.c"
    dst_c="src/app-layer-${protoname_lower}.c"

    fail_if_exists ${dst_h}
    fail_if_exists ${dst_c}

    copy_template_file ${src_h} ${dst_h}
    copy_template_file ${src_c} ${dst_c}
}

function patch_makefile_am {
    filename="src/Makefile.am"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/app-layer-template
t-
s/template/${protoname_lower}/g
w
EOF
}

function patch_app_layer_protos_h {
    filename="src/app-layer-protos.h"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/ALPROTO_TEMPLATE
t-
s/TEMPLATE/${protoname_upper}/
w
EOF
}

function patch_app_layer_protos_c {
    filename="src/app-layer-protos.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/case ALPROTO_TEMPLATE
.,+2t-
-2
s/TEMPLATE/${protoname_upper}/
+
s/template/${protoname_lower}/
w
EOF
}

function patch_app_layer_detect_proto_c() {
    filename="src/app-layer-detect-proto.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/== ALPROTO_TEMPLATE
.,+t-
-,.s/TEMPLATE/${protoname_upper}/
+3
/== ALPROTO_TEMPLATE
.,+t-
-,.s/TEMPLATE/${protoname_upper}/
+3
w
EOF
}

function patch_app_layer_parser_c() {
    filename="src/app-layer-parser.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/#include "app-layer-template.h"
t-
s/template/${protoname_lower}/
/RegisterTemplateParsers
t-
s/Template/${protoname}/
w
EOF
}

function patch_suricata_yaml_in() {
    filename="suricata.yaml.in"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/^app-layer:
/protocols:
a
    ${protoname_lower}:
      enabled: yes
.
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

copy_app_layer_templates
patch_makefile_am
patch_app_layer_protos_h
patch_app_layer_protos_c
patch_app_layer_detect_proto_c
patch_app_layer_parser_c
patch_suricata_yaml_in

cat <<EOF

An application detector and parser for the protocol ${protoname} has
now been setup in the files:

    src/app-layer-${protoname_lower}.h
    src/app-layer-${protoname_lower}.c

and should now build cleanly. Try running 'make'.

EOF
