#! /bin/sh
#
# Script to provision a new application layer detector and parser.

set -e

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

function copy_app_layer_templates {
    dest_h="src/app-layer-${protoname_lower}.h"
    dest_c="src/app-layer-${protoname_lower}.c"

    if [ -e "${dest_h}" ]; then
	echo "error: file exists: ${dest_h}"
	exit 1
    fi

    if [ -e "${dest_c}" ]; then
	echo "error: file exists: ${dest_c}"
	exit 1
    fi

    echo "Copying src/app-layer-template.h -> ${dest_h}."
    cp src/app-layer-template.h ${dest_h}
    echo "Patching ${dest_h}."
    sed -i "s/TEMPLATE/${protoname_upper}/g" ${dest_h}
    sed -i "s/template/${protoname_lower}/g" ${dest_h}
    sed -i "s/Template/${protoname}/g" ${dest_h}

    echo "Copying src/app-layer-template.c -> ${dest_c}."
    cp src/app-layer-template.c ${dest_c}
    echo "Patching ${dest_h}."
    sed -i "s/TEMPLATE/${protoname_upper}/g" ${dest_c}
    sed -i "s/template/${protoname_lower}/g" ${dest_c}
    sed -i "s/Template/${protoname}/g" ${dest_c}
}

function patch_makefile_am {
    filename="src/Makefile.am"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/app-layer-template
.y
-
x
s/template/${protoname_lower}/g
w
EOF
}

function patch_app_layer_protos_h {
    filename="src/app-layer-protos.h"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/ALPROTO_TEMPLATE
.y
x
s/TEMPLATE/${protoname_upper}/
w
EOF
}

function patch_app_layer_protos_c {
    filename="src/app-layer-protos.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/case ALPROTO_TEMPLATE
.,+2y
-
x
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
.,+y
-x
-,.s/TEMPLATE/${protoname_upper}/
+3
/== ALPROTO_TEMPLATE
.,+y
-x
-,.s/TEMPLATE/${protoname_upper}/
w
EOF
}

function patch_app_layer_parser_c() {
    filename="src/app-layer-parser.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/#include "app-layer-template.h"
.y
-
x
s/template/${protoname_lower}/
/RegisterTemplateParsers
.y
-
x
s/Template/${protoname}/
w
EOF
}

function patch_suricata_yaml_in() {
    filename="suricata.yaml.in"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/app-layer
/template
.,+y
-
x
-
s/template/${protoname_lower}
w
EOF
}

protoname="$1"

if [ "${protoname}" = "" ]; then
    usage
    exit 1
fi

protoname_lower=${protoname,,}
protoname_upper=${protoname^^}

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
