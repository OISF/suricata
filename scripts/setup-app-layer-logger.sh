#! /bin/sh

set -e

function usage() {
    cat <<EOF

usage: $0 <protocol name>

This script will provision a new JSON application layer transaction
logger for the protocol name specified on the command line. This is
done by copying and patching src/output-json-template.h and
src/output-json-template.c then link the new files into the build
system.

It is required that the application layer parser has already been
provisioned by the setup-app-layer.sh script.

Examples:

    $0 DNP3
    $0 Gopher

EOF
}

function copy_templates() {
    src_h="src/output-json-template.h"
    src_c="src/output-json-template.c"

    dest_h="src/output-json-${protoname_lower}.h"
    dest_c="src/output-json-${protoname_lower}.c"

    if [ -e "${dest_h}" ]; then
	echo "error: file exists: ${dest_h}"
	exit 1
    fi

    if [ -e "${dest_c}" ]; then
	echo "error: file exists: ${dest_c}"
	exit 1
    fi

    echo "Copying ${src_h} to ${dest_h}."
    cp ${src_h} ${dest_h}

    echo "Copying ${src_c} to ${dest_c}."
    cp ${src_c} ${dest_c}

    echo "Patching ${dest_h}."
    sed -i "s/TEMPLATE/${protoname_upper}/g" ${dest_h}
    sed -i "s/template/${protoname_lower}/g" ${dest_h}
    sed -i "s/Template/${protoname}/g" ${dest_h}

    echo "Patching ${dest_c}."
    sed -i "s/TEMPLATE/${protoname_upper}/g" ${dest_c}
    sed -i "s/template/${protoname_lower}/g" ${dest_c}
    sed -i "s/Template/${protoname}/g" ${dest_c}
}

function patch_makefile_am() {
    filename="src/Makefile.am"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/output-json-template.c
.y
-
x
s/template/${protoname_lower}/
w
EOF
}

function patch_suricata_c() {
    filename="src/suricata.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/#include "output-json-template.h"
.y
-
x
s/template/${protoname_lower}/
/TmModuleJsonTemplateLogRegister
-
.,+y
-
x
-
.,+s/Template/${protoname}/
w
EOF
}

patch_tm_modules_c() {
    filename="src/tm-modules.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/TMM_JSONTEMPLATELOG
y
-
x
s/TEMPLATE/${protoname_upper}
w
EOF
}

patch_tm_threads_common_h() {
    filename="src/tm-threads-common.h"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/TMM_JSONTEMPLATELOG
y
-
x
s/TEMPLATE/${protoname_upper}
w
EOF
}

patch_suricata_yaml_in() {
    filename="suricata.yaml.in"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/eve-log
/- template
y
-
x
s/template/${protoname_lower}/
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

# Requires that the protocol has already been setup.
if ! grep -q "ALPROTO_${protoname_upper}" src/app-layer-protos.h; then
    echo "error: no app-layer parser exists for ALPROTO_${protoname_upper}."
    exit 1
fi

copy_templates
patch_makefile_am
patch_suricata_c
patch_tm_modules_c
patch_tm_threads_common_h
patch_suricata_yaml_in

cat <<EOF

A JSON application layer transaction logger for the protocol
${protoname} has not been set in the files:

    src/output-json-${protoname_lower}.h
    src/output-json-${protoname_lower}.c

and should now build cleanly. Try running 'make'.

EOF
