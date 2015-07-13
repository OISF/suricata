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
    src_h="src/output-json-template.h"
    dst_h="src/output-json-${protoname_lower}.h"
    src_c="src/output-json-template.c"
    dst_c="src/output-json-${protoname_lower}.c"

    fail_if_exists ${dst_h}
    fail_if_exists ${dst_c}

    copy_template_file ${src_h} ${dst_h}
    copy_template_file ${src_c} ${dst_c}
}

function patch_makefile_am() {
    filename="src/Makefile.am"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/output-json-template.c
t-
s/template/${protoname_lower}/g
w
EOF
}

function patch_suricata_c() {
    filename="src/suricata.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/#include "output-json-template.h"
t-
s/template/${protoname_lower}/
/TmModuleJsonTemplateLogRegister
-
.,+t-
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
t-
s/TEMPLATE/${protoname_upper}
w
EOF
}

patch_tm_threads_common_h() {
    filename="src/tm-threads-common.h"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/TMM_JSONTEMPLATELOG
t-
s/TEMPLATE/${protoname_upper}
w
EOF
}

patch_suricata_yaml_in() {
    filename="suricata.yaml.in"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/eve-log:
/types:
a
        - ${protoname_lower}
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
${protoname} has now been set in the files:

    src/output-json-${protoname_lower}.h
    src/output-json-${protoname_lower}.c

and should now build cleanly. Try running 'make'.

EOF
