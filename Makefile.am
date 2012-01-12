# not a GNU package. You can remove this line, if
# have all needed files, that a GNU package needs
AUTOMAKE_OPTIONS = foreign 1.4
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = ChangeLog COPYING LICENSE suricata.yaml \
             classification.config \
             reference.config
if BUILD_LIBHTP
 HTP_DIR = libhtp
endif
SUBDIRS = $(HTP_DIR) src qa rules doc

