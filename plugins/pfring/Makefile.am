pkglib_LTLIBRARIES = pfring.la

pfring_la_SOURCES = runmode-pfring.c source-pfring.c plugin.c
pfring_la_LDFLAGS = -module -avoid-version -shared
pfring_la_LIBADD = -lpfring

noinst_HEADERS = \
	runmode-pfring.h \
	source-pfring.h

# default CFLAGS
AM_CFLAGS = ${OPTIMIZATION_CFLAGS} ${GCC_CFLAGS} ${CLANG_CFLAGS}            \
    ${SECCFLAGS} ${PCAP_CFLAGS} ${EXTRA_CFLAGS}                                                         \
    -Wall -Wno-unused-parameter -Wmissing-prototypes -Wmissing-declarations \
    -Wstrict-prototypes -Wwrite-strings -Wbad-function-cast                 \
    -Wformat-security -Wno-format-nonliteral -Wmissing-format-attribute     \
    -funsigned-char

# different flags for different cases
if DEBUG
AM_CFLAGS += -ggdb -O0
endif

AM_LDFLAGS = ${SECLDFLAGS}

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
