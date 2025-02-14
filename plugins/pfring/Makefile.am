pkglib_LTLIBRARIES = pfring.la

AM_CPPFLAGS = -I$(top_srcdir)/src -I@top_srcdir@/rust/gen -I@top_srcdir@/rust/dist

pfring_la_SOURCES = runmode-pfring.c source-pfring.c plugin.c
pfring_la_LDFLAGS = -module -avoid-version -shared
pfring_la_LIBADD = -lpfring

noinst_HEADERS = \
	runmode-pfring.h \
	source-pfring.h

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
