pkglib_LTLIBRARIES = pfring.la

pfring_la_SOURCES = runmode-pfring.c source-pfring.c plugin.c
pfring_la_LDFLAGS = -module -avoid-version -shared
pfring_la_LIBADD = -lpfring

noinst_HEADERS = \
	runmode-pfring.h \
	source-pfring.h

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
