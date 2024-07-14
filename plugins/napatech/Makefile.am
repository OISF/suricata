pkglib_LTLIBRARIES = napatech.la

napatech_la_SOURCES = runmode-napatech.c source-napatech.c util-napatech.c plugin.c
napatech_la_LDFLAGS = -module -avoid-version -shared
napatech_la_LIBADD = -lntapi

noinst_HEADERS = \
	runmode-napatech.h \
	source-napatech.h \
	util-napatech.h

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
