pkglib_LTLIBRARIES = ndpi.la

ndpi_la_LDFLAGS = -module -avoid-version -shared

ndpi_la_SOURCES = ndpi.c

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
