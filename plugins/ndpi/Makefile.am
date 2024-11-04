pkglib_LTLIBRARIES = ndpi.la

ndpi_la_LDFLAGS = -module -avoid-version -shared
ndpi_la_LIBADD = @NDPI_LIB@

# Only required to find these headers when building plugins from the
# source directory.
ndpi_la_CFLAGS = -I../../rust/gen -I../../rust/dist

ndpi_la_SOURCES = ndpi.c

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
