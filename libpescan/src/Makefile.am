h_sources=libpescan.h
c_sources=libpescan.c

library_includedir = $(includedir)/$(GENERIC_LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

INCLUDES = -I$(top_srcdir)
AM_CFLAGS = -D_GNU_SOURCE -g -O2 -Wall -Wextra -std=gnu99 -pedantic

ACLOCAL_AMFLAGS=-I m4

lib_LTLIBRARIES=libpescan.la
libpescan_la_SOURCES=$(h_sources) $(c_sources)
libpescan_la_LDFLAGS= -version-info $(GENERIC_LIBRARY_VERSION) -release $(GENERIC_RELEASE)
