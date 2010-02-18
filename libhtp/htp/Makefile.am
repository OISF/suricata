
h_sources = bstr.h dslib.h hooks.h htp.h utf8_decoder.h htp_decompressors.h
c_sources = bstr.c hooks.c htp_config.c htp_connection_parser.c htp_request_apache_2_2.c htp_request_generic.c htp_request_parsers.c htp_response_generic.c htp_util.c dslib.c htp.c htp_connection.c htp_parsers.c htp_request.c htp_response.c htp_transaction.c utf8_decoder.c htp_decompressors.c

library_includedir = $(includedir)/$(GENERIC_LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

INCLUDES = -I$(top_srcdir)
AM_CFLAGS = -D_GNU_SOURCE -g -O2 -Wall -Wextra -std=gnu99 -pedantic

lib_LTLIBRARIES= libhtp.la
libhtp_la_SOURCES= $(h_sources) $(c_sources)
libhtp_la_LDFLAGS= -version-info $(GENERIC_LIBRARY_VERSION) -release $(GENERIC_RELEASE)

