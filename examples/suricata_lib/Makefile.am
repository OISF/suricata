bin_PROGRAMS = suricata_client

# Set the include path.
AM_CPPFLAGS = -I$(top_srcdir)/src
AM_CPPFLAGS += -I$(top_srcdir)/rust/gen

suricata_client_SOURCES = callbacks.c \
                          preload.c \
                          main.c

noinst_HEADERS = callbacks.h \
                 preload.h

# The library search path.
suricata_client_LDADD = $(top_builddir)/src/.libs/libsuricata.la -lm

if !BUILD_SHARED_LIBRARY
suricata_client_LDFLAGS = -Wl,--whole-archive,../$(RUST_SURICATA_LIB),--no-whole-archive
endif