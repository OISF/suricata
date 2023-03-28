bin_PROGRAMS = suricata_client

# Set the include path.
AM_CPPFLAGS = -I$(top_srcdir)/src
AM_CPPFLAGS += -I$(top_srcdir)/rust/gen

# Handle bundled htp.
if BUNDLED_HTP
HTP_LIB = ../$(HTP_LDADD)
AM_CPPFLAGS += -I$(top_srcdir)/libhtp
endif

suricata_client_SOURCES = callbacks.c \
                          eve.c \
                          preload.c \
                          main.c

include_HEADERS = callbacks.h \
                  eve.h \
                  preload.h

# The library search path.
suricata_client_LDFLAGS = $(all_libraries) ${SECLDFLAGS} -Wl,--whole-archive,$(top_builddir)/src/libsuricata_c.a,--no-whole-archive
suricata_client_LDADD = ../$(RUST_SURICATA_LIB) $(HTP_LIB) $(RUST_LDADD)
