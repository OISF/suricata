bin_PROGRAMS = suricata_client

# Set the include path.
AM_CPPFLAGS = -I$(top_srcdir)/src

suricata_client_SOURCES = main.c

# The library search path.
suricata_client_LDFLAGS = $(all_libraries) ${SECLDFLAGS} -Wl,--whole-archive,$(top_builddir)/src/libsuricata_c.a,--no-whole-archive
suricata_client_LDADD = ../$(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)
