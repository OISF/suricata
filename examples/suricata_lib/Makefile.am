bin_PROGRAMS = suricata_client

# Set the include path.
AM_CPPFLAGS = -I$(top_srcdir)/src

suricata_client_SOURCES = main.c

# The library search path.
suricata_client_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
suricata_client_LDADD = $(top_builddir)/src/libsuricata_c.a ../$(RUST_SURICATA_LIB) ../$(HTP_LDADD) $(RUST_LDADD)
suricata_client_DEPENDENCIES = $(top_builddir)/src/libsuricata_c.a ../$(RUST_SURICATA_LIB)