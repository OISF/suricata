bin_PROGRAMS = libcapture

libcapture_SOURCES = main.c

AM_CPPFLAGS = -I$(top_srcdir)/src

libcapture_LDFLAGS = $(all_libraries) $(SECLDFLAGS)
libcapture_LDADD = $(top_builddir)/src/libsuricata_c.a ../../$(RUST_SURICATA_LIB) $(RUST_LDADD)
if HTP_LDADD
libcapture_LDADD += ../../$(HTP_LDADD)
endif
libcapture_DEPENDENCIES = $(top_builddir)/src/libsuricata_c.a ../../$(RUST_SURICATA_LIB)
