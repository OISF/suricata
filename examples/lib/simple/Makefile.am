bin_PROGRAMS = simple

simple_SOURCES = main.c

AM_CPPFLAGS = -I$(top_srcdir)/src

simple_LDFLAGS = $(all_libraries) $(SECLDFLAGS)
simple_LDADD = $(top_builddir)/src/libsuricata_c.a ../../$(RUST_SURICATA_LIB) $(RUST_LDADD)
simple_DEPENDENCIES = $(top_builddir)/src/libsuricata_c.a ../../$(RUST_SURICATA_LIB)
