bin_PROGRAMS = live

live_SOURCES = main.c

AM_CPPFLAGS = -I$(top_srcdir)/src

live_LDFLAGS = $(all_libraries) $(SECLDFLAGS)
live_LDADD = "-Wl,--start-group,$(top_builddir)/src/libsuricata_c.a,../../$(RUST_SURICATA_LIB),--end-group" $(RUST_LDADD)
live_DEPENDENCIES = $(top_builddir)/src/libsuricata_c.a ../../$(RUST_SURICATA_LIB)
