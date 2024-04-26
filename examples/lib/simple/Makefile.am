bin_PROGRAMS = simple

simple_SOURCES = main.c

AM_CPPFLAGS = -I$(top_srcdir)/src

simple_LDFLAGS = $(all_libraries) $(SECLDFLAGS)
simple_LDADD = "-Wl,--start-group,$(top_builddir)/src/libsuricata_c.a,../../$(RUST_SURICATA_LIB),--end-group" $(RUST_LDADD)
if HTP_LDADD
simple_LDADD += ../../$(HTP_LDADD)
endif
simple_DEPENDENCIES = $(top_builddir)/src/libsuricata_c.a ../../$(RUST_SURICATA_LIB)
