bin_PROGRAMS = custom

custom_SOURCES = main.c

AM_CPPFLAGS = -I$(top_srcdir)/src

custom_LDFLAGS = $(all_libraries) $(SECLDFLAGS)
custom_LDADD = "-Wl,--start-group,$(top_builddir)/src/libsuricata_c.a,../../$(RUST_SURICATA_LIB),--end-group" $(RUST_LDADD)
custom_DEPENDENCIES = $(top_builddir)/src/libsuricata_c.a ../../$(RUST_SURICATA_LIB)
