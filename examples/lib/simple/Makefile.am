bin_PROGRAMS = simple

simple_SOURCES = main.c

# Sources for the capture and runmode.
simple_SOURCES += source.c runmode.c

# Custom EVE output.
simple_SOURCES += output.c

AM_CPPFLAGS = -I$(top_srcdir)/src

simple_LDFLAGS = $(all_libraries) $(SECLDFLAGS)
simple_LDADD = $(top_builddir)/src/libsuricata_c.a ../../$(RUST_SURICATA_LIB) $(RUST_LDADD)
if HTP_LDADD
simple_LDADD += ../../$(HTP_LDADD)
endif
simple_DEPENDENCIES = $(top_builddir)/src/libsuricata_c.a ../../$(RUST_SURICATA_LIB)
