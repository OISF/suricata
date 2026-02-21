bin_PROGRAMS = bench_content_inspect

bench_content_inspect_SOURCES = main.c

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/rust/gen

bench_content_inspect_LDFLAGS = $(all_libraries) $(SECLDFLAGS)
bench_content_inspect_LDADD = "-Wl,--start-group,$(top_builddir)/src/libsuricata_c.a,../../$(RUST_SURICATA_LIB),--end-group" $(RUST_LDADD)
bench_content_inspect_DEPENDENCIES = $(top_builddir)/src/libsuricata_c.a ../../$(RUST_SURICATA_LIB)
