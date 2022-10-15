EXTRA_DIST= access-pkt-packet.cocci \
    banned-functions.cocci \
    direct-packet.cocci \
    malloc-error-check.cocci \
    pktnotset-packet.cocci \
    realloc.cocci \
    siginit.cocci \
    size_t.cocci \
    sz3.cocci \
    uint.cocci \
    run_check.sh struct-flags.py

if HAVE_COCCINELLE
struct-flags.cocci:
	$(srcdir)/struct-flags.py  $(top_srcdir)/src > $(top_builddir)/qa/coccinelle/struct-flags.cocci

check: struct-flags.cocci
	TOP_BUILDDIR=${abs_top_builddir} TOP_SRCDIR=$(abs_top_srcdir) $(top_srcdir)/qa/coccinelle/run_check.sh

distclean-local:
	-rm $(top_builddir)/qa/coccinelle/struct-flags.cocci
endif
