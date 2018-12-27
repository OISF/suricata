EXTRA_DIST= access-pkt-packet.cocci \
    action-pkt.cocci \
    banned-functions.cocci \
    direct-packet.cocci \
    malloc-error-check.cocci \
    pktnotset-packet.cocci \
    realloc.cocci \
    siginit.cocci \
    size_t.cocci \
    struct-flags.cocci \
    sz3.cocci \
    uint.cocci \
    run_check.sh struct-flags.py

if HAVE_COCCINELLE
struct-flags.cocci:
	$(srcdir)/struct-flags.py > $(top_builddir)/qa/coccinelle/struct-flags.cocci

check:
	TOP_SRCDIR=$(abs_top_srcdir) $(top_srcdir)/qa/coccinelle/run_check.sh

distclean-local:
	-rm $(top_builddir)/qa/coccinelle/struct-flags.cocci
endif
