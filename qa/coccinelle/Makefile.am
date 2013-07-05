EXTRA_DIST= access-pkt-packet.cocci \
    action-pkt.cocci \
    banned-functions.cocci \
    direct-packet.cocci \
    malloc-error-check.cocci \
    pktnotset-packet.cocci \
    size_t.cocci \
    struct-flags.cocci \
    sz3.cocci \
    run_check.sh struct-flags.py

struct-flags.cocci:
	$(srcdir)/struct-flags.py > $(top_builddir)/qa/coccinelle/struct-flags.cocci

if HAVE_COCCINELLE
check:
	$(top_srcdir)/qa/coccinelle/run_check.sh
endif

distclean-local:
	-rm $(top_builddir)/qa/coccinelle/struct-flags.cocci
