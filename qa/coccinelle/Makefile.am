EXTRA_DIST= access-pkt-packet.cocci banned-functions.cocci direct-packet.cocci \
		pktnotset-packet.cocci run_check.sh

if HAVE_COCCINELLE
check:
	$(top_srcdir)/qa/coccinelle/run_check.sh
endif
