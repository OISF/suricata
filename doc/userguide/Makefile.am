if HAVE_SPHINXBUILD
man1_MANS = _build/man/suricata.1

html:
	$(MAKE) -f Makefile.sphinx html

_build/man/suricata.1:
	$(MAKE) -f Makefile.sphinx man

distclean-local:
	rm -rf $(top_builddir)/doc/sphinx/_build
endif
