if HAVE_SPHINXBUILD
man1_MANS = _build/man/suricata.1

html:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
		sphinx-build -b html -d _build/doctrees . _build/html

_build/man/suricata.1:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
		sphinx-build -b man -d _build/doctrees . _build/man

clean-local:
	rm -rf $(top_builddir)/doc/userguide/_build
endif
