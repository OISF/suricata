EXTRA_DIST = \
	conf.py \
	index.rst \
	acknowledgements.rst \
	oinkmaster.rst \
	snort-compatibility.rst \
	command-line-options.rst \
	initscripts.rst \
	public-data-sets.rst \
	what-is-suricata.rst \
	dropping-privileges.rst \
	make-sense-alerts.rst \
	setting-up-ipsinline-for-linux.rst \
	capture-hardware \
	configuration \
	file-extraction \
	licenses \
	man \
	oinkmaster \
	output \
	performance \
	reputation \
	rules \
	setting-up-ipsinline-for-linux

if HAVE_SPHINXBUILD
man1_MANS = _build/man/suricata.1

html:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		sphinx-build -b html -d _build/doctrees \
		$(top_srcdir)/doc/userguide _build/html

_build/man/suricata.1:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		sphinx-build -b man -d _build/doctrees \
		$(top_srcdir)/doc/userguide _build/man

clean-local:
	rm -rf $(top_builddir)/doc/userguide/_build
endif
