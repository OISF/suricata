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
	manpages \
	oinkmaster \
	output \
	performance \
	reputation \
	rules \
	setting-up-ipsinline-for-linux

if HAVE_SPHINXBUILD
man1_MANS = _build/man/suricata.1

SPHINX_BUILD = sphinx-build -q

html:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -b html -d _build/doctrees \
		$(top_srcdir)/doc/userguide _build/html

pdf:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -b latex -d _build/doctrees \
		$(top_srcdir)/doc/userguide _build/latex
	cd _build/latex && $(MAKE) all-pdf

_build/man/suricata.1:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -b man -d _build/doctrees \
		$(top_srcdir)/doc/userguide _build/man
man: _build/man/suricata.1

clean-local:
	rm -rf $(top_builddir)/doc/userguide/_build
endif
