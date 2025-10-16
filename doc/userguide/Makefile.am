EXTRA_DIST = \
	_static \
	3rd-party-integration \
	acknowledgements.rst \
	capture-hardware \
	command-line-options.rst \
	conf.py \
	configuration \
	devguide \
	file-extraction \
	index.rst \
	known-issues.rst \
	upgrade \
	upgrade.rst \
	initscripts.rst \
	install.rst \
	licenses \
	lua \
	make-sense-alerts.rst \
	manpages \
	output \
	partials \
	performance \
	public-data-sets.rst \
	quickstart.rst \
	reputation \
	rule-management \
	rules \
	security.rst \
	setting-up-ipsinline-for-linux \
	setting-up-ipsinline-for-linux.rst \
	setting-up-ipsinline-for-windows.rst \
	support-status.rst \
	unix-socket.rst \
	what-is-suricata.rst \
	verifying-source-files.rst

if HAVE_SURICATA_MAN
dist_man1_MANS = suricata.1 suricatasc.1 suricatactl.1 suricatactl-filestore.1
endif

if SPHINX_BUILD
dist_man1_MANS = suricata.1 suricatasc.1 suricatactl.1 suricatactl-filestore.1

if HAVE_PDFLATEX
EXTRA_DIST += userguide.pdf
endif

SPHINX_BUILD = sphinx-build -q

html:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -W -b html -d _build/doctrees \
		$(top_srcdir)/doc/userguide _build/html

_build/latex/Suricata.pdf:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -W -b latex -d _build/doctrees \
		$(top_srcdir)/doc/userguide _build/latex
# The Sphinx generated Makefile is GNU Make specific, so just do what
# it does here - yes, multiple passes of pdflatex is required.
	cd _build/latex && pdflatex Suricata.tex
	cd _build/latex && pdflatex Suricata.tex
	cd _build/latex && pdflatex Suricata.tex
	cd _build/latex && makeindex -s python.ist Suricata.idx
	cd _build/latex && pdflatex Suricata.tex
	cd _build/latex && pdflatex Suricata.tex

userguide.pdf: _build/latex/Suricata.pdf
	cp _build/latex/Suricata.pdf userguide.pdf

pdf: userguide.pdf

_build/man: manpages/suricata.rst manpages/suricatasc.rst manpages/suricatactl.rst manpages/suricatactl-filestore.rst
	RELEASE_DATE=$(RELEASE_DATE) \
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -W -b man -d _build/doctrees \
		$(top_srcdir)/doc/userguide _build/man
	touch _build/man

$(dist_man1_MANS): _build/man
	cp _build/man/$@ .

man: $(dist_man1_MANS)

# Remove build artifacts that aren't tracked by autotools.
clean-local:
	rm -rf $(top_builddir)/doc/userguide/_build
	rm -f $(top_builddir)/doc/userguide/suricata*.1
	rm -f $(top_builddir)/doc/userguide/userguide.pdf

endif # SPHINX_BUILD
