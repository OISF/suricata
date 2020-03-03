if HAVE_SURICATA_MAN
man1_MANS = suricata.1
endif

if HAVE_SPHINXBUILD
man1_MANS = suricata.1

if HAVE_PDFLATEX
EXTRA_DIST = $(man1_MANS) devguide.pdf
endif

SPHINX_BUILD = sphinx-build -q

html:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -W -b html -d _build/doctrees \
		$(top_srcdir)/doc/devguide _build/html

_build/latex/Suricata.pdf:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -W -b latex -d _build/doctrees \
		$(top_srcdir)/doc/devguide _build/latex
# The Sphinx generated Makefile is GNU Make specific, so just do what
# it does here - yes, multiple passes of pdflatex is required.
	cd _build/latex && pdflatex Suricata.tex
	cd _build/latex && pdflatex Suricata.tex
	cd _build/latex && pdflatex Suricata.tex
	cd _build/latex && makeindex -s python.ist Suricata.idx
	cd _build/latex && pdflatex Suricata.tex
	cd _build/latex && pdflatex Suricata.tex

devguide.pdf: _build/latex/Suricata.pdf
	cp _build/latex/Suricata.pdf devguide.pdf

pdf: devguide.pdf

_build/man/suricata.1:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -W -b man -d _build/doctrees \
		$(top_srcdir)/doc/devguide _build/man

suricata.1: _build/man/suricata.1
	cp _build/man/suricata.1 suricata.1

man: _build/man/suricata.1

# Remove build artifacts that aren't tracked by autotools.
clean-local:
	rm -rf $(top_builddir)/doc/devguide/_build
	rm -f $(top_builddir)/doc/devguide/suricata.1
	rm -f $(top_builddir)/doc/devguide/devguide.pdf

endif # HAVE_SPHINXBUILD
