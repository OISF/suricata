EXTRA_DIST = \
	conf.py \
	_static \
	index.rst \
	extending/detect/index.rst \
	extending/decoder/index.rst \
	extending/index.rst \
	extending/app-layer/index.rst \
	extending/app-layer/app-layer-frames.rst \
	extending/app-layer/parser.rst \
	extending/app-layer/transactions.rst \
	extending/app-layer/diagrams \
	extending/app-layer/img \
	extending/capture/index.rst \
	extending/output/index.rst \
	internals/engines/index.rst \
	internals/threading/index.rst \
	internals/index.rst \
	internals/pipeline/index.rst \
	internals/datastructs/index.rst \
	codebase/index.rst \
	codebase/code-style.rst \
	codebase/contributing/code-submission-process.rst \
	codebase/contributing/index.rst \
	codebase/fuzz-testing.rst \
	codebase/testing.rst \
	codebase/unittests-c.rst \
	codebase/unittests-rust.rst

if HAVE_SPHINXBUILD
if HAVE_MSCGEN

if HAVE_PDFLATEX
EXTRA_DIST += devguide.pdf
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

# Remove build artifacts that aren't tracked by autotools.
clean-local:
	rm -rf $(top_builddir)/doc/devguide/_build
	rm -f $(top_builddir)/doc/devguide/suricata.1
	rm -f $(top_builddir)/doc/devguide/devguide.pdf

endif # HAVE_MSCGEN
endif # HAVE_SPHINXBUILD
