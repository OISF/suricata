if HAVE_PYTHON
if HAVE_PYTHON_DISTUTILS
if HAVE_PYTHON_YAML

install-exec-local:
	cd $(srcdir) && \
		$(HAVE_PYTHON) setup.py build --build-base $(abs_builddir) \
		install --prefix $(DESTDIR)$(prefix)

uninstall-local:
	rm -f $(DESTDIR)$(bindir)/suricata-update
	rm -rf $(DESTDIR)$(prefix)/lib*/python*/site-packages/suricata-update
	rm -rf $(DESTDIR)$(prefix)/lib*/python*/site-packages/suricata_update-[0-9]*.egg-info

clean-local:
	cd $(srcdir) && \
		$(HAVE_PYTHON) setup.py clean \
		--build-base $(abs_builddir)
	rm -rf scripts-* lib* build
	find . -name \*.pyc -print0 | xargs -0 rm -f

distclean-local:

endif
endif
endif
