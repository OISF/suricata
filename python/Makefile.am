LIBS =	\
		suricata/__init__.py \
		suricata/config/__init__.py \
		suricata/ctl/__init__.py \
		suricata/ctl/filestore.py \
		suricata/ctl/loghandler.py \
		suricata/ctl/main.py \
		suricata/ctl/test_filestore.py \
		suricata/sc/__init__.py \
		suricata/sc/specs.py \
		suricata/sc/suricatasc.py \
		suricatasc/__init__.py

BINS =	\
		suricatasc \
		suricatactl

EXTRA_DIST = $(LIBS) bin suricata/config/defaults.py

if HAVE_PYTHON

install-exec-local:
	install -d -m 0755 "$(DESTDIR)$(prefix)/lib/suricata/python/suricata/config"
	install -d -m 0755 "$(DESTDIR)$(prefix)/lib/suricata/python/suricata/ctl"
	install -d -m 0755 "$(DESTDIR)$(prefix)/lib/suricata/python/suricata/sc"
	install -d -m 0755 "$(DESTDIR)$(prefix)/lib/suricata/python/suricatasc"
	install -d -m 0755 "$(DESTDIR)$(prefix)/bin"
	for src in $(LIBS); do \
		install $(srcdir)/$$src "$(DESTDIR)$(prefix)/lib/suricata/python/$$src"; \
	done
	install suricata/config/defaults.py \
		"$(DESTDIR)$(prefix)/lib/suricata/python/suricata/config/defaults.py"
	for bin in $(BINS); do \
		cat "$(srcdir)/bin/$$bin" | \
		    sed -e "1 s,.*,#"'!'" ${HAVE_PYTHON}," > "${DESTDIR}$(bindir)/$$bin"; \
		chmod 0755 "$(DESTDIR)$(bindir)/$$bin"; \
	done

uninstall-local:
	rm -f $(DESTDIR)$(bindir)/suricatactl
	rm -f $(DESTDIR)$(bindir)/suricatasc
	rm -rf $(DESTDIR)$(prefix)/lib/suricata/python

clean-local:
	find . -name \*.pyc -print0 | xargs -0 rm -f

endif
