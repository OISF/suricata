LIBS =	\
		suricata/__init__.py \
		suricata/config/__init__.py

EXTRA_DIST = $(LIBS) suricata/config/defaults.py

if HAVE_PYTHON

install-exec-local:
	install -d -m 0755 "$(DESTDIR)$(prefix)/lib/suricata/python/suricata/config"
	install -m 0644 suricata/config/defaults.py \
		"$(DESTDIR)$(prefix)/lib/suricata/python/suricata/config/defaults.py"

uninstall-local:
	rm -rf $(DESTDIR)$(prefix)/lib/suricata/python

clean-local:
	find . -name \*.pyc -print0 | xargs -0 rm -f

endif
