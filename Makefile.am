# not a GNU package. You can remove this line, if
# have all needed files, that a GNU package needs
AUTOMAKE_OPTIONS = foreign 1.4
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = ChangeLog COPYING LICENSE suricata.yaml.in \
             classification.config threshold.config \
             reference.config
SUBDIRS = $(HTP_DIR) src qa rules doc contrib scripts

CLEANFILES = stamp-h[0-9]*

install-data-am:
	@echo "Run 'make install-conf' if you want to install initial configuration files. Or 'make install-full' to install configuration and rules";

install-full: install install-conf install-rules

install-conf:
	install -d "$(DESTDIR)$(e_sysconfdir)"
	@test -e "$(DESTDIR)$(e_sysconfdir)/suricata.yaml" || install -m 600 "$(top_srcdir)/suricata.yaml" "$(DESTDIR)$(e_sysconfdir)"
	@test -e "$(DESTDIR)$(e_sysconfdir)/classification.config" || install -m 600 "$(top_srcdir)/classification.config" "$(DESTDIR)$(e_sysconfdir)"
	@test -e "$(DESTDIR)$(e_sysconfdir)/reference.config" || install -m 600 "$(top_srcdir)/reference.config" "$(DESTDIR)$(e_sysconfdir)"
	@test -e "$(DESTDIR)$(e_sysconfdir)/threshold.config" || install -m 600 "$(top_srcdir)/threshold.config" "$(DESTDIR)$(e_sysconfdir)"
	install -d "$(DESTDIR)$(e_logfilesdir)"
	install -d "$(DESTDIR)$(e_logcertsdir)"
	install -d "$(DESTDIR)$(e_rundir)"
	install -m 770 -d "$(DESTDIR)$(e_localstatedir)"

install-rules:
	install -d "$(DESTDIR)$(e_sysconfrulesdir)"
if HAVE_FETCH_COMMAND
if HAVE_WGET_COMMAND
	$(HAVE_WGET) -qO - http://rules.emergingthreats.net/open/suricata-2.0/emerging.rules.tar.gz | tar -x -z -C "$(DESTDIR)$(e_sysconfdir)" -f -
else
	$(HAVE_CURL) -s http://rules.emergingthreats.net/open/suricata-2.0/emerging.rules.tar.gz | tar -x -z -C "$(DESTDIR)$(e_sysconfdir)" -f -
endif
else
	@echo "UNABLE to load ruleset wget or curl are not installed on system."
endif
	@test -e "$(DESTDIR)$(e_sysconfrulesdir)decoder-events.rules" || install -m 600 "$(top_srcdir)/rules/decoder-events.rules" "$(DESTDIR)$(e_sysconfrulesdir)"
	@test -e "$(DESTDIR)$(e_sysconfrulesdir)stream-events.rules" || install -m 600 "$(top_srcdir)/rules/stream-events.rules" "$(DESTDIR)$(e_sysconfrulesdir)"
	@test -e "$(DESTDIR)$(e_sysconfrulesdir)smtp-events.rules" || install -m 600 "$(top_srcdir)/rules/smtp-events.rules" "$(DESTDIR)$(e_sysconfrulesdir)"
	@test -e "$(DESTDIR)$(e_sysconfrulesdir)http-events.rules" || install -m 600 "$(top_srcdir)/rules/http-events.rules" "$(DESTDIR)$(e_sysconfrulesdir)"
	@test -e "$(DESTDIR)$(e_sysconfrulesdir)dns-events.rules" || install -m 600 "$(top_srcdir)/rules/dns-events.rules" "$(DESTDIR)$(e_sysconfrulesdir)"
	@test -e "$(DESTDIR)$(e_sysconfrulesdir)modbus-events.rules" || install -m 600 "$(top_srcdir)/rules/modbus-events.rules" "$(DESTDIR)$(e_sysconfrulesdir)"
	@echo ""
	@echo "You can now start suricata by running as root something like '$(DESTDIR)$(bindir)/suricata -c $(DESTDIR)$(e_sysconfdir)/suricata.yaml -i eth0'."
	@echo ""
	@echo "If a library like libhtp.so is not found, you can run suricata with:"
	@echo "'LD_LIBRARY_PATH="$(DESTDIR)$(prefix)/lib" "$(DESTDIR)$(bindir)/suricata" -c "$(DESTDIR)$(e_sysconfdir)/suricata.yaml" -i eth0'."
	@echo ""
	@echo "While rules are installed now, it's highly recommended to use a rule manager for maintaining rules."
	@echo "The two most common are Oinkmaster and Pulledpork. For a guide see:"
	@echo "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Rule_Management_with_Oinkmaster"
