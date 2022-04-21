# not a GNU package. You can remove this line, if
# have all needed files, that a GNU package needs
AUTOMAKE_OPTIONS = foreign 1.4
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = ChangeLog COPYING LICENSE suricata.yaml.in \
             threshold.config \
             $(SURICATA_UPDATE_DIR) \
	     lua \
	     acsite.m4 \
	     scripts/generate-images.sh
SUBDIRS = $(HTP_DIR) rust src qa rules doc contrib etc python ebpf dpdk \
          $(SURICATA_UPDATE_DIR)

CLEANFILES = stamp-h[0-9]*

install-data-am:
	@echo "Run 'make install-conf' if you want to install initial configuration files. Or 'make install-full' to install configuration and rules";

install-full:
	$(MAKE) install
	$(MAKE) install-conf
	$(MAKE) install-rules

install-conf:
	install -d "$(DESTDIR)$(e_sysconfdir)"
	@test -e "$(DESTDIR)$(e_sysconfdir)/suricata.yaml" || install -m 600 "$(top_srcdir)/suricata.yaml" "$(DESTDIR)$(e_sysconfdir)"
	@test -e "$(DESTDIR)$(e_sysconfdir)/classification.config" || install -m 600 "$(top_srcdir)/etc/classification.config" "$(DESTDIR)$(e_sysconfdir)"
	@test -e "$(DESTDIR)$(e_sysconfdir)/reference.config" || install -m 600 "$(top_srcdir)/etc/reference.config" "$(DESTDIR)$(e_sysconfdir)"
	@test -e "$(DESTDIR)$(e_sysconfdir)/threshold.config" || install -m 600 "$(top_srcdir)/threshold.config" "$(DESTDIR)$(e_sysconfdir)"
	install -d "$(DESTDIR)$(e_logfilesdir)"
	install -d "$(DESTDIR)$(e_logcertsdir)"
	install -d "$(DESTDIR)$(e_rundir)"
	install -m 770 -d "$(DESTDIR)$(e_localstatedir)"

install-rules:
if INSTALL_SURICATA_UPDATE
	LD_LIBRARY_PATH=$(libdir) $(DESTDIR)$(bindir)/suricata-update \
		--suricata $(DESTDIR)$(bindir)/suricata \
		--suricata-conf $(DESTDIR)$(sysconfdir)/suricata/suricata.yaml \
		--no-test --no-reload
else
	@echo ""
	@echo "Warning: No rules will be downloaded as suricata-update"
	@echo "   is not available: ${install_suricata_update_reason}"
endif
	@echo ""
	@echo "You can now start suricata by running as root something like:"
	@echo "  $(DESTDIR)$(bindir)/suricata -c $(DESTDIR)$(e_sysconfdir)suricata.yaml -i eth0"
	@echo ""
	@echo "If a library like libhtp.so is not found, you can run suricata with:"
	@echo "  LD_LIBRARY_PATH="$(DESTDIR)$(prefix)/lib" "$(DESTDIR)$(bindir)/suricata" -c "$(DESTDIR)$(e_sysconfdir)suricata.yaml" -i eth0"
	@echo ""
	@echo "The Emerging Threats Open rules are now installed. Rules can be"
	@echo "updated and managed with the suricata-update tool."
	@echo ""
	@echo "For more information please see:"
	@echo "  https://suricata.readthedocs.io/en/latest/rule-management/index.html"
	@echo ""

install-library:
	cd src && $(MAKE) $@
	cd rust && $(MAKE) $@
	$(INSTALL) libsuricata-config "$(DESTDIR)$(bindir)/libsuricata-config"

install-headers:
	cd src && $(MAKE) $@

dpdk-apps-prereq: install install-headers install-library

dpdk-apps: dpdk-apps-prereq
	cd dpdk && $(MAKE) shared
