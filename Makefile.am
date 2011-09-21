# not a GNU package. You can remove this line, if
# have all needed files, that a GNU package needs
AUTOMAKE_OPTIONS = foreign 1.4
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = ChangeLog COPYING LICENSE suricata.yaml.in \
             classification.config \
             reference.config
if BUILD_LIBHTP
 HTP_DIR = libhtp
endif
SUBDIRS = $(HTP_DIR) src qa rules doc

install-data-am:
	@echo "Run 'make install-conf' if you want to install initial configuration files. Or 'make install-full' to install configuration and rules";

install-full: install-conf install-rules

install-conf:
	install -d $(sysconfdir)
	test -e $(sysconfdir)/suricata.yaml || install -m 600 $(top_srcdir)/suricata.yaml $(sysconfdir)
	test -e $(sysconfdir)/classification.config || install -m 600 $(top_srcdir)/classification.config $(sysconfdir)
	test -e $(sysconfdir)/reference.config || install -m 600 $(top_srcdir)/reference.config $(sysconfdir)
	install -d $(localstatedir)/log/suricata

install-rules:
	install -d $(sysconfdir)/rules
	wget -qO - http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz | tar zkxv -C $(sysconfdir)
	test -e $(sysconfdir)/rules/decoder-events.rules || install -m 600 $(top_srcdir)/rules/decoder-events.rules $(sysconfdir)/rules/
	test -e $(sysconfdir)/rules/stream-events.rules || install -m 600 $(top_srcdir)/rules/stream-events.rules $(sysconfdir)/rules/
	test -e $(sysconfdir)/rules/smtp-events.rules || install -m 600 $(top_srcdir)/rules/smtp-events.rules $(sysconfdir)/rules/
	test -e $(sysconfdir)/rules/http-events.rules || install -m 600 $(top_srcdir)/rules/http-events.rules $(sysconfdir)/rules/
	@echo "You can now start suricata by running as root something like '$(bindir)/suricata -c $(sysconfdir)/suricata.yaml -i eth0'"
