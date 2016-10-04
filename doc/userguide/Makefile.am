EXTRA_DIST = \
	conf.py \
	_static \
	acknowledgements.rst \
	command-line-options.rst \
	index.rst \
	initscripts.rst \
	make-sense-alerts.rst \
	oinkmaster.rst \
	public-data-sets.rst \
	setting-up-ipsinline-for-linux.rst \
	unix-socket.rst \
	what-is-suricata.rst \
	capture-hardware \
	configuration \
	file-extraction \
	licenses \
	manpages \
	oinkmaster \
	output \
	partials \
	performance \
	reputation \
	rules \
	setting-up-ipsinline-for-linux

if HAVE_SURICATA_MAN
man1_MANS = suricata.1
endif

if HAVE_SPHINXBUILD
man1_MANS = suricata.1

EXTRA_DIST += $(man1_MANS) userguide.pdf

SPHINX_BUILD = sphinx-build -q

# find _build/html -type f  -name "*.html"  -o -name "*.png" -o -name "*.css" -o -name "*.js" -o -name "*.gif"  | perl -ne 's/$/ \\/; print "\t$_"'
# TODO: to build a script that creetes the install DATA targets and rules

_static_html_dir = $(docdir)/_static
_static_html__DATA = _build/html/_static/jquery.js \
	_build/html/_static/up.png \
	_build/html/_static/pygments.css \
	_build/html/_static/ajax-loader.gif \
	_build/html/_static/up-pressed.png \
	_build/html/_static/file.png \
	_build/html/_static/default.css \
	_build/html/_static/comment-close.png \
	_build/html/_static/underscore.js \
	_build/html/_static/down-pressed.png \
	_build/html/_static/minus.png \
	_build/html/_static/sidebar.js \
	_build/html/_static/websupport.js \
	_build/html/_static/searchtools.js \
	_build/html/_static/doctools.js \
	_build/html/_static/comment-bright.png \
	_build/html/_static/plus.png \
	_build/html/_static/down.png \
	_build/html/_static/basic.css \
	_build/html/_static/comment.png \
	_build/html/_static/classic.css

images_html_dir = $(docdir)/_images
images_html__DATA = _build/html/_images/pcre6.png \
	_build/html/_images/ICMP_type_code.png \
	_build/html/_images/within2.png \
	_build/html/_images/intro_sig.png \
	_build/html/_images/urilen1.png \
	_build/html/_images/iptables4.png \
	_build/html/_images/stat-code1.png \
	_build/html/_images/oinkmasterconf.png \
	_build/html/_images/stat_msg.png \
	_build/html/_images/request.png \
	_build/html/_images/content6.png \
	_build/html/_images/Flow2.png \
	_build/html/_images/grouping_tree_detail.png \
	_build/html/_images/header1.png \
	_build/html/_images/client_body1.png \
	_build/html/_images/sameip.png \
	_build/html/_images/uricontent.png \
	_build/html/_images/distance1.png \
	_build/html/_images/Normal_ids_ack_d.png \
	_build/html/_images/pcre4.png \
	_build/html/_images/NFQ.png \
	_build/html/_images/response1.png \
	_build/html/_images/threading.png \
	_build/html/_images/grouping_tree.png \
	_build/html/_images/urilen.png \
	_build/html/_images/within_distance.png \
	_build/html/_images/ack.png \
	_build/html/_images/fragoffset.png \
	_build/html/_images/content5.png \
	_build/html/_images/within1.png \
	_build/html/_images/rev.png \
	_build/html/_images/content4.png \
	_build/html/_images/ICMP_types.png \
	_build/html/_images/fragbits.png \
	_build/html/_images/stat_msg_1.png \
	_build/html/_images/Flow1.png \
	_build/html/_images/replace1.png \
	_build/html/_images/method1.png \
	_build/html/_images/replace.png \
	_build/html/_images/Direction.png \
	_build/html/_images/threading1.png \
	_build/html/_images/iptables2.png \
	_build/html/_images/Tuple1.png \
	_build/html/_images/gid.png \
	_build/html/_images/action.png \
	_build/html/_images/uricontent1.png \
	_build/html/_images/IPtables.png \
	_build/html/_images/Wireshark_ack.png \
	_build/html/_images/normal_ids.png \
	_build/html/_images/Runmode_autofp.png \
	_build/html/_images/distance4.png \
	_build/html/_images/ipfw_reinjection.png \
	_build/html/_images/Source-port.png \
	_build/html/_images/Legenda_rules.png \
	_build/html/_images/distance5.png \
	_build/html/_images/request2.png \
	_build/html/_images/pcre3.png \
	_build/html/_images/balancing_workload.png \
	_build/html/_images/file_data.png \
	_build/html/_images/Flowbit_3.png \
	_build/html/_images/distance3.png \
	_build/html/_images/header.png \
	_build/html/_images/classification.png \
	_build/html/_images/seq.png \
	_build/html/_images/icmp_id.png \
	_build/html/_images/pcre.png \
	_build/html/_images/distance.png \
	_build/html/_images/client_body.png \
	_build/html/_images/IPtables3.png \
	_build/html/_images/Legenda_rules1.png \
	_build/html/_images/dsize.png \
	_build/html/_images/content3.png \
	_build/html/_images/NFQ2.png \
	_build/html/_images/method2.png \
	_build/html/_images/ipopts_rule.png \
	_build/html/_images/reference.png \
	_build/html/_images/dns_query.png \
	_build/html/_images/user_agent.png \
	_build/html/_images/inline_mode.png \
	_build/html/_images/reassembly1.png \
	_build/html/_images/destination.png \
	_build/html/_images/fast_pattern.png \
	_build/html/_images/MPM2.png \
	_build/html/_images/id.png \
	_build/html/_images/Inline_reassembly_unackd_data.png \
	_build/html/_images/classtype.png \
	_build/html/_images/sid.png \
	_build/html/_images/isdataat1.png \
	_build/html/_images/suricata_yaml.png \
	_build/html/_images/http_uri.png \
	_build/html/_images/iptables1.png \
	_build/html/_images/overlap.png \
	_build/html/_images/cookie1.png \
	_build/html/_images/flow.png \
	_build/html/_images/Source.png \
	_build/html/_images/IDS_chunk_size.png \
	_build/html/_images/within_distance2.png \
	_build/html/_images/Wireshark_seq.png \
	_build/html/_images/content.png \
	_build/html/_images/Dest_port.png \
	_build/html/_images/msg.png \
	_build/html/_images/cookie.png \
	_build/html/_images/rpc.png \
	_build/html/_images/ip_proto.png \
	_build/html/_images/protocol.png \
	_build/html/_images/ipopts.png \
	_build/html/_images/TCP-session.png \
	_build/html/_images/icode.png \
	_build/html/_images/NFQ1.png \
	_build/html/_images/iptables_vnL.png \
	_build/html/_images/content2.png \
	_build/html/_images/stat_code.png \
	_build/html/_images/normalization1.png \
	_build/html/_images/uri.png \
	_build/html/_images/uri1.png \
	_build/html/_images/method.png
	_build/html/_images/icmp_seq.png \
	_build/html/_images/user_agent_match.png \
	_build/html/_images/icmp_type.png \
	_build/html/_images/pcre5.png \
	_build/html/_images/ttl.png \
	_build/html/_images/Window.png

configuration_html_dir = $(docdir)/configuration
configuration_html__DATA = _build/html/configuration/index.html \
	_build/html/configuration/multi-tenant.html \
	_build/html/configuration/dropping-privileges.html \
	_build/html/configuration/global-thresholds.html \
	_build/html/configuration/snort-to-suricata.html \
	_build/html/configuration/suricata-yaml.html \
	_build/html/configuration/log-rotation.html

file_extraction_html_dir = $(docdir)/file-extraction
file_extraction_html__DATA = _build/html/file-extraction/file-extraction.html \
	_build/html/file-extraction/public-sha1-md5-data-sets.html \
	_build/html/file-extraction/md5.html

performance_html_dir = $(docdir)/performace
performance_html__DATA = _build/html/performance/index.html \
	_build/html/performance/tcmalloc.html \
	_build/html/performance/statistics.html \
	_build/html/performance/packet-capture.html \
	_build/html/performance/ignoring-traffic.html \
	_build/html/performance/packet-profiling.html \
	_build/html/performance/hyperscan.html \
	_build/html/performance/tuning-considerations.html \
	_build/html/performance/runmodes.html \
	_build/html/performance/high-performance-config.html \
	_build/html/performance/rule-profiling.html

rules_html_dir = $(docdir)/rules
rules_html__DATA =  _build/html/rules/intro.html \
	_build/html/rules/index.html \
	_build/html/rules/normalized-buffers.html \
	_build/html/rules/meta.html \
	_build/html/rules/file-keywords.html \
	_build/html/rules/http-uri-normalization.html \
	_build/html/rules/dns-keywords.html \
	_build/html/rules/pcre.html \
	_build/html/rules/flowint.html \
	_build/html/rules/tls-keywords.html \
	_build/html/rules/modbus-keyword.html \
	_build/html/rules/live-rule-swap.html \
	_build/html/rules/header-keywords.html \
	_build/html/rules/prefilter.html \
	_build/html/rules/snort-compatibility.html \
	_build/html/rules/payload-keywords.html \
	_build/html/rules/enip-keyword.html \
	_build/html/rules/thresholding.html \
	_build/html/rules/adding-your-own-rules.html \
	_build/html/rules/dnp3-keywords.html \
	_build/html/rules/rule-lua-scripting.html \
	_build/html/rules/http-keywords.html \
	_build/html/rules/flow-keywords.html \
	_build/html/rules/fast-pattern-explained.html \
	_build/html/rules/fast-pattern.html

partials_html_dir = $(docdir)/partials
partials_html__DATA = _build/html/partials/options.html \
	_build/html/partials/options-unittests.html

output_html_dir = $(docdir)/output
output_html__DATA = _build/html/output/index.html \
	_build/html/output/lua-output.html
	_build/html/output/custom-http-logging.html \
	_build/html/output/syslog-alerting-comp.html

output_eve_html_dir = $(docdir)/output/eve
output_eve_html__DATA =  _build/html/output/eve/index.html \
	_build/html/output/eve/eve-json-output.html \
	_build/html/output/eve/eve-json-format.html \
	_build/html/output/eve/eve-json-examplesjq.html 

reputation_html_dir = $(docdir)/output/reputation
reputation_html__DATA =  _build/html/reputation/index.html

reputation_ipreputation_html_dir = $(docdir)/output/reputation/ipreputation
reputation_ipreputation_html__DATA = _build/html/reputation/ipreputation/ip-reputation-format.html \
	_build/html/reputation/ipreputation/ip-reputation-rules.html \
	_build/html/reputation/ipreputation/ip-reputation-config.html \
	_build/html/reputation/ipreputation/ip-reputation.html

capture_hardware_html_dir = $(docdir)/output/capture-hardware
capture_hardware_html__DATA = _build/html/capture-hardware/index.html \
	_build/html/capture-hardware/myricom.html \
	_build/html/capture-hardware/endace-dag.html

manpages_html_dir = $(docdir)/manpages
manpages_html__DATA =  _build/html/manpages/index.html \
	_build/html/manpages/suricata.html

licenses_html_dir = $(docdir)/licenses
licenses_html__DATA =  _build/html/licenses/index.html \
	_build/html/licenses/gnu-gpl-v2.0.html \
	_build/html/licenses/cc-nc-4.0.html

ROOT_html_dir = $(docdir)/
ROOT_html__DATA =  _build/html/what-is-suricata.html \
	_build/html/command-line-options.html \
	_build/html/searchindex.js \
	_build/html/genindex.html \
	_build/html/oinkmaster.html \
	_build/html/public-data-sets.html \
	_build/html/make-sense-alerts.html
	_build/html/acknowledgements.html \
	_build/html/initscripts.html \
	_build/html/unix-socket.html \
	_build/html/setting-up-ipsinline-for-linux.html \
	_build/html/search.html \
	_build/html/index.html

$(_static_html_dir): html
$(_images_html_dir): html
$(configuration_html_dir): html
$(file_extraction_html_dir): html
$(performance_html_dir): html
$(rules_html_dir): html
$(partials_html_dir): html
$(output_html_dir): html
$(output_eve_html_dir): html
$(reputation_html_dir): html
$(reputation_ipreputation_html_dir): html
$(capture_hardware_html_dir): html
$(manpages_html_dir): html
$(licenses_html_dir): html
$(ROOT_html__DATA): html


html: what-is-suricata.rst
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -W -b html -d $(abs_srcdir)/_build/doctrees \
		$(abs_srcdir) $(abs_srcdir)/_build/html

_build/latex/Suricata.pdf:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -W -b latex -d $(abs_srcdir)/_build/doctrees \
		$(abs_srcdir) $(abs_srcdir)/_build/latex
	cd $(abs_srcdir)/_build/latex && $(MAKE) all-pdf

userguide.pdf: _build/latex/Suricata.pdf
	cp $(abs_srcdir)/_build/latex/Suricata.pdf userguide.pdf

pdf: userguide.pdf

_build/man/suricata.1:
	sysconfdir=$(sysconfdir) \
	localstatedir=$(localstatedir) \
	version=$(PACKAGE_VERSION) \
		$(SPHINX_BUILD) -b man -d $(abs_srcdir)/_build/doctrees \
		$(abs_srcdir) $(abs_srcdir)/_build/man

suricata.1: _build/man/suricata.1
	cp $(abs_srcdir)/_build/man/suricata.1 suricata.1

man: _build/man/suricata.1

# Remove build artifacts that aren't tracked by autotools.
clean-local:
	rm -rf $(abs_srcdir)/_build
	rm -f $(abs_srcdir)/_build/man/suricata.1
	rm -f $(abs_srcdir)/_build/latex/Suricata.pdf
	rm -f suricata.1 userguide.pdf

all-local: html suricata.1 userguide.pdf



endif # HAVE_SPHINXBUILD
