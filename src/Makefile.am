bin_PROGRAMS = suricata
if BUILD_FUZZTARGETS
    bin_PROGRAMS += fuzz_applayerprotodetectgetproto \
    fuzz_applayerparserparse fuzz_siginit \
    fuzz_confyamlloadstring fuzz_decodepcapfile \
    fuzz_sigpcap fuzz_mimedecparseline fuzz_decodebase64
if HAS_FUZZPCAP
    bin_PROGRAMS += fuzz_sigpcap_aware fuzz_predefpcap_aware
endif
endif

# Headers that should never be installed.
PRIVATE_INCLUDES = \
	util-device-private.h

# Headers that are installed with "make install-headers". They are
# declared as "noinst_HEADERS" to avoid them being installed by
# default.
noinst_HEADERS = \
	action-globals.h \
	alert-debuglog.h \
	alert-fastlog.h \
	alert-syslog.h \
	app-layer-detect-proto.h \
	app-layer-dnp3-objects.h \
	app-layer-dnp3.h \
	app-layer-events.h \
	app-layer-expectation.h \
	app-layer-frames.h \
	app-layer-ftp.h \
	app-layer-htp-body.h \
	app-layer-htp-file.h \
	app-layer-htp-mem.h \
	app-layer-htp-range.h \
	app-layer-htp-xff.h \
	app-layer-htp.h \
	app-layer-http2.h \
	app-layer-ike.h \
	app-layer-imap.h \
	app-layer-modbus.h \
	app-layer-nfs-tcp.h \
	app-layer-nfs-udp.h \
	app-layer-parser.h \
	app-layer-protos.h \
	app-layer-register.h \
	app-layer-smb.h \
	app-layer-smtp.h \
	app-layer-ssh.h \
	app-layer-ssl.h \
	app-layer-tftp.h \
	app-layer.h \
	bindgen.h \
	build-info.h \
	conf-yaml-loader.h \
	conf.h \
	counters.h \
	datasets-context-json.h \
	datasets-ipv4.h \
	datasets-ipv6.h \
	datasets-md5.h \
	datasets-reputation.h \
	datasets-sha256.h \
	datasets-string.h \
	datasets.h \
	decode-arp.h \
	decode-chdlc.h \
	decode-erspan.h \
	decode-esp.h \
	decode-etag.h \
	decode-ethernet.h \
	decode-events.h \
	decode-geneve.h \
	decode-gre.h \
	decode-icmpv4.h \
	decode-icmpv6.h \
	decode-ipv4.h \
	decode-ipv6.h \
	decode-mpls.h \
	decode-nsh.h \
	decode-ppp.h \
	decode-pppoe.h \
	decode-raw.h \
	decode-sctp.h \
	decode-sll.h \
	decode-sll2.h \
	decode-tcp.h \
	decode-template.h \
	decode-teredo.h \
	decode-udp.h \
	decode-vlan.h \
	decode-vntag.h \
	decode-vxlan.h \
	decode.h \
	defrag-config.h \
	defrag-hash.h \
	defrag-stack.h \
	defrag-timeout.h \
	defrag.h \
	detect-app-layer-event.h \
	detect-app-layer-protocol.h \
	detect-app-layer-state.h \
	detect-asn1.h \
	detect-base64-data.h \
	detect-base64-decode.h \
	detect-bsize.h \
	detect-bypass.h \
	detect-byte-extract.h \
	detect-byte.h \
	detect-bytejump.h \
	detect-bytemath.h \
	detect-bytetest.h \
	detect-classtype.h \
	detect-config.h \
	detect-content.h \
	detect-csum.h \
	detect-datarep.h \
	detect-dataset.h \
	detect-dce-iface.h \
	detect-dce-opnum.h \
	detect-dce-stub-data.h \
	detect-depth.h \
	detect-detection-filter.h \
	detect-distance.h \
	detect-dnp3.h \
	detect-dns-name.h \
	detect-dns-response.h \
	detect-dsize.h \
	detect-email.h \
	detect-engine-address-ipv4.h \
	detect-engine-address-ipv6.h \
	detect-engine-address.h \
	detect-engine-alert.h \
	detect-engine-analyzer.h \
	detect-engine-buffer.h \
	detect-engine-build.h \
	detect-engine-content-inspection.h \
	detect-engine-dcepayload.h \
	detect-engine-event.h \
	detect-engine-file.h \
	detect-engine-frame.h \
	detect-engine-helper.h \
	detect-engine-inspect-buffer.h \
	detect-engine-iponly.h \
	detect-engine-loader.h \
	detect-engine-mpm.h \
	detect-engine-payload.h \
	detect-engine-port.h \
	detect-engine-prefilter-common.h \
	detect-engine-prefilter.h \
	detect-engine-profile.h \
	detect-engine-proto.h \
	detect-engine-register.h \
	detect-engine-siggroup.h \
	detect-engine-sigorder.h \
	detect-engine-state.h \
	detect-engine-tag.h \
	detect-engine-threshold.h \
	detect-engine-uint.h \
	detect-engine.h \
	detect-entropy.h \
	detect-fast-pattern.h \
	detect-file-data.h \
	detect-file-hash-common.h \
	detect-filemagic.h \
	detect-filemd5.h \
	detect-filename.h \
	detect-filesha1.h \
	detect-filesha256.h \
	detect-filesize.h \
	detect-filestore.h \
	detect-flow-age.h \
	detect-flow-pkts.h \
	detect-flow.h \
	detect-flowbits.h \
	detect-flowint.h \
	detect-flowvar.h \
	detect-fragbits.h \
	detect-fragoffset.h \
	detect-frame.h \
	detect-ftp-command-data.h \
	detect-ftp-command.h \
	detect-ftp-dynamic-port.h \
	detect-ftp-completion-code.h \
	detect-ftp-reply.h \
	detect-ftpbounce.h \
	detect-ftpdata.h \
	detect-ftp-mode.h \
	detect-ftp-reply-received.h \
	detect-geoip.h \
	detect-gid.h \
	detect-hostbits.h \
	detect-http-accept-enc.h \
	detect-http-accept-lang.h \
	detect-http-accept.h \
	detect-http-client-body.h \
	detect-http-connection.h \
	detect-http-content-len.h \
	detect-http-content-type.h \
	detect-http-cookie.h \
	detect-http-header-common.h \
	detect-http-header-names.h \
	detect-http-header.h \
	detect-http-headers-stub.h \
	detect-http-headers.h \
	detect-http-host.h \
	detect-http-location.h \
	detect-http-method.h \
	detect-http-protocol.h \
	detect-http-raw-header.h \
	detect-http-referer.h \
	detect-http-request-line.h \
	detect-http-response-line.h \
	detect-http-server-body.h \
	detect-http-server.h \
	detect-http-start.h \
	detect-http-stat-code.h \
	detect-http-stat-msg.h \
	detect-http-ua.h \
	detect-http-uri.h \
	detect-http2.h \
	detect-icmp-id.h \
	detect-icmp-seq.h \
	detect-icmpv4hdr.h \
	detect-icmpv6-mtu.h \
	detect-icmpv6hdr.h \
	detect-icode.h \
	detect-id.h \
	detect-ike-chosen-sa.h \
	detect-ike-exch-type.h \
	detect-ike-key-exchange-payload-length.h \
	detect-ike-key-exchange-payload.h \
	detect-ike-nonce-payload-length.h \
	detect-ike-nonce-payload.h \
	detect-ike-spi.h \
	detect-ike-vendor.h \
	detect-ipaddr.h \
	detect-ipopts.h \
	detect-ipproto.h \
	detect-iprep.h \
	detect-ipv4hdr.h \
	detect-ipv6hdr.h \
	detect-isdataat.h \
	detect-itype.h \
	detect-ja4-hash.h \
	detect-krb5-cname.h \
	detect-krb5-errcode.h \
	detect-krb5-sname.h \
	detect-krb5-ticket-encryption.h \
	detect-l3proto.h \
	detect-lua-extensions.h \
	detect-lua.h \
	detect-mark.h \
	detect-metadata.h \
	detect-modbus.h \
	detect-msg.h \
	detect-nfs-version.h \
	detect-noalert.h \
	detect-nocase.h \
	detect-offset.h \
	detect-parse.h \
	detect-pcre.h \
	detect-pkt-data.h \
	detect-pktvar.h \
	detect-prefilter.h \
	detect-priority.h \
	detect-quic-cyu-hash.h \
	detect-quic-cyu-string.h \
	detect-quic-sni.h \
	detect-quic-ua.h \
	detect-quic-version.h \
	detect-rawbytes.h \
	detect-reference.h \
	detect-replace.h \
	detect-requires.h \
	detect-rev.h \
	detect-rpc.h \
	detect-sameip.h \
	detect-sid.h \
	detect-sip-method.h \
	detect-sip-uri.h \
	detect-smb-ntlmssp.h \
	detect-smb-share.h \
	detect-smb-version.h \
	detect-smtp.h \
	detect-ssh-hassh-server-string.h \
	detect-ssh-hassh-server.h \
	detect-ssh-hassh-string.h \
	detect-ssh-hassh.h \
	detect-ssh-proto-version.h \
	detect-ssh-proto.h \
	detect-ssh-software-version.h \
	detect-ssh-software.h \
	detect-ssl-state.h \
	detect-ssl-version.h \
	detect-stream_size.h \
	detect-tag.h \
	detect-target.h \
	detect-tcp-ack.h \
	detect-tcp-flags.h \
	detect-tcp-seq.h \
	detect-tcp-window.h \
	detect-tcp-wscale.h \
	detect-tcphdr.h \
	detect-tcpmss.h \
	detect-template.h \
	detect-template2.h \
	detect-threshold.h \
	detect-tls-alpn.h \
	detect-tls-cert-fingerprint.h \
	detect-tls-cert-issuer.h \
	detect-tls-cert-serial.h \
	detect-tls-cert-subject.h \
	detect-tls-cert-validity.h \
	detect-tls-certs.h \
	detect-tls-ja3-hash.h \
	detect-tls-ja3-string.h \
	detect-tls-ja3s-hash.h \
	detect-tls-ja3s-string.h \
	detect-tls-random.h \
	detect-tls-sni.h \
	detect-tls-subjectaltname.h \
	detect-tls-version.h \
	detect-tls.h \
	detect-tos.h \
	detect-transform-luaxform.h \
	detect-transform-pcrexform.h \
	detect-ttl.h \
	detect-udphdr.h \
	detect-uricontent.h \
	detect-urilen.h \
	detect-vlan.h \
	detect-within.h \
	detect-xbits.h \
	detect.h \
	device-storage.h \
	feature.h \
	flow-bindgen.h \
	flow-bit.h \
	flow-bypass.h \
	flow-callbacks.h \
	flow-hash.h \
	flow-manager.h \
	flow-private.h \
	flow-queue.h \
	flow-spare-pool.h \
	flow-storage.h \
	flow-timeout.h \
	flow-util.h \
	flow-var.h \
	flow-worker.h \
	flow.h \
	host-bit.h \
	host-queue.h \
	host-storage.h \
	host-timeout.h \
	host.h \
	interval-tree.h \
	ippair-bit.h \
	ippair-queue.h \
	ippair-storage.h \
	ippair-timeout.h \
	ippair.h \
	log-cf-common.h \
	log-flush.h \
	log-httplog.h \
	log-pcap.h \
	log-stats.h \
	log-tcp-data.h \
	log-tlslog.h \
	log-tlsstore.h \
	output-eve-bindgen.h \
	output-eve-null.h \
	output-eve-stream.h \
	output-eve-syslog.h \
	output-eve.h \
	output-file.h \
	output-filedata.h \
	output-filestore.h \
	output-flow.h \
	output-json-alert.h \
	output-json-anomaly.h \
	output-json-arp.h \
	output-json-dcerpc.h \
	output-json-dhcp.h \
	output-json-dnp3-objects.h \
	output-json-dnp3.h \
	output-json-dns.h \
	output-json-drop.h \
	output-json-email-common.h \
	output-json-file.h \
	output-json-flow.h \
	output-json-frame.h \
	output-json-ftp.h \
	output-json-http.h \
	output-json-ike.h \
	output-json-mdns.h \
	output-json-metadata.h \
	output-json-mqtt.h \
	output-json-netflow.h \
	output-json-nfs.h \
	output-json-pgsql.h \
	output-json-smb.h \
	output-json-smtp.h \
	output-json-stats.h \
	output-json-tls.h \
	output-json.h \
	output-lua.h \
	output-packet.h \
	output-stats.h \
	output-streaming.h \
	output-tx.h \
	output.h \
	packet-queue.h \
	packet.h \
	pkt-var.h \
	queue.h \
	reputation.h \
	respond-reject-libnet11.h \
	respond-reject.h \
	runmode-af-packet.h \
	runmode-af-xdp.h \
	runmode-dpdk.h \
	runmode-erf-dag.h \
	runmode-erf-file.h \
	runmode-ipfw.h \
	runmode-lib.h \
	runmode-netmap.h \
	runmode-nflog.h \
	runmode-nfq.h \
	runmode-pcap-file.h \
	runmode-pcap.h \
	runmode-unittests.h \
	runmode-unix-socket.h \
	runmode-windivert.h \
	runmodes.h \
	rust.h \
	source-af-packet.h \
	source-af-xdp.h \
	source-dpdk.h \
	source-erf-dag.h \
	source-erf-file.h \
	source-ipfw.h \
	source-lib.h \
	source-netmap.h \
	source-nflog.h \
	source-nfq-prototypes.h \
	source-nfq.h \
	source-pcap-file-directory-helper.h \
	source-pcap-file-helper.h \
	source-pcap-file.h \
	source-pcap.h \
	source-windivert-prototypes.h \
	source-windivert.h \
	stream-tcp-cache.h \
	stream-tcp-inline.h \
	stream-tcp-list.h \
	stream-tcp-private.h \
	stream-tcp-reassemble.h \
	stream-tcp-sack.h \
	stream-tcp-util.h \
	stream-tcp.h \
	stream.h \
	suricata-common.h \
	suricata-plugin.h \
	suricata.h \
	thread-callbacks.h \
	thread-storage.h \
	threads-debug.h \
	threads-profile.h \
	threads.h \
	threadvars.h \
	tm-modules.h \
	tm-queuehandlers.h \
	tm-queues.h \
	tm-threads-common.h \
	tm-threads.h \
	tmqh-flow.h \
	tmqh-packetpool.h \
	tmqh-simple.h \
	tree.h \
	tx-bit.h \
	unix-manager.h \
	util-action.h \
	util-affinity.h \
	util-atomic.h \
	util-bpf.h \
	util-buffer.h \
	util-byte.h \
	util-checksum.h \
	util-cidr.h \
	util-classification-config.h \
	util-clock.h \
	util-conf.h \
	util-config.h \
	util-coredump-config.h \
	util-cpu.h \
	util-daemon.h \
	util-datalink.h \
	util-debug-filters.h \
	util-debug.h \
	util-detect.h \
	util-device.h \
	util-dpdk-bonding.h \
	util-dpdk-common.h \
	util-dpdk-i40e.h \
	util-dpdk-ice.h \
	util-dpdk-ixgbe.h \
	util-dpdk-mlx5.h \
	util-dpdk-rss.h \
	util-dpdk.h \
	util-ebpf.h \
	util-enum.h \
	util-error.h \
	util-exception-policy-types.h \
	util-exception-policy.h \
	util-file-decompression.h \
	util-file-swf-decompression.h \
	util-file.h \
	util-fix_checksum.h \
	util-flow-rate.h \
	util-fmemopen.h \
	util-hash-lookup3.h \
	util-hash-string.h \
	util-hash.h \
	util-hashlist.h \
	util-host-info.h \
	util-host-os-info.h \
	util-hugepages.h \
	util-hyperscan.h \
	util-ioctl.h \
	util-ip.h \
	util-ja3.h \
	util-landlock.h \
	util-log-redis.h \
	util-logopenfile.h \
	util-lua-base64lib.h \
	util-lua-builtins.h \
	util-lua-common.h \
	util-lua-config.h \
	util-lua-dataset.h \
	util-lua-dnp3-objects.h \
	util-lua-dnp3.h \
	util-lua-dns.h \
	util-lua-filelib.h \
	util-lua-flowintlib.h \
	util-lua-flowlib.h \
	util-lua-flowvarlib.h \
	util-lua-bytevarlib.h \
	util-lua-hashlib.h \
	util-lua-http.h \
	util-lua-ja3.h \
	util-lua-log.h \
	util-lua-packetlib.h \
	util-lua-rule.h \
	util-lua-sandbox.h \
	util-lua-smtp.h \
	util-lua-ssh.h \
	util-lua-tls.h \
	util-lua-util.h \
	util-lua.h \
	util-macset.h \
	util-magic.h \
	util-mem.h \
	util-memcmp.h \
	util-memcpy.h \
	util-memrchr.h \
	util-misc.h \
	util-mpm-ac-ks.h \
	util-mpm-ac-queue.h \
	util-mpm-ac.h \
	util-mpm-hs-cache.h \
	util-mpm-hs-core.h \
	util-mpm-hs.h \
	util-mpm.h \
	util-optimize.h \
	util-pages.h \
	util-path.h \
	util-pidfile.h \
	util-plugin.h \
	util-pool-thread.h \
	util-pool.h \
	util-port-interval-tree.h \
	util-prefilter.h \
	util-print.h \
	util-privs.h \
	util-profiling-locks.h \
	util-profiling.h \
	util-proto-name.h \
	util-radix-tree-common.h \
	util-radix4-tree.h \
	util-radix6-tree.h \
	util-random.h \
	util-reference-config.h \
	util-rohash.h \
	util-rule-vars.h \
	util-runmodes.h \
	util-running-modes.h \
	util-signal.h \
	util-spm-bm.h \
	util-spm-bs.h \
	util-spm-bs2bm.h \
	util-spm-hs.h \
	util-spm.h \
	util-storage.h \
	util-streaming-buffer.h \
	util-sysfs.h \
	util-syslog.h \
	util-systemd.h \
	util-thash.h \
	util-threshold-config.h \
	util-time.h \
	util-unittest-helper.h \
	util-unittest.h \
	util-validate.h \
	util-var-name.h \
	util-var.h \
	win32-misc.h \
	win32-service.h \
	win32-syscall.h \
	win32-syslog.h

libsuricata_c_a_SOURCES = \
	alert-debuglog.c \
	alert-fastlog.c \
	alert-syslog.c \
	app-layer-detect-proto.c \
	app-layer-dnp3-objects.c \
	app-layer-dnp3.c \
	app-layer-events.c \
	app-layer-expectation.c \
	app-layer-frames.c \
	app-layer-ftp.c \
	app-layer-htp-body.c \
	app-layer-htp-file.c \
	app-layer-htp-mem.c \
	app-layer-htp-range.c \
	app-layer-htp-xff.c \
	app-layer-htp.c \
	app-layer-http2.c \
	app-layer-ike.c \
	app-layer-imap.c \
	app-layer-modbus.c \
	app-layer-nfs-tcp.c \
	app-layer-nfs-udp.c \
	app-layer-parser.c \
	app-layer-protos.c \
	app-layer-register.c \
	app-layer-smb.c \
	app-layer-smtp.c \
	app-layer-ssh.c \
	app-layer-ssl.c \
	app-layer-tftp.c \
	app-layer.c \
	conf-yaml-loader.c \
	conf.c \
	counters.c \
	datasets-context-json.c \
	datasets-ipv4.c \
	datasets-ipv6.c \
	datasets-md5.c \
	datasets-sha256.c \
	datasets-string.c \
	datasets.c \
	decode-arp.c \
	decode-chdlc.c \
	decode-erspan.c \
	decode-esp.c \
	decode-etag.c \
	decode-ethernet.c \
	decode-events.c \
	decode-geneve.c \
	decode-gre.c \
	decode-icmpv4.c \
	decode-icmpv6.c \
	decode-ipv4.c \
	decode-ipv6.c \
	decode-mpls.c \
	decode-nsh.c \
	decode-null.c \
	decode-ppp.c \
	decode-pppoe.c \
	decode-raw.c \
	decode-sctp.c \
	decode-sll.c \
	decode-sll2.c \
	decode-tcp.c \
	decode-template.c \
	decode-teredo.c \
	decode-udp.c \
	decode-vlan.c \
	decode-vntag.c \
	decode-vxlan.c \
	decode.c \
	defrag-config.c \
	defrag-hash.c \
	defrag-stack.c \
	defrag-timeout.c \
	defrag.c \
	detect-app-layer-event.c \
	detect-app-layer-protocol.c \
	detect-app-layer-state.c \
	detect-asn1.c \
	detect-base64-data.c \
	detect-base64-decode.c \
	detect-bsize.c \
	detect-bypass.c \
	detect-byte-extract.c \
	detect-byte.c \
	detect-bytejump.c \
	detect-bytemath.c \
	detect-bytetest.c \
	detect-classtype.c \
	detect-config.c \
	detect-content.c \
	detect-csum.c \
	detect-datarep.c \
	detect-dataset.c \
	detect-dce-iface.c \
	detect-dce-opnum.c \
	detect-dce-stub-data.c \
	detect-depth.c \
	detect-detection-filter.c \
	detect-distance.c \
	detect-dnp3.c \
	detect-dns-name.c \
	detect-dns-response.c \
	detect-dsize.c \
	detect-email.c \
	detect-engine-address-ipv4.c \
	detect-engine-address-ipv6.c \
	detect-engine-address.c \
	detect-engine-alert.c \
	detect-engine-analyzer.c \
	detect-engine-buffer.c \
	detect-engine-build.c \
	detect-engine-content-inspection.c \
	detect-engine-dcepayload.c \
	detect-engine-event.c \
	detect-engine-file.c \
	detect-engine-frame.c \
	detect-engine-helper.c \
	detect-engine-inspect-buffer.c \
	detect-engine-iponly.c \
	detect-engine-loader.c \
	detect-engine-mpm.c \
	detect-engine-payload.c \
	detect-engine-port.c \
	detect-engine-prefilter-common.c \
	detect-engine-prefilter.c \
	detect-engine-profile.c \
	detect-engine-proto.c \
	detect-engine-register.c \
	detect-engine-siggroup.c \
	detect-engine-sigorder.c \
	detect-engine-state.c \
	detect-engine-tag.c \
	detect-engine-threshold.c \
	detect-engine-uint.c \
	detect-engine.c \
	detect-entropy.c \
	detect-fast-pattern.c \
	detect-file-data.c \
	detect-file-hash-common.c \
	detect-filemagic.c \
	detect-filemd5.c \
	detect-filename.c \
	detect-filesha1.c \
	detect-filesha256.c \
	detect-filesize.c \
	detect-filestore.c \
	detect-flow-age.c \
	detect-flow-pkts.c \
	detect-flow.c \
	detect-flowbits.c \
	detect-flowint.c \
	detect-flowvar.c \
	detect-fragbits.c \
	detect-fragoffset.c \
	detect-frame.c \
	detect-ftp-command-data.c \
	detect-ftp-command.c \
	detect-ftp-dynamic-port.c \
	detect-ftp-completion-code.c \
	detect-ftp-reply.c \
	detect-ftpbounce.c \
	detect-ftpdata.c \
	detect-ftp-mode.c \
	detect-ftp-reply-received.c \
	detect-geoip.c \
	detect-gid.c \
	detect-hostbits.c \
	detect-http-accept-enc.c \
	detect-http-accept-lang.c \
	detect-http-accept.c \
	detect-http-client-body.c \
	detect-http-connection.c \
	detect-http-content-len.c \
	detect-http-content-type.c \
	detect-http-cookie.c \
	detect-http-header-common.c \
	detect-http-header-names.c \
	detect-http-header.c \
	detect-http-headers.c \
	detect-http-host.c \
	detect-http-location.c \
	detect-http-method.c \
	detect-http-protocol.c \
	detect-http-raw-header.c \
	detect-http-referer.c \
	detect-http-request-line.c \
	detect-http-response-line.c \
	detect-http-server-body.c \
	detect-http-server.c \
	detect-http-start.c \
	detect-http-stat-code.c \
	detect-http-stat-msg.c \
	detect-http-ua.c \
	detect-http-uri.c \
	detect-http2.c \
	detect-icmp-id.c \
	detect-icmp-seq.c \
	detect-icmpv4hdr.c \
	detect-icmpv6-mtu.c \
	detect-icmpv6hdr.c \
	detect-icode.c \
	detect-id.c \
	detect-ike-chosen-sa.c \
	detect-ike-exch-type.c \
	detect-ike-key-exchange-payload-length.c \
	detect-ike-key-exchange-payload.c \
	detect-ike-nonce-payload-length.c \
	detect-ike-nonce-payload.c \
	detect-ike-spi.c \
	detect-ike-vendor.c \
	detect-ipaddr.c \
	detect-ipopts.c \
	detect-ipproto.c \
	detect-iprep.c \
	detect-ipv4hdr.c \
	detect-ipv6hdr.c \
	detect-isdataat.c \
	detect-itype.c \
	detect-ja4-hash.c \
	detect-krb5-cname.c \
	detect-krb5-errcode.c \
	detect-krb5-sname.c \
	detect-krb5-ticket-encryption.c \
	detect-l3proto.c \
	detect-lua-extensions.c \
	detect-lua.c \
	detect-mark.c \
	detect-metadata.c \
	detect-modbus.c \
	detect-msg.c \
	detect-nfs-version.c \
	detect-noalert.c \
	detect-nocase.c \
	detect-offset.c \
	detect-parse.c \
	detect-pcre.c \
	detect-pkt-data.c \
	detect-pktvar.c \
	detect-prefilter.c \
	detect-priority.c \
	detect-quic-cyu-hash.c \
	detect-quic-cyu-string.c \
	detect-quic-sni.c \
	detect-quic-ua.c \
	detect-quic-version.c \
	detect-rawbytes.c \
	detect-reference.c \
	detect-replace.c \
	detect-requires.c \
	detect-rev.c \
	detect-rpc.c \
	detect-sameip.c \
	detect-sid.c \
	detect-sip-method.c \
	detect-sip-uri.c \
	detect-smb-ntlmssp.c \
	detect-smb-share.c \
	detect-smb-version.c \
	detect-smtp.c \
	detect-ssh-hassh-server-string.c \
	detect-ssh-hassh-server.c \
	detect-ssh-hassh-string.c \
	detect-ssh-hassh.c \
	detect-ssh-proto-version.c \
	detect-ssh-proto.c \
	detect-ssh-software-version.c \
	detect-ssh-software.c \
	detect-ssl-state.c \
	detect-ssl-version.c \
	detect-stream_size.c \
	detect-tag.c \
	detect-target.c \
	detect-tcp-ack.c \
	detect-tcp-flags.c \
	detect-tcp-seq.c \
	detect-tcp-window.c \
	detect-tcp-wscale.c \
	detect-tcphdr.c \
	detect-tcpmss.c \
	detect-template.c \
	detect-template2.c \
	detect-threshold.c \
	detect-tls-alpn.c \
	detect-tls-cert-fingerprint.c \
	detect-tls-cert-issuer.c \
	detect-tls-cert-serial.c \
	detect-tls-cert-subject.c \
	detect-tls-cert-validity.c \
	detect-tls-certs.c \
	detect-tls-ja3-hash.c \
	detect-tls-ja3-string.c \
	detect-tls-ja3s-hash.c \
	detect-tls-ja3s-string.c \
	detect-tls-random.c \
	detect-tls-sni.c \
	detect-tls-subjectaltname.c \
	detect-tls-version.c \
	detect-tls.c \
	detect-tos.c \
	detect-transform-luaxform.c \
	detect-transform-pcrexform.c \
	detect-ttl.c \
	detect-udphdr.c \
	detect-uricontent.c \
	detect-urilen.c \
	detect-vlan.c \
	detect-within.c \
	detect-xbits.c \
	detect.c \
	device-storage.c \
	feature.c \
	flow-bit.c \
	flow-bypass.c \
	flow-callbacks.c \
	flow-hash.c \
	flow-manager.c \
	flow-queue.c \
	flow-spare-pool.c \
	flow-storage.c \
	flow-timeout.c \
	flow-util.c \
	flow-var.c \
	flow-worker.c \
	flow.c \
	host-bit.c \
	host-queue.c \
	host-storage.c \
	host-timeout.c \
	host.c \
	ippair-bit.c \
	ippair-queue.c \
	ippair-storage.c \
	ippair-timeout.c \
	ippair.c \
	log-cf-common.c \
	log-flush.c \
	log-httplog.c \
	log-pcap.c \
	log-stats.c \
	log-tcp-data.c \
	log-tlslog.c \
	log-tlsstore.c \
	output-eve-null.c \
	output-eve-stream.c \
	output-eve-syslog.c \
	output-eve.c \
	output-file.c \
	output-filedata.c \
	output-filestore.c \
	output-flow.c \
	output-json-alert.c \
	output-json-anomaly.c \
	output-json-arp.c \
	output-json-common.c \
	output-json-dcerpc.c \
	output-json-dhcp.c \
	output-json-dnp3-objects.c \
	output-json-dnp3.c \
	output-json-dns.c \
	output-json-drop.c \
	output-json-email-common.c \
	output-json-file.c \
	output-json-flow.c \
	output-json-frame.c \
	output-json-ftp.c \
	output-json-http.c \
	output-json-ike.c \
	output-json-mdns.c \
	output-json-metadata.c \
	output-json-mqtt.c \
	output-json-netflow.c \
	output-json-nfs.c \
	output-json-pgsql.c \
	output-json-smb.c \
	output-json-smtp.c \
	output-json-stats.c \
	output-json-tls.c \
	output-json.c \
	output-lua.c \
	output-packet.c \
	output-stats.c \
	output-streaming.c \
	output-tx.c \
	output.c \
	packet-queue.c \
	packet.c \
	pkt-var.c \
	reputation.c \
	respond-reject-libnet11.c \
	respond-reject.c \
	runmode-af-packet.c \
	runmode-af-xdp.c \
	runmode-dpdk.c \
	runmode-erf-dag.c \
	runmode-erf-file.c \
	runmode-ipfw.c \
	runmode-lib.c \
	runmode-netmap.c \
	runmode-nflog.c \
	runmode-nfq.c \
	runmode-pcap-file.c \
	runmode-pcap.c \
	runmode-unittests.c \
	runmode-unix-socket.c \
	runmode-windivert.c \
	runmodes.c \
	source-af-packet.c \
	source-af-xdp.c \
	source-dpdk.c \
	source-erf-dag.c \
	source-erf-file.c \
	source-ipfw.c \
	source-lib.c \
	source-netmap.c \
	source-nflog.c \
	source-nfq.c \
	source-pcap-file-directory-helper.c \
	source-pcap-file-helper.c \
	source-pcap-file.c \
	source-pcap.c \
	source-windivert.c \
	stream-tcp-cache.c \
	stream-tcp-inline.c \
	stream-tcp-list.c \
	stream-tcp-reassemble.c \
	stream-tcp-sack.c \
	stream-tcp-util.c \
	stream-tcp.c \
	stream.c \
	suricata.c \
	thread-callbacks.c \
	thread-storage.c \
	threads.c \
	tm-modules.c \
	tm-queuehandlers.c \
	tm-queues.c \
	tm-threads.c \
	tmqh-flow.c \
	tmqh-packetpool.c \
	tmqh-simple.c \
	tx-bit.c \
	unix-manager.c \
	util-action.c \
	util-affinity.c \
	util-atomic.c \
	util-bpf.c \
	util-buffer.c \
	util-byte.c \
	util-checksum.c \
	util-cidr.c \
	util-classification-config.c \
	util-conf.c \
	util-coredump-config.c \
	util-cpu.c \
	util-daemon.c \
	util-datalink.c \
	util-debug-filters.c \
	util-debug.c \
	util-detect.c \
	util-device.c \
	util-dpdk-bonding.c \
	util-dpdk-common.c \
	util-dpdk-i40e.c \
	util-dpdk-ice.c \
	util-dpdk-ixgbe.c \
	util-dpdk-mlx5.c \
	util-dpdk-rss.c \
	util-dpdk.c \
	util-ebpf.c \
	util-enum.c \
	util-error.c \
	util-exception-policy.c \
	util-file-decompression.c \
	util-file-swf-decompression.c \
	util-file.c \
	util-fix_checksum.c \
	util-flow-rate.c \
	util-fmemopen.c \
	util-hash-lookup3.c \
	util-hash-string.c \
	util-hash.c \
	util-hashlist.c \
	util-host-info.c \
	util-host-os-info.c \
	util-hugepages.c \
	util-hyperscan.c \
	util-ioctl.c \
	util-ip.c \
	util-ja3.c \
	util-landlock.c \
	util-log-redis.c \
	util-logopenfile.c \
	util-lua-base64lib.c \
	util-lua-builtins.c \
	util-lua-common.c \
	util-lua-config.c \
	util-lua-dataset.c \
	util-lua-dnp3-objects.c \
	util-lua-dnp3.c \
	util-lua-dns.c \
	util-lua-filelib.c \
	util-lua-flowintlib.c \
	util-lua-flowlib.c \
	util-lua-flowvarlib.c \
	util-lua-bytevarlib.c \
	util-lua-hashlib.c \
	util-lua-http.c \
	util-lua-ja3.c \
	util-lua-log.c \
	util-lua-packetlib.c \
	util-lua-rule.c \
	util-lua-sandbox.c \
	util-lua-smtp.c \
	util-lua-ssh.c \
	util-lua-tls.c \
	util-lua-util.c \
	util-lua.c \
	util-macset.c \
	util-magic.c \
	util-mem.c \
	util-memcmp.c \
	util-memrchr.c \
	util-misc.c \
	util-mpm-ac-ks-small.c \
	util-mpm-ac-ks.c \
	util-mpm-ac-queue.c \
	util-mpm-ac.c \
	util-mpm-hs-cache.c \
	util-mpm-hs-core.c \
	util-mpm-hs.c \
	util-mpm.c \
	util-pages.c \
	util-path.c \
	util-pidfile.c \
	util-plugin.c \
	util-pool-thread.c \
	util-pool.c \
	util-port-interval-tree.c \
	util-prefilter.c \
	util-print.c \
	util-privs.c \
	util-profiling-keywords.c \
	util-profiling-locks.c \
	util-profiling-prefilter.c \
	util-profiling-rulegroups.c \
	util-profiling-rules.c \
	util-profiling.c \
	util-proto-name.c \
	util-radix4-tree.c \
	util-radix6-tree.c \
	util-random.c \
	util-reference-config.c \
	util-rohash.c \
	util-rule-vars.c \
	util-runmodes.c \
	util-running-modes.c \
	util-signal.c \
	util-spm-bm.c \
	util-spm-bs.c \
	util-spm-bs2bm.c \
	util-spm-hs.c \
	util-spm.c \
	util-storage.c \
	util-streaming-buffer.c \
	util-strlcatu.c \
	util-strlcpyu.c \
	util-strptime.c \
	util-sysfs.c \
	util-syslog.c \
	util-systemd.c \
	util-thash.c \
	util-threshold-config.c \
	util-time.c \
	util-unittest-helper.c \
	util-unittest.c \
	util-var-name.c \
	util-var.c \
	win32-misc.c \
	win32-service.c \
	win32-syscall.c

EXTRA_DIST = \
	${PRIVATE_INCLUDES} \
	tests/stream-tcp-inline.c \
	tests/stream-tcp-list.c \
	tests/detect-ipv4hdr.c \
	tests/detect-ipv6hdr.c \
	tests/detect-tcphdr.c \
	tests/detect-udphdr.c \
	tests/reputation.c \
	tests/detect-bsize.c \
	tests/detect-http2.c \
	tests/detect-icmpv6-mtu.c \
	tests/detect-icmpv6hdr.c \
	tests/detect-template.c \
	tests/detect-transform-pcrexform.c \
	tests/detect-ttl.c \
	tests/source-pcap.c \
	tests/app-layer-htp-file.c \
	tests/detect-engine-alert.c \
	tests/detect-engine-content-inspection.c \
	tests/detect-icmpv4hdr.c \
	tests/detect-parse.c \
	tests/stream-tcp-reassemble.c \
	tests/detect-file-data.c \
	tests/detect-http-client-body.c \
	tests/detect-http-cookie.c \
	tests/detect-http-header.c \
	tests/detect-http-host.c \
	tests/detect-http-method.c \
	tests/detect-http-raw-header.c \
	tests/detect-http-server-body.c \
	tests/detect-http-stat-code.c \
	tests/detect-http-stat-msg.c \
	tests/detect-http-uri.c \
	tests/detect-http-user-agent.c \
	tests/detect-ssl-state.c \
	tests/detect-ssl-version.c \
	tests/detect-tls-cert-fingerprint.c \
	tests/detect-tls-cert-issuer.c \
	tests/detect-tls-cert-serial.c \
	tests/detect-tls-cert-subject.c \
	tests/detect-tls-cert-validity.c \
	tests/detect-tls-certs.c \
	tests/detect-tls-version.c \
	tests/detect-ipaddr.c \
	tests/detect.c \
	tests/stream-tcp.c \
	tests/output-json-stats.c

EXTRA_CFLAGS =

install-headers:
	mkdir -p $(DESTDIR)${includedir}/suricata
	for header in $(noinst_HEADERS); do \
		$(INSTALL_DATA) $$header "$(DESTDIR)${includedir}/suricata"; \
	done
	if test -e ../rust/dist/rust-bindings.h; then \
		$(INSTALL_DATA) ../rust/dist/rust-bindings.h "$(DESTDIR)${includedir}/suricata"; \
	fi
	if test -e ../rust/gen/rust-bindings.h; then \
		$(INSTALL_DATA) ../rust/gen/rust-bindings.h "$(DESTDIR)${includedir}/suricata"; \
	fi

# Until we can remove autoconf.h from our headers, we need to to
# provide this for library/plugin users.
	$(INSTALL_DATA) autoconf.h "$(DESTDIR)${includedir}/suricata"

# set the include path found by configure
AM_CPPFLAGS = $(all_includes)

noinst_LIBRARIES = libsuricata_c.a

suricata_SOURCES = main.c

# the library search path.
suricata_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
# rust library depends also on c
if LINKER_SUPPORTS_GROUP
LDADD_GENERIC = "-Wl,--start-group,libsuricata_c.a,$(RUST_SURICATA_LIB),--end-group" $(RUST_LDADD)
else
LDADD_GENERIC = libsuricata_c.a $(RUST_SURICATA_LIB) libsuricata_c.a $(RUST_SURICATA_LIB) $(RUST_LDADD)
endif
suricata_LDADD = $(LDADD_GENERIC)
suricata_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)

if BUILD_SHARED_LIBRARY
libsuricata.so.$(VERSION): libsuricata_c.a
	$(CC) -shared -o $@ -Wl,-soname,$@ -Wl,--whole-archive \
		libsuricata_c.a \
		$(RUST_SURICATA_LIB) \
		-Wl,--no-whole-archive
libsuricata.so: libsuricata.so.$(VERSION)
else
libsuricata.so:
	@echo "shared library support not enabled"
	@exit 1
endif

if BUILD_SHARED_LIBRARY
install-library: libsuricata.so.$(VERSION)
else
install-library:
endif
	$(MKDIR_P) "$(DESTDIR)$(libdir)"
	$(INSTALL_DATA) libsuricata_c.a "$(DESTDIR)$(libdir)"
if BUILD_SHARED_LIBRARY
	$(INSTALL) libsuricata.so.$(VERSION) "$(DESTDIR)$(libdir)"
	ln -sf libsuricata.so.$(VERSION) "$(DESTDIR)$(libdir)/libsuricata.so"
endif

uninstall-local:
	rm -f "$(DESTDIR)$(libdir)/libsuricata_c.a"
	rm -f "$(DESTDIR)$(libdir)/libsuricata.so"
	rm -f "$(DESTDIR)$(libdir)/libsuricata.$(VERSION)"

if BUILD_FUZZTARGETS

LDFLAGS_FUZZ = $(all_libraries) $(SECLDFLAGS)
LDADD_FUZZ = $(LDADD_GENERIC)

fuzz_applayerprotodetectgetproto_SOURCES = tests/fuzz/fuzz_applayerprotodetectgetproto.c tests/fuzz/confyaml.c
fuzz_applayerprotodetectgetproto_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_applayerprotodetectgetproto_LDADD = $(LDADD_FUZZ)
fuzz_applayerprotodetectgetproto_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_applayerprotodetectgetproto_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_applayerprotodetectgetproto_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_applayerprotodetectgetproto_SOURCES = force-cxx-linking.cxx

fuzz_applayerparserparse_SOURCES = tests/fuzz/fuzz_applayerparserparse.c tests/fuzz/confyaml.c
fuzz_applayerparserparse_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_applayerparserparse_LDADD = $(LDADD_FUZZ)
fuzz_applayerparserparse_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_applayerparserparse_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_applayerparserparse_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_applayerparserparse_SOURCES = force-cxx-linking.cxx

fuzz_siginit_SOURCES = tests/fuzz/fuzz_siginit.c
fuzz_siginit_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_siginit_LDADD = $(LDADD_FUZZ)
fuzz_siginit_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_siginit_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_siginit_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_siginit_SOURCES = force-cxx-linking.cxx

fuzz_confyamlloadstring_SOURCES = tests/fuzz/fuzz_confyamlloadstring.c
fuzz_confyamlloadstring_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_confyamlloadstring_LDADD = $(LDADD_FUZZ)
fuzz_confyamlloadstring_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_confyamlloadstring_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_confyamlloadstring_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_confyamlloadstring_SOURCES = force-cxx-linking.cxx

fuzz_decodepcapfile_SOURCES = tests/fuzz/fuzz_decodepcapfile.c
fuzz_decodepcapfile_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_decodepcapfile_LDADD = $(LDADD_FUZZ)
fuzz_decodepcapfile_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_decodepcapfile_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_decodepcapfile_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_decodepcapfile_SOURCES = force-cxx-linking.cxx

fuzz_sigpcap_SOURCES = tests/fuzz/fuzz_sigpcap.c tests/fuzz/confyaml.c
fuzz_sigpcap_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_sigpcap_LDADD = $(LDADD_FUZZ)
fuzz_sigpcap_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_sigpcap_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_sigpcap_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_sigpcap_SOURCES = force-cxx-linking.cxx

if HAS_FUZZPCAP
fuzz_sigpcap_aware_SOURCES = tests/fuzz/fuzz_sigpcap_aware.c tests/fuzz/confyaml.c
fuzz_sigpcap_aware_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_sigpcap_aware_LDADD = $(LDADD_FUZZ) -lfuzzpcap
fuzz_sigpcap_aware_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_sigpcap_aware_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_sigpcap_aware_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_sigpcap_aware_SOURCES = force-cxx-linking.cxx

fuzz_predefpcap_aware_SOURCES = tests/fuzz/fuzz_predefpcap_aware.c tests/fuzz/confyaml.c
fuzz_predefpcap_aware_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_predefpcap_aware_LDADD = $(LDADD_FUZZ) -lfuzzpcap
fuzz_predefpcap_aware_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_predefpcap_aware_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_predefpcap_aware_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_predefpcap_aware_SOURCES = force-cxx-linking.cxx
endif

fuzz_decodebase64_SOURCES = tests/fuzz/fuzz_decodebase64.c
fuzz_decodebase64_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_decodebase64_LDADD = $(LDADD_FUZZ)
fuzz_decodebase64_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_decodebase64_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_decodebase64_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_decodebase64_SOURCES = force-cxx-linking.cxx

fuzz_mimedecparseline_SOURCES = tests/fuzz/fuzz_mimedecparseline.c
fuzz_mimedecparseline_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_mimedecparseline_LDADD = $(LDADD_FUZZ)
fuzz_mimedecparseline_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_mimedecparseline_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_mimedecparseline_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_mimedecparseline_SOURCES = force-cxx-linking.cxx
endif

# default CFLAGS
AM_CFLAGS = ${OPTIMIZATION_CFLAGS} ${GCC_CFLAGS} ${CLANG_CFLAGS}            \
    ${SECCFLAGS} ${PCAP_CFLAGS} ${EXTRA_CFLAGS}								\
    -Wall -Wno-unused-parameter -Wmissing-prototypes -Wmissing-declarations \
    -Wstrict-prototypes -Wwrite-strings -Wbad-function-cast                 \
    -Wformat-security -Wno-format-nonliteral -Wmissing-format-attribute     \
    -funsigned-char

# different flags for different cases
if DEBUG
AM_CFLAGS += -ggdb -O0
endif

AM_LDFLAGS = ${SECLDFLAGS}

if BUILD_UNITTESTS
check-am:
	-mkdir $(top_builddir)/qa/log/
	$(top_builddir)/src/suricata -u -l $(top_builddir)/qa/log/
	-rm -rf $(top_builddir)/qa/log
endif

distclean-local:
	-rm -rf $(top_builddir)/src/build-info.h
