bin_PROGRAMS = suricata
if BUILD_FUZZTARGETS
    bin_PROGRAMS += fuzz_applayerprotodetectgetproto \
    fuzz_applayerparserparse fuzz_siginit \
    fuzz_confyamlloadstring fuzz_decodepcapfile \
    fuzz_sigpcap fuzz_mimedecparseline
if HAS_FUZZPCAP
    bin_PROGRAMS += fuzz_sigpcap_aware fuzz_predefpcap_aware
endif
endif

noinst_HEADERS = \
	action-globals.h \
	alert-debuglog.h \
	alert-fastlog.h \
	alert-syslog.h \
	app-layer-detect-proto.h \
	app-layer-events.h \
	app-layer-expectation.h \
	app-layer-frames.h \
	app-layer-parser.h \
	app-layer-protos.h \
	app-layer-register.h \
	app-layer.h \
	app-layer/bittorrent-dht/logger.h \
	app-layer/dcerpc/logger.h \
	app-layer/dhcp/detect-leasetime.h \
	app-layer/dhcp/detect-rebinding-time.h \
	app-layer/dhcp/detect-renewal-time.h \
	app-layer/dhcp/logger.h \
	app-layer/dnp3/detect.h \
	app-layer/dnp3/logger-objects.h \
	app-layer/dnp3/logger.h \
	app-layer/dnp3/lua-objects.h \
	app-layer/dnp3/lua.h \
	app-layer/dnp3/parser-objects.h \
	app-layer/dnp3/parser.h \
	app-layer/dns/detect-opcode.h \
	app-layer/dns/detect-query.h \
	app-layer/dns/logger.h \
	app-layer/dns/lua.h \
	app-layer/enip/parser-common.h \
	app-layer/enip/parser.h \
	app-layer/ftp/detect-bounce.h \
	app-layer/ftp/detect-data.h \
	app-layer/ftp/logger.h \
	app-layer/ftp/parser.h \
	app-layer/http/detect-accept-enc.h \
	app-layer/http/detect-accept-lang.h \
	app-layer/http/detect-accept.h \
	app-layer/http/detect-client-body.h \
	app-layer/http/detect-connection.h \
	app-layer/http/detect-content-len.h \
	app-layer/http/detect-content-type.h \
	app-layer/http/detect-cookie.h \
	app-layer/http/detect-header-common.h \
	app-layer/http/detect-header-names.h \
	app-layer/http/detect-header.h \
	app-layer/http/detect-headers-stub.h \
	app-layer/http/detect-headers.h \
	app-layer/http/detect-host.h \
	app-layer/http/detect-location.h \
	app-layer/http/detect-method.h \
	app-layer/http/detect-protocol.h \
	app-layer/http/detect-raw-header.h \
	app-layer/http/detect-referer.h \
	app-layer/http/detect-request-line.h \
	app-layer/http/detect-response-line.h \
	app-layer/http/detect-server-body.h \
	app-layer/http/detect-server.h \
	app-layer/http/detect-start.h \
	app-layer/http/detect-stat-code.h \
	app-layer/http/detect-stat-msg.h \
	app-layer/http/detect-ua.h \
	app-layer/http/detect-uri.h \
	app-layer/http/log-httplog.h \
	app-layer/http/logger.h \
	app-layer/http/lua.h \
	app-layer/http/parser-body.h \
	app-layer/http/parser-file.h \
	app-layer/http/parser-libhtp.h \
	app-layer/http/parser-mem.h \
	app-layer/http/parser-range.h \
	app-layer/http/parser-xff.h \
	app-layer/http/parser.h \
	app-layer/http2/detect.h \
	app-layer/http2/logger.h \
	app-layer/http2/parser.h \
	app-layer/ike/detect-chosen-sa.h \
	app-layer/ike/detect-exch-type.h \
	app-layer/ike/detect-key-exchange-payload-length.h \
	app-layer/ike/detect-key-exchange-payload.h \
	app-layer/ike/detect-nonce-payload-length.h \
	app-layer/ike/detect-nonce-payload.h \
	app-layer/ike/detect-spi.h \
	app-layer/ike/detect-vendor.h \
	app-layer/ike/logger.h \
	app-layer/ike/parser.h \
	app-layer/krb5/detect-cname.h \
	app-layer/krb5/detect-errcode.h \
	app-layer/krb5/detect-msgtype.h \
	app-layer/krb5/detect-sname.h \
	app-layer/krb5/detect-ticket-encryption.h \
	app-layer/krb5/logger.h \
	app-layer/krb5/parser.h \
	app-layer/modbus/detect.h \
	app-layer/modbus/logger.h \
	app-layer/modbus/parser.h \
	app-layer/mqtt/detect-connack-sessionpresent.h \
	app-layer/mqtt/detect-connect-clientid.h \
	app-layer/mqtt/detect-connect-flags.h \
	app-layer/mqtt/detect-connect-password.h \
	app-layer/mqtt/detect-connect-protocol-string.h \
	app-layer/mqtt/detect-connect-username.h \
	app-layer/mqtt/detect-connect-willmessage.h \
	app-layer/mqtt/detect-connect-willtopic.h \
	app-layer/mqtt/detect-flags.h \
	app-layer/mqtt/detect-protocol-version.h \
	app-layer/mqtt/detect-publish-message.h \
	app-layer/mqtt/detect-publish-topic.h \
	app-layer/mqtt/detect-qos.h \
	app-layer/mqtt/detect-reason-code.h \
	app-layer/mqtt/detect-subscribe-topic.h \
	app-layer/mqtt/detect-type.h \
	app-layer/mqtt/detect-unsubscribe-topic.h \
	app-layer/mqtt/logger.h \
	app-layer/mqtt/parser.h \
	app-layer/nfs/detect-procedure.h \
	app-layer/nfs/detect-version.h \
	app-layer/nfs/logger.h \
	app-layer/nfs/parser-tcp.h \
	app-layer/nfs/parser-udp.h \
	app-layer/ntp/parser.h \
	app-layer/pgsql/logger.h \
	app-layer/quic/detect-cyu-hash.h \
	app-layer/quic/detect-cyu-string.h \
	app-layer/quic/detect-sni.h \
	app-layer/quic/detect-ua.h \
	app-layer/quic/detect-version.h \
	app-layer/quic/logger.h \
	app-layer/quic/parser.h \
	app-layer/rdp/logger.h \
	app-layer/rdp/parser.h \
	app-layer/rfb/detect-name.h \
	app-layer/rfb/detect-secresult.h \
	app-layer/rfb/detect-sectype.h \
	app-layer/rfb/logger.h \
	app-layer/rfb/parser.h \
	app-layer/sip/detect-method.h \
	app-layer/sip/detect-protocol.h \
	app-layer/sip/detect-request-line.h \
	app-layer/sip/detect-response-line.h \
	app-layer/sip/detect-stat-code.h \
	app-layer/sip/detect-stat-msg.h \
	app-layer/sip/detect-uri.h \
	app-layer/sip/logger.h \
	app-layer/sip/parser.h \
	app-layer/smb/detect-ntlmssp.h \
	app-layer/smb/detect-share.h \
	app-layer/smb/logger.h \
	app-layer/smb/parser.h \
	app-layer/smtp/logger.h \
	app-layer/smtp/lua.h \
	app-layer/smtp/parser.h \
	app-layer/snmp/detect-community.h \
	app-layer/snmp/detect-pdu_type.h \
	app-layer/snmp/detect-usm.h \
	app-layer/snmp/detect-version.h \
	app-layer/snmp/logger.h \
	app-layer/snmp/parser.h \
	app-layer/ssh/detect-hassh-server-string.h \
	app-layer/ssh/detect-hassh-server.h \
	app-layer/ssh/detect-hassh-string.h \
	app-layer/ssh/detect-hassh.h \
	app-layer/ssh/detect-proto-version.h \
	app-layer/ssh/detect-proto.h \
	app-layer/ssh/detect-software-version.h \
	app-layer/ssh/detect-software.h \
	app-layer/ssh/logger.h \
	app-layer/ssh/lua-hassh.h \
	app-layer/ssh/lua.h \
	app-layer/ssh/parser.h \
	app-layer/ssl/detect-state.h \
	app-layer/ssl/detect-version.h \
	app-layer/ssl/parser.h \
	app-layer/template/detect-2.h \
	app-layer/template/detect-rust-buffer.h \
	app-layer/template/detect.h \
	app-layer/template/logger.h \
	app-layer/tftp/logger.h \
	app-layer/tftp/parser.h \
	app-layer/tls/detect-cert-fingerprint.h \
	app-layer/tls/detect-cert-issuer.h \
	app-layer/tls/detect-cert-serial.h \
	app-layer/tls/detect-cert-subject.h \
	app-layer/tls/detect-cert-validity.h \
	app-layer/tls/detect-certs.h \
	app-layer/tls/detect-ja3-hash.h \
	app-layer/tls/detect-ja3-string.h \
	app-layer/tls/detect-ja3s-hash.h \
	app-layer/tls/detect-ja3s-string.h \
	app-layer/tls/detect-random.h \
	app-layer/tls/detect-sni.h \
	app-layer/tls/detect-version.h \
	app-layer/tls/detect.h \
	app-layer/tls/log-tlslog.h \
	app-layer/tls/log-tlsstore.h \
	app-layer/tls/logger.h \
	app-layer/tls/lua.h \
	autoconf.h \
	build-info.h \
	conf-yaml-loader.h \
	conf.h \
	counters.h \
	datasets-ipv4.h \
	datasets-ipv6.h \
	datasets-md5.h \
	datasets-reputation.h \
	datasets-sha256.h \
	datasets-string.h \
	datasets.h \
	decode-chdlc.h \
	decode-erspan.h \
	decode-esp.h \
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
	defrag-queue.h \
	defrag-timeout.h \
	defrag.h \
	detect-app-layer-event.h \
	detect-app-layer-protocol.h \
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
	detect-cipservice.h \
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
	detect-dsize.h \
	detect-engine-address-ipv4.h \
	detect-engine-address-ipv6.h \
	detect-engine-address.h \
	detect-engine-alert.h \
	detect-engine-analyzer.h \
	detect-engine-build.h \
	detect-engine-content-inspection.h \
	detect-engine-dcepayload.h \
	detect-engine-enip.h \
	detect-engine-event.h \
	detect-engine-file.h \
	detect-engine-frame.h \
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
	detect-geoip.h \
	detect-gid.h \
	detect-hostbits.h \
	detect-icmp-id.h \
	detect-icmp-seq.h \
	detect-icmpv4hdr.h \
	detect-icmpv6-mtu.h \
	detect-icmpv6hdr.h \
	detect-icode.h \
	detect-id.h \
	detect-ipaddr.h \
	detect-ipopts.h \
	detect-ipproto.h \
	detect-iprep.h \
	detect-ipv4hdr.h \
	detect-ipv6hdr.h \
	detect-isdataat.h \
	detect-itype.h \
	detect-l3proto.h \
	detect-lua-extensions.h \
	detect-lua.h \
	detect-mark.h \
	detect-metadata.h \
	detect-msg.h \
	detect-noalert.h \
	detect-nocase.h \
	detect-offset.h \
	detect-parse.h \
	detect-pcre.h \
	detect-pkt-data.h \
	detect-pktvar.h \
	detect-prefilter.h \
	detect-priority.h \
	detect-rawbytes.h \
	detect-reference.h \
	detect-replace.h \
	detect-rev.h \
	detect-rpc.h \
	detect-sameip.h \
	detect-sid.h \
	detect-stream_size.h \
	detect-tag.h \
	detect-target.h \
	detect-tcp-ack.h \
	detect-tcp-flags.h \
	detect-tcp-seq.h \
	detect-tcp-window.h \
	detect-tcphdr.h \
	detect-tcpmss.h \
	detect-threshold.h \
	detect-tos.h \
	detect-transform-casechange.h \
	detect-transform-compress-whitespace.h \
	detect-transform-dotprefix.h \
	detect-transform-header-lowercase.h \
	detect-transform-md5.h \
	detect-transform-pcrexform.h \
	detect-transform-sha1.h \
	detect-transform-sha256.h \
	detect-transform-strip-whitespace.h \
	detect-transform-urldecode.h \
	detect-transform-xor.h \
	detect-ttl.h \
	detect-udphdr.h \
	detect-uricontent.h \
	detect-urilen.h \
	detect-within.h \
	detect-xbits.h \
	detect.h \
	device-storage.h \
	feature.h \
	flow-bit.h \
	flow-bypass.h \
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
	ippair-bit.h \
	ippair-queue.h \
	ippair-storage.h \
	ippair-timeout.h \
	ippair.h \
	log-cf-common.h \
	log-pcap.h \
	log-stats.h \
	log-tcp-data.h \
	output/eve/output-eve-null.h \
	output/eve/output-eve-stream.h \
	output/eve/output-eve-syslog.h \
	output/eve/output-json-alert.h \
	output/eve/output-json-anomaly.h \
	output/eve/output-json-drop.h \
	output/eve/output-json-email-common.h \
	output/eve/output-json-file.h \
	output/eve/output-json-flow.h \
	output/eve/output-json-frame.h \
	output/eve/output-json-metadata.h \
	output/eve/output-json-netflow.h \
	output/eve/output-json-stats.h \
	output/eve/output-json.h \
	output/output-file.h \
	output/output-filedata.h \
	output/output-filestore.h \
	output/output-flow.h \
	output/output-lua.h \
	output/output-packet.h \
	output/output-stats.h \
	output/output-streaming.h \
	output/output-tx.h \
	output/output.h \
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
	runmode-napatech.h \
	runmode-netmap.h \
	runmode-nflog.h \
	runmode-nfq.h \
	runmode-pcap-file.h \
	runmode-pcap.h \
	runmode-pfring.h \
	runmode-unittests.h \
	runmode-unix-socket.h \
	runmode-windivert.h \
	runmodes.h \
	rust-context.h \
	rust.h \
	source-af-packet.h \
	source-af-xdp.h \
	source-dpdk.h \
	source-erf-dag.h \
	source-erf-file.h \
	source-ipfw.h \
	source-napatech.h \
	source-netmap.h \
	source-nflog.h \
	source-nfq-prototypes.h \
	source-nfq.h \
	source-pcap-file-directory-helper.h \
	source-pcap-file-helper.h \
	source-pcap-file.h \
	source-pcap.h \
	source-pfring.h \
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
	unix-manager.h \
	util/action.h \
	util/affinity.h \
	util/atomic.h \
	util/base64.h \
	util/bloomfilter-counting.h \
	util/bloomfilter.h \
	util/bpf.h \
	util/buffer.h \
	util/byte.h \
	util/checksum.h \
	util/cidr.h \
	util/classification-config.h \
	util/clock.h \
	util/conf.h \
	util/config.h \
	util/coredump-config.h \
	util/cpu.h \
	util/daemon.h \
	util/datalink.h \
	util/debug-filters.h \
	util/debug.h \
	util/decode-mime.h \
	util/detect.h \
	util/device.h \
	util/dpdk-bonding.h \
	util/dpdk-i40e.h \
	util/dpdk-ice.h \
	util/dpdk-ixgbe.h \
	util/dpdk.h \
	util/ebpf.h \
	util/enum.h \
	util/error.h \
	util/exception-policy.h \
	util/file-decompression.h \
	util/file-swf-decompression.h \
	util/file.h \
	util/fix_checksum.h \
	util/fmemopen.h \
	util/hash-lookup3.h \
	util/hash-string.h \
	util/hash.h \
	util/hashlist.h \
	util/host-info.h \
	util/host-os-info.h \
	util/hyperscan.h \
	util/ioctl.h \
	util/ip.h \
	util/ja3.h \
	util/landlock.h \
	util/log-redis.h \
	util/logopenfile.h \
	util/lua/lua-common.h \
	util/lua/lua-ja3.h \
	util/lua/lua.h \
	util/lua/luajit.h \
	util/macset.h \
	util/magic.h \
	util/mem.h \
	util/memcmp.h \
	util/memcpy.h \
	util/memrchr.h \
	util/misc.h \
	util/mpm/mpm-ac-ks.h \
	util/mpm/mpm-ac.h \
	util/mpm/mpm-hs.h \
	util/mpm/mpm.h \
	util/napatech.h \
	util/optimize.h \
	util/pages.h \
	util/path.h \
	util/pidfile.h \
	util/plugin.h \
	util/pool-thread.h \
	util/pool.h \
	util/prefilter.h \
	util/print.h \
	util/privs.h \
	util/profiling-locks.h \
	util/profiling.h \
	util/proto-name.h \
	util/radix-tree.h \
	util/random.h \
	util/reference-config.h \
	util/rohash.h \
	util/rule-vars.h \
	util/runmodes.h \
	util/running-modes.h \
	util/signal.h \
	util/spm-bm.h \
	util/spm-bs.h \
	util/spm-bs2bm.h \
	util/spm-hs.h \
	util/spm.h \
	util/storage.h \
	util/streaming-buffer.h \
	util/sysfs.h \
	util/syslog.h \
	util/thash.h \
	util/threshold-config.h \
	util/time.h \
	util/unittest-helper.h \
	util/unittest.h \
	util/validate.h \
	util/var-name.h \
	util/var.h \
	windows/win32-misc.h \
	windows/win32-service.h \
	windows/win32-syscall.h \
	windows/win32-syslog.h

libsuricata_c_a_SOURCES = \
	alert-debuglog.c \
	alert-fastlog.c \
	alert-syslog.c \
	app-layer-detect-proto.c \
	app-layer-events.c \
	app-layer-expectation.c \
	app-layer-frames.c \
	app-layer-parser.c \
	app-layer-protos.c \
	app-layer-register.c \
	app-layer.c \
	app-layer/bittorrent-dht/logger.c \
	app-layer/dcerpc/logger.c \
	app-layer/dhcp/detect-leasetime.c \
	app-layer/dhcp/detect-rebinding-time.c \
	app-layer/dhcp/detect-renewal-time.c \
	app-layer/dhcp/logger.c \
	app-layer/dnp3/detect.c \
	app-layer/dnp3/logger-objects.c \
	app-layer/dnp3/logger.c \
	app-layer/dnp3/lua-objects.c \
	app-layer/dnp3/lua.c \
	app-layer/dnp3/parser-objects.c \
	app-layer/dnp3/parser.c \
	app-layer/dns/detect-opcode.c \
	app-layer/dns/detect-query.c \
	app-layer/dns/logger.c \
	app-layer/dns/lua.c \
	app-layer/enip/parser-common.c \
	app-layer/enip/parser.c \
	app-layer/ftp/detect-bounce.c \
	app-layer/ftp/detect-data.c \
	app-layer/ftp/logger.c \
	app-layer/ftp/parser.c \
	app-layer/http/detect-accept-enc.c \
	app-layer/http/detect-accept-lang.c \
	app-layer/http/detect-accept.c \
	app-layer/http/detect-client-body.c \
	app-layer/http/detect-connection.c \
	app-layer/http/detect-content-len.c \
	app-layer/http/detect-content-type.c \
	app-layer/http/detect-cookie.c \
	app-layer/http/detect-header-common.c \
	app-layer/http/detect-header-names.c \
	app-layer/http/detect-header.c \
	app-layer/http/detect-headers.c \
	app-layer/http/detect-host.c \
	app-layer/http/detect-location.c \
	app-layer/http/detect-method.c \
	app-layer/http/detect-protocol.c \
	app-layer/http/detect-raw-header.c \
	app-layer/http/detect-referer.c \
	app-layer/http/detect-request-line.c \
	app-layer/http/detect-response-line.c \
	app-layer/http/detect-server-body.c \
	app-layer/http/detect-server.c \
	app-layer/http/detect-start.c \
	app-layer/http/detect-stat-code.c \
	app-layer/http/detect-stat-msg.c \
	app-layer/http/detect-ua.c \
	app-layer/http/detect-uri.c \
	app-layer/http/log-httplog.c \
	app-layer/http/logger.c \
	app-layer/http/lua.c \
	app-layer/http/parser-body.c \
	app-layer/http/parser-file.c \
	app-layer/http/parser-libhtp.c \
	app-layer/http/parser-mem.c \
	app-layer/http/parser-range.c \
	app-layer/http/parser-xff.c \
	app-layer/http/parser.c \
	app-layer/http2/detect.c \
	app-layer/http2/logger.c \
	app-layer/http2/parser.c \
	app-layer/ike/detect-chosen-sa.c \
	app-layer/ike/detect-exch-type.c \
	app-layer/ike/detect-key-exchange-payload-length.c \
	app-layer/ike/detect-key-exchange-payload.c \
	app-layer/ike/detect-nonce-payload-length.c \
	app-layer/ike/detect-nonce-payload.c \
	app-layer/ike/detect-spi.c \
	app-layer/ike/detect-vendor.c \
	app-layer/ike/logger.c \
	app-layer/ike/parser.c \
	app-layer/krb5/detect-cname.c \
	app-layer/krb5/detect-errcode.c \
	app-layer/krb5/detect-msgtype.c \
	app-layer/krb5/detect-sname.c \
	app-layer/krb5/detect-ticket-encryption.c \
	app-layer/krb5/logger.c \
	app-layer/krb5/parser.c \
	app-layer/modbus/detect.c \
	app-layer/modbus/logger.c \
	app-layer/modbus/parser.c \
	app-layer/mqtt/detect-connack-sessionpresent.c \
	app-layer/mqtt/detect-connect-clientid.c \
	app-layer/mqtt/detect-connect-flags.c \
	app-layer/mqtt/detect-connect-password.c \
	app-layer/mqtt/detect-connect-protocol-string.c \
	app-layer/mqtt/detect-connect-username.c \
	app-layer/mqtt/detect-connect-willmessage.c \
	app-layer/mqtt/detect-connect-willtopic.c \
	app-layer/mqtt/detect-flags.c \
	app-layer/mqtt/detect-protocol-version.c \
	app-layer/mqtt/detect-publish-message.c \
	app-layer/mqtt/detect-publish-topic.c \
	app-layer/mqtt/detect-qos.c \
	app-layer/mqtt/detect-reason-code.c \
	app-layer/mqtt/detect-subscribe-topic.c \
	app-layer/mqtt/detect-type.c \
	app-layer/mqtt/detect-unsubscribe-topic.c \
	app-layer/mqtt/logger.c \
	app-layer/mqtt/parser.c \
	app-layer/nfs/detect-procedure.c \
	app-layer/nfs/detect-version.c \
	app-layer/nfs/logger.c \
	app-layer/nfs/parser-tcp.c \
	app-layer/nfs/parser-udp.c \
	app-layer/ntp/parser.c \
	app-layer/pgsql/logger.c \
	app-layer/quic/detect-cyu-hash.c \
	app-layer/quic/detect-cyu-string.c \
	app-layer/quic/detect-sni.c \
	app-layer/quic/detect-ua.c \
	app-layer/quic/detect-version.c \
	app-layer/quic/logger.c \
	app-layer/quic/parser.c \
	app-layer/rdp/logger.c \
	app-layer/rdp/parser.c \
	app-layer/rfb/detect-name.c \
	app-layer/rfb/detect-secresult.c \
	app-layer/rfb/detect-sectype.c \
	app-layer/rfb/logger.c \
	app-layer/rfb/parser.c \
	app-layer/sip/detect-method.c \
	app-layer/sip/detect-protocol.c \
	app-layer/sip/detect-request-line.c \
	app-layer/sip/detect-response-line.c \
	app-layer/sip/detect-stat-code.c \
	app-layer/sip/detect-stat-msg.c \
	app-layer/sip/detect-uri.c \
	app-layer/sip/logger.c \
	app-layer/sip/parser.c \
	app-layer/smb/detect-ntlmssp.c \
	app-layer/smb/detect-share.c \
	app-layer/smb/logger.c \
	app-layer/smb/parser.c \
	app-layer/smtp/logger.c \
	app-layer/smtp/lua.c \
	app-layer/smtp/parser.c \
	app-layer/snmp/detect-community.c \
	app-layer/snmp/detect-pdu_type.c \
	app-layer/snmp/detect-usm.c \
	app-layer/snmp/detect-version.c \
	app-layer/snmp/logger.c \
	app-layer/snmp/parser.c \
	app-layer/ssh/detect-hassh-server-string.c \
	app-layer/ssh/detect-hassh-server.c \
	app-layer/ssh/detect-hassh-string.c \
	app-layer/ssh/detect-hassh.c \
	app-layer/ssh/detect-proto-version.c \
	app-layer/ssh/detect-proto.c \
	app-layer/ssh/detect-software-version.c \
	app-layer/ssh/detect-software.c \
	app-layer/ssh/logger.c \
	app-layer/ssh/lua-hassh.c \
	app-layer/ssh/lua.c \
	app-layer/ssh/parser.c \
	app-layer/ssl/detect-state.c \
	app-layer/ssl/detect-version.c \
	app-layer/ssl/parser.c \
	app-layer/template/detect-2.c \
	app-layer/template/detect-rust-buffer.c \
	app-layer/template/detect.c \
	app-layer/template/logger.c \
	app-layer/tftp/logger.c \
	app-layer/tftp/parser.c \
	app-layer/tls/detect-cert-fingerprint.c \
	app-layer/tls/detect-cert-issuer.c \
	app-layer/tls/detect-cert-serial.c \
	app-layer/tls/detect-cert-subject.c \
	app-layer/tls/detect-cert-validity.c \
	app-layer/tls/detect-certs.c \
	app-layer/tls/detect-ja3-hash.c \
	app-layer/tls/detect-ja3-string.c \
	app-layer/tls/detect-ja3s-hash.c \
	app-layer/tls/detect-ja3s-string.c \
	app-layer/tls/detect-random.c \
	app-layer/tls/detect-sni.c \
	app-layer/tls/detect-version.c \
	app-layer/tls/detect.c \
	app-layer/tls/log-tlslog.c \
	app-layer/tls/log-tlsstore.c \
	app-layer/tls/logger.c \
	app-layer/tls/lua.c \
	conf-yaml-loader.c \
	conf.c \
	counters.c \
	datasets-ipv4.c \
	datasets-ipv6.c \
	datasets-md5.c \
	datasets-sha256.c \
	datasets-string.c \
	datasets.c \
	decode-chdlc.c \
	decode-erspan.c \
	decode-esp.c \
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
	defrag-queue.c \
	defrag-timeout.c \
	defrag.c \
	detect-app-layer-event.c \
	detect-app-layer-protocol.c \
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
	detect-cipservice.c \
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
	detect-dsize.c \
	detect-engine-address-ipv4.c \
	detect-engine-address-ipv6.c \
	detect-engine-address.c \
	detect-engine-alert.c \
	detect-engine-analyzer.c \
	detect-engine-build.c \
	detect-engine-content-inspection.c \
	detect-engine-dcepayload.c \
	detect-engine-enip.c \
	detect-engine-event.c \
	detect-engine-file.c \
	detect-engine-frame.c \
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
	detect-geoip.c \
	detect-gid.c \
	detect-hostbits.c \
	detect-icmp-id.c \
	detect-icmp-seq.c \
	detect-icmpv4hdr.c \
	detect-icmpv6-mtu.c \
	detect-icmpv6hdr.c \
	detect-icode.c \
	detect-id.c \
	detect-ipaddr.c \
	detect-ipopts.c \
	detect-ipproto.c \
	detect-iprep.c \
	detect-ipv4hdr.c \
	detect-ipv6hdr.c \
	detect-isdataat.c \
	detect-itype.c \
	detect-l3proto.c \
	detect-lua-extensions.c \
	detect-lua.c \
	detect-mark.c \
	detect-metadata.c \
	detect-msg.c \
	detect-noalert.c \
	detect-nocase.c \
	detect-offset.c \
	detect-parse.c \
	detect-pcre.c \
	detect-pkt-data.c \
	detect-pktvar.c \
	detect-prefilter.c \
	detect-priority.c \
	detect-rawbytes.c \
	detect-reference.c \
	detect-replace.c \
	detect-rev.c \
	detect-rpc.c \
	detect-sameip.c \
	detect-sid.c \
	detect-stream_size.c \
	detect-tag.c \
	detect-target.c \
	detect-tcp-ack.c \
	detect-tcp-flags.c \
	detect-tcp-seq.c \
	detect-tcp-window.c \
	detect-tcphdr.c \
	detect-tcpmss.c \
	detect-threshold.c \
	detect-tos.c \
	detect-transform-casechange.c \
	detect-transform-compress-whitespace.c \
	detect-transform-dotprefix.c \
	detect-transform-header-lowercase.c \
	detect-transform-md5.c \
	detect-transform-pcrexform.c \
	detect-transform-sha1.c \
	detect-transform-sha256.c \
	detect-transform-strip-whitespace.c \
	detect-transform-urldecode.c \
	detect-transform-xor.c \
	detect-ttl.c \
	detect-udphdr.c \
	detect-uricontent.c \
	detect-urilen.c \
	detect-within.c \
	detect-xbits.c \
	detect.c \
	device-storage.c \
	feature.c \
	flow-bit.c \
	flow-bypass.c \
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
	log-pcap.c \
	log-stats.c \
	log-tcp-data.c \
	output/eve/output-eve-null.c \
	output/eve/output-eve-stream.c \
	output/eve/output-eve-syslog.c \
	output/eve/output-json-alert.c \
	output/eve/output-json-anomaly.c \
	output/eve/output-json-common.c \
	output/eve/output-json-drop.c \
	output/eve/output-json-email-common.c \
	output/eve/output-json-file.c \
	output/eve/output-json-flow.c \
	output/eve/output-json-frame.c \
	output/eve/output-json-metadata.c \
	output/eve/output-json-netflow.c \
	output/eve/output-json-stats.c \
	output/eve/output-json.c \
	output/output-file.c \
	output/output-filedata.c \
	output/output-filestore.c \
	output/output-flow.c \
	output/output-lua.c \
	output/output-packet.c \
	output/output-stats.c \
	output/output-streaming.c \
	output/output-tx.c \
	output/output.c \
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
	runmode-napatech.c \
	runmode-netmap.c \
	runmode-nflog.c \
	runmode-nfq.c \
	runmode-pcap-file.c \
	runmode-pcap.c \
	runmode-pfring.c \
	runmode-unittests.c \
	runmode-unix-socket.c \
	runmode-windivert.c \
	runmodes.c \
	rust-context.c \
	source-af-packet.c \
	source-af-xdp.c \
	source-dpdk.c \
	source-erf-dag.c \
	source-erf-file.c \
	source-ipfw.c \
	source-napatech.c \
	source-netmap.c \
	source-nflog.c \
	source-nfq.c \
	source-pcap-file-directory-helper.c \
	source-pcap-file-helper.c \
	source-pcap-file.c \
	source-pcap.c \
	source-pfring.c \
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
	threads.c \
	tm-modules.c \
	tm-queuehandlers.c \
	tm-queues.c \
	tm-threads.c \
	tmqh-flow.c \
	tmqh-packetpool.c \
	tmqh-simple.c \
	unix-manager.c \
	util/action.c \
	util/affinity.c \
	util/atomic.c \
	util/base64.c \
	util/bloomfilter-counting.c \
	util/bloomfilter.c \
	util/bpf.c \
	util/buffer.c \
	util/byte.c \
	util/checksum.c \
	util/cidr.c \
	util/classification-config.c \
	util/conf.c \
	util/coredump-config.c \
	util/cpu.c \
	util/daemon.c \
	util/datalink.c \
	util/debug-filters.c \
	util/debug.c \
	util/decode-mime.c \
	util/detect.c \
	util/device.c \
	util/dpdk-bonding.c \
	util/dpdk-i40e.c \
	util/dpdk-ice.c \
	util/dpdk-ixgbe.c \
	util/dpdk.c \
	util/ebpf.c \
	util/enum.c \
	util/error.c \
	util/exception-policy.c \
	util/file-decompression.c \
	util/file-swf-decompression.c \
	util/file.c \
	util/fix_checksum.c \
	util/fmemopen.c \
	util/hash-lookup3.c \
	util/hash-string.c \
	util/hash.c \
	util/hashlist.c \
	util/host-info.c \
	util/host-os-info.c \
	util/hyperscan.c \
	util/ioctl.c \
	util/ip.c \
	util/ja3.c \
	util/landlock.c \
	util/log-redis.c \
	util/logopenfile.c \
	util/lua/lua-common.c \
	util/lua/lua-ja3.c \
	util/lua/lua.c \
	util/lua/luajit.c \
	util/macset.c \
	util/magic.c \
	util/mem.c \
	util/memcmp.c \
	util/memrchr.c \
	util/misc.c \
	util/mpm/mpm-ac-ks-small.c \
	util/mpm/mpm-ac-ks.c \
	util/mpm/mpm-ac.c \
	util/mpm/mpm-hs.c \
	util/mpm/mpm.c \
	util/napatech.c \
	util/pages.c \
	util/path.c \
	util/pidfile.c \
	util/plugin.c \
	util/pool-thread.c \
	util/pool.c \
	util/prefilter.c \
	util/print.c \
	util/privs.c \
	util/profiling-keywords.c \
	util/profiling-locks.c \
	util/profiling-prefilter.c \
	util/profiling-rulegroups.c \
	util/profiling-rules.c \
	util/profiling.c \
	util/proto-name.c \
	util/radix-tree.c \
	util/random.c \
	util/reference-config.c \
	util/rohash.c \
	util/rule-vars.c \
	util/runmodes.c \
	util/running-modes.c \
	util/signal.c \
	util/spm-bm.c \
	util/spm-bs.c \
	util/spm-bs2bm.c \
	util/spm-hs.c \
	util/spm.c \
	util/storage.c \
	util/streaming-buffer.c \
	util/strlcatu.c \
	util/strlcpyu.c \
	util/strptime.c \
	util/sysfs.c \
	util/syslog.c \
	util/thash.c \
	util/threshold-config.c \
	util/time.c \
	util/unittest-helper.c \
	util/unittest.c \
	util/var-name.c \
	util/var.c \
	windows/win32-misc.c \
	windows/win32-service.c \
	windows/win32-syscall.c

EXTRA_DIST = \
	tests/app-layer-htp-file.c \
	tests/detect-bsize.c \
	tests/detect-engine-alert.c \
	tests/detect-engine-content-inspection.c \
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
	tests/detect-http2.c \
	tests/detect-icmpv4hdr.c \
	tests/detect-icmpv6-mtu.c \
	tests/detect-icmpv6hdr.c \
	tests/detect-ipaddr.c \
	tests/detect-ipv4hdr.c \
	tests/detect-ipv6hdr.c \
	tests/detect-parse.c \
	tests/detect-snmp-community.c \
	tests/detect-snmp-pdu_type.c \
	tests/detect-snmp-version.c \
	tests/detect-ssl-state.c \
	tests/detect-ssl-version.c \
	tests/detect-tcphdr.c \
	tests/detect-template-buffer.c \
	tests/detect-template.c \
	tests/detect-tls-cert-fingerprint.c \
	tests/detect-tls-cert-issuer.c \
	tests/detect-tls-cert-serial.c \
	tests/detect-tls-cert-subject.c \
	tests/detect-tls-cert-validity.c \
	tests/detect-tls-certs.c \
	tests/detect-tls-version.c \
	tests/detect-transform-pcrexform.c \
	tests/detect-transform-xor.c \
	tests/detect-ttl.c \
	tests/detect-udphdr.c \
	tests/detect.c \
	tests/reputation.c \
	tests/source-pcap.c \
	tests/stream-tcp-inline.c \
	tests/stream-tcp-list.c \
	tests/stream-tcp-reassemble.c \
	tests/stream-tcp.c

install-headers:
	mkdir -p $(DESTDIR)${includedir}/suricata
	for header in $(noinst_HEADERS); do \
		$(INSTALL_DATA) $$header "$(DESTDIR)${includedir}/suricata"; \
	done

# set the include path found by configure
AM_CPPFLAGS = $(all_includes)

noinst_LIBRARIES = libsuricata_c.a

suricata_SOURCES = main.c

# the library search path.
suricata_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
suricata_LDADD = libsuricata_c.a $(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)
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
LDADD_FUZZ = libsuricata_c.a $(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)

fuzz_applayerprotodetectgetproto_SOURCES = tests/fuzz/fuzz_applayerprotodetectgetproto.c
fuzz_applayerprotodetectgetproto_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_applayerprotodetectgetproto_LDADD = $(LDADD_FUZZ)
if HAS_FUZZLDFLAGS
    fuzz_applayerprotodetectgetproto_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_applayerprotodetectgetproto_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_applayerprotodetectgetproto_SOURCES = force-cxx-linking.cxx

fuzz_applayerparserparse_SOURCES = tests/fuzz/fuzz_applayerparserparse.c
fuzz_applayerparserparse_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_applayerparserparse_LDADD = $(LDADD_FUZZ)
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
if HAS_FUZZLDFLAGS
    fuzz_decodepcapfile_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_decodepcapfile_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_decodepcapfile_SOURCES = force-cxx-linking.cxx

fuzz_sigpcap_SOURCES = tests/fuzz/fuzz_sigpcap.c
fuzz_sigpcap_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_sigpcap_LDADD = $(LDADD_FUZZ)
if HAS_FUZZLDFLAGS
    fuzz_sigpcap_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_sigpcap_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_sigpcap_SOURCES = force-cxx-linking.cxx

if HAS_FUZZPCAP
fuzz_sigpcap_aware_SOURCES = tests/fuzz/fuzz_sigpcap_aware.c
fuzz_sigpcap_aware_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_sigpcap_aware_LDADD = $(LDADD_FUZZ) -lfuzzpcap
if HAS_FUZZLDFLAGS
    fuzz_sigpcap_aware_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_sigpcap_aware_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_sigpcap_aware_SOURCES = force-cxx-linking.cxx

fuzz_predefpcap_aware_SOURCES = tests/fuzz/fuzz_predefpcap_aware.c
fuzz_predefpcap_aware_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_predefpcap_aware_LDADD = $(LDADD_FUZZ) -lfuzzpcap
if HAS_FUZZLDFLAGS
    fuzz_predefpcap_aware_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_predefpcap_aware_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_predefpcap_aware_SOURCES = force-cxx-linking.cxx
endif

fuzz_mimedecparseline_SOURCES = tests/fuzz/fuzz_mimedecparseline.c
fuzz_mimedecparseline_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_mimedecparseline_LDADD = $(LDADD_FUZZ)
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
    ${SECCFLAGS} ${PCAP_CFLAGS} -DLOCAL_STATE_DIR=\"$(localstatedir)\"      \
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
