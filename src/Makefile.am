noinst_HEADERS = action-globals.h \
    app-layer-nbss.h app-layer-dcerpc-common.h \
    debug.h \
	flow-private.h queue.h source-nfq-prototypes.h \
	source-windivert-prototypes.h \
	suricata-common.h threadvars.h tree.h \
    util-validate.h
bin_PROGRAMS = suricata
if BUILD_FUZZTARGETS
    bin_PROGRAMS += fuzz_applayerprotodetectgetproto \
    fuzz_applayerparserparse fuzz_siginit \
    fuzz_confyamlloadstring fuzz_decodepcapfile \
    fuzz_sigpcap fuzz_mimedecparseline
endif

COMMON_SOURCES = \
outputs/alert-debuglog.c outputs/alert-debuglog.h \
outputs/alert-fastlog.c outputs/alert-fastlog.h \
outputs/alert-prelude.c outputs/alert-prelude.h \
outputs/alert-syslog.c outputs/alert-syslog.h \
app-layer.c app-layer.h \
app-layer-dcerpc.c app-layer-dcerpc.h \
app-layer-dcerpc-udp.c app-layer-dcerpc-udp.h \
app-layer-detect-proto.c app-layer-detect-proto.h \
app-layer-dnp3.c app-layer-dnp3.h \
app-layer-dnp3-objects.c app-layer-dnp3-objects.h \
app-layer-enip.c app-layer-enip.h \
app-layer-enip-common.c app-layer-enip-common.h \
app-layer-events.c app-layer-events.h \
app-layer-expectation.c app-layer-expectation.h \
app-layer-ftp.c app-layer-ftp.h \
app-layer-htp-body.c app-layer-htp-body.h \
app-layer-htp.c app-layer-htp.h \
app-layer-htp-file.c app-layer-htp-file.h \
app-layer-htp-libhtp.c app-layer-htp-libhtp.h \
app-layer-htp-mem.c app-layer-htp-mem.h \
app-layer-htp-xff.c app-layer-htp-xff.h \
app-layer-modbus.c app-layer-modbus.h \
app-layer-parser.c app-layer-parser.h \
app-layer-protos.c app-layer-protos.h \
app-layer-smb.c app-layer-smb.h \
app-layer-smtp.c app-layer-smtp.h \
app-layer-snmp.c app-layer-snmp.h \
app-layer-nfs-tcp.c app-layer-nfs-tcp.h \
app-layer-nfs-udp.c app-layer-nfs-udp.h \
app-layer-ntp.c app-layer-ntp.h \
app-layer-register.c app-layer-register.h \
app-layer-tftp.c app-layer-tftp.h \
app-layer-ikev2.c app-layer-ikev2.h \
app-layer-krb5.c app-layer-krb5.h \
app-layer-rfb.c app-layer-rfb.h \
app-layer-template.c app-layer-template.h \
app-layer-template-rust.c app-layer-template-rust.h \
app-layer-rdp.c app-layer-rdp.h \
app-layer-ssh.c app-layer-ssh.h \
app-layer-ssl.c app-layer-ssl.h \
app-layer-sip.c app-layer-sip.h \
conf.c conf.h \
conf-yaml-loader.c conf-yaml-loader.h \
counters.c counters.h \
datasets.c datasets.h datasets-reputation.h \
datasets-string.c datasets-string.h \
datasets-sha256.c datasets-sha256.h \
datasets-md5.c datasets-md5.h \
decode.c decode.h \
decode-erspan.c decode-erspan.h \
decode-ethernet.c decode-ethernet.h \
decode-events.c decode-events.h \
decode-gre.c decode-gre.h \
decode-icmpv4.c decode-icmpv4.h \
decode-icmpv6.c decode-icmpv6.h \
decode-ipv4.c decode-ipv4.h \
decode-ipv6.c decode-ipv6.h \
decode-null.c decode-null.h \
decode-ppp.c decode-ppp.h \
decode-pppoe.c decode-pppoe.h \
decode-raw.c decode-raw.h \
decode-sctp.c decode-sctp.h \
decode-sll.c decode-sll.h \
decode-tcp.c decode-tcp.h \
decode-teredo.c decode-teredo.h \
decode-udp.c decode-udp.h \
decode-vlan.c decode-vlan.h \
decode-vxlan.c decode-vxlan.h \
decode-mpls.c decode-mpls.h \
decode-template.c decode-template.h \
defrag-config.c defrag-config.h \
defrag.c defrag.h \
defrag-hash.c defrag-hash.h \
defrag-queue.c defrag-queue.h \
defrag-timeout.c defrag-timeout.h \
detect/keywords/app-layer-event.c detect/keywords/app-layer-event.h \
detect/keywords/app-layer-protocol.c detect/keywords/app-layer-protocol.h \
detect/keywords/asn1.c detect/keywords/asn1.h \
detect/keywords/base64-data.c detect/keywords/base64-data.h \
detect/keywords/base64-decode.c detect/keywords/base64-decode.h \
detect/keywords/bsize.c detect/keywords/bsize.h \
detect/keywords/byte-extract.c detect/keywords/byte-extract.h \
detect/keywords/bytejump.c detect/keywords/bytejump.h \
detect/keywords/bytetest.c detect/keywords/bytetest.h \
detect/keywords/bypass.c detect/keywords/bypass.h \
detect.c detect.h \
detect/keywords/classtype.c detect/keywords/classtype.h \
detect/keywords/content.c detect/keywords/content.h \
detect/keywords/csum.c detect/keywords/csum.h \
detect/keywords/datarep.c detect/keywords/datarep.h \
detect/keywords/dataset.c detect/keywords/dataset.h \
detect/keywords/dce-iface.c detect/keywords/dce-iface.h \
detect/keywords/dce-opnum.c detect/keywords/dce-opnum.h \
detect/keywords/dce-stub-data.c detect/keywords/dce-stub-data.h \
detect/keywords/depth.c detect/keywords/depth.h \
detect/keywords/detection-filter.c detect/keywords/detection-filter.h \
detect/keywords/distance.c detect/keywords/distance.h \
detect/keywords/dnp3.c detect/keywords/dnp3.h \
detect/keywords/dns-opcode.c detect/keywords/dns-opcode.h \
detect/keywords/dns-query.c detect/keywords/dns-query.h \
detect/keywords/tls-ja3-hash.c detect/keywords/tls-ja3-hash.h \
detect/keywords/tls-ja3-string.c detect/keywords/tls-ja3-string.h \
detect/keywords/tls-ja3s-hash.c detect/keywords/tls-ja3s-hash.h \
detect/keywords/tls-ja3s-string.c detect/keywords/tls-ja3s-string.h \
detect/keywords/tls-sni.c detect/keywords/tls-sni.h \
detect/keywords/tls-cert-issuer.c detect/keywords/tls-cert-issuer.h \
detect/keywords/tls-cert-subject.c detect/keywords/tls-cert-subject.h \
detect/keywords/tls-cert-serial.c detect/keywords/tls-cert-serial.h \
detect/keywords/tls-cert-fingerprint.c detect/keywords/tls-cert-fingerprint.h \
detect/keywords/tls-certs.c detect/keywords/tls-certs.h \
detect/keywords/dsize.c detect/keywords/dsize.h \
detect/keywords/engine.c detect/keywords/engine.h \
detect-engine-address.c detect-engine-address.h \
detect-engine-address-ipv4.c detect-engine-address-ipv4.h \
detect-engine-address-ipv6.c detect-engine-address-ipv6.h \
detect/keywords/engine-alert.c detect/keywords/engine-alert.h \
detect/keywords/engine-analyzer.c detect/keywords/engine-analyzer.h \
detect/keywords/engine-build.c detect/keywords/engine-build.h \
detect-engine-content-inspection.c detect-engine-content-inspection.h \
detect-engine-dcepayload.c detect-engine-dcepayload.h \
detect-engine-dns.c detect-engine-dns.h \
detect-engine-modbus.c detect-engine-modbus.h \
detect-engine-enip.c detect-engine-enip.h \
detect/keywords/engine-event.c detect/keywords/engine-event.h \
detect/keywords/engine-file.c detect/keywords/engine-file.h \
detect/keywords/engine-iponly.c detect/keywords/engine-iponly.h \
detect-engine-loader.c detect-engine-loader.h \
detect/keywords/engine-mpm.c detect/keywords/engine-mpm.h \
detect-engine-payload.c detect-engine-payload.h \
detect-engine-port.c detect-engine-port.h \
detect/keywords/engine-prefilter.c detect/keywords/engine-prefilter.h \
detect/keywords/engine-prefilter-common.c detect/keywords/engine-prefilter-common.h \
detect-engine-proto.c detect-engine-proto.h \
detect-engine-profile.c detect-engine-profile.h \
detect/keywords/engine-register.c detect/keywords/engine-register.h \
detect-engine-siggroup.c detect-engine-siggroup.h \
detect-engine-sigorder.c detect-engine-sigorder.h \
detect-engine-state.c detect-engine-state.h \
detect-engine-tag.c detect-engine-tag.h \
detect-engine-threshold.c detect-engine-threshold.h \
detect-engine-uint.c detect-engine-uint.h \
detect/keywords/fast-pattern.c detect/keywords/fast-pattern.h \
detect/keywords/file-data.c detect/keywords/file-data.h \
detect-file-hash-common.c detect-file-hash-common.h \
detect/keywords/fileext.c detect/keywords/fileext.h \
detect/keywords/filemagic.c detect/keywords/filemagic.h \
detect/keywords/filemd5.c detect/keywords/filemd5.h \
detect/keywords/filesha1.c detect/keywords/filesha1.h \
detect/keywords/filesha256.c detect/keywords/filesha256.h \
detect/keywords/filename.c detect/keywords/filename.h \
detect/keywords/filesize.c detect/keywords/filesize.h \
detect/keywords/filestore.c detect/keywords/filestore.h \
detect/keywords/flowbits.c detect/keywords/flowbits.h \
detect/keywords/flow.c detect/keywords/flow.h \
detect/keywords/flowint.c detect/keywords/flowint.h \
detect/keywords/flowvar.c detect/keywords/flowvar.h \
detect/keywords/fragbits.c detect/keywords/fragbits.h \
detect/keywords/fragoffset.c detect/keywords/fragoffset.h \
detect/keywords/ftpbounce.c detect/keywords/ftpbounce.h \
detect/keywords/geoip.c detect/keywords/geoip.h \
detect/keywords/gid.c detect/keywords/gid.h \
detect/keywords/hostbits.c detect/keywords/hostbits.h \
detect-http-accept.c detect-http-accept.h \
detect-http-accept-enc.c detect-http-accept-enc.h \
detect-http-accept-lang.c detect-http-accept-lang.h \
detect/keywords/http-client-body.c detect/keywords/http-client-body.h \
detect-http-connection.c detect-http-connection.h \
detect-http-content-len.c detect-http-content-len.h \
detect-http-content-type.c detect-http-content-type.h \
detect/keywords/http-cookie.c detect/keywords/http-cookie.h \
detect/keywords/http-header.c detect/keywords/http-header.h \
detect-http-headers.c detect-http-headers.h detect-http-headers-stub.h \
detect-http-header-common.c detect-http-header-common.h \
detect/keywords/http-header-names.c detect/keywords/http-header-names.h \
detect/keywords/http-host.c detect/keywords/http-host.h \
detect-http-location.c detect-http-location.h \
detect/keywords/http-method.c detect/keywords/http-method.h \
detect/keywords/http-protocol.c detect/keywords/http-protocol.h \
detect/keywords/http-raw-header.c detect/keywords/http-raw-header.h \
detect-http-referer.c detect-http-referer.h \
detect/keywords/http-request-line.c detect/keywords/http-request-line.h \
detect/keywords/http-response-line.c detect/keywords/http-response-line.h \
detect-http-server.c detect-http-server.h \
detect/keywords/http-server-body.c detect/keywords/http-server-body.h \
detect/keywords/http-start.c detect/keywords/http-start.h \
detect/keywords/http-stat-code.c detect/keywords/http-stat-code.h \
detect/keywords/http-stat-msg.c detect/keywords/http-stat-msg.h \
detect/keywords/http-ua.c detect/keywords/http-ua.h \
detect/keywords/http-uri.c detect/keywords/http-uri.h \
detect/keywords/icmp-id.c detect/keywords/icmp-id.h \
detect/keywords/icmp-seq.c detect/keywords/icmp-seq.h \
detect/keywords/icmpv6hdr.c detect/keywords/icmpv6hdr.h \
detect/keywords/icmpv6-mtu.c detect/keywords/icmpv6-mtu.h \
detect/keywords/icode.c detect/keywords/icode.h \
detect/keywords/id.c detect/keywords/id.h \
detect/keywords/ipopts.c detect/keywords/ipopts.h \
detect/keywords/ipproto.c detect/keywords/ipproto.h \
detect/keywords/iprep.c detect/keywords/iprep.h \
detect/keywords/ipv4hdr.c detect/keywords/ipv4hdr.h \
detect/keywords/ipv6hdr.c detect/keywords/ipv6hdr.h \
detect/keywords/isdataat.c detect/keywords/isdataat.h \
detect/keywords/itype.c detect/keywords/itype.h \
detect/keywords/krb5-cname.c detect/keywords/krb5-cname.h \
detect/keywords/krb5-errcode.c detect/keywords/krb5-errcode.h \
detect/keywords/krb5-msgtype.c detect/keywords/krb5-msgtype.h \
detect/keywords/krb5-sname.c detect/keywords/krb5-sname.h \
detect/keywords/l3proto.c detect/keywords/l3proto.h \
detect/keywords/lua.c detect/keywords/lua.h \
detect-lua-extensions.c detect-lua-extensions.h \
detect/keywords/mark.c detect/keywords/mark.h \
detect/keywords/metadata.c detect/keywords/metadata.h \
detect/keywords/msg.c detect/keywords/msg.h \
detect/keywords/nfs-procedure.c detect/keywords/nfs-procedure.h \
detect/keywords/nfs-version.c detect/keywords/nfs-version.h \
detect/keywords/noalert.c detect/keywords/noalert.h \
detect/keywords/nocase.c detect/keywords/nocase.h \
detect/keywords/offset.c detect/keywords/offset.h \
detect-parse.c detect-parse.h \
detect/keywords/pcre.c detect/keywords/pcre.h \
detect/keywords/pkt-data.c detect/keywords/pkt-data.h \
detect/keywords/pktvar.c detect/keywords/pktvar.h \
detect/keywords/prefilter.c detect/keywords/prefilter.h \
detect/keywords/priority.c detect/keywords/priority.h \
detect/keywords/rawbytes.c detect/keywords/rawbytes.h \
detect/keywords/reference.c detect/keywords/reference.h \
detect/keywords/replace.c detect/keywords/replace.h \
detect/keywords/rev.c detect/keywords/rev.h \
detect/keywords/rpc.c detect/keywords/rpc.h \
detect/keywords/sameip.c detect/keywords/sameip.h \
detect/keywords/sid.c detect/keywords/sid.h \
detect/keywords/snmp-community.c detect/keywords/snmp-community.h \
detect/keywords/snmp-pdu_type.c detect/keywords/snmp-pdu_type.h \
detect/keywords/snmp-version.c detect/keywords/snmp-version.h \
detect/keywords/sip-method.c detect/keywords/sip-method.h \
detect/keywords/sip-uri.c detect/keywords/sip-uri.h \
detect/keywords/sip-protocol.c detect/keywords/sip-protocol.h \
detect/keywords/sip-stat-code.c detect/keywords/sip-stat-code.h \
detect/keywords/sip-stat-msg.c detect/keywords/sip-stat-msg.h \
detect/keywords/sip-request-line.c detect/keywords/sip-request-line.h \
detect/keywords/sip-response-line.c detect/keywords/sip-response-line.h \
detect/keywords/rfb-secresult.c detect/keywords/rfb-secresult.h \
detect/keywords/rfb-sectype.c detect/keywords/rfb-sectype.h \
detect/keywords/rfb-name.c detect/keywords/rfb-name.h \
detect/keywords/ssh-proto.c detect/keywords/ssh-proto.h \
detect/keywords/ssh-proto-version.c detect/keywords/ssh-proto-version.h \
detect/keywords/ssh-software.c detect/keywords/ssh-software.h \
detect/keywords/ssh-software-version.c detect/keywords/ssh-software-version.h \
detect/keywords/smb-share.c detect/keywords/smb-share.h \
detect/keywords/ssl-state.c detect/keywords/ssl-state.h \
detect/keywords/ssl-version.c detect/keywords/ssl-version.h \
detect/keywords/stream_size.c detect/keywords/stream_size.h \
detect/keywords/tag.c detect/keywords/tag.h \
detect/keywords/target.c detect/keywords/target.h \
detect/keywords/tcp-ack.c detect/keywords/tcp-ack.h \
detect/keywords/tcp-flags.c detect/keywords/tcp-flags.h \
detect/keywords/tcp-seq.c detect/keywords/tcp-seq.h \
detect/keywords/tcp-window.c detect/keywords/tcp-window.h \
detect/keywords/tcphdr.c detect/keywords/tcphdr.h \
detect/keywords/udphdr.c detect/keywords/udphdr.h \
detect/keywords/tcpmss.c detect/keywords/tcpmss.h \
detect/keywords/template.c detect/keywords/template.h \
detect/keywords/template2.c detect/keywords/template2.h \
detect/keywords/ftpdata.c detect/keywords/ftpdata.h \
detect/keywords/template-rust-buffer.c detect/keywords/template-rust-buffer.h \
detect/keywords/template-buffer.c detect/keywords/template-buffer.h \
detect/keywords/threshold.c detect/keywords/threshold.h \
detect/keywords/tls.c detect/keywords/tls.h \
detect/keywords/tls-cert-validity.c detect/keywords/tls-cert-validity.h \
detect/keywords/tls-version.c detect/keywords/tls-version.h \
detect/keywords/tos.c detect/keywords/tos.h \
detect/keywords/transform-compress-whitespace.c detect/keywords/transform-compress-whitespace.h \
detect/keywords/transform-strip-whitespace.c detect/keywords/transform-strip-whitespace.h \
detect/keywords/transform-md5.c detect/keywords/transform-md5.h \
detect/keywords/transform-sha1.c detect/keywords/transform-sha1.h \
detect/keywords/transform-sha256.c detect/keywords/transform-sha256.h \
detect/keywords/transform-dotprefix.c detect/keywords/transform-dotprefix.h \
detect/keywords/ttl.c detect/keywords/ttl.h \
detect/keywords/uricontent.c detect/keywords/uricontent.h \
detect/keywords/urilen.c detect/keywords/urilen.h \
detect/keywords/within.c detect/keywords/within.h \
detect/keywords/modbus.c detect/keywords/modbus.h \
detect/keywords/xbits.c detect/keywords/xbits.h \
detect/keywords/cipservice.c detect/keywords/cipservice.h \
device-storage.c device-storage.h \
feature.c feature.h \
flow-bit.c flow-bit.h \
flow.c flow.h \
flow-bypass.c flow-bypass.h \
flow-hash.c flow-hash.h \
flow-manager.c flow-manager.h \
flow-queue.c flow-queue.h \
flow-storage.c flow-storage.h \
flow-timeout.c flow-timeout.h \
flow-util.c flow-util.h \
flow-var.c flow-var.h \
flow-worker.c flow-worker.h \
host.c host.h \
host-bit.c host-bit.h \
host-queue.c host-queue.h \
host-storage.c host-storage.h \
host-timeout.c host-timeout.h \
ippair.c ippair.h \
ippair-bit.c ippair-bit.h \
ippair-queue.c ippair-queue.h \
ippair-storage.c ippair-storage.h \
ippair-timeout.c ippair-timeout.h \
outputs/log-droplog.c outputs/log-droplog.h \
outputs/log-filestore.c outputs/log-filestore.h \
outputs/log-cf-common.c outputs/log-cf-common.h \
outputs/log-httplog.c outputs/log-httplog.h \
outputs/log-pcap.c outputs/log-pcap.h \
outputs/log-stats.c outputs/log-stats.h \
outputs/log-tcp-data.c outputs/log-tcp-data.h \
outputs/log-tlslog.c outputs/log-tlslog.h \
outputs/log-tlsstore.c outputs/log-tlsstore.h \
output.c output.h \
outputs/file.c outputs/file.h \
outputs/filedata.c outputs/filedata.h \
outputs/filestore.c outputs/filestore.h \
outputs/flow.c outputs/flow.h \
outputs/json-alert.c outputs/json-alert.h \
outputs/json-anomaly.c outputs/json-anomaly.h \
outputs/json-dns.c outputs/json-dns.h \
outputs/json-dnp3.c outputs/json-dnp3.h \
outputs/json-dnp3-objects.c outputs/json-dnp3-objects.h \
outputs/json-drop.c outputs/json-drop.h \
outputs/json-email-common.c outputs/json-email-common.h \
outputs/json-file.c outputs/json-file.h \
outputs/json-flow.c outputs/json-flow.h \
outputs/json-ftp.c outputs/json-ftp.h \
outputs/json-netflow.c outputs/json-netflow.h \
outputs/json-http.c outputs/json-http.h \
outputs/json-sip.c outputs/json-sip.h \
outputs/json-smtp.c outputs/json-smtp.h \
outputs/json-ssh.c outputs/json-ssh.h \
outputs/json-stats.c outputs/json-stats.h \
outputs/json-tls.c outputs/json-tls.h \
outputs/json-nfs.c outputs/json-nfs.h \
outputs/json-tftp.c outputs/json-tftp.h \
outputs/json-smb.c outputs/json-smb.h \
outputs/json-ikev2.c outputs/json-ikev2.h \
outputs/json-krb5.c outputs/json-krb5.h \
outputs/json-dhcp.c outputs/json-dhcp.h \
outputs/json-snmp.c outputs/json-snmp.h \
outputs/json-rfb.c outputs/json-rfb.h \
outputs/json-template.c outputs/json-template.h \
outputs/json-template-rust.c outputs/json-template-rust.h \
outputs/json-rdp.c outputs/json-rdp.h \
outputs/json-metadata.c outputs/json-metadata.h \
outputs/lua.c outputs/lua.h \
outputs/packet.c outputs/packet.h \
outputs/stats.c outputs/stats.h \
outputs/streaming.c outputs/streaming.h \
outputs/tx.c outputs/tx.h \
outputs/json.c outputs/json.h \
outputs/json-common.c \
packet-queue.c packet-queue.h \
pkt-var.c pkt-var.h \
reputation.c reputation.h \
respond-reject.c respond-reject.h \
respond-reject-libnet11.h respond-reject-libnet11.c \
runmode-af-packet.c runmode-af-packet.h \
runmode-erf-dag.c runmode-erf-dag.h \
runmode-erf-file.c runmode-erf-file.h \
runmode-ipfw.c runmode-ipfw.h \
runmode-napatech.c runmode-napatech.h \
runmode-netmap.c runmode-netmap.h \
runmode-nfq.c runmode-nfq.h \
runmode-nflog.c runmode-nflog.h \
runmode-pcap.c runmode-pcap.h \
runmode-pcap-file.c runmode-pcap-file.h \
runmode-pfring.c runmode-pfring.h \
runmode-unittests.c runmode-unittests.h \
runmode-unix-socket.c runmode-unix-socket.h \
runmode-windivert.c runmode-windivert.h \
runmodes.c runmodes.h \
rust.h \
rust-context.h \
sources/af-packet.c sources/af-packet.h \
sources/erf-dag.c sources/erf-dag.h \
sources/erf-file.c sources/erf-file.h \
sources/ipfw.c sources/ipfw.h \
sources/napatech.c sources/napatech.h \
sources/netmap.c sources/netmap.h \
sources/nfq.c sources/nfq.h \
sources/nflog.c sources/nflog.h \
sources/pcap.c sources/pcap.h \
sources/pcap-file.c sources/pcap-file.h \
sources/pcap-file-directory-helper.c sources/pcap-file-directory-helper.h \
sources/pcap-file-helper.c sources/pcap-file-helper.h \
sources/pfring.c sources/pfring.h \
sources/windivert.c sources/windivert.h \
stream.c stream.h \
stream-tcp.c stream-tcp.h stream-tcp-private.h \
stream-tcp-inline.c stream-tcp-inline.h \
stream-tcp-list.c stream-tcp-list.h \
stream-tcp-reassemble.c stream-tcp-reassemble.h \
stream-tcp-sack.c stream-tcp-sack.h \
stream-tcp-util.c stream-tcp-util.h \
suricata.c suricata.h \
threads.c threads.h \
threads-debug.h threads-profile.h \
tm-modules.c tm-modules.h \
tmqh-flow.c tmqh-flow.h \
tmqh-packetpool.c tmqh-packetpool.h \
tmqh-simple.c tmqh-simple.h \
tm-queuehandlers.c tm-queuehandlers.h \
tm-queues.c tm-queues.h \
tm-threads.c tm-threads.h tm-threads-common.h \
unix-manager.c unix-manager.h \
util/action.c util/action.h \
util/atomic.c util/atomic.h \
util/base64.c util/base64.h \
util/bloomfilter-counting.c util/bloomfilter-counting.h \
util/bloomfilter.c util/bloomfilter.h \
util/bpf.c util/bpf.h \
util/buffer.c util/buffer.h \
util/byte.c util/byte.h \
util/checksum.c util/checksum.h \
util/cidr.c util/cidr.h \
util/classification-config.c util/classification-config.h \
util/conf.c util/conf.h \
util/coredump-config.c util/coredump-config.h \
util/cpu.c util/cpu.h \
util/crypt.c util/crypt.h \
util/daemon.c util/daemon.h \
util/debug.c util/debug.h \
util/debug-filters.c util/debug-filters.h \
util/decode-asn1.c util/decode-asn1.h \
util/decode-mime.c util/decode-mime.h \
util/detect.c util/detect.h \
util/device.c util/device.h \
util/ebpf.c util/ebpf.h \
util/enum.c util/enum.h \
util/error.c util/error.h \
util/file.c util/file.h \
util/file-decompression.c util/file-decompression.h \
util/file-swf-decompression.c util/file-swf-decompression.h \
util/fix_checksum.c util/fix_checksum.h \
util/fmemopen.c util/fmemopen.h \
util/hash.c util/hash.h \
util/hashlist.c util/hashlist.h \
util/hash-lookup3.c util/hash-lookup3.h \
util/hash-string.c util/hash-string.h \
util/host-os-info.c util/host-os-info.h \
util/host-info.c util/host-info.h \
util/hyperscan.c util/hyperscan.h \
util/ioctl.h util/ioctl.c \
util/ip.h util/ip.c \
util/ja3.h util/ja3.c \
util/logopenfile.h util/logopenfile.c \
util/log-redis.h util/log-redis.c \
util/lua.c util/lua.h \
util/luajit.c util/luajit.h \
util/lua-common.c util/lua-common.h \
util/lua-dnp3.c util/lua-dnp3.h \
util/lua-dnp3-objects.c util/lua-dnp3-objects.h \
util/lua-dns.c util/lua-dns.h \
util/lua-http.c util/lua-http.h \
util/lua-ja3.c util/lua-ja3.h \
util/lua-tls.c util/lua-tls.h \
util/lua-ssh.c util/lua-ssh.h \
util/lua-smtp.c util/lua-smtp.h \
util/magic.c util/magic.h \
util/memcmp.c util/memcmp.h \
util-memcpy.h \
util-mem.h \
util/memrchr.c util/memrchr.h \
util/misc.c util/misc.h \
util/mpm-ac-bs.c util/mpm-ac-bs.h \
util/mpm-ac.c util/mpm-ac.h \
util/mpm-ac-ks.c util/mpm-ac-ks.h \
util/mpm-ac-ks-small.c \
util/mpm-hs.c util/mpm-hs.h \
util/mpm.c util/mpm.h \
util/napatech.c util/napatech.h \
util-optimize.h \
util/pages.c util/pages.h \
util/path.c util/path.h \
util/pidfile.c util/pidfile.h \
util/pool.c util/pool.h \
util/pool-thread.c util/pool-thread.h \
util/prefilter.c util/prefilter.h \
util/print.c util/print.h \
util/privs.c util/privs.h \
util/profiling.c util/profiling.h \
util/profiling-keywords.c \
util/profiling-locks.c util/profiling-locks.h \
util/profiling-prefilter.c \
util/profiling-rulegroups.c \
util/profiling-rules.c \
util/proto-name.c util/proto-name.h \
util/radix-tree.c util/radix-tree.h \
util/random.c util/random.h \
util/reference-config.c util/reference-config.h \
util/rohash.c util/rohash.h \
util/rule-vars.c util/rule-vars.h \
util/runmodes.c util/runmodes.h \
util/running-modes.c util/running-modes.h \
util/signal.c util/signal.h \
util/spm-bm.c util/spm-bm.h \
util/spm-bs2bm.c util/spm-bs2bm.h \
util/spm-bs.c util/spm-bs.h \
util/spm-hs.c util/spm-hs.h \
util/spm.c util/spm.h util-clock.h \
util/storage.c util/storage.h \
util/streaming-buffer.c util/streaming-buffer.h \
util/strlcatu.c \
util/strlcpyu.c \
util/strptime.c \
util/syslog.c util/syslog.h \
util/thash.c util/thash.h \
util/threshold-config.c util/threshold-config.h \
util/time.c util/time.h \
util/unittest.c util/unittest.h \
util/unittest-helper.c util/unittest-helper.h \
util-validate.h util/affinity.h util/affinity.c \
util/var.c util/var.h \
util/var-name.c util/var-name.h \
util-vector.h \
win32/syscall.c win32/syscall.h \
win32/misc.c win32/misc.h \
win32/service.c win32/service.h \
win32-syslog.h

EXTRA_DIST = tests

# set the include path found by configure
AM_CPPFLAGS = $(all_includes)

suricata_SOURCES = main.c $(COMMON_SOURCES)

# the library search path.
suricata_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
suricata_LDADD = $(HTP_LDADD) $(RUST_LDADD)
suricata_DEPENDENCIES = $(RUST_SURICATA_LIB)

nodist_fuzz_applayerprotodetectgetproto_SOURCES = tests/fuzz/fuzz_applayerprotodetectgetproto.c $(COMMON_SOURCES)
fuzz_applayerprotodetectgetproto_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
fuzz_applayerprotodetectgetproto_LDADD = $(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)
if HAS_FUZZLDFLAGS
    fuzz_applayerprotodetectgetproto_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    nodist_fuzz_applayerprotodetectgetproto_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_applayerprotodetectgetproto_SOURCES = force-cxx-linking.cxx

nodist_fuzz_applayerparserparse_SOURCES = tests/fuzz/fuzz_applayerparserparse.c $(COMMON_SOURCES)
fuzz_applayerparserparse_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
fuzz_applayerparserparse_LDADD = $(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)
if HAS_FUZZLDFLAGS
    fuzz_applayerparserparse_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    nodist_fuzz_applayerparserparse_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_applayerparserparse_SOURCES = force-cxx-linking.cxx

nodist_fuzz_siginit_SOURCES = tests/fuzz/fuzz_siginit.c $(COMMON_SOURCES)
fuzz_siginit_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
fuzz_siginit_LDADD = $(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)
if HAS_FUZZLDFLAGS
    fuzz_siginit_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    nodist_fuzz_siginit_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_siginit_SOURCES = force-cxx-linking.cxx

nodist_fuzz_confyamlloadstring_SOURCES = tests/fuzz/fuzz_confyamlloadstring.c $(COMMON_SOURCES)
fuzz_confyamlloadstring_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
fuzz_confyamlloadstring_LDADD = $(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)
if HAS_FUZZLDFLAGS
    fuzz_confyamlloadstring_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    nodist_fuzz_confyamlloadstring_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_confyamlloadstring_SOURCES = force-cxx-linking.cxx

nodist_fuzz_decodepcapfile_SOURCES = tests/fuzz/fuzz_decodepcapfile.c $(COMMON_SOURCES)
fuzz_decodepcapfile_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
fuzz_decodepcapfile_LDADD = $(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)
if HAS_FUZZLDFLAGS
    fuzz_decodepcapfile_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    nodist_fuzz_decodepcapfile_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_decodepcapfile_SOURCES = force-cxx-linking.cxx

nodist_fuzz_sigpcap_SOURCES = tests/fuzz/fuzz_sigpcap.c $(COMMON_SOURCES)
fuzz_sigpcap_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
fuzz_sigpcap_LDADD = $(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)
if HAS_FUZZLDFLAGS
    fuzz_sigpcap_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    nodist_fuzz_sigpcap_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_sigpcap_SOURCES = force-cxx-linking.cxx

nodist_fuzz_mimedecparseline_SOURCES = tests/fuzz/fuzz_mimedecparseline.c $(COMMON_SOURCES)
fuzz_mimedecparseline_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
fuzz_mimedecparseline_LDADD = $(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)
if HAS_FUZZLDFLAGS
    fuzz_mimedecparseline_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    nodist_fuzz_mimedecparseline_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_mimedecparseline_SOURCES = force-cxx-linking.cxx

# default CFLAGS
AM_CFLAGS = ${OPTIMIZATION_CFLAGS} ${GCC_CFLAGS} ${CLANG_CFLAGS}            \
    ${SECCFLAGS} ${PCAP_CFLAGS} -DLOCAL_STATE_DIR=\"$(localstatedir)\"      \
    -std=gnu99                                                              \
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
