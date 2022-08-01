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
alert-debuglog.c alert-debuglog.h \
alert-fastlog.c alert-fastlog.h \
alert-prelude.c alert-prelude.h \
alert-syslog.c alert-syslog.h \
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
app-layer-http2.c app-layer-http2.h \
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
app-layer-mqtt.c app-layer-mqtt.h \
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
decode-chdlc.c decode-chdlc.h \
decode-erspan.c decode-erspan.h \
decode-ethernet.c decode-ethernet.h \
decode-events.c decode-events.h \
decode-geneve.c decode-geneve.h \
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
decode-vntag.c decode-vntag.h \
decode-mpls.c decode-mpls.h \
decode-template.c decode-template.h \
defrag-config.c defrag-config.h \
defrag.c defrag.h \
defrag-hash.c defrag-hash.h \
defrag-queue.c defrag-queue.h \
defrag-timeout.c defrag-timeout.h \
detect-app-layer-event.c detect-app-layer-event.h \
detect-app-layer-protocol.c detect-app-layer-protocol.h \
detect-asn1.c detect-asn1.h \
detect-base64-data.c detect-base64-data.h \
detect-base64-decode.c detect-base64-decode.h \
detect-bsize.c detect-bsize.h \
detect-byte.c detect-byte.h \
detect-byte-extract.c detect-byte-extract.h \
detect-bytejump.c detect-bytejump.h \
detect-bytemath.c detect-bytemath.h \
detect-bytetest.c detect-bytetest.h \
detect-bypass.c detect-bypass.h \
detect.c detect.h \
detect-classtype.c detect-classtype.h \
detect-config.c detect-config.h \
detect-content.c detect-content.h \
detect-csum.c detect-csum.h \
detect-datarep.c detect-datarep.h \
detect-dataset.c detect-dataset.h \
detect-dce-iface.c detect-dce-iface.h \
detect-dce-opnum.c detect-dce-opnum.h \
detect-dce-stub-data.c detect-dce-stub-data.h \
detect-depth.c detect-depth.h \
detect-detection-filter.c detect-detection-filter.h \
detect-distance.c detect-distance.h \
detect-dnp3.c detect-dnp3.h \
detect-dns-opcode.c detect-dns-opcode.h \
detect-dns-query.c detect-dns-query.h \
detect-tls-ja3-hash.c detect-tls-ja3-hash.h \
detect-tls-ja3-string.c detect-tls-ja3-string.h \
detect-tls-ja3s-hash.c detect-tls-ja3s-hash.h \
detect-tls-ja3s-string.c detect-tls-ja3s-string.h \
detect-tls-sni.c detect-tls-sni.h \
detect-tls-cert-issuer.c detect-tls-cert-issuer.h \
detect-tls-cert-subject.c detect-tls-cert-subject.h \
detect-tls-cert-serial.c detect-tls-cert-serial.h \
detect-tls-cert-fingerprint.c detect-tls-cert-fingerprint.h \
detect-tls-certs.c detect-tls-certs.h \
detect-dsize.c detect-dsize.h \
detect-engine.c detect-engine.h \
detect-engine-address.c detect-engine-address.h \
detect-engine-address-ipv4.c detect-engine-address-ipv4.h \
detect-engine-address-ipv6.c detect-engine-address-ipv6.h \
detect-engine-alert.c detect-engine-alert.h \
detect-engine-analyzer.c detect-engine-analyzer.h \
detect-engine-build.c detect-engine-build.h \
detect-engine-content-inspection.c detect-engine-content-inspection.h \
detect-engine-dcepayload.c detect-engine-dcepayload.h \
detect-engine-dns.c detect-engine-dns.h \
detect-engine-modbus.c detect-engine-modbus.h \
detect-engine-enip.c detect-engine-enip.h \
detect-engine-event.c detect-engine-event.h \
detect-engine-file.c detect-engine-file.h \
detect-engine-iponly.c detect-engine-iponly.h \
detect-engine-loader.c detect-engine-loader.h \
detect-engine-mpm.c detect-engine-mpm.h \
detect-engine-payload.c detect-engine-payload.h \
detect-engine-port.c detect-engine-port.h \
detect-engine-prefilter.c detect-engine-prefilter.h \
detect-engine-prefilter-common.c detect-engine-prefilter-common.h \
detect-engine-proto.c detect-engine-proto.h \
detect-engine-profile.c detect-engine-profile.h \
detect-engine-register.c detect-engine-register.h \
detect-engine-siggroup.c detect-engine-siggroup.h \
detect-engine-sigorder.c detect-engine-sigorder.h \
detect-engine-state.c detect-engine-state.h \
detect-engine-tag.c detect-engine-tag.h \
detect-engine-threshold.c detect-engine-threshold.h \
detect-engine-uint.c detect-engine-uint.h \
detect-fast-pattern.c detect-fast-pattern.h \
detect-file-data.c detect-file-data.h \
detect-file-hash-common.c detect-file-hash-common.h \
detect-fileext.c detect-fileext.h \
detect-filemagic.c detect-filemagic.h \
detect-filemd5.c detect-filemd5.h \
detect-filesha1.c detect-filesha1.h \
detect-filesha256.c detect-filesha256.h \
detect-filename.c detect-filename.h \
detect-filesize.c detect-filesize.h \
detect-filestore.c detect-filestore.h \
detect-flowbits.c detect-flowbits.h \
detect-flow.c detect-flow.h \
detect-flowint.c detect-flowint.h \
detect-flowvar.c detect-flowvar.h \
detect-fragbits.c detect-fragbits.h \
detect-fragoffset.c detect-fragoffset.h \
detect-ftpbounce.c detect-ftpbounce.h \
detect-geoip.c detect-geoip.h \
detect-gid.c detect-gid.h \
detect-hostbits.c detect-hostbits.h \
detect-http-accept.c detect-http-accept.h \
detect-http-accept-enc.c detect-http-accept-enc.h \
detect-http-accept-lang.c detect-http-accept-lang.h \
detect-http-client-body.c detect-http-client-body.h \
detect-http-connection.c detect-http-connection.h \
detect-http-content-len.c detect-http-content-len.h \
detect-http-content-type.c detect-http-content-type.h \
detect-http-cookie.c detect-http-cookie.h \
detect-http-header.c detect-http-header.h \
detect-http-headers.c detect-http-headers.h detect-http-headers-stub.h \
detect-http-header-common.c detect-http-header-common.h \
detect-http-header-names.c detect-http-header-names.h \
detect-http-host.c detect-http-host.h \
detect-http-location.c detect-http-location.h \
detect-http-method.c detect-http-method.h \
detect-http-protocol.c detect-http-protocol.h \
detect-http-raw-header.c detect-http-raw-header.h \
detect-http-referer.c detect-http-referer.h \
detect-http-request-line.c detect-http-request-line.h \
detect-http-response-line.c detect-http-response-line.h \
detect-http-server.c detect-http-server.h \
detect-http-server-body.c detect-http-server-body.h \
detect-http-start.c detect-http-start.h \
detect-http-stat-code.c detect-http-stat-code.h \
detect-http-stat-msg.c detect-http-stat-msg.h \
detect-http-ua.c detect-http-ua.h \
detect-http-uri.c detect-http-uri.h \
detect-http2.c detect-http2.h \
detect-icmp-id.c detect-icmp-id.h \
detect-icmp-seq.c detect-icmp-seq.h \
detect-icmpv4hdr.c detect-icmpv4hdr.h \
detect-icmpv6hdr.c detect-icmpv6hdr.h \
detect-icmpv6-mtu.c detect-icmpv6-mtu.h \
detect-icode.c detect-icode.h \
detect-id.c detect-id.h \
detect-ipopts.c detect-ipopts.h \
detect-ipproto.c detect-ipproto.h \
detect-iprep.c detect-iprep.h \
detect-ipv4hdr.c detect-ipv4hdr.h \
detect-ipv6hdr.c detect-ipv6hdr.h \
detect-isdataat.c detect-isdataat.h \
detect-itype.c detect-itype.h \
detect-krb5-cname.c detect-krb5-cname.h \
detect-krb5-errcode.c detect-krb5-errcode.h \
detect-krb5-msgtype.c detect-krb5-msgtype.h \
detect-krb5-sname.c detect-krb5-sname.h \
detect-l3proto.c detect-l3proto.h \
detect-lua.c detect-lua.h \
detect-lua-extensions.c detect-lua-extensions.h \
detect-mark.c detect-mark.h \
detect-metadata.c detect-metadata.h \
detect-msg.c detect-msg.h \
detect-nfs-procedure.c detect-nfs-procedure.h \
detect-nfs-version.c detect-nfs-version.h \
detect-noalert.c detect-noalert.h \
detect-nocase.c detect-nocase.h \
detect-offset.c detect-offset.h \
detect-parse.c detect-parse.h \
detect-pcre.c detect-pcre.h \
detect-pkt-data.c detect-pkt-data.h \
detect-pktvar.c detect-pktvar.h \
detect-prefilter.c detect-prefilter.h \
detect-priority.c detect-priority.h \
detect-rawbytes.c detect-rawbytes.h \
detect-reference.c detect-reference.h \
detect-replace.c detect-replace.h \
detect-rev.c detect-rev.h \
detect-rpc.c detect-rpc.h \
detect-sameip.c detect-sameip.h \
detect-sid.c detect-sid.h \
detect-snmp-community.c detect-snmp-community.h \
detect-snmp-pdu_type.c detect-snmp-pdu_type.h \
detect-snmp-version.c detect-snmp-version.h \
detect-sip-method.c detect-sip-method.h \
detect-sip-uri.c detect-sip-uri.h \
detect-sip-protocol.c detect-sip-protocol.h \
detect-sip-stat-code.c detect-sip-stat-code.h \
detect-sip-stat-msg.c detect-sip-stat-msg.h \
detect-sip-request-line.c detect-sip-request-line.h \
detect-sip-response-line.c detect-sip-response-line.h \
detect-rfb-secresult.c detect-rfb-secresult.h \
detect-rfb-sectype.c detect-rfb-sectype.h \
detect-rfb-name.c detect-rfb-name.h \
detect-ssh-proto.c detect-ssh-proto.h \
detect-ssh-proto-version.c detect-ssh-proto-version.h \
detect-ssh-software.c detect-ssh-software.h \
detect-ssh-software-version.c detect-ssh-software-version.h \
detect-ssh-hassh.c detect-ssh-hassh.h \
detect-ssh-hassh-server.c detect-ssh-hassh-server.h \
detect-ssh-hassh-string.c detect-ssh-hassh-string.h \
detect-ssh-hassh-server-string.c detect-ssh-hassh-server-string.h \
detect-smb-share.c detect-smb-share.h \
detect-ssl-state.c detect-ssl-state.h \
detect-ssl-version.c detect-ssl-version.h \
detect-stream_size.c detect-stream_size.h \
detect-tag.c detect-tag.h \
detect-target.c detect-target.h \
detect-tcp-ack.c detect-tcp-ack.h \
detect-tcp-flags.c detect-tcp-flags.h \
detect-tcp-seq.c detect-tcp-seq.h \
detect-tcp-window.c detect-tcp-window.h \
detect-tcphdr.c detect-tcphdr.h \
detect-udphdr.c detect-udphdr.h \
detect-tcpmss.c detect-tcpmss.h \
detect-template.c detect-template.h \
detect-template2.c detect-template2.h \
detect-ftpdata.c detect-ftpdata.h \
detect-template-rust-buffer.c detect-template-rust-buffer.h \
detect-mqtt-type.c detect-mqtt-type.h \
detect-mqtt-flags.c detect-mqtt-flags.h \
detect-mqtt-qos.c detect-mqtt-qos.h \
detect-mqtt-protocol-version.c detect-mqtt-protocol-version.h \
detect-mqtt-reason-code.c detect-mqtt-reason-code.h \
detect-mqtt-connect-flags.c detect-mqtt-connect-flags.h \
detect-mqtt-connect-clientid.c detect-mqtt-connect-clientid.h \
detect-mqtt-connect-username.c detect-mqtt-connect-username.h \
detect-mqtt-connect-password.c detect-mqtt-connect-password.h \
detect-mqtt-connect-willtopic.c detect-mqtt-connect-willtopic.h \
detect-mqtt-connect-willmessage.c detect-mqtt-connect-willmessage.h \
detect-mqtt-connack-sessionpresent.c detect-mqtt-connack-sessionpresent.h \
detect-mqtt-publish-message.c detect-mqtt-publish-message.h \
detect-mqtt-publish-topic.c detect-mqtt-publish-topic.h \
detect-mqtt-subscribe-topic.c detect-mqtt-subscribe-topic.h \
detect-mqtt-unsubscribe-topic.c detect-mqtt-unsubscribe-topic.h \
detect-template-buffer.c detect-template-buffer.h \
detect-threshold.c detect-threshold.h \
detect-tls.c detect-tls.h \
detect-tls-cert-validity.c detect-tls-cert-validity.h \
detect-tls-version.c detect-tls-version.h \
detect-tos.c detect-tos.h \
detect-transform-compress-whitespace.c detect-transform-compress-whitespace.h \
detect-transform-strip-whitespace.c detect-transform-strip-whitespace.h \
detect-transform-md5.c detect-transform-md5.h \
detect-transform-sha1.c detect-transform-sha1.h \
detect-transform-sha256.c detect-transform-sha256.h \
detect-transform-dotprefix.c detect-transform-dotprefix.h \
detect-transform-pcrexform.c detect-transform-pcrexform.h \
detect-transform-urldecode.c detect-transform-urldecode.h \
detect-ttl.c detect-ttl.h \
detect-uricontent.c detect-uricontent.h \
detect-urilen.c detect-urilen.h \
detect-within.c detect-within.h \
detect-modbus.c detect-modbus.h \
detect-xbits.c detect-xbits.h \
detect-cipservice.c detect-cipservice.h \
device-storage.c device-storage.h \
feature.c feature.h \
flow-bit.c flow-bit.h \
flow.c flow.h \
flow-bypass.c flow-bypass.h \
flow-hash.c flow-hash.h \
flow-manager.c flow-manager.h \
flow-queue.c flow-queue.h \
flow-storage.c flow-storage.h \
flow-spare-pool.c flow-spare-pool.h \
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
log-cf-common.c log-cf-common.h \
log-httplog.c log-httplog.h \
log-pcap.c log-pcap.h \
log-stats.c log-stats.h \
log-tcp-data.c log-tcp-data.h \
log-tlslog.c log-tlslog.h \
log-tlsstore.c log-tlsstore.h \
output.c output.h \
output-file.c output-file.h \
output-filedata.c output-filedata.h \
output-filestore.c output-filestore.h \
output-flow.c output-flow.h \
output-json-alert.c output-json-alert.h \
output-json-anomaly.c output-json-anomaly.h \
output-json-dns.c output-json-dns.h \
output-json-dnp3.c output-json-dnp3.h \
output-json-dnp3-objects.c output-json-dnp3-objects.h \
output-json-drop.c output-json-drop.h \
output-json-email-common.c output-json-email-common.h \
output-json-file.c output-json-file.h \
output-json-flow.c output-json-flow.h \
output-json-ftp.c output-json-ftp.h \
output-json-netflow.c output-json-netflow.h \
output-json-http.c output-json-http.h \
output-json-http2.c output-json-http2.h \
output-json-sip.c output-json-sip.h \
output-json-smtp.c output-json-smtp.h \
output-json-ssh.c output-json-ssh.h \
output-json-stats.c output-json-stats.h \
output-json-tls.c output-json-tls.h \
output-json-nfs.c output-json-nfs.h \
output-json-tftp.c output-json-tftp.h \
output-json-smb.c output-json-smb.h \
output-json-ikev2.c output-json-ikev2.h \
output-json-krb5.c output-json-krb5.h \
output-json-dhcp.c output-json-dhcp.h \
output-json-snmp.c output-json-snmp.h \
output-json-rfb.c output-json-rfb.h \
output-json-mqtt.c output-json-mqtt.h \
output-json-template.c output-json-template.h \
output-json-template-rust.c output-json-template-rust.h \
output-json-rdp.c output-json-rdp.h \
output-json-dcerpc.c output-json-dcerpc.h \
output-json-metadata.c output-json-metadata.h \
output-lua.c output-lua.h \
output-packet.c output-packet.h \
output-stats.c output-stats.h \
output-streaming.c output-streaming.h \
output-tx.c output-tx.h \
output-json.c output-json.h \
output-json-common.c \
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
rust-context.c rust-context.h \
source-af-packet.c source-af-packet.h \
source-erf-dag.c source-erf-dag.h \
source-erf-file.c source-erf-file.h \
source-ipfw.c source-ipfw.h \
source-napatech.c source-napatech.h \
source-netmap.c source-netmap.h \
source-nfq.c source-nfq.h \
source-nflog.c source-nflog.h \
source-pcap.c source-pcap.h \
source-pcap-file.c source-pcap-file.h \
source-pcap-file-directory-helper.c source-pcap-file-directory-helper.h \
source-pcap-file-helper.c source-pcap-file-helper.h \
source-pfring.c source-pfring.h \
source-windivert.c source-windivert.h \
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
util-action.c util-action.h \
util-atomic.c util-atomic.h \
util-base64.c util-base64.h \
util-bloomfilter-counting.c util-bloomfilter-counting.h \
util-bloomfilter.c util-bloomfilter.h \
util-bpf.c util-bpf.h \
util-buffer.c util-buffer.h \
util-byte.c util-byte.h \
util-checksum.c util-checksum.h \
util-cidr.c util-cidr.h \
util-classification-config.c util-classification-config.h \
util-config.h \
util-conf.c util-conf.h \
util-coredump-config.c util-coredump-config.h \
util-cpu.c util-cpu.h \
util-crypt.c util-crypt.h \
util-daemon.c util-daemon.h \
util-debug.c util-debug.h \
util-debug-filters.c util-debug-filters.h \
util-decode-mime.c util-decode-mime.h \
util-detect.c util-detect.h \
util-device.c util-device.h \
util-ebpf.c util-ebpf.h \
util-enum.c util-enum.h \
util-error.c util-error.h \
util-exception-policy.c util-exception-policy.h \
util-file.c util-file.h \
util-file-decompression.c util-file-decompression.h \
util-file-swf-decompression.c util-file-swf-decompression.h \
util-fix_checksum.c util-fix_checksum.h \
util-fmemopen.c util-fmemopen.h \
util-hash.c util-hash.h \
util-hashlist.c util-hashlist.h \
util-hash-lookup3.c util-hash-lookup3.h \
util-hash-string.c util-hash-string.h \
util-host-os-info.c util-host-os-info.h \
util-host-info.c util-host-info.h \
util-hyperscan.c util-hyperscan.h \
util-ioctl.h util-ioctl.c \
util-ip.h util-ip.c \
util-ja3.h util-ja3.c \
util-logopenfile.h util-logopenfile.c \
util-log-redis.h util-log-redis.c \
util-lua.c util-lua.h \
util-luajit.c util-luajit.h \
util-lua-common.c util-lua-common.h \
util-lua-dnp3.c util-lua-dnp3.h \
util-lua-dnp3-objects.c util-lua-dnp3-objects.h \
util-lua-dns.c util-lua-dns.h \
util-lua-http.c util-lua-http.h \
util-lua-ja3.c util-lua-ja3.h \
util-lua-tls.c util-lua-tls.h \
util-lua-ssh.c util-lua-ssh.h \
util-lua-hassh.c util-lua-hassh.h \
util-lua-smtp.c util-lua-smtp.h \
util-macset.c util-macset.h \
util-magic.c util-magic.h \
util-memcmp.c util-memcmp.h \
util-memcpy.h \
util-mem.c util-mem.h \
util-memrchr.c util-memrchr.h \
util-misc.c util-misc.h \
util-mpm-ac-bs.c util-mpm-ac-bs.h \
util-mpm-ac.c util-mpm-ac.h \
util-mpm-ac-ks.c util-mpm-ac-ks.h \
util-mpm-ac-ks-small.c \
util-mpm-hs.c util-mpm-hs.h \
util-mpm.c util-mpm.h \
util-napatech.c util-napatech.h \
util-optimize.h \
util-pages.c util-pages.h \
util-path.c util-path.h \
util-pidfile.c util-pidfile.h \
util-plugin.c util-plugin.h \
util-pool.c util-pool.h \
util-pool-thread.c util-pool-thread.h \
util-prefilter.c util-prefilter.h \
util-print.c util-print.h \
util-privs.c util-privs.h \
util-profiling.c util-profiling.h \
util-profiling-keywords.c \
util-profiling-locks.c util-profiling-locks.h \
util-profiling-prefilter.c \
util-profiling-rulegroups.c \
util-profiling-rules.c \
util-proto-name.c util-proto-name.h \
util-radix-tree.c util-radix-tree.h \
util-random.c util-random.h \
util-reference-config.c util-reference-config.h \
util-rohash.c util-rohash.h \
util-rule-vars.c util-rule-vars.h \
util-runmodes.c util-runmodes.h \
util-running-modes.c util-running-modes.h \
util-signal.c util-signal.h \
util-spm-bm.c util-spm-bm.h \
util-spm-bs2bm.c util-spm-bs2bm.h \
util-spm-bs.c util-spm-bs.h \
util-spm-hs.c util-spm-hs.h \
util-spm.c util-spm.h util-clock.h \
util-storage.c util-storage.h \
util-streaming-buffer.c util-streaming-buffer.h \
util-strlcatu.c \
util-strlcpyu.c \
util-strptime.c \
util-syslog.c util-syslog.h \
util-thash.c util-thash.h \
util-threshold-config.c util-threshold-config.h \
util-time.c util-time.h \
util-unittest.c util-unittest.h \
util-unittest-helper.c util-unittest-helper.h \
util-validate.h util-affinity.h util-affinity.c \
util-var.c util-var.h \
util-var-name.c util-var-name.h \
util-vector.h \
win32-syscall.c win32-syscall.h \
win32-misc.c win32-misc.h \
win32-service.c win32-service.h \
win32-syslog.h

include_HEADERS = \
suricata-plugin.h

EXTRA_DIST = \
	tests/app-layer-htp-file.c \
	tests/detect-bsize.c \
	tests/detect.c \
	tests/detect-engine-alert.c \
	tests/detect-engine-content-inspection.c \
	tests/detect-file-data.c \
	tests/detect-http2.c \
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
	tests/detect-icmpv4hdr.c \
	tests/detect-icmpv6hdr.c \
	tests/detect-icmpv6-mtu.c \
	tests/detect-ipv4hdr.c \
	tests/detect-ipv6hdr.c \
	tests/detect-parse.c \
	tests/detect-snmp-community.c \
	tests/detect-snmp-pdu_type.c \
	tests/detect-snmp-version.c \
	tests/detect-ssl-state.c \
	tests/detect-ssl-version.c \
	tests/detect-tcphdr.c \
	tests/detect-tcpmss.c \
	tests/detect-template2.c \
	tests/detect-template-buffer.c \
	tests/detect-template.c \
	tests/detect-tls-cert-fingerprint.c \
	tests/detect-tls-cert-issuer.c \
	tests/detect-tls-certs.c \
	tests/detect-tls-cert-serial.c \
	tests/detect-tls-cert-subject.c \
	tests/detect-tls-cert-validity.c \
	tests/detect-tls-ja3-hash.c \
	tests/detect-tls-ja3s-hash.c \
	tests/detect-tls-ja3s-string.c \
	tests/detect-tls-ja3-string.c \
	tests/detect-tls-sni.c \
	tests/detect-tls-version.c \
	tests/detect-transform-pcrexform.c \
	tests/detect-ttl.c \
	tests/detect-udphdr.c \
	tests/fuzz/confyaml.c \
	tests/fuzz/fuzz_applayerparserparse.c \
	tests/fuzz/fuzz_applayerprotodetectgetproto.c \
	tests/fuzz/fuzz_confyamlloadstring.c \
	tests/fuzz/fuzz_decodepcapfile.c \
	tests/fuzz/fuzz_mimedecparseline.c \
	tests/fuzz/fuzz_siginit.c \
	tests/fuzz/fuzz_sigpcap.c \
	tests/fuzz/onefile.c \
	tests/fuzz/oss-fuzz-configure.sh \
	tests/fuzz/README \
	tests/reputation.c \
	tests/source-pcap.c \
	tests/stream-tcp-inline.c \
	tests/stream-tcp-list.c \
	tests/stream-tcp-reassemble.c

# set the include path found by configure
AM_CPPFLAGS = $(all_includes)

suricata_SOURCES = main.c $(COMMON_SOURCES)

# the library search path.
suricata_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
suricata_LDADD = $(HTP_LDADD) $(RUST_LDADD)
suricata_DEPENDENCIES = $(RUST_SURICATA_LIB)

if BUILD_FUZZTARGETS
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
