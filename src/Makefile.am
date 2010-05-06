noinst_HEADERS = action-globals.h \
    app-layer-nbss.h app-layer-dcerpc-common.h \
    debug.h decode-events.h \
	flow-private.h queue.h source-nfq-prototypes.h \
	suricata-common.h threadvars.h util-binsearch.h
bin_PROGRAMS = suricata
suricata_SOURCES = suricata.c suricata.h \
runmodes.c runmodes.h \
packet-queue.c packet-queue.h \
threads.c threads.h \
source-nfq.c source-nfq.h \
source-pcap.c source-pcap.h \
source-pcap-file.c source-pcap-file.h \
source-pfring.c source-pfring.h \
source-ipfw.c source-ipfw.h \
decode.c decode.h \
decode-ethernet.c decode-ethernet.h \
decode-vlan.c decode-vlan.h \
decode-sll.c decode-sll.h \
decode-gre.c decode-gre.h \
decode-ppp.c decode-ppp.h \
decode-pppoe.c decode-pppoe.h \
decode-ipv4.c decode-ipv4.h \
decode-ipv6.c decode-ipv6.h \
decode-raw.c decode-raw.h \
decode-icmpv4.c decode-icmpv4.h \
decode-icmpv6.c decode-icmpv6.h \
decode-tcp.c decode-tcp.h \
decode-udp.c decode-udp.h \
flow.c flow.h \
flow-queue.c flow-queue.h \
flow-hash.c flow-hash.h \
flow-util.c flow-util.h \
util-mem.h \
flow-var.c flow-var.h \
flow-bit.c flow-bit.h \
flow-alert-sid.c flow-alert-sid.h \
pkt-var.c pkt-var.h \
host.c host.h \
reputation.c reputation.h \
detect.c detect.h \
detect-engine-sigorder.c detect-engine-sigorder.h \
detect-engine-alert.c detect-engine-alert.h \
detect-engine.c detect-engine.h \
detect-rpc.c detect-rpc.h \
detect-isdataat.c detect-isdataat.h \
detect-window.c detect-window.h \
detect-ftpbounce.c detect-ftpbounce.h \
detect-engine-address.c detect-engine-address.h \
detect-engine-threshold.c detect-engine-threshold.h \
detect-engine-address-ipv4.c detect-engine-address-ipv4.h \
detect-engine-address-ipv6.c detect-engine-address-ipv6.h \
detect-engine-proto.c detect-engine-proto.h \
detect-engine-port.c detect-engine-port.h \
detect-engine-siggroup.c detect-engine-siggroup.h \
detect-engine-mpm.c detect-engine-mpm.h \
detect-engine-iponly.c detect-engine-iponly.h \
detect-engine-payload.c detect-engine-payload.h \
detect-engine-uri.c detect-engine-uri.h \
detect-parse.c detect-parse.h \
detect-ack.c detect-ack.h \
detect-seq.c detect-seq.h \
detect-content.c detect-content.h \
detect-uricontent.c detect-uricontent.h \
detect-flowbits.c detect-flowbits.h \
detect-flowvar.c detect-flowvar.h \
detect-flowint.c detect-flowint.h \
detect-pktvar.c detect-pktvar.h \
detect-pcre.c detect-pcre.h \
detect-depth.c detect-depth.h \
detect-nocase.c detect-nocase.h \
detect-fast-pattern.c detect-fast-pattern.h \
detect-recursive.c detect-recursive.h \
detect-rawbytes.c detect-rawbytes.h \
detect-bytetest.c detect-bytetest.h \
detect-bytejump.c detect-bytejump.h \
detect-sameip.c detect-sameip.h \
detect-ipproto.c detect-ipproto.h \
detect-within.c detect-within.h \
detect-distance.c detect-distance.h \
detect-offset.c detect-offset.h \
detect-sid.c detect-sid.h \
detect-priority.c detect-priority.h \
detect-rev.c detect-rev.h \
detect-classtype.c detect-classtype.h \
detect-reference.c detect-reference.h \
detect-tag.c detect-tag.h \
detect-threshold.c detect-threshold.h \
detect-metadata.c detect-metadata.h \
detect-msg.c detect-msg.h \
detect-id.c detect-id.h \
detect-flow.c detect-flow.h \
detect-dsize.c detect-dsize.h \
detect-stream_size.c detect-stream_size.h \
detect-decode-event.c detect-decode-event.h \
detect-ipopts.c detect-ipopts.h \
detect-flags.c detect-flags.h \
detect-fragbits.c detect-fragbits.h \
detect-fragoffset.c detect-fragoffset.h \
detect-gid.c detect-gid.h \
detect-noalert.c detect-noalert.h \
detect-csum.c detect-csum.h \
detect-ttl.c detect-ttl.h \
detect-itype.c detect-itype.h \
detect-icode.c detect-icode.h \
detect-http-cookie.c detect-http-cookie.h \
detect-http-method.c detect-http-method.h \
detect-http-header.c detect-http-header.h \
detect-tls-version.c detect-tls-version.h \
detect-icmp-id.c detect-icmp-id.h \
detect-icmp-seq.c detect-icmp-seq.h \
detect-dce-iface.c detect-dce-iface.h \
detect-dce-opnum.c detect-dce-opnum.h \
detect-dce-stub-data.c detect-dce-stub-data.h \
detect-urilen.c detect-urilen.h \
detect-detection-filter.c detect-detection-filter.h \
detect-http-client-body.c detect-http-client-body.h \
util-print.c util-print.h \
util-fmemopen.c util-fmemopen.h \
util-cpu.c util-cpu.h \
util-pidfile.c util-pidfile.h \
util-mpm.c util-mpm.h \
util-spm.c util-spm.h util-clock.h \
util-spm-bs.c util-spm-bs.h \
util-spm-bs2bm.c util-spm-bs2bm.h \
util-spm-bm.c util-spm-bm.h \
util-mpm-wumanber.c util-mpm-wumanber.h \
util-mpm-b2g.c util-mpm-b2g.h \
util-mpm-b2g-cuda.c util-mpm-b2g-cuda.h \
util-mpm-b3g.c util-mpm-b3g.h \
util-cidr.c util-cidr.h \
util-unittest.c util-unittest.h \
util-unittest-helper.c util-unittest-helper.h \
util-hash.c util-hash.h \
util-hashlist.c util-hashlist.h \
util-bloomfilter.c util-bloomfilter.h \
util-bloomfilter-counting.c util-bloomfilter-counting.h \
util-pool.c util-pool.h \
util-time.c util-time.h \
util-var.c util-var.h \
util-var-name.c util-var-name.h \
util-byte.c util-byte.h \
util-debug.c util-debug.h \
util-debug-filters.c util-debug-filters.h \
util-error.c util-error.h \
util-enum.c util-enum.h \
util-radix-tree.c util-radix-tree.h \
util-host-os-info.c util-host-os-info.h \
util-rule-vars.c util-rule-vars.h \
util-fix_checksum.c util-fix_checksum.h \
util-daemon.c util-daemon.h \
util-random.c util-random.h \
util-classification-config.c util-classification-config.h \
util-threshold-config.c util-threshold-config.h \
util-strlcatu.c \
util-strlcpyu.c \
util-cuda.c util-cuda.h \
util-cuda-handlers.c util-cuda-handlers.h \
util-privs.c util-privs.h \
tm-modules.c tm-modules.h \
tm-queues.c tm-queues.h \
tm-queuehandlers.c tm-queuehandlers.h \
tm-threads.c tm-threads.h \
tmqh-simple.c tmqh-simple.h \
tmqh-nfq.c tmqh-nfq.h \
tmqh-packetpool.c tmqh-packetpool.h \
tmqh-flow.c tmqh-flow.h \
alert-fastlog.c alert-fastlog.h \
alert-debuglog.c alert-debuglog.h \
alert-prelude.c alert-prelude.h \
alert-unified-log.c alert-unified-log.h \
alert-unified-alert.c alert-unified-alert.h \
alert-unified2-alert.c alert-unified2-alert.h \
log-httplog.c log-httplog.h \
stream.c stream.h \
stream-tcp.c stream-tcp.h stream-tcp-private.h \
stream-tcp-reassemble.c stream-tcp-reassemble.h \
respond-reject.c respond-reject.h \
respond-reject-libnet11.h respond-reject-libnet11.c \
conf.c conf.h \
conf-yaml-loader.c conf-yaml-loader.h \
counters.c counters.h \
app-layer.c app-layer.h \
app-layer-detect-proto.c app-layer-detect-proto.h \
app-layer-parser.c app-layer-parser.h \
app-layer-protos.h \
app-layer-htp.c app-layer-htp.h \
app-layer-tls.c app-layer-tls.h \
app-layer-smb.c app-layer-smb.h \
app-layer-smb2.c app-layer-smb2.h \
app-layer-dcerpc.c app-layer-dcerpc.h \
app-layer-ftp.c app-layer-ftp.h \
defrag.c defrag.h \
output.c output.h \
win32-misc.c win32-misc.h \
util-action.c util-action.h \
win32-syslog.h

# set the include path found by configure
INCLUDES= $(all_includes)


# the library search path.
suricata_LDFLAGS = $(all_libraries)

if BUILD_LIBHTP
suricata_LDADD = $(top_builddir)/libhtp/htp/libhtp.la
INCLUDES += -I$(top_srcdir)/libhtp
endif

#suricata_CFLAGS = -Wall -fno-strict-aliasing 

