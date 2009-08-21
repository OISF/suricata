bin_PROGRAMS = eidps
eidps_SOURCES = eidps.c eidps.h \
packet-queue.c packet-queue.h \
threads.c threads.h \
source-nfq.c source-nfq.h \
source-pcap.c source-pcap.h \
source-pcap-file.c source-pcap-file.h \
decode.c decode.h \
decode-ethernet.c decode-ethernet.h \
decode-sll.c decode-sll.h \
decode-ppp.c decode-ppp.h \
decode-pppoe.c decode-pppoe.h \
decode-ipv4.c decode-ipv4.h \
decode-ipv6.c decode-ipv6.h \
decode-icmpv4.c decode-icmpv4.h \
decode-icmpv6.c decode-icmpv6.h \
decode-tcp.c decode-tcp.h \
decode-udp.c decode-udp.h \
flow.c flow.h \
flow-queue.c flow-queue.h \
flow-hash.c flow-hash.h \
flow-util.c flow-util.h \
flow-var.c flow-var.h \
flow-bit.c flow-bit.h \
pkt-var.c pkt-var.h \
host.c host.h \
detect.c detect.h \
detect-engine.c detect-engine.h \
detect-engine-address.c detect-engine-address.h \
detect-engine-address-ipv4.c detect-engine-address-ipv4.h \
detect-engine-address-ipv6.c detect-engine-address-ipv6.h \
detect-engine-proto.c detect-engine-proto.h \
detect-engine-port.c detect-engine-port.h \
detect-engine-siggroup.c detect-engine-siggroup.h \
detect-engine-mpm.c detect-engine-mpm.h \
detect-engine-iponly.c detect-engine-iponly.h \
detect-parse.c detect-parse.h \
detect-content.c detect-content.h \
detect-uricontent.c detect-uricontent.h \
detect-flowbits.c detect-flowbits.h \
detect-flowvar.c detect-flowvar.h \
detect-pktvar.c detect-pktvar.h \
detect-pcre.c detect-pcre.h \
detect-depth.c detect-depth.h \
detect-nocase.c detect-nocase.h \
detect-recursive.c detect-recursive.h \
detect-rawbytes.c detect-rawbytes.h \
detect-within.c detect-within.h \
detect-distance.c detect-distance.h \
detect-offset.c detect-offset.h \
detect-sid.c detect-sid.h \
detect-priority.c detect-priority.h \
detect-rev.c detect-rev.h \
detect-classtype.c detect-classtype.h \
detect-reference.c detect-reference.h \
detect-threshold.c detect-threshold.h \
detect-metadata.c detect-metadata.h \
detect-msg.c detect-msg.h \
detect-flow.c detect-flow.h \
detect-dsize.c detect-dsize.h \
detect-decode-event.c detect-decode-event.h \
detect-noalert.c detect-noalert.h \
util-print.c util-print.h \
util-mpm.c util-mpm.h \
util-binsearch.c util-binsearch.h \
util-mpm-wumanber.c util-mpm-wumanber.h \
util-mpm-b2g.c util-mpm-b2g.h \
util-mpm-b3g.c util-mpm-b3g.h \
util-cidr.c util-cidr.h \
util-unittest.c util-unittest.h \
util-hash.c util-hash.h \
util-hashlist.c util-hashlist.h \
util-bloomfilter.c util-bloomfilter.h \
util-bloomfilter-counting.c util-bloomfilter-counting.h \
util-pool.c util-pool.h \
util-time.c util-time.h \
util-var.c util-var.h \
util-var-name.c util-var-name.h \
tm-modules.c tm-modules.h \
tm-queues.c tm-queues.h \
tm-queuehandlers.c tm-queuehandlers.h \
tm-threads.c tm-threads.h \
tmqh-simple.c tmqh-simple.h \
tmqh-nfq.c tmqh-nfq.h \
tmqh-packetpool.c tmqh-packetpool.h \
alert-fastlog.c alert-fastlog.h \
alert-debuglog.c alert-debuglog.h \
log-httplog.c log-httplog.h \
alert-unified-log.c alert-unified-log.h \
alert-unified-alert.c alert-unified-alert.h \
stream.c stream.h \
stream-tcp.c stream-tcp.h stream-tcp-private.h \
stream-tcp-reassemble.c stream-tcp-reassemble.h \
respond-reject.c respond-reject.h \
respond-reject-libnet11.h respond-reject-libnet11.c \
counters.c counter.h \
app-layer-detect-proto.c app-layer-detect-proto.h \
app-layer-parser.c app-layer-parser.h \
app-layer-http.c app-layer-http.h \
app-layer-protos.h \
conf.c conf.h

# set the include path found by configure
INCLUDES= $(all_includes)

# the library search path.
eidps_LDFLAGS = $(all_libraries) 
#eidps_LDADD = -lnetfilter_queue -lpthread -lpcre 
#eidps_CFLAGS = -Wall -fno-strict-aliasing 

