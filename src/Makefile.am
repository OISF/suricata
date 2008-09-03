bin_PROGRAMS = vips
vips_SOURCES = vips.c vips.h \
config.c config.h \
packet-queue.c packet-queue.h \
threads.c threads.h \
source-nfq.c source-nfq.h \
decode.c decode.h \
decode-ipv4.c decode-ipv4.h \
decode-ipv6.c decode-ipv6.h \
decode-icmpv4.c decode-icmpv4.h \
decode-icmpv6.c decode-icmpv6.h \
decode-tcp.c decode-tcp.h \
decode-http.c decode-http.h \
flow.c flow.h \
flow-queue.c flow-queue.h \
flow-hash.c flow-hash.h \
flow-util.c flow-util.h \
flow-var.c flow-var.h \
host.c host.h \
detect.c detect.h \
detect-engine.c detect-engine.h \
detect-siggroup.c detect-siggroup.h \
detect-parse.c detect-parse.h \
detect-mpm.c detect-mpm.h \
detect-content.c detect-content.h \
detect-uricontent.c detect-uricontent.h \
detect-flowvar.c detect-flowvar.h \
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
detect-noalert.c detect-noalert.h \
detect-address.c detect-address.h \
detect-address-ipv4.c detect-address-ipv4.h \
detect-address-ipv6.c detect-address-ipv6.h \
util-mpm-trie.c util-mpm-trie.h \
util-mpm.c util-mpm.h \
util-binsearch.c util-binsearch.h \
util-mpm-wumanber.c util-mpm-wumanber.h \
util-cidr.c util-cidr.h \
util-unittest.c util-unittest.h \
tm-modules.c tm-modules.h \
tm-queues.c tm-queues.h \
tm-queuehandlers.c tm-queuehandlers.h \
tm-threads.c tm-threads.h \
tmqh-simple.c tmqh-simple.h \
tmqh-nfq.c tmqh-nfq.h \
tmqh-packetpool.c tmqh-packetpool.h \
alert-fastlog.c alert-fastlog.h \
log-httplog.c log-httplog.h \
alert-unified-log.c alert-unified-log.h \
alert-unified-alert.c alert-unified-alert.h \
respond-reject.c respond-reject.h \
respond-reject-libnet11.h respond-reject-libnet11.c

# set the include path found by configure
INCLUDES= $(all_includes)

# the library search path.
vips_LDFLAGS = $(all_libraries) 
#vips_LDADD = -lnetfilter_queue -lpthread -lpcre 
#vips_CFLAGS = -Wall -fno-strict-aliasing 

