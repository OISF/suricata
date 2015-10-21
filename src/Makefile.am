noinst_HEADERS = action-globals.h \
    app-layer-nbss.h app-layer-dcerpc-common.h \
    debug.h \
	flow-private.h queue.h source-nfq-prototypes.h \
	suricata-common.h threadvars.h util-binsearch.h \
    util-validate.h
bin_PROGRAMS = suricata

suricata_SOURCES = \
alert-debuglog.c alert-debuglog.h \
alert-fastlog.c alert-fastlog.h \
alert-prelude.c alert-prelude.h \
alert-syslog.c alert-syslog.h \
alert-unified2-alert.c alert-unified2-alert.h \
app-layer.c app-layer.h \
app-layer-dcerpc.c app-layer-dcerpc.h \
app-layer-dcerpc-udp.c app-layer-dcerpc-udp.h \
app-layer-detect-proto.c app-layer-detect-proto.h \
app-layer-dns-common.c app-layer-dns-common.h \
app-layer-dns-tcp.c app-layer-dns-tcp.h \
app-layer-dns-udp.c app-layer-dns-udp.h \
app-layer-events.c app-layer-events.h \
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
app-layer-smb2.c app-layer-smb2.h \
app-layer-smb.c app-layer-smb.h \
app-layer-smtp.c app-layer-smtp.h \
app-layer-template.c app-layer-template.h \
app-layer-ssh.c app-layer-ssh.h \
app-layer-ssl.c app-layer-ssl.h \
app-layer-tls-handshake.c app-layer-tls-handshake.h \
conf.c conf.h \
conf-yaml-loader.c conf-yaml-loader.h \
counters.c counters.h \
data-queue.c data-queue.h \
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
decode-mpls.c decode-mpls.h \
decode-template.c decode-template.h \
defrag-config.c defrag-config.h \
defrag.c defrag.h \
defrag-hash.c defrag-hash.h \
defrag-queue.c defrag-queue.h \
defrag-timeout.c defrag-timeout.h \
detect-ack.c detect-ack.h \
detect-app-layer-event.c detect-app-layer-event.h \
detect-app-layer-protocol.c detect-app-layer-protocol.h \
detect-asn1.c detect-asn1.h \
detect-base64-data.c detect-base64-data.h \
detect-base64-decode.c detect-base64-decode.h \
detect-byte-extract.c detect-byte-extract.h \
detect-bytejump.c detect-bytejump.h \
detect-bytetest.c detect-bytetest.h \
detect.c detect.h \
detect-classtype.c detect-classtype.h \
detect-content.c detect-content.h \
detect-csum.c detect-csum.h \
detect-dce-iface.c detect-dce-iface.h \
detect-dce-opnum.c detect-dce-opnum.h \
detect-dce-stub-data.c detect-dce-stub-data.h \
detect-depth.c detect-depth.h \
detect-detection-filter.c detect-detection-filter.h \
detect-distance.c detect-distance.h \
detect-dns-query.c detect-dns-query.h \
detect-dsize.c detect-dsize.h \
detect-engine-address.c detect-engine-address.h \
detect-engine-address-ipv4.c detect-engine-address-ipv4.h \
detect-engine-address-ipv6.c detect-engine-address-ipv6.h \
detect-engine-alert.c detect-engine-alert.h \
detect-engine-analyzer.c detect-engine-analyzer.h \
detect-engine-apt-event.c detect-engine-apt-event.h \
detect-engine.c detect-engine.h \
detect-engine-content-inspection.c detect-engine-content-inspection.h \
detect-engine-dcepayload.c detect-engine-dcepayload.h \
detect-engine-dns.c detect-engine-dns.h \
detect-engine-modbus.c detect-engine-modbus.h \
detect-engine-event.c detect-engine-event.h \
detect-engine-file.c detect-engine-file.h \
detect-engine-filedata-smtp.c detect-engine-filedata-smtp.h \
detect-engine-hcbd.c detect-engine-hcbd.h \
detect-engine-hcd.c detect-engine-hcd.h \
detect-engine-hhd.c detect-engine-hhd.h \
detect-engine-hhhd.c detect-engine-hhhd.h \
detect-engine-hmd.c detect-engine-hmd.h \
detect-engine-hrhd.c detect-engine-hrhd.h \
detect-engine-hrhhd.c detect-engine-hrhhd.h \
detect-engine-hrud.c detect-engine-hrud.h \
detect-engine-hrl.c detect-engine-hrl.h \
detect-engine-hsbd.c detect-engine-hsbd.h \
detect-engine-hscd.c detect-engine-hscd.h \
detect-engine-hsmd.c detect-engine-hsmd.h \
detect-engine-hua.c detect-engine-hua.h \
detect-engine-iponly.c detect-engine-iponly.h \
detect-engine-loader.c detect-engine-loader.h \
detect-engine-mpm.c detect-engine-mpm.h \
detect-engine-payload.c detect-engine-payload.h \
detect-engine-port.c detect-engine-port.h \
detect-engine-proto.c detect-engine-proto.h \
detect-engine-siggroup.c detect-engine-siggroup.h \
detect-engine-sigorder.c detect-engine-sigorder.h \
detect-engine-state.c detect-engine-state.h \
detect-engine-tag.c detect-engine-tag.h \
detect-engine-template.c detect-engine-template.h \
detect-engine-threshold.c detect-engine-threshold.h \
detect-engine-uri.c detect-engine-uri.h \
detect-fast-pattern.c detect-fast-pattern.h \
detect-file-data.c detect-file-data.h \
detect-fileext.c detect-fileext.h \
detect-filemagic.c detect-filemagic.h \
detect-filemd5.c detect-filemd5.h \
detect-filename.c detect-filename.h \
detect-filesize.c detect-filesize.h \
detect-filestore.c detect-filestore.h \
detect-flags.c detect-flags.h \
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
detect-http-client-body.c detect-http-client-body.h \
detect-http-cookie.c detect-http-cookie.h \
detect-http-header.c detect-http-header.h \
detect-http-hh.c detect-http-hh.h \
detect-http-hrh.c detect-http-hrh.h \
detect-http-method.c detect-http-method.h \
detect-http-raw-header.c detect-http-raw-header.h \
detect-http-raw-uri.c detect-http-raw-uri.h \
detect-http-server-body.c detect-http-server-body.h \
detect-http-stat-code.c detect-http-stat-code.h \
detect-http-stat-msg.c detect-http-stat-msg.h \
detect-http-ua.c detect-http-ua.h \
detect-http-uri.c detect-http-uri.h \
detect-icmp-id.c detect-icmp-id.h \
detect-icmp-seq.c detect-icmp-seq.h \
detect-icode.c detect-icode.h \
detect-id.c detect-id.h \
detect-ipopts.c detect-ipopts.h \
detect-ipproto.c detect-ipproto.h \
detect-iprep.c detect-iprep.h \
detect-isdataat.c detect-isdataat.h \
detect-itype.c detect-itype.h \
detect-l3proto.c detect-l3proto.h \
detect-lua.c detect-lua.h \
detect-lua-extensions.c detect-lua-extensions.h \
detect-mark.c detect-mark.h \
detect-metadata.c detect-metadata.h \
detect-msg.c detect-msg.h \
detect-noalert.c detect-noalert.h \
detect-nocase.c detect-nocase.h \
detect-offset.c detect-offset.h \
detect-parse.c detect-parse.h \
detect-pcre.c detect-pcre.h \
detect-pkt-data.c detect-pkt-data.h \
detect-pktvar.c detect-pktvar.h \
detect-priority.c detect-priority.h \
detect-rawbytes.c detect-rawbytes.h \
detect-reference.c detect-reference.h \
detect-replace.c detect-replace.h \
detect-rev.c detect-rev.h \
detect-rpc.c detect-rpc.h \
detect-sameip.c detect-sameip.h \
detect-seq.c detect-seq.h \
detect-sid.c detect-sid.h \
detect-ssh-proto-version.c detect-ssh-proto-version.h \
detect-ssh-software-version.c detect-ssh-software-version.h \
detect-ssl-state.c detect-ssl-state.h \
detect-ssl-version.c detect-ssl-version.h \
detect-stream_size.c detect-stream_size.h \
detect-tag.c detect-tag.h \
detect-template.c detect-template.h \
detect-template-buffer.c detect-template-buffer.h \
detect-threshold.c detect-threshold.h \
detect-tls.c detect-tls.h \
detect-tls-version.c detect-tls-version.h \
detect-tos.c detect-tos.h \
detect-ttl.c detect-ttl.h \
detect-uricontent.c detect-uricontent.h \
detect-urilen.c detect-urilen.h \
detect-window.c detect-window.h \
detect-within.c detect-within.h \
detect-modbus.c detect-modbus.h \
detect-xbits.c detect-xbits.h \
flow-bit.c flow-bit.h \
flow.c flow.h \
flow-hash.c flow-hash.h \
flow-manager.c flow-manager.h \
flow-queue.c flow-queue.h \
flow-storage.c flow-storage.h \
flow-timeout.c flow-timeout.h \
flow-util.c flow-util.h \
flow-var.c flow-var.h \
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
log-dnslog.c log-dnslog.h \
log-droplog.c log-droplog.h \
log-file.c log-file.h \
log-filestore.c log-filestore.h \
log-httplog.c log-httplog.h \
log-pcap.c log-pcap.h \
log-stats.c log-stats.h \
log-tcp-data.c log-tcp-data.h \
log-tlslog.c log-tlslog.h \
log-tlsstore.c log-tlsstore.h \
output.c output.h \
output-file.c output-file.h \
output-filedata.c output-filedata.h \
output-flow.c output-flow.h \
output-json-alert.c output-json-alert.h \
output-json-dns.c output-json-dns.h \
output-json-drop.c output-json-drop.h \
output-json-email-common.c output-json-email-common.h \
output-json-file.c output-json-file.h \
output-json-flow.c output-json-flow.h \
output-json-netflow.c output-json-netflow.h \
output-json-http.c output-json-http.h \
output-json-smtp.c output-json-smtp.h \
output-json-ssh.c output-json-ssh.h \
output-json-stats.c output-json-stats.h \
output-json-tls.c output-json-tls.h \
output-json-template.c output-json-template.h \
output-lua.c output-lua.h \
output-packet.c output-packet.h \
output-stats.c output-stats.h \
output-streaming.c output-streaming.h \
output-tx.c output-tx.h \
output-json.c output-json.h \
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
runmode-tile.c runmode-tile.h \
runmodes.c runmodes.h \
source-af-packet.c source-af-packet.h \
source-erf-dag.c source-erf-dag.h \
source-erf-file.c source-erf-file.h \
source-ipfw.c source-ipfw.h \
source-mpipe.c source-mpipe.h \
source-napatech.c source-napatech.h \
source-netmap.c source-netmap.h \
source-nfq.c source-nfq.h \
source-nflog.c source-nflog.h \
source-pcap.c source-pcap.h \
source-pcap-file.c source-pcap-file.h \
source-pfring.c source-pfring.h \
stream.c stream.h \
stream-tcp.c stream-tcp.h stream-tcp-private.h \
stream-tcp-inline.c stream-tcp-inline.h \
stream-tcp-reassemble.c stream-tcp-reassemble.h \
stream-tcp-sack.c stream-tcp-sack.h \
stream-tcp-util.c stream-tcp-util.h \
suricata.c suricata.h \
threads.c threads.h threads-arch-tile.h \
threads-debug.h threads-profile.h \
tm-modules.c tm-modules.h \
tmqh-flow.c tmqh-flow.h \
tmqh-nfq.c tmqh-nfq.h \
tmqh-packetpool.c tmqh-packetpool.h \
tmqh-ringbuffer.c tmqh-ringbuffer.h \
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
util-buffer.c util-buffer.h \
util-byte.c util-byte.h \
util-checksum.c util-checksum.h \
util-cidr.c util-cidr.h \
util-classification-config.c util-classification-config.h \
util-conf.c util-conf.h \
util-coredump-config.c util-coredump-config.h \
util-cpu.c util-cpu.h \
util-crypt.c util-crypt.h \
util-cuda.c util-cuda.h \
util-cuda-buffer.c util-cuda-buffer.h \
util-cuda-handlers.c util-cuda-handlers.h \
util-cuda-vars.c util-cuda-vars.h \
util-daemon.c util-daemon.h \
util-debug.c util-debug.h \
util-debug-filters.c util-debug-filters.h \
util-decode-asn1.c util-decode-asn1.h \
util-decode-der.c util-decode-der.h \
util-decode-der-get.c util-decode-der-get.h \
util-decode-mime.c util-decode-mime.h \
util-device.c util-device.h \
util-enum.c util-enum.h \
util-error.c util-error.h \
util-file.c util-file.h \
util-fix_checksum.c util-fix_checksum.h \
util-fmemopen.c util-fmemopen.h \
util-hash.c util-hash.h \
util-hashlist.c util-hashlist.h \
util-hash-lookup3.c util-hash-lookup3.h \
util-host-os-info.c util-host-os-info.h \
util-host-info.c util-host-info.h \
util-ioctl.h util-ioctl.c \
util-ip.h util-ip.c \
util-logopenfile.h util-logopenfile.c \
util-logopenfile-tile.h util-logopenfile-tile.c \
util-lua.c util-lua.h \
util-lua-common.c util-lua-common.h \
util-lua-dns.c util-lua-dns.h \
util-lua-http.c util-lua-http.h \
util-lua-tls.c util-lua-tls.h \
util-lua-ssh.c util-lua-ssh.h \
util-magic.c util-magic.h \
util-memcmp.c util-memcmp.h \
util-memcpy.h \
util-mem.h \
util-memrchr.c util-memrchr.h \
util-misc.c util-misc.h \
util-mpm-ac-bs.c util-mpm-ac-bs.h \
util-mpm-ac.c util-mpm-ac.h \
util-mpm-ac-gfbs.c util-mpm-ac-gfbs.h \
util-mpm-ac-tile.c util-mpm-ac-tile.h \
util-mpm-ac-tile-small.c \
util-mpm-b2g.c util-mpm-b2g.h \
util-mpm-b3g.c util-mpm-b3g.h \
util-mpm.c util-mpm.h \
util-mpm-wumanber.c util-mpm-wumanber.h \
util-optimize.h \
util-path.c util-path.h \
util-pidfile.c util-pidfile.h \
util-pool.c util-pool.h \
util-pool-thread.c util-pool-thread.h \
util-print.c util-print.h \
util-privs.c util-privs.h \
util-profiling.c util-profiling.h \
util-profiling-locks.c util-profiling-locks.h \
util-profiling-rules.c \
util-profiling-keywords.c \
util-proto-name.c util-proto-name.h \
util-radix-tree.c util-radix-tree.h \
util-random.c util-random.h \
util-reference-config.c util-reference-config.h \
util-ringbuffer.c util-ringbuffer.h \
util-rohash.c util-rohash.h \
util-rule-vars.c util-rule-vars.h \
util-runmodes.c util-runmodes.h \
util-running-modes.c util-running-modes.h \
util-signal.c util-signal.h \
util-spm-bm.c util-spm-bm.h \
util-spm-bs2bm.c util-spm-bs2bm.h \
util-spm-bs.c util-spm-bs.h \
util-spm.c util-spm.h util-clock.h \
util-storage.c util-storage.h \
util-strlcatu.c \
util-strlcpyu.c \
util-syslog.c util-syslog.h \
util-threshold-config.c util-threshold-config.h \
util-time.c util-time.h \
util-unittest.c util-unittest.h \
util-unittest-helper.c util-unittest-helper.h \
util-validate.h util-affinity.h util-affinity.c \
util-var.c util-var.h \
util-var-name.c util-var-name.h \
util-vector.h \
win32-misc.c win32-misc.h \
win32-service.c win32-service.h \
win32-syslog.h

EXTRA_DIST = util-mpm-ac-cuda-kernel.cu ptxdump.py

# set the include path found by configure
AM_CPPFLAGS = $(all_includes)

# the library search path.
suricata_LDFLAGS = $(all_libraries)
suricata_LDADD = $(HTP_LDADD)

# Rules to build CUDA ptx modules
if BUILD_CUDA
BUILT_SOURCES = cuda-ptxdump.h

suricata_CUDA_KERNELS = \
util-mpm-ac-cuda-kernel.cu

NVCCFLAGS=-O2

SUFFIXES = \
.ptx_sm_10 \
.ptx_sm_11 \
.ptx_sm_12 \
.ptx_sm_13 \
.ptx_sm_20 \
.ptx_sm_21 \
.ptx_sm_30 \
.ptx_sm_35

PTXS =  $(suricata_CUDA_KERNELS:.cu=.ptx_sm_10)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_11)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_12)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_13)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_20)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_21)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_30)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_35)

.cu.ptx_sm_10:
	$(NVCC) $(NVCCFLAGS) -o $@ -arch=sm_10 -ptx $<

.cu.ptx_sm_11:
	$(NVCC) $(NVCCFLAGS) -o $@ -arch=sm_11 -ptx $<

.cu.ptx_sm_12:
	$(NVCC) $(NVCCFLAGS) -o $@ -arch=sm_12 -ptx $<

.cu.ptx_sm_13:
	$(NVCC) $(NVCCFLAGS) -o $@ -arch=sm_13 -ptx $<

.cu.ptx_sm_20:
	$(NVCC) $(NVCCFLAGS) -o $@ -arch=sm_20 -ptx $<

.cu.ptx_sm_21:
	$(NVCC) $(NVCCFLAGS) -o $@ -arch=sm_21 -ptx $<

.cu.ptx_sm_30:
	$(NVCC) $(NVCCFLAGS) -o $@ -arch=sm_30 -ptx $<

.cu.ptx_sm_35:
	$(NVCC) $(NVCCFLAGS) -o $@ -arch=sm_35 -ptx $<

cuda-ptxdump.h: $(PTXS)
	$(PYTHON) ptxdump.py cuda-ptxdump $(PTXS)

CLEANFILES = $(PTXS) cuda-ptxdump.h
endif

# default CFLAGS
AM_CFLAGS = ${OPTIMIZATION_CFLAGS} ${GCC_CFLAGS} ${CLANG_CFLAGS} ${SECCFLAGS} ${PCAP_CFLAGS} -Wall -Wno-unused-parameter -std=gnu99 -DLOCAL_STATE_DIR=\"$(localstatedir)\"
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
