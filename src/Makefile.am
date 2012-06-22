noinst_HEADERS = action-globals.h \
    app-layer-nbss.h app-layer-dcerpc-common.h \
    debug.h \
	flow-private.h queue.h source-nfq-prototypes.h \
	suricata-common.h threadvars.h util-binsearch.h \
        util-validate.h
bin_PROGRAMS = suricata

AM_CPPFLAGS = -DCONFIG_DIR=\"$(e_sysconfdir)\"

suricata_SOURCES = suricata.c suricata.h \
runmodes.c runmodes.h \
runmode-pcap.c runmode-pcap.h \
runmode-pcap-file.c runmode-pcap-file.h \
runmode-pfring.c runmode-pfring.h \
runmode-nfq.c runmode-nfq.h \
runmode-ipfw.c runmode-ipfw.h \
runmode-erf-file.c runmode-erf-file.h \
runmode-erf-dag.c runmode-erf-dag.h \
runmode-napatech.c runmode-napatech.h \
runmode-af-packet.c runmode-af-packet.h \
packet-queue.c packet-queue.h \
data-queue.c data-queue.h \
threads.c threads.h \
source-nfq.c source-nfq.h \
source-pcap.c source-pcap.h \
source-pcap-file.c source-pcap-file.h \
source-pfring.c source-pfring.h \
source-ipfw.c source-ipfw.h \
source-erf-file.c source-erf-file.h \
source-erf-dag.c source-erf-dag.h \
source-napatech.c source-napatech.h \
source-af-packet.c source-af-packet.h \
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
decode-sctp.c decode-sctp.h \
flow.c flow.h \
flow-timeout.c flow-timeout.h \
flow-manager.c flow-manager.h \
flow-queue.c flow-queue.h \
flow-hash.c flow-hash.h \
flow-util.c flow-util.h \
util-mem.h \
flow-var.c flow-var.h \
flow-bit.c flow-bit.h \
flow-alert-sid.c flow-alert-sid.h \
pkt-var.c pkt-var.h \
host.c host.h \
host-queue.c host-queue.h \
host-timeout.c host-timeout.h \
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
detect-engine-tag.c detect-engine-tag.h \
detect-engine-address-ipv4.c detect-engine-address-ipv4.h \
detect-engine-address-ipv6.c detect-engine-address-ipv6.h \
detect-engine-proto.c detect-engine-proto.h \
detect-engine-port.c detect-engine-port.h \
detect-engine-siggroup.c detect-engine-siggroup.h \
detect-engine-mpm.c detect-engine-mpm.h \
detect-engine-iponly.c detect-engine-iponly.h \
detect-engine-content-inspection.c detect-engine-content-inspection.h \
detect-engine-payload.c detect-engine-payload.h \
detect-engine-dcepayload.c detect-engine-dcepayload.h \
detect-engine-uri.c detect-engine-uri.h \
detect-engine-hcbd.c detect-engine-hcbd.h \
detect-engine-hsbd.c detect-engine-hsbd.h \
detect-engine-hhd.c detect-engine-hhd.h \
detect-engine-hrhd.c detect-engine-hrhd.h \
detect-engine-hmd.c detect-engine-hmd.h \
detect-engine-hcd.c detect-engine-hcd.h \
detect-engine-hrud.c detect-engine-hrud.h \
detect-engine-hsmd.c detect-engine-hsmd.h \
detect-engine-hscd.c detect-engine-hscd.h \
detect-engine-hua.c detect-engine-hua.h \
detect-engine-state.c detect-engine-state.h \
detect-engine-file.c detect-engine-file.h \
detect-engine-analyzer.c detect-engine-analyzer.h \
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
detect-tos.c detect-tos.h \
detect-stream_size.c detect-stream_size.h \
detect-engine-event.c detect-engine-event.h \
detect-ipopts.c detect-ipopts.h \
detect-flags.c detect-flags.h \
detect-fragbits.c detect-fragbits.h \
detect-fragoffset.c detect-fragoffset.h \
detect-gid.c detect-gid.h \
detect-mark.c detect-mark.h \
detect-noalert.c detect-noalert.h \
detect-csum.c detect-csum.h \
detect-ttl.c detect-ttl.h \
detect-itype.c detect-itype.h \
detect-icode.c detect-icode.h \
detect-http-cookie.c detect-http-cookie.h \
detect-http-method.c detect-http-method.h \
detect-http-header.c detect-http-header.h \
detect-http-raw-header.c detect-http-raw-header.h \
detect-http-uri.c detect-http-uri.h \
detect-http-raw-uri.c detect-http-raw-uri.h \
detect-file-data.c detect-file-data.h \
detect-http-ua.c detect-http-ua.h \
detect-tls.c detect-tls.h \
detect-tls-version.c detect-tls-version.h \
detect-ssh-proto-version.c detect-ssh-proto-version.h \
detect-ssh-software-version.c detect-ssh-software-version.h \
detect-icmp-id.c detect-icmp-id.h \
detect-icmp-seq.c detect-icmp-seq.h \
detect-dce-iface.c detect-dce-iface.h \
detect-dce-opnum.c detect-dce-opnum.h \
detect-dce-stub-data.c detect-dce-stub-data.h \
detect-urilen.c detect-urilen.h \
detect-detection-filter.c detect-detection-filter.h \
detect-http-client-body.c detect-http-client-body.h \
detect-http-server-body.c detect-http-server-body.h \
detect-http-stat-msg.c detect-http-stat-msg.h \
detect-asn1.c detect-asn1.h \
detect-filename.c detect-filename.h \
detect-fileext.c detect-fileext.h \
detect-filestore.c detect-filestore.h \
detect-filemagic.c detect-filemagic.h \
detect-filemd5.c detect-filemd5.h \
detect-http-stat-code.c detect-http-stat-code.h \
detect-ssl-version.c detect-ssl-version.h \
detect-ssl-state.c detect-ssl-state.h \
detect-byte-extract.c detect-byte-extract.h \
detect-app-layer-event.c detect-app-layer-event.h \
decode-events.c decode-events.h \
detect-replace.c detect-replace.h \
util-magic.c util-magic.h \
util-misc.c util-misc.h \
util-atomic.c util-atomic.h \
util-signal.c util-signal.h \
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
util-mpm-b2gc.c util-mpm-b2gc.h \
util-mpm-b2gm.c util-mpm-b2gm.h \
util-mpm-ac.c util-mpm-ac.h \
util-mpm-ac-gfbs.c util-mpm-ac-gfbs.h \
util-mpm-ac-bs.c util-mpm-ac-bs.h \
util-cidr.c util-cidr.h \
util-unittest.c util-unittest.h \
util-unittest-helper.c util-unittest-helper.h \
util-hash.c util-hash.h \
util-hashlist.c util-hashlist.h \
util-hash-lookup3.c util-hash-lookup3.h \
util-rohash.c util-rohash.h \
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
util-reference-config.c util-reference-config.h \
util-coredump-config.c util-coredump-config.h \
util-strlcatu.c \
util-strlcpyu.c \
util-cuda.c util-cuda.h \
util-cuda-handlers.c util-cuda-handlers.h \
util-optimize.h \
util-privs.c util-privs.h \
util-decode-asn1.c util-decode-asn1.h \
util-decode-der.c util-decode-der.h \
util-decode-der-get.c util-decode-der-get.h \
util-ringbuffer.c util-ringbuffer.h \
util-validate.h util-affinity.h util-affinity.c \
util-memcmp.c util-memcmp.h \
util-proto-name.c util-proto-name.h \
util-syslog.c util-syslog.h \
util-vector.h \
util-device.c util-device.h \
util-checksum.c util-checksum.h \
util-runmodes.c util-runmodes.h \
util-file.c util-file.h \
util-path.c util-path.h \
util-buffer.c util-buffer.h \
tm-modules.c tm-modules.h \
tm-queues.c tm-queues.h \
tm-queuehandlers.c tm-queuehandlers.h \
tm-threads.c tm-threads.h tm-threads-common.h \
tmqh-simple.c tmqh-simple.h \
tmqh-nfq.c tmqh-nfq.h \
tmqh-packetpool.c tmqh-packetpool.h \
tmqh-flow.c tmqh-flow.h \
tmqh-ringbuffer.c tmqh-ringbuffer.h \
alert-fastlog.c alert-fastlog.h \
alert-debuglog.c alert-debuglog.h \
alert-prelude.c alert-prelude.h \
alert-unified2-alert.c alert-unified2-alert.h \
alert-syslog.c alert-syslog.h \
alert-pcapinfo.c alert-pcapinfo.h \
log-droplog.c log-droplog.h \
log-httplog.c log-httplog.h \
log-pcap.c log-pcap.h \
log-file.c log-file.h \
log-filestore.c log-filestore.h \
stream.c stream.h \
stream-tcp.c stream-tcp.h stream-tcp-private.h \
stream-tcp-reassemble.c stream-tcp-reassemble.h \
stream-tcp-inline.c stream-tcp-inline.h \
stream-tcp-sack.c stream-tcp-sack.h \
stream-tcp-util.c stream-tcp-util.h \
respond-reject.c respond-reject.h \
respond-reject-libnet11.h respond-reject-libnet11.c \
conf.c conf.h \
conf-yaml-loader.c conf-yaml-loader.h \
counters.c counters.h \
app-layer.c app-layer.h \
app-layer-detect-proto.c app-layer-detect-proto.h \
app-layer-parser.c app-layer-parser.h \
app-layer-protos.c app-layer-protos.h \
app-layer-htp.c app-layer-htp.h \
app-layer-htp-body.c app-layer-htp-body.h \
app-layer-htp-file.c app-layer-htp-file.h \
app-layer-smb.c app-layer-smb.h \
app-layer-smb2.c app-layer-smb2.h \
app-layer-dcerpc.c app-layer-dcerpc.h \
app-layer-dcerpc-udp.c app-layer-dcerpc-udp.h \
app-layer-ftp.c app-layer-ftp.h \
app-layer-ssl.c app-layer-ssl.h \
app-layer-ssh.c app-layer-ssh.h \
app-layer-tls-handshake.c app-layer-tls-handshake.h \
app-layer-smtp.c app-layer-smtp.h \
defrag.c defrag.h \
output.c output.h \
win32-misc.c win32-misc.h \
win32-service.c win32-service.h \
util-action.c util-action.h \
win32-syslog.h \
util-profiling.c util-profiling.h \
util-profiling-locks.c util-profiling-locks.h \
cuda-packet-batcher.c cuda-packet-batcher.h \
util-ioctl.h util-ioctl.c \
util-logopenfile.h util-logopenfile.c

EXTRA_DIST = util-mpm-b2g-cuda-kernel.cu ptxdump.py

# set the include path found by configure
INCLUDES= $(all_includes)


# the library search path.
suricata_LDFLAGS = $(all_libraries)

if BUILD_LIBHTP
suricata_LDADD = $(top_builddir)/libhtp/htp/libhtp.la
INCLUDES += -I$(top_srcdir)/libhtp
endif

# Rules to build CUDA ptx modules
if BUILD_CUDA
BUILT_SOURCES = cuda-ptxdump.h
suricata_SOURCES += cuda-ptxdump.h

suricata_CUDA_KERNELS = \
util-mpm-b2g-cuda-kernel.cu

NVCCFLAGS=-O2

SUFFIXES = \
.ptx_sm_10 \
.ptx_sm_11 \
.ptx_sm_12 \
.ptx_sm_13 \
.ptx_sm_20 \
.ptx_sm_21

PTXS =  $(suricata_CUDA_KERNELS:.cu=.ptx_sm_10)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_11)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_12)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_13)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_20)
PTXS += $(suricata_CUDA_KERNELS:.cu=.ptx_sm_21)

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

cuda-ptxdump.h: $(PTXS)
	$(PYTHON) ptxdump.py cuda-ptxdump $(PTXS)

CLEANFILES = $(PTXS) cuda-ptxdump.h
endif


#suricata_CFLAGS = -Wall -fno-strict-aliasing 

if BUILD_UNITTESTS
check-am:
	$(top_builddir)/src/suricata -u
endif
