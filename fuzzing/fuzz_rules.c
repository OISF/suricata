// Copyright (c) 2018 Code Intelligence. All rights reserved.

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "suricata-common.h"

#include "suricata.h"
#include "decode.h"
#include "detect.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "flow-worker.h"

#include "util-atomic.h"
#include "util-spm.h"
#include "util-cpu.h"
#include "util-action.h"
#include "util-pidfile.h"
#include "util-ioctl.h"
#include "util-device.h"
#include "util-misc.h"
#include "util-running-modes.h"

#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-fast-pattern.h"
#include "detect-engine-tag.h"
#include "detect-engine-threshold.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"

#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "tm-threads.h"

#include "tmqh-flow.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "stream-tcp.h"

#include "source-nfq.h"
#include "source-nfq-prototypes.h"

#include "source-nflog.h"

#include "source-ipfw.h"

#include "source-pcap.h"
#include "source-pcap-file.h"

#include "source-erf-file.h"
#include "source-erf-dag.h"
#include "source-napatech.h"

#include "source-af-packet.h"
#include "source-netmap.h"
#include "source-mpipe.h"

#include "source-windivert.h"
#include "source-windivert-prototypes.h"

#include "respond-reject.h"

#include "flow.h"
#include "flow-timeout.h"
#include "flow-manager.h"
#include "flow-bypass.h"
#include "flow-var.h"
#include "flow-bit.h"
#include "pkt-var.h"
#include "host-bit.h"

#include "ippair.h"
#include "ippair-bit.h"

#include "host.h"
#include "unix-manager.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-ssl.h"
#include "app-layer-dns-tcp.h"
#include "app-layer-dns-udp.h"
#include "app-layer-ssh.h"
#include "app-layer-ftp.h"
#include "app-layer-smtp.h"
#include "app-layer-smb.h"
#include "app-layer-modbus.h"
#include "app-layer-enip.h"
#include "app-layer-dnp3.h"

#include "util-decode-der.h"
#include "util-ebpf.h"
#include "util-radix-tree.h"
#include "util-host-os-info.h"
#include "util-cidr.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-time.h"
#include "util-rule-vars.h"
#include "util-classification-config.h"
#include "util-threshold-config.h"
#include "util-reference-config.h"
#include "util-profiling.h"
#include "util-magic.h"
#include "util-signal.h"

#include "util-coredump-config.h"

#include "util-decode-mime.h"

#include "defrag.h"

#include "runmodes.h"
#include "runmode-unittests.h"

#include "util-decode-asn1.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-daemon.h"
#include "util-byte.h"
#include "util-mem.h"
#include "reputation.h"

#include "output.h"

#include "util-privs.h"

#include "tmqh-packetpool.h"

#include "util-proto-name.h"
#include "util-mpm-hs.h"
#include "util-storage.h"
#include "host-storage.h"

#include "util-lua.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  MpmTableSetup();
  SpmTableSetup();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
	size_t input_len = size + 1;
	char buffer[input_len];
  memcpy(buffer, data, size);
	buffer[input_len-1] = '\0';

	SigTableSetup();
	SCReferenceConfInit();
	SCClassConfInit();

  DetectEngineCtx *de_ctx = DetectEngineCtxInit();
  if (de_ctx == NULL)
      goto out;

  Signature *s = SigInit(de_ctx, buffer);
  if (s != NULL) {
      SigFree(s);
			goto out;	
  }
  
out:
  DetectEngineCtxFree(de_ctx);
  SCClassConfDeinit();
  SCReferenceConfDeinit();
  return 0;

}
