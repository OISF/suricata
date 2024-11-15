#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

// We don't use these BPF tables for the E/W filter
void *cpus_count = NULL;
void *cpus_available = NULL;

#include "test_framework.h"
#define DEBUG 1
#include "../xdp_ew.c"
#include "test_mocks.h"

void test_IEEE8021ah_packet(struct xdp_md* ctx) {
  char packet[] =
    // ether header, next header == 8100
    "\002\020\000\377\377\360\000\027 \005\220\207\201\000"
    // vlan header, next header == 0x88e7
    "\017\323\210\347"
    // Provider backbone bridge (802.1ah), next header == 0x8100
    "\000\000-P\264\f%\340@\020\254\037k\263N\221\201\000"
    // vlan header, header header == 0x0800
    "\006@\b\000"
    // IPV4 header
    //  Src IP == 10.96.16.7 (internal)
    //  Dst IP == 10.16.98.31 (internal)
    "E\000\000(\251\017@\000\377\006L*\n`\020\a\n\020b\037an\n&mV\273\305\r\243\002ZP\020\002\002\202\217\000\000\000\000\000\000\000\000";
  CTX_SET(ctx, packet);

  int result = xdp_loadfilter(ctx);
  // expect it to be dropped, due to being internal <-> internal traffic
  assert((result & 0xffff) == XDP_DROP);
}

int main() {
  setup_mocks();

  // And our fake 32-bit addressable environment...
  struct xdp_md ctx;
  g_TopOfStack = HIGH32(&ctx);

  TEST(IEEE8021ah_packet);
}
