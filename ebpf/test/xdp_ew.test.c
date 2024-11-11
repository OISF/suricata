/**
 * This file defines a fairly light unit testing framework and some tests, meant to allow
 * some degree of sanity checking to be done on an XDP program.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

void *cpus_count = NULL;
void *cpus_available = NULL;

#include "test_framework.h"
#define DEBUG 1
#include "../xdp_ew.c"
#include "test_mocks.h"

void test_IEEE8021ah_packet(struct xdp_md* ctx) {
	char packet[] =
  "\002\020\000\377\377\360\000\027 \005\220\207\201\000\017\323\210\347\000\000-P\264\f%\340@\020\254\037k\263N\221\201\000\006@\b\000E\000\000(\251\017@\000\377\006L*\n`\020\a\n\020b\037an\n&mV\273\305\r\243\002ZP\020\002\002\202\217\000\000\000\000\000\000\000\000";
  CTX_SET(ctx, packet);

	int result = xdp_loadfilter(ctx);
	assert((result & 0xffff) == XDP_DROP);
}

int main() {
	setup_mocks();

	// And our fake 32-bit addressable environment...
	struct xdp_md ctx;
	g_TopOfStack = HIGH32(&ctx);

  TEST(IEEE8021ah_packet);
}
