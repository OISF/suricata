#ifndef __EBPF_TEST_FRAMEWORK__
#define __EBPF_TEST_FRAMEWORK__

/**
 * This file defines a fairly light unit testing framework and some tests, meant to allow
 * some degree of sanity checking to be done on an XDP program.
 */

#define TEST(name) \
  printf("Running test %s\n", #name); \
  test_##name(&ctx);

#define SWAP(x,y) \
{\
	int temp = y; \
	y = x; \
	x = temp; \
}

static int test_trace_hook(const char *fmt, int fmt_size, ...) {
	va_list args;
	va_start(args, fmt_size);

	// With very few exceptions, the compiler will always push args using the native word size.
	// So rather then implement a full-fledged printf, just extract a native word (an int) per
	// each arg, and pass it to printf... it doesn't matter if the variable is an int or not, we
	// just need to copy the data and pass it to the real printf, which will interpret it
	// as it wants...
	int term;
	char term_format[3] = "%d\0";

	while (*fmt != '\0') {
    	if (*fmt == '%') {
      		fmt++;
			switch(*fmt) {
				case '%':
					putchar('%');
					break;
				case 'c':
				case 'd':
				case 'x':
					term = va_arg(args, int);
					term_format[1] = *fmt;
					printf(term_format, term);
					break;
				default:
					assert(0);
			}
		} else {
      		putchar(*fmt);
    	}
    	fmt++;
  	}
  	va_end(args);

	return 0;
}

/* This is a fairly gross side-effect of an optimization done in the xdp_md
 * struct for Linux -- the struct uses 32-bit integers in order to hold 64-bit
 * pointers (i.e., the struct is very specialized for the Linux kernel's limited
 * address space, which can be 32-bit addressable).
 * Because we don't have that same environment, we must save off the upper
 * half of our stack segment, and use the macros below to patch up the resultant
 * pointers, whenever they're read from the xdp_md struct.
 */
#define HIGH32(val64) ((uint64_t)(val64) & 0xffffffff00000000l)
#define LOW32(val64) ((uint64_t)(val64) & 0xffffffffl)
uint64_t g_TopOfStack;

// Override these for our test environment...
#define CTX_GET_DATA(ctx) (void*)(g_TopOfStack | (uint64_t)ctx->data)
#define CTX_GET_DATA_END(ctx) (void*)(g_TopOfStack | (uint64_t)ctx->data_end)

#define CTX_SET(ctx, packet) \
	ctx->data = (uint32_t)packet; \
	ctx->data_end = (uint32_t)packet + sizeof(packet);


#endif
