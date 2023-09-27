/**
 * This file defines a fairly light unit testing framework and some tests, meant to allow 
 * some degree of sanity checking to be done on an XDP program.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

#define TEST(name) \
  printf("Running test %s\n", #name); \
  test_##name(&ctx);

#define SWAP(x,y) \
{\
	int temp = y; \
	y = x; \
	x = temp; \
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

#include "../xdp_lb.c"

// bpf_xdp_adjust_head is defined as a function pointer by the bpf headers, which 
// is patched at load time.
// This is convenient for us, as we can patch it ourselves...
int bpf_xdp_adjust_head_mock(void* privData, int offset) {
	struct xdp_md *ctx = (struct xdp_md *)privData;

	void * data = CTX_GET_DATA(ctx);
	data += offset;

	// this shouldn't change, but... if it did, our attempt to fake the 
	// 32-bit addressable environment of the kernel would fail...
	assert(HIGH32(data) == g_TopOfStack);

	ctx->data = (uint32_t)data;

	return 0;
}

// This value is arbitrary...
uint32_t g_cpuCount = 10;

void* bpf_map_lookup_elem_mock(void* map, void* key) {
	if(map == &cpus_count) {
		// This "map" is just a single value (index 0)
		return (void*)&g_cpuCount;
	} else if(map == &cpus_available) {
		// This map is 'cpus_count' long, and maps logical CPU ID to physical CPU ID
		// For simplicity, it's an identity map...
		return (void*)key;
	}
	return 0;
}

int bpf_redirect_map_mock(void* map, int key, int flags) {
	// I assume the kernel does something similar... but it really doesn't matter; we 
	// just need a way to encode the unique CPU and the fact that it's a redirect (not a 
	// PASS, ABORT, etc) in the same result...
	return (key << 16) + XDP_REDIRECT;
}

void test_inner_packet_balance(struct xdp_md* ctx) {
	// GRE packet from a capture, loaded into wireshark, and then "copy as escaped string"
	char packet[] = 
		// Outer eth header
		"\x00\x90\x0b\xa9\x49\x55\x00\x50\x56\x63\xf2\x58\x08\x00"         
		// Outer IP header
		// src 192.29.36.175
		// dest 172.29.35.160
		"\x45\x00\x00\x98\xd1\x3d\x00\x00\x40\x2f\x07\x7a\xac\x1d\x24\xaf\xac\x1d\x24\x96"
		// GRE
		"\x10\x00\x88\xbe\x39\x8b\xdf\x97"
		// ERSPAN
		"\x10\x00\x00\x00\x00\x00\x00\x01"
		// Inner eth header
		"\x00\x50\x56\x94\x2d\x12\x00\x50\x56\x0b\x07\xf0\x08\x00" 
		// Inner IP header
		"\x45\x00\x00\x66\x89\xf3\x40\x00\x40\x06\xdd\xb0\x0a\x00\x01\x10\xa5\xe1\x21\xfd"
		// TCP header
		"\xc4\x46\x01\xbb\xb6\x93\xef\x9f\x47\x24\xb2\x97" 
		"\x80\x18\x07\xfd\x74\xa5\x00\x00\x01\x01\x08\x0a\x65\xda\x08\x7e" 
		"\x4a\x02\xda\x1b"
		// Layer 5...
		"\x17\x03\x03\x00\x2d\x05\x74\xce\xee\x5f\xd7\xf9" 
		"\x0e\x52\xad\xd4\xf6\x5d\x51\x44\x7b\x41\x76\x4e\x61\x0b\x31\xaa" 
		"\x6b\x35\x01\x67\xae\x2c\x52\xf8\x42\x51\x25\xe4\x13\x95\x3a\x25" 
		"\x68\x25\xfe\x47\x9a\x2d";

	CTX_SET(ctx, packet);

	// ensure this packet is parsed and assigned a CPU (we don't care which one)
	int result = xdp_loadfilter(ctx);
	assert((result & 0xffff) == XDP_REDIRECT);

	// Modify the outter IP header.
	// With the same inner 5-tuple, it should balance to the same CPU
	assert(packet[14] == 0x45); // sanity; start of outter IP header
	struct iphdr* ip = (struct iphdr*)&packet[14];
	ip->saddr = 0;
	ip->daddr = 0;

	int result2 = xdp_loadfilter(ctx);
	assert(result2 == result);

	// Modify the inner 5-tuple, should balance to the different CPU
	assert(packet[64] == 0x45); // sanity; start of inner IP header
	ip = (struct iphdr*)&packet[64];
	ip->saddr = 0;
	ip->daddr = 0;

	int result3 = xdp_loadfilter(ctx);
	assert((result3 & 0xffff) == XDP_REDIRECT);
	assert(result3 != result);
}

void test_inner_packet_symmetry(struct xdp_md* ctx) {
	char packet[] = 
		"\x00\x90\x0b\xa9\x49\x55\x00\x50\x56\x63\xf2\x58\x08\x00\x45\x00"
		"\x00\x66\xd1\x3e\x00\x00\x40\x2f\x07\xab\xac\x1d\x24\xaf\xac\x1d"
		"\x24\x96\x10\x00\x88\xbe\x39\x8b\xdf\x98\x17\xd0\x10\x00\x00\x00"
		"\x00\x00\x84\xb2\x61\x19\x27\x4f\x00\x50\x56\x94\x7e\x73\x08\x00"
		"\x45\x00\x00\x34\x89\xf2\x40\x00\x3f\x06\xc4\xbb\xcc\x08\x59\x2f"
		"\xa5\xe1\x21\xfd\xc4\x46\x01\xbb\xb6\x93\xef\x9f\x47\x24\xb2\x97"
		"\x80\x10\x07\xfd\x89\x42\x00\x00\x01\x01\x08\x0a\x65\xda\x08\x7e"
		"\x4a\x02\xda\x1b";

	CTX_SET(ctx, packet);

	// ensure this packet is parsed and assigned a CPU (we don't care which one)
	int result = xdp_loadfilter(ctx);
	assert((result & 0xffff) == XDP_REDIRECT);

	// Now modify the inner packet such that it's 5-tuple is a response 
	// to the original packet...
	assert(packet[64] == 0x45); // sanity; start of inner IP header
	struct iphdr* ip = (struct iphdr*)&packet[64];
	SWAP(ip->saddr, ip->daddr);

	struct tcphdr* tcp = (struct tcphdr*)&packet[64 + sizeof(struct iphdr)];
	SWAP(tcp->source, tcp->dest);

	int result2 = xdp_loadfilter(ctx);
	assert(result == result2);

	// Now, the inverse... swap the ports back (thus making a new flow) 
	// and see that it balances to a different CPU
	SWAP(tcp->source, tcp->dest);
	int result3 = xdp_loadfilter(ctx);
	assert(result3 != result);
}

void test_ipv6_symmetry(struct xdp_md* ctx) {
	char packet[] = 
	"\x33\x33\x00\x01\x00\x02\x00\x22\xfb\x12\xda\xe8\x86\xdd\x60\x00"
	"\x00\x00\x00\x61\x11\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x35\xd0"
	"\xb3\x9e\xc3\xf7\xe2\x0f\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x01\x00\x02\x02\x22\x02\x23\x00\x61\x56\x62\x01\x00"
	"\x57\x03\x00\x08\x00\x02\x18\x9c\x00\x01\x00\x0e\x00\x01\x00\x01"
	"\x15\xb7\xc4\xfa\x00\x1c\x25\xbc\xea\x83\x00\x03\x00\x0c\x1d\x00"
	"\x22\xfb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x27\x00\x0b\x00\x09"
	"\x4c\x61\x70\x74\x6f\x70\x2d\x50\x43\x00\x10\x00\x0e\x00\x00\x01"
	"\x37\x00\x08\x4d\x53\x46\x54\x20\x35\x2e\x30\x00\x06\x00\x08\x00"
	"\x18\x00\x17\x00\x11\x00\x27";

	CTX_SET(ctx, packet);

	int result = xdp_loadfilter(ctx);
	assert((result & 0xffff) == XDP_REDIRECT);

	// create a return packet...
	assert(packet[14] == 0x60); // sanity; start of ipv6 header
	struct ipv6hdr *ip6 = (struct ipv6hdr *)&packet[14];
	for(int i = 0; i <= 3; i++) {
		SWAP(ip6->saddr.s6_addr32[i], ip6->daddr.s6_addr32[i]);
	}
	struct udphdr * udp = (struct udphdr *)&packet[54];
	SWAP(udp->dest, udp->source);

	int result2 = xdp_loadfilter(ctx);
	assert(result == result2);

	// modify the 5-tuple to see that it balances to a different CPU
	udp->dest = udp->dest ^ 0xffff;
	udp->source = udp->source ^ 0xffff;
	
	int result3 = xdp_loadfilter(ctx);
	assert((result3 & 0xffff) == XDP_REDIRECT);
	assert(result3 != result);
}

int main() {
	// setup our mocks...
	bpf_xdp_adjust_head = bpf_xdp_adjust_head_mock;
	bpf_map_lookup_elem = bpf_map_lookup_elem_mock;
	bpf_redirect_map = bpf_redirect_map_mock;

	// And our fake 32-bit addressable environment...
	struct xdp_md ctx;
	g_TopOfStack = HIGH32(&ctx);

	TEST(inner_packet_balance);
	TEST(inner_packet_symmetry);
	TEST(ipv6_symmetry);

	return 0;
}
