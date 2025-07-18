#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#include "test_framework.h"
#define DEBUG 1
#include "../xdp_lb.c"
#include "test_mocks.h"

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

void test_erpsan_type_i_packet(struct xdp_md* ctx) {
	char packet[] =
	// Ethernet, GRE, ERSPAN (no physical header), Ethernet IPv4, TCP
	"\x00\x90\x0b\xbd\x4c\x9c\x00\x22\xbd\xf8\x19\xff\x08\x00\x45\x00"
	"\x01\xda\x04\xd6\x00\x00\x3f\x2f\x68\xaa\x0a\xfd\xfb\x6f\x0a\xfd"
	"\xfb\x0b\x00\x00\x88\xbe\x00\x50\x56\xad\x8a\xf3\xb8\x59\x9f\x49"
	"\xfe\x4c\x81\x00\x01\xf4\x08\x00\x45\x00\x01\xb0\x1f\x4f\x40\x00"
	"\x40\x06\x03\xa7\x0a\xff\x00\x1e\x0a\xff\x00\x37\x0c\xea\x99\xfc"
	"\x80\x49\x86\x29\xe0\xfa\x3b\x2f\x50\x18\x48\xf7\xcf\xe1\x00\x00"
	// TCP payload (obfusticated)
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00"
	"\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
	"\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00\x03\x00"
	"\x08\xfe\x00\x00\x01\x00\x00\x00";

	CTX_SET(ctx, packet);

	int result = xdp_loadfilter(ctx);
	assert((result & 0xffff) == XDP_REDIRECT);
}

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
  // expect it parsed and balanced to a specific CPU
	assert((result & 0xffff) == XDP_REDIRECT);
}

// This test has GRE encapsulating an inner ether frame which contains a non-ip paylaod
// See gre_ecapsulating_non_ip for a test whereby the GRE header itself indicates a non-ip 
// payload following the GRE header (i.e., no inner ether header)
void test_non_ip_packet(struct xdp_md* ctx) {
	char packet[] =
	// outer ether
	"\x00\x90\x0b\xbd\x4c\x9c\x00\x22\xbd\xf8\x19\xff\x08\x00"
	// outer IP
	"\x45\x00\x00\x58\x06\x1b\x00\x00\x3f\x2f\x68\x83\x0a\xfd\xfb\xd3\x0a\xfd\xfb\x0b"
	// gre (TODO: this says er-span 0x88be and is directly followed by ether; is that correct?)
	"\x00\x00\x88\xbe"
	// inner ether
	"\xff\xff\xff\xff\xff\xff\x00\x50\x56\xad\x64\x4a\x81\x00"
	// vlan
	"\x0a\xff\x08\x06"
	// arp
	"\x00\x01\x08\x00\x06\x04\x00\x01\x00\x50\x56\xad\x64\x4a\xc0\xa8"
	"\xaa\x24\x00\x00\x00\x00\x00\x00\xc0\xa8\xaa\xec\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

	CTX_SET(ctx, packet);

	int result = xdp_loadfilter(ctx);
	assert((result & 0xffff) == XDP_PASS);
}

void test_gre_ecapsulating_non_ip(struct xdp_md* ctx) {
        unsigned char packet[] = {
	    // outer ether
	    0x0, 0x0, 0x5e, 0x0, 0x1, 0xea, 0x74, 0xfe, 0x48, 0x74, 0x9d, 0xfb, 0x8, 0x0, 
	    // outer IP
	    0x45, 0x0, 0x0, 0x76, 0x0, 0x0, 0x0, 0x0, 0xfd, 0x2f, 0x42, 0xe1, 0xa, 0x2f, 0x1, 0x4, 
	    0xa, 0x2d, 0x65, 0x18, 
	    // GRE     VVVVVVVVV-- Non-IP next ether
	    0x20, 0x0, 0x83, 0x0, 0x0, 0x1, 0xe0, 0x1f, 
	    // 802.11 data
	    0x8, 0x42, 0x84, 0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x7f, 0xf1, 0xab, 0x22, 0x40, 
	    0x0, 0x10, 0xf3, 0xbd, 0x74, 0xcc, 0x0, 0x0, 0xf0, 0xf7, 0x0, 0x60, 0x76, 0x1, 0x0, 0x0, 
	    // opaque data...
	    0xee, 0xca, 0x85, 0x6d, 0x4, 0x64, 0xae, 0xf7, 0xe9, 0x3, 0x3e, 0x80, 0x1a, 0x34, 0xf2, 0xdd, 
	    0x6, 0xa5, 0x2b, 0xcb, 0xb, 0x49, 0x2d, 0xe3, 0x67, 0x32, 0xd2, 0xd2, 0xcc, 0x6, 0x36, 0x9e, 
	    0x17, 0x7c, 0x13, 0x81, 0x15, 0x2f, 0xf8, 0x5a, 0x77, 0x8e, 0xe3, 0x36, 0x69, 0x83, 0x2e, 0x12, 
	    0x5d, 0xf6, 0x48, 0xd9, 0xc, 0x3a, 0x8e, 0x21, 0xee, 0x42};

        CTX_SET(ctx, packet);

	// we doin't expect this packet to be balanced, it'll just be passed through, due to the non-ip 
	// next ether type in the gre header
        int result = xdp_loadfilter(ctx);
        assert((result & 0xffff) == XDP_PASS);
}

int main() {
	setup_mocks();
	bpf_map_lookup_elem = bpf_map_lookup_elem_lb_mock;

	// And our fake 32-bit addressable environment...
	struct xdp_md ctx;
	g_TopOfStack = HIGH32(&ctx);

	TEST(inner_packet_balance);
	TEST(inner_packet_symmetry);
	TEST(ipv6_symmetry);
	TEST(erpsan_type_i_packet);
	TEST(non_ip_packet);
	TEST(IEEE8021ah_packet);
	TEST(gre_ecapsulating_non_ip);

	return 0;
}
