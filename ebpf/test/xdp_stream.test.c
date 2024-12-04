#include "test_framework.h"
#define DEBUG 1
#include "../xdp_lb_stream.c"
#include "test_mocks.h"


void test_ipv4_match(struct xdp_md* ctx) {
  char packet[] = 
    "\x0\x50\x56\x80\x83\xd8\x0\x50\x56\x80\xdf\x93\x8\x0\x45\x0\x0\x84\xf7\x78"
    "\x40\x0\x40\x6\x1f\xd4\xa\x8\x7\xb5\xa\x8\x7\x63\xb4\xa9\x0\x50\x29\x8b\xe3"
    "\x91\x28\xe9\x5e\x9b\x80\x18\x1\xf6\x4d\x3b\x0\x0\x1\x1\x8\xa\x10\x9d\xe4"
    "\x9a\x99\x4e\x3f\x1d\x47\x45\x54\x20\x2f\x50\x44\x46\x31\x30\x4d\x42\x20\x48"
    "\x54\x54\x50\x2f\x31\x2e\x31\xd\xa\x48\x6f\x73\x74\x3a\x20\x31\x30\x2e\x38"
    "\x2e\x37\x2e\x39\x39\xd\xa\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20"
    "\x63\x75\x72\x6c\x2f\x37\x2e\x36\x38\x2e\x30\xd\xa\x41\x63\x63\x65\x70\x74"
    "\x3a\x20\x2a\x2f\x2a\xd\xa\xd\xa";

  CTX_SET(ctx, packet);

  // Pointer value doesn't matter - just has to be non-NULL for a match
  struct pair bpf_ret_value = {0, 0}; 
  g_stream_map_lookup_value = &bpf_ret_value;

  // This will contain the key that the filter tried to look up
  struct flowv4_keys *key = &g_stream_map_v4_lookup_keys;

  int result = xdp_loadfilter(ctx);
  assert(result == XDP_DROP);

  // Value from the pcap above. They'll be in little-endian in the key.
  assert(key->ip_proto == 1);
  assert(key->src == 0xb507080a);
  assert(key->dst == 0x6307080a);
  assert(key->port16[0] == 0xa9b4);
  assert(key->port16[1] == 0x5000); // dest port: 80
  assert(key->vlan0 == 0);
  assert(key->vlan1 == 0);
}

void test_gre_match(struct xdp_md* ctx) {
  // Packet borrowed from xdp_lb.test.c
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
    // src0.0.1.16
    // dest 165.225.33.253
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

  struct pair bpf_ret_value = {0, 0}; 
  g_stream_map_lookup_value = &bpf_ret_value;

  struct flowv4_keys *key = &g_stream_map_v4_lookup_keys;

  int result = xdp_loadfilter(ctx);
  assert(result == XDP_DROP);

  //DPRINTF("key->ip_proto: %d, key->src: %x, key->dst: %x, key->port16[0]: %x, key->port16[1]: %x, key->vlan0: %d, key->vlan1: %d\n",
  //        key->ip_proto, key->src, key->dst, key->port16[0], key->port16[1], key->vlan0, key->vlan1);

  // little-endian
  assert(key->ip_proto == 1);
  assert(key->src == 0x1001000a);
  assert(key->dst == 0xfd21e1a5);
  assert(key->port16[0] == 0x46c4);
  assert(key->port16[1] == 0xbb01); // dest port: 443
  assert(key->vlan0 == 0);
  assert(key->vlan1 == 0);
}

void test_IEEE8021ah_packet_vlan(struct xdp_md* ctx) {
  // Example packet data in hex format (borrowed from xdp_lb.test.c)
  char packet[] =
  // ether header, next header == 8100
  "\x02\x10\x00\xff\xff\xf0\x00\x17\x20\x05\x90\x87\x81\x00"
  // vlan header, next header == 0x88e7
  "\x0f\xd3\x88\xe7" // vlan == d30f & 0x0fff == 30f
  // Provider backbone bridge (802.1ah), next header == 0x8100
  "\x00\x00\x2d\x50\xb4\x0c\x25\xe0\x40\x10\xac\x1f\x6b\xb3\x4e\x91\x81\x00"
  // vlan header, next header == 0x0800
  "\x06\x40\x08\x00" // vlan == 4006 & 0x0fff == 6
  // IPV4 header
  //  Src IP == 10.96.16.7 (internal)
  //  Dst IP == 10.16.98.31 (internal)
  "\x45\x00\x00\x28\xa9\x0f\x40\x00\xff\x06\x4c\x2a\x0a\x60\x10\x07\x0a\x10\x62\x1f"
  // TCP header and payload
  "\x61\x6e\x0a\x26\x6d\x56\xbb\xc5\x0d\xa3\x02\x5a\x50\x10\x02\x02\x82\x8f\x00\x00\x00\x00\x00\x00\x00\x00";

  CTX_SET(ctx, packet);

  struct pair bpf_ret_value = {0, 0}; 
  g_stream_map_lookup_value = &bpf_ret_value;

  struct flowv4_keys *key = &g_stream_map_v4_lookup_keys;

  int result = xdp_loadfilter(ctx);
  assert(result == XDP_DROP);

  assert(key->ip_proto == 1);
  assert(key->src == 0x0710600a);
  assert(key->dst == 0x1f62100a);
  assert(key->port16[0] == 0x6e61);
  assert(key->port16[1] == 0x260a);
  assert(key->vlan0 == 0x30f);
  assert(key->vlan1 == 6);

  //DPRINTF("key->ip_proto: %d, key->src: %x, key->dst: %x, key->port16[0]: %x, key->port16[1]: %x, key->vlan0: %x, key->vlan1: %x\n",
  //  key->ip_proto, key->src, key->dst, key->port16[0], key->port16[1], key->vlan0, key->vlan1);
}

void test_no_match(struct xdp_md* ctx) {
  char packet[] = 
    "\x0\x50\x56\x80\x83\xd8\x0\x50\x56\x80\xdf\x93\x8\x0\x45\x0\x0\x84\xf7\x78"
    "\x40\x0\x40\x6\x1f\xd4\xa\x8\x7\xb5\xa\x8\x7\x63\xb4\xa9\x0\x50\x29\x8b\xe3"
    "\x91\x28\xe9\x5e\x9b\x80\x18\x1\xf6\x4d\x3b\x0\x0\x1\x1\x8\xa\x10\x9d\xe4"
    "\x9a\x99\x4e\x3f\x1d\x47\x45\x54\x20\x2f\x50\x44\x46\x31\x30\x4d\x42\x20\x48"
    "\x54\x54\x50\x2f\x31\x2e\x31\xd\xa\x48\x6f\x73\x74\x3a\x20\x31\x30\x2e\x38"
    "\x2e\x37\x2e\x39\x39\xd\xa\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20"
    "\x63\x75\x72\x6c\x2f\x37\x2e\x36\x38\x2e\x30\xd\xa\x41\x63\x63\x65\x70\x74"
    "\x3a\x20\x2a\x2f\x2a\xd\xa\xd\xa";

  CTX_SET(ctx, packet);

  // make bpf_map_lookup_elem return NULL
  g_stream_map_lookup_value = NULL;

  // This will contain the key that the filter tried to look up
  struct flowv4_keys *key = &g_stream_map_v4_lookup_keys;

  int result = xdp_loadfilter(ctx);
  assert(result == XDP_PASS);

  // Key has been verified in test_ipv4_match (packet is the same)
}

void test_ipv6(struct xdp_md* ctx) {
  char packet[] =
  // Ethernet header
	"\x33\x33\x00\x01\x00\x02\x00\x22\xfb\x12\xda\xe8\x86\xdd"
  // Ipv6 header
  "\x60\x00\x00\x00\x00\x61\x11\x01"
  // Source IP: fe80::35d0:b39e:c3f7:e20f
  "\xfe\x80\x00\x00\x00\x00\x00\x00\x35\xd0\xb3\x9e\xc3\xf7\xe2\x0f"
  // Dest IP: ff02::1:2
  "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02"
  // Payload (UDP, DHCPv6)
  "\x02\x22\x02\x23\x00\x61\x56\x62\x01\x00"
	"\x57\x03\x00\x08\x00\x02\x18\x9c\x00\x01\x00\x0e\x00\x01\x00\x01"
	"\x15\xb7\xc4\xfa\x00\x1c\x25\xbc\xea\x83\x00\x03\x00\x0c\x1d\x00"
	"\x22\xfb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x27\x00\x0b\x00\x09"
	"\x4c\x61\x70\x74\x6f\x70\x2d\x50\x43\x00\x10\x00\x0e\x00\x00\x01"
	"\x37\x00\x08\x4d\x53\x46\x54\x20\x35\x2e\x30\x00\x06\x00\x08\x00"
	"\x18\x00\x17\x00\x11\x00\x27";

  CTX_SET(ctx, packet);

  struct pair bpf_ret_value = {0, 0}; 
  g_stream_map_lookup_value = &bpf_ret_value;

  bpf_map_lookup_elem = bpf_map_lookup_elem_stream_mock_v6;
  struct flowv6_keys *key = &g_stream_map_v6_lookup_keys;

  int result = xdp_loadfilter(ctx);
  assert(result == XDP_DROP);

  assert(key->ip_proto == 0);
  assert(memcmp(key->src, "\xfe\x80\x00\x00\x00\x00\x00\x00\x35\xd0\xb3\x9e\xc3\xf7\xe2\x0f", 16) == 0);
  assert(memcmp(key->dst, "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02", 16) == 0);
  assert(key->port16[0] == 0x2202);
  assert(key->port16[1] == 0x2302);
  assert(key->ip_proto == 0);
  assert(key->vlan0 == 0);
  assert(key->vlan1 == 0);

#ifdef DEBUG
  // Thanks, copilot! (Also, too many args for DPRINTF.)
  printf("key->ip_proto: %d, key->src: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x, key->dst: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x, key->port16[0]: %x, key->port16[1]: %x, key->vlan0: %x, key->vlan1: %x\n",
          key->ip_proto,
          ntohs(key->src[0] & 0xffff), ntohs((key->src[0] >> 16) & 0xffff), ntohs(key->src[1] & 0xffff), ntohs((key->src[1] >> 16) & 0xffff),
          ntohs(key->src[2] & 0xffff), ntohs((key->src[2] >> 16) & 0xffff), ntohs(key->src[3] & 0xffff), ntohs((key->src[3] >> 16) & 0xffff),
          ntohs(key->dst[0] & 0xffff), ntohs((key->dst[0] >> 16) & 0xffff), ntohs(key->dst[1] & 0xffff), ntohs((key->dst[1] >> 16) & 0xffff),
          ntohs(key->dst[2] & 0xffff), ntohs((key->dst[2] >> 16) & 0xffff), ntohs(key->dst[3] & 0xffff), ntohs((key->dst[3] >> 16) & 0xffff),
          ntohs(key->port16[0]), ntohs(key->port16[1]), key->vlan0, key->vlan1);
#endif

  // Not necessary right now, but will probably save me a headache later.
  bpf_map_lookup_elem = bpf_map_lookup_elem_stream_mock_v4;
}

int main() {
  setup_mocks();
  bpf_map_lookup_elem = bpf_map_lookup_elem_stream_mock_v4;

  // And our fake 32-bit addressable environment...
  struct xdp_md ctx;
  g_TopOfStack = HIGH32(&ctx);

  TEST(ipv4_match);
  TEST(gre_match);
  TEST(IEEE8021ah_packet_vlan);
  TEST(no_match);
  TEST(ipv6);

  return 0;
}