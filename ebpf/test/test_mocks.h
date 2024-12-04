#ifndef __EBPF_TEST_MOCKS__
#define __EBPF_TEST_MOCKS__

#include "../xdp_stream_filter_common.h" // for struct flowv4_keys

/**
 * Includes a set of mocks to assist in testing XDP programs.
 */

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

// This version of bpf_map_lookup_elem_mock is used by xdp_lb.test.c
void* bpf_map_lookup_elem_lb_mock(void* map, void* key) {
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

// Used by bpf_map_lookup_elem_stream_mock below to store the supplied keys
// for later assertions, and to allow the test to set the return value.
struct flowv4_keys g_stream_map_v4_lookup_keys;
void* g_stream_map_lookup_value = NULL; // This is set by the test.

// This version is used by xdp_stream.test.c
void* bpf_map_lookup_elem_stream_mock_v4(void* map, void* key) {
	// Make a copy of the key so the test can check it after the call finishes.
	memcpy(&g_stream_map_v4_lookup_keys, key, sizeof(struct flowv4_keys));
	return g_stream_map_lookup_value;
}

struct flowv6_keys g_stream_map_v6_lookup_keys;
void* bpf_map_lookup_elem_stream_mock_v6(void* map, void* key) {
	memcpy(&g_stream_map_v6_lookup_keys, key, sizeof(struct flowv6_keys));
	return g_stream_map_lookup_value;
}

int bpf_redirect_map_mock(void* map, int key, int flags) {
	// I assume the kernel does something similar... but it really doesn't matter; we
	// just need a way to encode the unique CPU and the fact that it's a redirect (not a
	// PASS, ABORT, etc) in the same result...
	return (key << 16) + XDP_REDIRECT;
}

void setup_mocks() {
  // setup our mocks...
  bpf_xdp_adjust_head = bpf_xdp_adjust_head_mock;
  bpf_redirect_map = bpf_redirect_map_mock;
  bpf_trace_printk = test_trace_hook;
}

#endif
