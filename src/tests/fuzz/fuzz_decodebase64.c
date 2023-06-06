/**
 * @file
 * @author Shivani Bhardwaj <shivani@oisf.net>
 * fuzz target for DecodeBase64
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-base64.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size, size_t dest_size);

static int initialized = 0;

static void Base64FuzzTest(const uint8_t *src, size_t len, size_t dest_size)
{
    for (uint8_t mode = BASE64_MODE_RELAX; mode <= BASE64_MODE_RFC4648; mode++) {
        uint8_t *dest = malloc(dest_size);
        uint32_t consumed_bytes = 0;
        uint32_t decoded_bytes = 0;

        DecodeBase64(dest, dest_size, src, len, &consumed_bytes, &decoded_bytes, mode);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size, size_t dest_size)
{
    if (initialized == 0) {
        // Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);
        // global init
        InitGlobal();
        run_mode = RUNMODE_UNITTEST;
        initialized = 1;
    }

    Base64FuzzTest(data, size, dest_size);

    return 0;
}
