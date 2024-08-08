/**
 * @file
 * @author Shivani Bhardwaj <shivani@oisf.net>
 * fuzz target for DecodeBase64
 */

#include "suricata-common.h"
#include "suricata.h"
#include "rust.h"

#define BLK_SIZE 2

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int initialized = 0;

static void Base64FuzzTest(const uint8_t *src, size_t len)
{
    uint8_t decoded[len];
    uint32_t num_decoded = 0;

    for (uint8_t mode = Base64ModeRFC2045; mode <= Base64ModeStrict; mode++) {
        (void)Base64Decode(src, len, 0, mode, decoded, &num_decoded);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (initialized == 0) {
        // Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);
        // global init
        InitGlobal();
        SCRunmodeSet(RUNMODE_UNITTEST);
        initialized = 1;
    }

    if (size < BLK_SIZE)
        return 0;

    Base64FuzzTest(data, size);

    return 0;
}
