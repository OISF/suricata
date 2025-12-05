/**
 * @file
 * @author Shivani Bhardwaj <shivani@oisf.net>
 * fuzz target for DecodeBase64
 */

#include "suricata-common.h"
#include "suricata.h"
#include "rust.h"
#include "nallocinc.c"

#define BLK_SIZE 2

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int initialized = 0;

static void Base64FuzzTest(const uint8_t *src, size_t len)
{
    uint32_t decoded_len = SCBase64DecodeBufferSize((uint32_t)len);
    uint8_t *decoded = SCCalloc(decoded_len, sizeof(uint8_t));

    for (uint8_t mode = SCBase64ModeRFC2045; mode <= SCBase64ModeStrict; mode++) {
        (void)SCBase64Decode(src, len, mode, decoded);
    }

    SCFree(decoded);
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
        nalloc_init(NULL);
        // do not restrict nalloc
        initialized = 1;
    }

    if (size < BLK_SIZE)
        return 0;

    nalloc_start(data, size);
    Base64FuzzTest(data, size);
    nalloc_end();

    return 0;
}
