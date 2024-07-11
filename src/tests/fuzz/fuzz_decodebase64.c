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
    Base64Decoded *b64d = NULL;
    for (uint8_t mode = Base64ModeRFC2045; mode <= Base64ModeStrict; mode++) {
        b64d = rs_base64_decode(src, len, 0, mode);
    }

    if (b64d != NULL)
        rs_base64_decode_free(b64d);
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
