/**
 * @file
 * @author Shivani Bhardwaj <shivani@oisf.net>
 * fuzz target for DecodeBase64
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-base64.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

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

#define BIT_SHIFT_SIZE 24
#define BLK_SIZE       4
#define BYTE_SIZE      8

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
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

    uint8_t shift = 0;
    uint32_t dest_size = 0;
    if (size > BLK_SIZE)
        shift = BIT_SHIFT_SIZE;
    else
        shift = BYTE_SIZE * (uint8_t)(size - 1);

    for (size_t i = 0; i < size; i++) {
        if (i == BLK_SIZE)
            break;
        dest_size |= (uint32_t)(data[i] << shift);
        shift -= BYTE_SIZE;
    }

    Base64FuzzTest(data, size, dest_size);

    return 0;
}
