/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for ConfYamlLoadString
 */


#include "suricata-common.h"
#include "suricata.h"
#include "rust.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (initialized == 0) {
        //Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);
        //global init
        InitGlobal();
        run_mode = RUNMODE_UNITTEST;
        initialized = 1;
    }

    uint32_t events;
    FileContainer *files = FileContainerAlloc();
    MimeStateSMTP *state = rs_mime_smtp_state_init(files);
    const uint8_t * buffer = data;
    while (1) {
        uint8_t * next = memchr(buffer, '\n', size);
        if (next == NULL) {
            if (rs_mime_smtp_get_state(state) >= MimeSmtpBody)
                (void)rs_smtp_mime_parse_line(buffer, size, 0, &events, state);
            break;
        } else {
            (void)rs_smtp_mime_parse_line(buffer, next - buffer, 1, &events, state);
            if (buffer + size < next + 1) {
                break;
            }
            size -= next - buffer + 1;
            buffer = next + 1;
        }
    }
    /* Completed */
    (void)rs_smtp_mime_complete(state, &events);
    /* De Init parser */
    rs_mime_smtp_state_free(state);
    FileContainerFree(files);

    return 0;
}
