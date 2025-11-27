/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for SCConfYamlLoadString
 */

#include "suricata-common.h"
#include "suricata.h"
#include "rust.h"
#include "nallocinc.c"

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
        SCRunmodeSet(RUNMODE_UNITTEST);
        nalloc_init(NULL);
        // do not restrict nalloc
        initialized = 1;
    }

    uint32_t events;
    FileContainer *files = FileContainerAlloc();
    StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;
    MimeStateSMTP *state = SCMimeSmtpStateInit(files, &sbcfg);
    const uint8_t * buffer = data;
    nalloc_start(data, size);
    while (1) {
        uint8_t * next = memchr(buffer, '\n', size);
        if (next == NULL) {
            if (SCMimeSmtpGetState(state) >= MimeSmtpBody)
                (void)SCSmtpMimeParseLine(buffer, (uint32_t)size, 0, &events, state);
            break;
        } else {
            (void)SCSmtpMimeParseLine(buffer, (uint32_t)(next - buffer), 1, &events, state);
            if (buffer + size < next + 1) {
                break;
            }
            size -= next - buffer + 1;
            buffer = next + 1;
        }
    }
    /* Completed */
    (void)SCSmtpMimeComplete(state);
    /* De Init parser */
    SCMimeSmtpStateFree(state);
    FileContainerFree(files, &sbcfg);
    nalloc_end();

    return 0;
}
