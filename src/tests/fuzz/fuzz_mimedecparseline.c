/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for ConfYamlLoadString
 */


#include "suricata-common.h"
#include "util-decode-mime.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int initialized = 0;
static int dummy = 0;

static int MimeParserDataFromFileCB(const uint8_t *chunk, uint32_t len,
                                    MimeDecParseState *state)
{
    if (len > 0 && chunk[len-1] == 0) {
        // do not get optimizd away
        dummy++;
    }
    return MIME_DEC_OK;
}

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

    uint32_t line_count = 0;

    MimeDecParseState *state = MimeDecInitParser(&line_count, MimeParserDataFromFileCB);
    MimeDecEntity *msg_head = state->msg;
    const uint8_t * buffer = data;
    while (1) {
        uint8_t * next = memchr(buffer, '\n', size);
        if (next == NULL) {
            if (state->state_flag >= BODY_STARTED)
                (void)MimeDecParseLine(buffer, size, 0, state);
            break;
        } else {
            (void) MimeDecParseLine(buffer, next - buffer, 1, state);
            if (buffer + size < next + 1) {
                break;
            }
            size -= next - buffer + 1;
            buffer = next + 1;
        }
    }
    /* Completed */
    (void)MimeDecParseComplete(state);
    /* De Init parser */
    MimeDecDeInitParser(state);
    MimeDecFreeEntity(msg_head);

    return 0;
}
