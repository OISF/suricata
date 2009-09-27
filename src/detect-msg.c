/* MSG part of the detection engine. */

#include "eidps-common.h"
#include "detect.h"
#include "util-debug.h"

int DetectMsgSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *msgstr);

void DetectMsgRegister (void) {
    sigmatch_table[DETECT_MSG].name = "msg";
    sigmatch_table[DETECT_MSG].Match = NULL;
    sigmatch_table[DETECT_MSG].Setup = DetectMsgSetup;
    sigmatch_table[DETECT_MSG].Free = NULL;
    sigmatch_table[DETECT_MSG].RegisterTests = NULL;
}

int DetectMsgSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *msgstr)
{
    char *str = NULL;
    uint16_t len;

    if (strlen(msgstr) == 0)
        goto error;

    /* strip "'s */
    if (msgstr[0] == '\"' && msgstr[strlen(msgstr)-1] == '\"') {
        str = strdup(msgstr+1);
        str[strlen(msgstr)-2] = '\0';
    } else if (msgstr[1] == '\"' && msgstr[strlen(msgstr)-1] == '\"') {
        /* XXX do this parsing in a better way */
        str = strdup(msgstr+2);
        str[strlen(msgstr)-3] = '\0';
        //printf("DetectMsgSetup: format hack applied: \'%s\'\n", str);
    } else {
        printf("DetectMsgSetup: format error \'%s\'\n", msgstr);
        goto error;
    }

    len = strlen(str);
    if (len == 0)
        goto error;

    char converted = 0;

    {
        uint16_t i, x;
        uint8_t escape = 0;

        for (i = 0, x = 0; i < len; i++) {
            //printf("str[%02u]: %c\n", i, str[i]);
            if(!escape && str[i] == '\\') {
                escape = 1;
            } else if (escape) {
                if (str[i] == ':' ||
                        str[i] == ';' ||
                        str[i] == '\\' ||
                        str[i] == '\"')
                {
                    str[x] = str[i];
                    x++;
                } else {
                    printf("Can't escape %c\n", str[i]);
                    goto error;
                }

                escape = 0;
                converted = 1;
            } else {
                str[x] = str[i];
                x++;
            }
        }
#if 0 //def DEBUG
        if (SCLogDebugEnabled()) {
            for (i = 0; i < x; i++) {
                printf("%c", str[i]);
            }
            printf("\n");
        }
#endif

        if (converted) {
            len = x;
        }
    }

    s->msg = strdup(str);

    free(str);
    return 0;

error:
    free(str);
    return -1;
}
