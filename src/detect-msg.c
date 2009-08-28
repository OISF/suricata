/* MSG part of the detection engine. */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

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
        return -1;
    }

    s->msg = strdup(str);

    free(str);
    return 0;
}

