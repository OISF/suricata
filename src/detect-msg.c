/* MSG part of the detection engine. */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

int DetectMsgSetup (Signature *s, SigMatch *m, char *msgstr);

void DetectMsgRegister (void) {
    sigmatch_table[DETECT_MSG].name = "msg";
    sigmatch_table[DETECT_MSG].Match = NULL;
    sigmatch_table[DETECT_MSG].Setup = DetectMsgSetup;
    sigmatch_table[DETECT_MSG].Free = NULL;
    sigmatch_table[DETECT_MSG].RegisterTests = NULL;
}

int DetectMsgSetup (Signature *s, SigMatch *m, char *msgstr)
{
    char *str = msgstr;
    char dubbed = 0;

    /* strip "'s */
    if (msgstr[0] == '\"' && msgstr[strlen(msgstr)-1] == '\"') {
        str = strdup(msgstr+1);
        str[strlen(msgstr)-2] = '\0';
        dubbed = 1;
    }

    s->msg = strdup(str);

    if (dubbed) free(str);
    return 0;
}

