/* CLASSTYPE part of the detection engine. */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

int DetectClasstypeSetup (Signature *s, SigMatch *m, char *str);

void DetectClasstypeRegister (void) {
    sigmatch_table[DETECT_CLASSTYPE].name = "classtype";
    sigmatch_table[DETECT_CLASSTYPE].Match = NULL;
    sigmatch_table[DETECT_CLASSTYPE].Setup = DetectClasstypeSetup;
    sigmatch_table[DETECT_CLASSTYPE].Free  = NULL;
    sigmatch_table[DETECT_CLASSTYPE].RegisterTests = NULL;
}

int DetectClasstypeSetup (Signature *s, SigMatch *m, char *rawstr)
{
    char *str = rawstr;
    char dubbed = 0;

    /* strip "'s */
    if (rawstr[0] == '\"' && rawstr[strlen(rawstr)-1] == '\"') {
        str = strdup(rawstr+1);
        str[strlen(rawstr)-2] = '\0';
        dubbed = 1;
    }

    /* XXX */

    if (dubbed) free(str);
    return 0;
}

