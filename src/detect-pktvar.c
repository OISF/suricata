/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the pktvar keyword
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "threads.h"
#include "pkt-var.h"
#include "detect-pktvar.h"
#include "util-spm.h"
#include "util-debug.h"

#define PARSE_REGEX         "(.*),(.*)"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectPktvarMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectPktvarSetup (DetectEngineCtx *, Signature *, char *);

void DetectPktvarRegister (void)
{
    sigmatch_table[DETECT_PKTVAR].name = "pktvar";
    sigmatch_table[DETECT_PKTVAR].Match = DetectPktvarMatch;
    sigmatch_table[DETECT_PKTVAR].Setup = DetectPktvarSetup;
    sigmatch_table[DETECT_PKTVAR].Free  = NULL;
    sigmatch_table[DETECT_PKTVAR].RegisterTests  = NULL;

    sigmatch_table[DETECT_PKTVAR].flags |= SIGMATCH_PAYLOAD;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    return;

error:
    return;
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectPktvarMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectPktvarData *pd = (const DetectPktvarData *)ctx;

    PktVar *pv = PktVarGet(p, pd->name);
    if (pv != NULL) {
        uint8_t *ptr = SpmSearch(pv->value, pv->value_len, pd->content, pd->content_len);
        if (ptr != NULL)
            ret = 1;
    }

    return ret;
}

static int DetectPktvarSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    DetectPktvarData *cd = NULL;
    SigMatch *sm = NULL;
    char *str = rawstr;
    char dubbed = 0;
    uint16_t len;
    char *varname = NULL, *varcontent = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "\"%s\" is not a valid setting for pktvar.", rawstr);
        return -1;

    }

    const char *str_ptr;
    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        return -1;
    }
    varname = (char *)str_ptr;

    if (ret > 2) {
        res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            return -1;
        }
        varcontent = (char *)str_ptr;
    }

    SCLogDebug("varname %s, varcontent %s", varname, varcontent);

    if (varcontent[0] == '\"' && varcontent[strlen(varcontent)-1] == '\"') {
        str = SCStrdup(varcontent+1);
        if (unlikely(str == NULL)) {
            return -1;
        }
        str[strlen(varcontent)-2] = '\0';
        dubbed = 1;
    }

    len = strlen(str);
    if (len == 0) {
        if (dubbed) SCFree(str);
        return -1;
    }

    cd = SCMalloc(sizeof(DetectPktvarData));
    if (unlikely(cd == NULL))
        goto error;

    char converted = 0;

    {
        uint16_t i, x;
        uint8_t bin = 0, binstr[3] = "", binpos = 0;
        for (i = 0, x = 0; i < len; i++) {
            // printf("str[%02u]: %c\n", i, str[i]);
            if (str[i] == '|') {
                if (bin) {
                    bin = 0;
                } else {
                    bin = 1;
                }
            } else {
                if (bin) {
                    if (isdigit((unsigned char)str[i]) ||
                        str[i] == 'A' || str[i] == 'a' ||
                        str[i] == 'B' || str[i] == 'b' ||
                        str[i] == 'C' || str[i] == 'c' ||
                        str[i] == 'D' || str[i] == 'd' ||
                        str[i] == 'E' || str[i] == 'e' ||
                        str[i] == 'F' || str[i] == 'f') {
                        // printf("part of binary: %c\n", str[i]);

                        binstr[binpos] = (char)str[i];
                        binpos++;

                        if (binpos == 2) {
                            uint8_t c = strtol((char *)binstr, (char **) NULL, 16) & 0xFF;
                            binpos = 0;
                            str[x] = c;
                            x++;
                            converted = 1;
                        }
                    } else if (str[i] == ' ') {
                        // printf("space as part of binary string\n");
                    }
                } else {
                    str[x] = str[i];
                    x++;
                }
            }
        }
#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        for (i = 0; i < x; i++) {
            if (isprint((unsigned char)str[i])) printf("%c", str[i]);
            else printf("\\x%02u", str[i]);
        }
        printf("\n");
    }
#endif

        if (converted)
            len = x;
    }

    cd->content = SCMalloc(len);
    if (cd->content == NULL) {
        SCFree(cd);
        if (dubbed) SCFree(str);
        return -1;
    }

    cd->name = SCStrdup(varname);
    if (cd->name == NULL) {
        SCFree(cd);
        if (dubbed) SCFree(str);
        return -1;
    }

    memcpy(cd->content, str, len);
    cd->content_len = len;
    cd->flags = 0;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_PKTVAR;
    sm->ctx = (SigMatchCtx *)cd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    if (dubbed) SCFree(str);
    return 0;

error:
    if (dubbed)
        SCFree(str);
    if (cd) {
        if (cd->name)
            SCFree(cd->name);
        SCFree(cd);
    }
    if (sm)
        SCFree(sm);
    return -1;
}


