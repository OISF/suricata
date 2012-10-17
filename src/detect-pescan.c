/* Copyright (C) 2012 BAE Systems
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
 * \author David Abarbanel <david.abarbanel@baesystems.com>
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-pescan.h"
#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"

#include "stream-tcp.h"

#include "detect-pescan.h"
#include "libpescan.h"

/* Constants */
#define EPSILON            0.00000001
#define PESCAN_KEYWORD     "pescan"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]*\\.?[0-9]*)?\\s*(=|[<>-]=?)?\\s*((?:[0-9]+\\.?|\\.)[0-9]*)?\\s*$"

/* Static regex pointers */
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* Prototypes */
static int DetectPescanMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *,
        uint8_t, File *, Signature *, SigMatch *);
static int DetectPescanSetup (DetectEngineCtx *, Signature *, char *);
static void DetectPescanFree(void *);
static void DetectPescanRegisterTests(void);

/**
 * \brief Registration function for rule keyword: pescan
 *
 * This registers all the callback functions needed to manage
 * the workflow of the detection engine whenever the 'pescan'
 * keyword is invoked by a rule.
 */
void DetectPescanRegister(void) {
    sigmatch_table[DETECT_PESCAN].name = PESCAN_KEYWORD;
    sigmatch_table[DETECT_PESCAN].Match = NULL;
    sigmatch_table[DETECT_PESCAN].FileMatch = DetectPescanMatch;
    sigmatch_table[DETECT_PESCAN].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_PESCAN].Setup = DetectPescanSetup;
    sigmatch_table[DETECT_PESCAN].Free  = DetectPescanFree;
    sigmatch_table[DETECT_PESCAN].RegisterTests = DetectPescanRegisterTests;

    /* Init regex */
    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %"
                PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    SCLogDebug("registering pescan rule keyword");

    return;

error:
    if (parse_regex != NULL) SCFree(parse_regex);
    if (parse_regex_study != NULL) SCFree(parse_regex_study);
    return;
}

/**
 * \brief Compare two floating point double-precision numbers using EPSILON value
 * for handling margin of error
 *
 * \param a left side floating point number
 * \param b right side floating point number
 *
 * \retval 1 if a > b
 * \retval 0 if a == b
 * \retval -1 if a < b
 */
static int DblCmp(double a, double b) {

    int ret = 0;

    /* A > B */
    if (a - b > EPSILON) {
        ret = 1;

    } else if (b - a > EPSILON) {
        ret = -1;
    }

    /* Otherwise A == B */
    return ret;
}

/**
 * \brief Check whether a PE score matches the rule options
 *
 * \param pedata Rule option data
 * \param peattrib Structure containing the PE score
 *
 * \retval 1 if the score is a match
 * \retval 0 if the score is not a match
 */
static int CheckScoreMatch (DetectPescanData *pedata, peattrib_t *peattrib) {

    int match = 0;

    /* Now check if there is a score check required or not */
    switch (pedata->mode) {
    case DETECT_PESCAN_ANY:
        SCLogDebug("Match on any");
        match = 1;
        break;

    case DETECT_PESCAN_LT:
        SCLogDebug("Match on LT");
        match = (DblCmp(peattrib->pescore, pedata->score1) == -1);
        break;

    case DETECT_PESCAN_LTEQ:
        SCLogDebug("Match on LTEQ");
        match = (DblCmp(peattrib->pescore, pedata->score1) <= 0);
        break;

    case DETECT_PESCAN_EQ:
        SCLogDebug("Match on EQ");
        match = (DblCmp(peattrib->pescore, pedata->score1) == 0);
        break;

    case DETECT_PESCAN_GT:
        SCLogDebug("Match on GT");
        match = (DblCmp(peattrib->pescore, pedata->score1) == 1);
        break;

    case DETECT_PESCAN_GTEQ:
        SCLogDebug("Match on GTEQ");
        match = (DblCmp(peattrib->pescore, pedata->score1) >= 0);
        break;

    case DETECT_PESCAN_RA:
        SCLogDebug("Match on RA");
        match = (DblCmp(peattrib->pescore, pedata->score1) == 1 &&
                DblCmp(peattrib->pescore, pedata->score2) == -1);
        break;

    case DETECT_PESCAN_RAEQ:
        SCLogDebug("Match on RAEQ");
        match = (DblCmp(peattrib->pescore, pedata->score1) >= 0 &&
                DblCmp(peattrib->pescore, pedata->score2) <= 0);
        break;

    default:
        SCLogInfo("Invalid comparison mode");
        break;
    }

    return match;
}

/**
 * \brief match the specified pescan search (match occurs when
 * PE found and if score comparison is a match)
 *
 * A match occurs either when the 'pescan' keyword is chosen
 * without any options and a PE file is detected by the PE
 * scanner or when the keyword options (floating point score comparisons) are
 * selected and the PE Score matches the specified criteria.
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param f pointer to the current flow
 * \param flags bitwise flow flags
 * \param state pointer to the application layer state object
 * \param s pointer to the full rule signature
 * \param m pointer to the sigmatch that we will cast into DetectPescanData
 *
 * \retval 0 no match
 * \retval 1 match
 *
 * \todo when we start supporting more protocols, the logic in this function
 *       needs to be put behind a api.
 */
static int DetectPescanMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, File *file, Signature *s, SigMatch *m)
{
    SCEnter();

    int ret, pefound = 0, match = 0;
    DetectPescanData *pedata = NULL;

    /* Ensure basic file criteria is met */
    if (file == NULL) {
        SCLogDebug("File is NULL");
        SCReturnInt(0);
    }

    /* If file already scanned, don't scan again */
    if (file->peattrib != NULL) {
        pefound = 1;
    } else if (!(file->pescan_flags & PEFILE_SCANNED)) {
        /* Scan the file */
        ret = PEScanFile(file);
        if (ret != PE_NOT_PE && ret != PE_INDETERMINATE) {
            pefound = 1;
        }
    }

    if (pefound) {
        /* Get rule options from context */
        pedata = (DetectPescanData *) m->ctx;
        if (pedata == NULL) {
            goto error;
        }

        /* Now check if there is a match in the score */
        match = CheckScoreMatch(pedata, file->peattrib);
        if (match == 0) {
            SCLogDebug("PE does not match rule signature");
        } else {
            SCLogInfo("PE matches rule signature");
        }
    }

    /* Return with the match flag */
    SCReturnInt(match);

error:
    if (file->peattrib != NULL) {
        SCFree(file->peattrib);
    }
    file->peattrib = NULL;
    SCReturnInt(0);
}

/**
 * \brief Parse the pescan keyword for options
 *
 * Valid options are formatted as (pescan: [float_score1][oper][float_score2];)
 *
 * Valid operators are as follows:
 * <   less than (eg. <3.0)
 * <=  less than or equal to (eg. <=3.0)
 * >   greater than (eg. >0.0)
 * >=  greater than or equal to (eg. >=1.0)
 * =   equal to (eg. =2.0 or 2.0 if ommitted)
 * -   range excluding (eg. 1.0-5.0)
 * -=  range including (eg. 1.0-=5.0)
 *
 * If no arguments are specified, then all PE scores will be considered a match
 * for the rule.
 * A value without an operator is treated as the 'equal to' operator
 *
 * \param str Pointer to the user provided option (null or zero-length string is allowed)
 *
 * \retval pointer to DetectPescanData on success
 * \retval NULL on failure
 */
static DetectPescanData *DetectPescanParse (char *str) {

    DetectPescanData *pedata = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    /* Always return a structure on success */
    pedata = SCMalloc(sizeof(DetectPescanData));
    if (unlikely(pedata == NULL))
        goto error;
    memset(pedata, 0x00, sizeof(DetectPescanData));

    /* Process any options (pescan:[score1][operator][score2])
     * - default is to match on any PE regardless of score */
    if (str != NULL && str[0] != 0) {
        SCLogDebug("str %s", str);

        /* Capture 3 possible arguments from the regular expression match */
        ret = pcre_exec(parse_regex, parse_regex_study, str, strlen(str),
                0, 0, ov, MAX_SUBSTRINGS);
        if (ret < 2 || ret > 4) {
            SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
            goto error;
        }
        const char *str_ptr;

        /* Extract first argument */
        res = pcre_get_substring((char *) str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg1 = (char *) str_ptr;
        SCLogDebug("Arg1 \"%s\"", arg1);

        if (ret >= 3) {
            /* Extract second argument */
            res = pcre_get_substring((char *) str, ov, MAX_SUBSTRINGS, 2, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            arg2 = (char *) str_ptr;
            SCLogDebug("Arg2 \"%s\"", arg2);

            if (ret >= 4) {
                /* Extract third argument */
                res = pcre_get_substring((char *) str, ov, MAX_SUBSTRINGS, 3, &str_ptr);
                if (res < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }
                arg3 = (char *) str_ptr;
                SCLogDebug("Arg3 \"%s\"", arg3);
            }
        }

        /* Found an operator */
        if (arg2 != NULL && arg2[0] != 0) {

            /* Must have a 3rd argument */
            if (arg3 == NULL || arg3[0] == 0)
                goto error;


            /* Parse out the operators */
            switch (arg2[0]) {
            case '<':

                /* Must not have arg1 */
                if (arg1 != NULL && arg1[0] != 0)
                    goto error;

                if (arg2[1] == '=') {
                    pedata->mode = DETECT_PESCAN_LTEQ;
                } else {
                    pedata->mode = DETECT_PESCAN_LT;
                }
                pedata->score1 = atof(arg3);

                SCLogDebug("score1 is %f", pedata->score1);
                break;
            case '>':

                /* Must not have arg1 */
                if (arg1 != NULL && arg1[0] != 0)
                    goto error;

                if (arg2[1] == '=') {
                    pedata->mode = DETECT_PESCAN_GTEQ;
                } else {
                    pedata->mode = DETECT_PESCAN_GT;
                }
                pedata->score1 = atof(arg3);

                SCLogDebug("score1 is %f",pedata->score1);
                break;
            case '-':

                /* Must have arg1 */
                if (arg1 == NULL || arg1[0] == 0)
                    goto error;

                if (arg2[1] == '=') {
                    pedata->mode = DETECT_PESCAN_RAEQ;
                } else {
                    pedata->mode = DETECT_PESCAN_RA;
                }
                pedata->score1 = atof(arg1);
                pedata->score2 = atof(arg3);
                SCLogDebug("score ra is %f to %f", pedata->score1, pedata->score2);
                if (pedata->score1 >= pedata->score2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid pescore range. ");
                    goto error;
                }
                break;

            case '=':

                /* Must not have arg1 */
                if (arg1 != NULL && arg1[0] != 0)
                    goto error;

                pedata->mode = DETECT_PESCAN_EQ;
                pedata->score1 = atof(arg1);

                SCLogDebug("score1 is %f",pedata->score1);
                break;

            default:

                SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid pescore operator. ");
                goto error;
                break;
            }
        } else {
            /* No operator found so default to EQ */
            pedata->mode = DETECT_PESCAN_EQ;

            /* Must have arg1 but not arg3 */
            if (arg1 == NULL || arg1[0] == 0 || (arg3 != NULL && arg3[0] != 0))
                goto error;

            pedata->score1 = atof(arg1);
            SCLogDebug("score1 is %f", pedata->score1);
        }
    } else {
        /* Default is to match on any score */
        pedata->mode = DETECT_PESCAN_ANY;
    }

    if (arg1) SCFree(arg1);
    if (arg2) SCFree(arg2);
    if (arg3) SCFree(arg3);

    return pedata;

error:
    DetectPescanFree(pedata);
    if (arg1) SCFree(arg1);
    if (arg2) SCFree(arg2);
    if (arg3) SCFree(arg3);
    return NULL;
}

/**
 * \brief Sets up the signature matching context
 *
 * Set up involves creating a signature matching data structure
 * that holds the rule options.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the current rule Signature
 * \param str pointer to the user provided "pescan" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectPescanSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SCEnter();

    DetectPescanData *pedata = NULL;
    SigMatch *sm = NULL;

    /* Init Sig match data structure */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->type = DETECT_PESCAN;

    /* Parse options and store in context (null is not acceptable) */
    pedata = DetectPescanParse(str);
    if (pedata == NULL) {
        goto error;
    }
    sm->ctx = pedata;

    /* Notify this is a special file matching detector */
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_FILEMATCH);

    /* TODO: This should probably be removed */
    AppLayerHtpNeedFileInspection();

    /* Set relevant file flags */
    s->file_flags |= (FILE_SIG_NEED_FILE | FILE_SIG_NEED_FILECONTENT);

    /* Set crucial flag that enables file storing / file content extraction */
    s->flags |= (SIG_FLAG_PESCAN);

    SCReturnInt(0);

    /* All error conditions go through here */
error:
    DetectPescanFree(pedata);
    if (sm != NULL)
        SCFree(sm);
    SCReturnInt(-1);
}

/**
 * \brief Free DetectPescanData pointer if non-NULL
 *
 * \param ptr pointer to the DetectPescsanData structure
 *
 */
static void DetectPescanFree(void *ptr) {
    if (ptr != NULL) {
        SCFree(ptr);
    }
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectPescanTest01
 */
int DetectPescanTest01(void){
    int result = 0;

    char data[] = "\x4D\x5A\x00\x00\x50\x45\x00\x00\x4C\x01\x01\x00\x6A\x2A\x58"
            "\xC3\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x03\x01\x0B\x01\x08\x00"
            "\x01\x00\x00\x80\x00\x00\x00\x00\x79\x00\x00\x00\x0C\x00\x00\x00\x79"
            "\x00\x00\x00\x0C\x00\x00\x00\x00\x00\x40\x00\x04\x00\x00\x00\x04\x00"
            "\x00\x00\x74\x00\x00\x00\x20\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00"
            "\x00\x04\x01\x00\x00\x88\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5C"
            "\x5C\x36\x36\x2E\x39\x33\x2E\x36\x38\x2E\x36\x5C\x7A\x00\x00\x38";
    peattrib_t *peattrib = NULL;
    uint32_t dlen = sizeof(data);

    peattrib = SCMalloc(sizeof(peattrib_t));
    memset(peattrib, 0x00, sizeof(peattrib_t));

    result = pescan(peattrib, (unsigned char *)data, dlen, SCLogDebugEnabled());

    return result;
}


/**
 *  \brief Tests to determine if the File data structure is being read properly.
 *  \test DetectPescanMatchTest01
 */
int DetectPescanMatchTest01(void){
    int result = 0;

    FileData *file_data;
    file_data = SCMalloc(sizeof(FileData));
    char data[] = "\x4D\x5A\x00\x00\x50\x45\x00\x00\x4C\x01\x01\x00\x6A\x2A\x58"
            "\xC3\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x03\x01\x0B\x01\x08\x00"
            "\x01\x00\x00\x80\x00\x00\x00\x00\x79\x00\x00\x00\x0C\x00\x00\x00\x79"
            "\x00\x00\x00\x0C\x00\x00\x00\x00\x00\x40\x00\x04\x00\x00\x00\x04\x00"
            "\x00\x00\x74\x00\x00\x00\x20\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00"
            "\x00\x04\x01\x00\x00\x88\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5C"
            "\x5C\x36\x36\x2E\x39\x33\x2E\x36\x38\x2E\x36\x5C\x7A\x00\x00\x38";
    file_data->data = (uint8_t *)data;
    file_data->len = sizeof(data);
    file_data->next = NULL;

    File *file;
    file = SCMalloc(sizeof(File));
    file->flags = 0;
    file->chunks_head = file_data;
    file->size = file_data->len;
    char file_name[] = "test.exe";
    file->name = (uint8_t *)file_name;
    file->name_len = sizeof(file_name);
    file->pescan_flags = 0;
    file->peattrib = NULL;
    file->next = NULL;

    ThreadVars *t = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow *f = NULL;
    uint8_t flags = 0;
    Signature *s = NULL;
    SigMatch *m = NULL;

    m = SCMalloc(sizeof(SigMatch));
    memset(m, 0, sizeof(SigMatch));

    DetectPescanData *pedata = SCMalloc(sizeof(DetectPescanData));
    memset(pedata, 0, sizeof(DetectPescanData));
    pedata->mode = DETECT_PESCAN_ANY;

    m->ctx = pedata;

    result = DetectPescanMatch(t, det_ctx,f, flags, file, s, m);

    SCFree(file_data);
    SCFree(file);
    SCFree(pedata);
    SCFree(m);

    return result;
}

/**
 *    \brief Tests to determine if the File chunck reader
 *
 */
int DetectPescanMatchTest02(void){
    int result = 0;

    FileData *file_data=NULL, *tmp=NULL;
    char *data[] = {"\x4D\x5A\x00\x00\x50\x45\x00\x00\x4C\x01\x01\x00",
            "\x6A\x2A\x58\xC3\x00\x00\x00\x00\x00\x00\x00\x00\x04",
            "\x00\x03\x01\x0B\x01\x08\x00\x01\x00\x00\x80\x00\x00",
            "\x00\x00\x79\x00\x00\x00\x0C\x00\x00\x00\x79\x00\x00",
            "\x00\x0C\x00\x00\x00\x00\x00\x40\x00\x04\x00\x00\x00",
            "\x04\x00\x00\x00\x74\x00\x00\x00\x20\x00\x00\x00\x04",
            "\x00\x00\x00\x00\x00\x00\x00\x04\x01\x00\x00\x88\x00",
            "\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00",
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            "\x5C\x5C\x36\x36\x2E\x39\x33\x2E\x36\x38\x2E\x36\x5C",
            "\x7A\x00\x00\x38"};
    int i = 0;
    File *file;
    file = SCMalloc(sizeof(File));

    if(file_data == NULL){
        file_data = SCMalloc(sizeof(FileData));
        tmp = file_data;
        tmp->data = (uint8_t *)data[i];
        tmp->len = 12;
        file->size += tmp->len;
        tmp->next = NULL;
        i++;
    }

    do{
        tmp->next = SCMalloc(sizeof(FileData));
        tmp = tmp->next;
        tmp->data = (uint8_t *)data[i];
        if(i < 10){
            tmp->len = 13;
        } else {
            tmp->len = 4;
        }
        file->size += tmp->len;
        tmp->next = NULL;
        i++;
    }while(i<11);

    file->flags = 0;
    file->chunks_head = file_data;
    char file_name[] = "test2.exe";
    file->name = (uint8_t *)file_name;
    file->name_len = sizeof(file_name);
    file->pescan_flags = 0;
    file->peattrib = NULL;
    file->next = NULL;

    ThreadVars *t = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow *f = NULL;
    uint8_t flags = 0;
    Signature *s = NULL;
    SigMatch *m = NULL;

    m = SCMalloc(sizeof(SigMatch));
    memset(m, 0, sizeof(SigMatch));

    DetectPescanData *pedata = SCMalloc(sizeof(DetectPescanData));
    memset(pedata, 0, sizeof(DetectPescanData));
    pedata->mode = DETECT_PESCAN_ANY;

    m->ctx = pedata;

    result = DetectPescanMatch(t, det_ctx,f, flags, file, s, m);

    SCFree(file);
    SCFree(file_data);
    SCFree(pedata);
    SCFree(m);

    return result;

}

int CheckScoreMatchTest01(void){
    int result = 0;
    DetectPescanData *pescore = DetectPescanParse(">=2");
    if (pescore != NULL && pescore->mode == DETECT_PESCAN_GTEQ) {
        peattrib_t peattrib;

        peattrib.pescore = 2.00000001;
        result = CheckScoreMatch(pescore, &peattrib);
    }
    DetectPescanFree(pescore);

    return result;
}

int CheckScoreMatchTest02(void){
    int result = 0;
    DetectPescanData *pescore = DetectPescanParse(">2");
    if (pescore != NULL && pescore->mode == DETECT_PESCAN_GT) {
        peattrib_t peattrib;

        peattrib.pescore = 2.00000001;
        result = !CheckScoreMatch(pescore, &peattrib);
    }
    DetectPescanFree(pescore);

    return result;
}

int DetectPescanParseTest01(void){
    int result = 0;

    DetectPescanData *pescore = NULL;

    pescore = DetectPescanParse("1.0");
    if(pescore != NULL){
        if(pescore->score1 == 1.0 && pescore->mode == DETECT_PESCAN_EQ) {
            result = 1;
        }
        SCFree(pescore);
    }

    return result;
}

int DetectPescanParseTest02(void){
    int result = 0;

    DetectPescanData *pescore = NULL;

    pescore = DetectPescanParse(">100.0");
    if(pescore != NULL) {
        if(pescore->score1 == 100.0 && pescore->mode == DETECT_PESCAN_GT)
            result = 1;
        SCFree(pescore);
    }
    return result;
}

int DetectPescanParseTest03(void){
    int result = 0;
    DetectPescanData *pescore = NULL;

    pescore = DetectPescanParse("");
    if(pescore != NULL && pescore->score1 == 0 &&
            pescore->mode == DETECT_PESCAN_ANY)
        result = 1;
    SCFree(pescore);

    return result;
}

int DetectPescanParseTest04(void) {
    int result = 0;
    DetectPescanData *pescore = NULL;

    pescore = DetectPescanParse("x");
    if(pescore == NULL)
        result = 1;
    SCFree(pescore);

    return result;
}

int DetectPescanParseTest05(void){
    int result = 0;
    DetectPescanData *pescore = NULL;

    pescore = DetectPescanParse("<5.");
    if(pescore != NULL && pescore->score1 == 5 &&
            pescore->mode == DETECT_PESCAN_LT)
        result = 1;
    SCFree(pescore);

    return result;
}

int DetectPescanParseTest06(void){
    int result = 0;
    DetectPescanData *pescore = NULL;

    pescore = DetectPescanParse(".-.1");
    if(pescore != NULL && pescore->score1 == 0 &&
            pescore->mode == DETECT_PESCAN_RA)
        result = 1;
    SCFree(pescore);

    return result;
}

int DetectPescanParseTest07(void){
    int result = 0;
    DetectPescanData *pescore = NULL;

    pescore = DetectPescanParse(">=5.");
    if(pescore != NULL && pescore->score1 == 5.0 &&
            pescore->mode == DETECT_PESCAN_GTEQ)
        result = 1;
    SCFree(pescore);

    return result;
}

int DetectPescanParseTest08(void){
    int result = 0;
    DetectPescanData *pescore = NULL;

    pescore = DetectPescanParse("==4");
    if (pescore == NULL)
        result = 1;
    SCFree(pescore);

    return result;
}

int DetectPescanParseTest09(void){
    int result = 0;
    DetectPescanData *pescore = NULL;

    pescore = DetectPescanParse("1.0-0.5");
    if (pescore == NULL)
        result = 1;
    SCFree(pescore);

    return result;
}

int DetectPescanParseTest10(void){
    int result = 0;
    DetectPescanData *pescore = NULL;

    pescore = DetectPescanParse(".-=.1");
    if(pescore != NULL && pescore->score1 == 0 &&
            pescore->mode == DETECT_PESCAN_RAEQ)
        result = 1;
    SCFree(pescore);

    return result;
}

int DetectPescanInitTest01(void){
    int result = 0;

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if(p == NULL)
        return 0;

    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    IPV4Hdr ip4h;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p+1);
    memset(&ip4h, 0, sizeof(ip4h));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->ip4h = &ip4h;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    if(de_ctx == NULL){
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any"
            " (msg:\"with pescan\"; pescan; sid:12345;)");
    if(s == NULL)
        goto end;


    s = s->next = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any"
            " (msg:\"with pescan and a min score for 1\"; pescan:1 ; sid:12345;)");
    if(s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if(PacketAlertCheck(p,1)){
        printf("sid 1 alerted, but shouldnt have");
        goto cleanup;
    }else if(PacketAlertCheck(p,2)){
        printf("sid 2 alerted, but shouldnt have");
        goto cleanup;
    }

    result = 1;

    cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    end:
    SCFree(p);
    return result;
}

int DetectPescanSetupTest01(void){

    int result = 0;
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;

    s = SigAlloc();
    result = DetectPescanSetup(de_ctx, s, "1.0");
    SCFree(s);

    return result;
}

int DetectPescanSetupTest02(void){

    int result = 0;
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;

    s = SigAlloc();
    result = DetectPescanSetup(de_ctx, s, "x");

    SCFree(s);

    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers UnitTests for Detect-Pescan
 */
static void DetectPescanRegisterTests(void){
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectPescanTest01", DetectPescanTest01, -1);
    UtRegisterTest("DetectPescanMatchTest01", DetectPescanMatchTest01, 1);
    UtRegisterTest("DetectPescanMatchTest02", DetectPescanMatchTest02, 1);
    UtRegisterTest("PescanCheckScoreMatchTest01", CheckScoreMatchTest01, 1);
    UtRegisterTest("PescanCheckScoreMatchTest02", CheckScoreMatchTest02, 1);
    UtRegisterTest("DetectPescanParseTest01", DetectPescanParseTest01, 1);
    UtRegisterTest("DetectPescanParseTest02", DetectPescanParseTest02, 1);
    UtRegisterTest("DetectPescanParseTest03", DetectPescanParseTest03, 1);
    UtRegisterTest("DetectPescanParseTest04", DetectPescanParseTest04, 1);
    UtRegisterTest("DetectPescanParseTest05", DetectPescanParseTest05, 1);
    UtRegisterTest("DetectPescanParseTest06", DetectPescanParseTest06, 1);
    UtRegisterTest("DetectPescanParseTest07", DetectPescanParseTest07, 1);
    UtRegisterTest("DetectPescanParseTest08", DetectPescanParseTest08, 1);
    UtRegisterTest("DetectPescanParseTest09", DetectPescanParseTest09, 1);
    UtRegisterTest("DetectPescanParseTest10", DetectPescanParseTest10, 1);
    UtRegisterTest("DetectPescanInitTest01", DetectPescanInitTest01, 1);
    UtRegisterTest("DetectPescanSetupTest01", DetectPescanSetupTest01, 0);
    UtRegisterTest("DetectPescanSetupTest02", DetectPescanSetupTest02, -1);

#endif /* UNITTESTS */
}
