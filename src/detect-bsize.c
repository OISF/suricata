/* Copyright (C) 2017 Open Information Security Foundation
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
 * Implements the bsize generic buffer length keyword
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-content.h"

#include "detect-bsize.h"

#include "util-misc.h"

/*prototypes*/
static int DetectBsizeSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectBsizeFree (void *);
#ifdef UNITTESTS
static void DetectBsizeRegisterTests (void);
#endif

/**
 * \brief Registration function for bsize: keyword
 */

void DetectBsizeRegister(void)
{
    sigmatch_table[DETECT_BSIZE].name = "bsize";
    sigmatch_table[DETECT_BSIZE].desc = "match on the length of a buffer";
    sigmatch_table[DETECT_BSIZE].url = DOC_URL DOC_VERSION "/rules/payload-keywords.html#bsize";
    sigmatch_table[DETECT_BSIZE].Match = NULL;
    sigmatch_table[DETECT_BSIZE].Setup = DetectBsizeSetup;
    sigmatch_table[DETECT_BSIZE].Free = DetectBsizeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_BSIZE].RegisterTests = DetectBsizeRegisterTests;
#endif
}

#define DETECT_BSIZE_LT 0
#define DETECT_BSIZE_GT 1
#define DETECT_BSIZE_RA 2
#define DETECT_BSIZE_EQ 3

typedef struct DetectBsizeData {
    uint8_t mode;
    uint64_t lo;
    uint64_t hi;
} DetectBsizeData;

/** \brief bsize match function
 *
 *  \param ctx match ctx
 *  \param buffer_size size of the buffer
 *  \param eof is the buffer closed?
 *
 *  \retval r 1 match, 0 no match, -1 can't match
 *
 *  \todo check logic around < vs <=
 */
int DetectBsizeMatch(const SigMatchCtx *ctx, const uint64_t buffer_size, bool eof)
{
    const DetectBsizeData *bsz = (const DetectBsizeData *)ctx;
    switch (bsz->mode) {
        case DETECT_BSIZE_LT:
            if (buffer_size < bsz->lo) {
                return 1;
            }
            return -1;

        case DETECT_BSIZE_GT:
            if (buffer_size > bsz->lo) {
                return 1;
            } else if (eof) {
                return -1;
            }
            return 0;

        case DETECT_BSIZE_EQ:
            if (buffer_size == bsz->lo) {
                return 1;
            } else if (buffer_size > bsz->lo) {
                return -1;
            } else if (eof) {
                return -1;
            } else {
                return 0;
            }

        case DETECT_BSIZE_RA:
            if (buffer_size > bsz->lo && buffer_size < bsz->hi) {
                return 1;
            } else if (buffer_size <= bsz->lo && eof) {
                return -1;
            } else if (buffer_size <= bsz->lo) {
                return 0;
            } else if (buffer_size >= bsz->hi) {
                return -1;
            }
    }
    return 0;
}

#define ERR(...) do { \
    char _buf[2048];              \
    snprintf(_buf, sizeof(_buf), __VA_ARGS__);  \
    SCLogError(SC_ERR_INVALID_RULE_ARGUMENT, "bsize: bad input, %s", _buf); \
} while(0)

/**
 * \brief This function is used to parse bsize options passed via bsize: keyword
 *
 * \param bsizestr Pointer to the user provided bsize options
 *
 * \retval bsized pointer to DetectBsizeData on success
 * \retval NULL on failure
 */

static DetectBsizeData *DetectBsizeParse (const char *str)
{
    uint32_t lo = 0;
    uint32_t hi = 0;

    if (str == NULL)
        return NULL;

    size_t len = strlen(str);
    if (len == 0)
        return NULL;

    /* allow for leading spaces */
    while (isspace(*str))
        (str++);
    len = strlen(str);
    if (len == 0)
        return NULL;

    int mode = DETECT_BSIZE_EQ;
    switch (*str) {
        case '>':
            mode = DETECT_BSIZE_GT;
            str++;
            break;
        case '<':
            mode = DETECT_BSIZE_LT;
            str++;
            break;
    }

    /* allow for spaces between mode and value */
    while (isspace(*str))
        (str++);

    char str1[11], *p = str1;
    memset(str1, 0, sizeof(str1));
    while (*str && isdigit(*str)) {
        if (p - str1 >= (int)sizeof(str1))
            return NULL;
        *p++ = *str++;
    }
    /* skip trailing space */
    while (*str && isspace(*str)) {
        str++;
    }
    if (*str == '\0') {
        // done
        SCLogDebug("str1 '%s'", str1);

        uint64_t val = 0;
        if (ParseSizeStringU64(str1, &val) < 0) {
            return NULL;
        }
        lo = val;

    } else if (*str == '<') {
        str++;
        if (*str != '>') {
            ERR("only '<>' allowed");
            return NULL;
        }
        str++;

        // range
        if (mode != DETECT_BSIZE_EQ) {
            ERR("mode already set");
            return NULL;
        }
        mode = DETECT_BSIZE_RA;

        uint64_t val = 0;
        if (ParseSizeStringU64(str1, &val) < 0) {
            return NULL;
        }
        lo = val;

        /* allow for spaces between mode and value */
        while (*str && isspace(*str))
            (str++);

        char str2[11];
        p = str2;
        memset(str2, 0, sizeof(str2));
        while (*str && isdigit(*str)) {
            if (p - str2 >= (int)sizeof(str2))
                return NULL;
            *p++ = *str++;
        }
        /* skip trailing space */
        while (*str && isspace(*str)) {
            str++;
        }
        if (*str == '\0') {
            // done
            SCLogDebug("str2 '%s'", str2);

            if (ParseSizeStringU64(str2, &val) < 0) {
                ERR("'%s' is not a valid u32", str2);
                return NULL;
            }
            hi = val;
            if (lo >= hi) {
                ERR("%u > %u", lo, hi);
                return NULL;
            }

        } else {
            ERR("trailing data");
            return NULL;
        }

    } else {
        ERR("'%s'", str);
        return NULL;
    }

    DetectBsizeData *bsz = SCCalloc(1, sizeof(*bsz));
    if (bsz == NULL) {
        return NULL;
    }
    bsz->mode = (uint8_t)mode;
    bsz->lo = lo;
    bsz->hi = hi;
    return bsz;
}

/**
 * \brief this function is used to parse bsize data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param bsizestr pointer to the user provided bsize options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectBsizeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *sizestr)
{
    SCEnter();
    SigMatch *sm = NULL;

    int list = s->init_data->list;
    if (list == DETECT_SM_LIST_NOTSET)
        SCReturnInt(-1);

    DetectBsizeData *bsz = DetectBsizeParse(sizestr);
    if (bsz == NULL)
        goto error;
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->type = DETECT_BSIZE;
    sm->ctx = (void *)bsz;

    SigMatchAppendSMToList(s, sm, list);

    SCReturnInt(0);

error:
    DetectBsizeFree(bsz);
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectBsizeData
 *
 * \param ptr pointer to DetectBsizeData
 */
void DetectBsizeFree(void *ptr)
{
    if (ptr == NULL)
        return;

    DetectBsizeData *bsz = (DetectBsizeData *)ptr;
    SCFree(bsz);
}

#ifdef UNITTESTS
#include "tests/detect-bsize.c"
#endif
