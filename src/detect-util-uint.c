/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 *
 */

#include "suricata-common.h"

#include "util-byte.h"
#include "detect-parse.h"
#include "detect-util-uint.h"

/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^\\s*([0-9]*)?\\s*([<>=-]+)?\\s*([0-9]+)?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;


int DetectU32Match(const uint32_t parg, const DetectU32Data *du32)
{
    switch (du32->mode) {
        case DETECT_UINT_EQ:
            if (parg == du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_LT:
            if (parg < du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_GT:
            if (parg > du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_RA:
            if (parg > du32->arg1 && parg < du32->arg2) {
                return 1;
            }
            return 0;
        default:
            BUG_ON("unknown mode");
    }
    return 0;
}


/**
 * \brief This function is used to parse u32 options passed via some u32 keyword
 *
 * \param u32str Pointer to the user provided u32 options
 *
 * \retval DetectU32Data pointer to DetectU32Data on success
 * \retval NULL on failure
 */

DetectU32Data *DetectU32Parse (const char *u32str)
{
    DetectU32Data *u32d = NULL;
    char arg1[16] = "";
    char arg2[16] = "";
    char arg3[16] = "";

#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, u32str, strlen(u32str), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }

    res = pcre_copy_substring((char *) u32str, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_copy_substring((char *) u32str, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_copy_substring((char *) u32str, ov, MAX_SUBSTRINGS, 3, arg3, sizeof(arg3));
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                goto error;
            }
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    u32d = SCMalloc(sizeof (DetectU32Data));
    if (unlikely(u32d == NULL))
        goto error;

    if (strlen(arg2) > 0) {
        /*set the values*/
        switch(arg2[0]) {
            case '<':
            case '>':
                if (strlen(arg3) == 0)
                    goto error;

                if (ByteExtractStringUint32(&u32d->arg1, 10, strlen(arg3), arg3) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
                    goto error;
                }

                SCLogDebug("u32 is %"PRIu32"",u32d->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                if (arg2[0] == '<') {
                    u32d->mode = DETECT_UINT_LT;
                } else { // arg2[0] == '>'
                    u32d->mode = DETECT_UINT_GT;
                }
                break;
            case '-':
                if (strlen(arg1)== 0)
                    goto error;
                if (strlen(arg3)== 0)
                    goto error;

                u32d->mode = DETECT_UINT_RA;
                if (ByteExtractStringUint32(&u32d->arg1, 10, strlen(arg1), arg1) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
                    goto error;
                }
                if (ByteExtractStringUint32(&u32d->arg2, 10, strlen(arg3), arg3) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
                    goto error;
                }

                SCLogDebug("u32 is %"PRIu32" to %"PRIu32"",u32d->arg1, u32d->arg2);
                if (u32d->arg1 >= u32d->arg2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid u32 range. ");
                    goto error;
                }
                break;
            default:
                u32d->mode = DETECT_UINT_EQ;

                if (strlen(arg2) > 0 ||
                    strlen(arg3) > 0 ||
                    strlen(arg1) == 0)
                    goto error;

                if (ByteExtractStringUint32(&u32d->arg1, 10, strlen(arg1), arg1) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
                    goto error;
                }
        }
    } else {
        u32d->mode = DETECT_UINT_EQ;

        if (strlen(arg3) > 0 ||
            strlen(arg1) == 0)
            goto error;

        if (ByteExtractStringUint32(&u32d->arg1, 10, strlen(arg1), arg1) < 0) {
            SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
            goto error;
        }
    }

    return u32d;

error:
    if (u32d)
        SCFree(u32d);
    return NULL;
}

void
PrefilterPacketU32Set(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectU32Data *a = smctx;
    v->u8[0] = a->mode;
    v->u32[1] = a->arg1;
    v->u32[2] = a->arg2;
}

bool
PrefilterPacketU32Compare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectU32Data *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u32[1] == a->arg1 &&
        v.u32[2] == a->arg2)
        return true;
    return false;
}

static int g_detect_u32_registered = 0;

void DetectU32Register(void)
{
    if (g_detect_u32_registered == 0) {
        // register only once
        DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
        g_detect_u32_registered = 1;
    }
}
